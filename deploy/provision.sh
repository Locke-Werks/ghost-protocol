#!/usr/bin/env bash
#
# First-time setup for Ghost Protocol on its host. Run once, as root:
#
#   scp deploy/provision.sh deploy/*.service deploy/*.caddy root@<host>:/tmp/
#   scp -r deploy/fail2ban root@<host>:/tmp/
#   ssh root@<host> 'GHOST_VHOST=ghost.example.com bash /tmp/provision.sh'
#
# Idempotent: every step checks before it acts, so re-running after a failure
# picks up where it stopped. It creates accounts, the tree, the database, the
# secrets and the units. It does not deploy any code; deploy.sh does that.
#
# It prints a summary of what it made at the end. If you track deployments
# anywhere, that is what to record.
set -euo pipefail

APP=ghost-protocol
MCP_USER=ghostmcp
BROWSER_USER=ghostbrowser
ROOT=/opt/$APP
CONF=/etc/$APP
DB_NAME=ghost_protocol
DB_ROLE=ghost_protocol_rw
MCP_PORT=17719
BROWSER_PORT=17716
PROXY_PORT=17715
VHOST=${GHOST_VHOST:?set GHOST_VHOST to the public name this relay answers on}
NODE_VERSION=${NODE_VERSION:-24.13.0}

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"

# ---------------------------------------------------------------- port check
note "Checking the ports are free"
for port in $MCP_PORT $BROWSER_PORT $PROXY_PORT; do
  if ss -tlnH "sport = :$port" | grep -q .; then
    die "port $port is already bound; claim a different one and update the config"
  fi
done

# ------------------------------------------------------------------ accounts
for user in $MCP_USER $BROWSER_USER; do
  if id "$user" >/dev/null 2>&1; then
    note "User $user already exists"
  else
    note "Creating system user $user"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
done

# --------------------------------------------------------------------- tree
note "Creating $ROOT"
install -d -o "$MCP_USER" -g "$MCP_USER" -m 0755 "$ROOT" "$ROOT/releases" "$ROOT/runtime"
# 0755 rather than 0750: the browser account has to read the built code and the
# vendored Node out of this tree. It reads; it never writes.

# ------------------------------------------------------------------- Node 24
if [ -x "$ROOT/runtime/bin/node" ] && "$ROOT/runtime/bin/node" -v | grep -q "^v${NODE_VERSION%%.*}\."; then
  note "Node $("$ROOT/runtime/bin/node" -v) already vendored"
else
  # The system node is v20 and past end of life, shared with nursery and
  # deadletter. Vendoring rather than upgrading it keeps this deployment from
  # being able to break those two.
  note "Vendoring Node $NODE_VERSION into $ROOT/runtime"
  tmp=$(mktemp -d)
  tarball="node-v${NODE_VERSION}-linux-x64.tar.xz"
  curl -fsSL -o "$tmp/$tarball" "https://nodejs.org/dist/v${NODE_VERSION}/${tarball}"
  curl -fsSL -o "$tmp/SHASUMS256.txt" "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt"
  ( cd "$tmp" && grep " ${tarball}\$" SHASUMS256.txt | sha256sum -c - ) \
    || die "Node tarball failed its checksum"
  tar -xJf "$tmp/$tarball" -C "$tmp"
  rm -rf "$ROOT/runtime"
  mv "$tmp/node-v${NODE_VERSION}-linux-x64" "$ROOT/runtime"
  chown -R "$MCP_USER:$MCP_USER" "$ROOT/runtime"
  chmod -R a+rX "$ROOT/runtime"
  rm -rf "$tmp"
  note "Vendored $("$ROOT/runtime/bin/node" -v)"
fi

# -------------------------------------------------------------------- Chrome
if [ -x /opt/google/chrome/chrome ]; then
  note "Chrome already installed: $(/opt/google/chrome/chrome --version)"
else
  note "Installing Google Chrome from Google's apt repository"
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
    | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
    > /etc/apt/sources.list.d/google-chrome.list
  apt-get update -qq
  apt-get install -y -qq google-chrome-stable
  note "Installed $(/opt/google/chrome/chrome --version)"
fi

# Screenshots of a box with no fonts are boxes. These cover Latin, CJK and
# emoji, which is most of what a documentation site will throw at it.
note "Installing fonts"
apt-get install -y -qq fonts-liberation fonts-noto-core fonts-noto-cjk fonts-noto-color-emoji >/dev/null

# Chrome's sandbox needs unprivileged user namespaces. Fail loudly here rather
# than letting someone reach for --no-sandbox when the browser will not start.
userns=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)
[ "$userns" = "1" ] || die "kernel.unprivileged_userns_clone is 0; Chrome's sandbox cannot start"
apparmor_userns=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)
[ "$apparmor_userns" = "0" ] || warn "kernel.apparmor_restrict_unprivileged_userns is 1; Chrome may need an AppArmor profile"

# ------------------------------------------------------------------ database
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_ROLE'" | grep -q 1; then
  note "Role $DB_ROLE already exists"
  DB_PASSWORD=$(grep -oP '^DB_PASSWORD=\K.*' "$CONF/db_password" 2>/dev/null || true)
  [ -n "${DB_PASSWORD:-}" ] || warn "role exists but $CONF/db_password is missing; reset it by hand"
else
  note "Creating role $DB_ROLE and database $DB_NAME"
  DB_PASSWORD=$(openssl rand -base64 33 | tr -d '/+=' | head -c 40)
  sudo -u postgres psql -qc "CREATE ROLE $DB_ROLE LOGIN PASSWORD '$DB_PASSWORD'"
  sudo -u postgres psql -qc "CREATE DATABASE $DB_NAME OWNER $DB_ROLE"
  # Loopback only. Nothing about this application wants its database reachable
  # from anywhere but the machine it runs on.
  sudo -u postgres psql -qc "REVOKE ALL ON DATABASE $DB_NAME FROM PUBLIC"
fi

# ------------------------------------------------------------------- secrets
note "Creating $CONF"
# Written while still root-owned, then handed over. Nothing here writes into a
# directory a service account already controls.
install -d -o root -g root -m 0711 "$CONF"

if [ ! -f "$CONF/browser_ws_path" ]; then
  # The websocket path is the only thing between another local account and
  # control of the browser, so it is a secret and it is long.
  openssl rand -hex 24 > "$CONF/browser_ws_path"
fi
WS_PATH=$(cat "$CONF/browser_ws_path")

if [ ! -f "$CONF/env" ]; then
  note "Writing $CONF/env"
  [ -n "${DB_PASSWORD:-}" ] || die "no database password to write; delete the role and re-run"
  {
    echo "DATABASE_URL=postgres://$DB_ROLE:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME"
    echo "GHOST_BROWSER_WS_PATH=$WS_PATH"
    # A stolen credentials table is useless without this, and it lives in the
    # service environment rather than anywhere near the database.
    echo "GHOST_PASSWORD_PEPPER=$(openssl rand -base64 33 | tr -d '/+=' | head -c 44)"
  } > "$CONF/env"
  printf 'DB_PASSWORD=%s\n' "$DB_PASSWORD" > "$CONF/db_password"
fi

if [ ! -f "$CONF/browser.env" ]; then
  note "Writing $CONF/browser.env"
  # Deliberately thin. The browser account gets the websocket path and the
  # proxy address, and nothing else: no database URL, no pepper, no key.
  {
    echo "GHOST_BROWSER_WS_PATH=$WS_PATH"
    echo "GHOST_BROWSER_PORT=$BROWSER_PORT"
    echo "GHOST_EGRESS_PROXY=http://127.0.0.1:$PROXY_PORT"
  } > "$CONF/browser.env"
fi

# One pass, and the end state is what matters:
#
#   dir            root:root         0711   traversable by both, listable by neither
#   env            root:ghostmcp     0640   database URL, pepper, ws path
#   db_password    root:ghostmcp     0640
#   browser_ws_path root:ghostmcp    0640
#   browser.env    root:ghostbrowser 0640   ws path and proxy address, nothing else
#
# The directory deviates from the house `root:<app> 0750` because two different
# service accounts each need to reach one file inside it and neither may read
# the other's. 0711 grants traversal without listing; the file modes are what
# actually separate them.
chown root:root "$CONF"
chmod 0711 "$CONF"
chown root:"$MCP_USER" "$CONF/env" "$CONF/db_password" "$CONF/browser_ws_path"
chown root:"$BROWSER_USER" "$CONF/browser.env"
chmod 0640 "$CONF/env" "$CONF/db_password" "$CONF/browser_ws_path" "$CONF/browser.env"

if [ ! -f "$CONF/oauth_signing_key.pem" ]; then
  warn "No OAuth signing key yet. After the first deploy, run:"
  warn "  sudo -u $MCP_USER $ROOT/runtime/bin/node $ROOT/current/dist/cli.js oauth keygen $CONF/oauth_signing_key.pem"
  warn "  chown $MCP_USER:$MCP_USER $CONF/oauth_signing_key.pem && chmod 0600 $CONF/oauth_signing_key.pem"
fi

# --------------------------------------------------------------------- units
note "Installing systemd units"
for unit in ghost-protocol.service ghost-protocol-browser.service; do
  if [ -f "/tmp/$unit" ]; then
    install -o root -g root -m 0644 "/tmp/$unit" "/etc/systemd/system/$unit"
  else
    warn "/tmp/$unit not found; copy deploy/$unit up and re-run"
  fi
done
systemctl daemon-reload

# --------------------------------------------------------------------- Caddy
if [ -f /tmp/ghost-protocol-site.caddy ]; then
  note "Installing the Caddy site block"
  install -o root -g root -m 0644 /tmp/ghost-protocol-site.caddy /etc/caddy/conf.d/ghost-protocol-site.caddy
  install -d -o caddy -g caddy -m 0755 /var/log/caddy

  # Create the log file as caddy before anything else can, because
  # `caddy validate` does not merely parse: it provisions the config, which
  # opens every log writer in it. Run as root that leaves a root:root 0600 file
  # behind, and the real Caddy, running as caddy, then cannot open its own log.
  # The reload fails atomically so the box keeps serving the old config, which
  # means the symptom is a deploy that looks broken while nothing is down.
  install -o caddy -g caddy -m 0640 /dev/null /var/log/caddy/ghost-protocol.log
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null \
    || die "Caddyfile does not validate; the site block was installed but Caddy was not reloaded"
  # Belt, in case validate created something else as root.
  chown caddy:caddy /var/log/caddy/ghost-protocol.log
  # Reload, never restart: a restart drops every other vhost on this box.
  systemctl reload caddy
else
  warn "/tmp/ghost-protocol-site.caddy not found; the vhost was not installed"
fi

# ------------------------------------------------------------------ fail2ban
if [ -d /tmp/fail2ban ]; then
  note "Installing fail2ban filters and jail"
  install -o root -g root -m 0644 /tmp/fail2ban/filter.d/*.conf /etc/fail2ban/filter.d/
  install -o root -g root -m 0644 /tmp/fail2ban/jail.d/ghost-protocol.conf /etc/fail2ban/jail.d/
  systemctl reload fail2ban || systemctl restart fail2ban
fi

# ------------------------------------------------------------------- sudoers
note "Installing the deploy sudoers drop-in"
cat > /tmp/ghost-sudoers <<SUDOERS
# Ghost Protocol deploys. The tree is owned by $MCP_USER, so unpack, build and
# the symlink flip are ordinary file operations for that account. The only step
# that genuinely needs root is the restart.
root ALL=($MCP_USER) NOPASSWD: ALL
root ALL=(root) NOPASSWD: /usr/bin/systemctl restart $APP, /usr/bin/systemctl restart $APP-browser, /usr/bin/systemctl start $APP, /usr/bin/systemctl start $APP-browser, /usr/bin/systemctl stop $APP, /usr/bin/systemctl stop $APP-browser, /usr/bin/systemctl status $APP, /usr/bin/systemctl status $APP-browser, /usr/bin/journalctl -u $APP*
SUDOERS
visudo -cf /tmp/ghost-sudoers >/dev/null || die "generated sudoers does not validate"
install -o root -g root -m 0440 /tmp/ghost-sudoers /etc/sudoers.d/ghost-protocol
rm -f /tmp/ghost-sudoers

# -------------------------------------------------------------------- report
cat <<REPORT

$(note "Provisioned. Next:")

  1. Copy config/ghost-protocol.toml.example to $CONF/ghost-protocol.toml.
     Set issuer and resource to https://$VHOST, put this host's own public
     address in deny_addresses, then chown root:$MCP_USER and chmod 0640.
  2. Deploy the code:            ./deploy/deploy.sh
  3. Mint the OAuth signing key: see the warning above.
  4. Set a login password:       printf '%s\n' 'your-password' | \
                                   sudo -u $MCP_USER env GHOST_CONFIG=$CONF/ghost-protocol.toml \
                                   \$(grep -h . $CONF/env | tr '\n' ' ') \
                                   $ROOT/runtime/bin/node $ROOT/current/dist/cli.js passwd <principal>
  5. systemctl enable --now $APP-browser $APP

What this created, for whatever you record deployments in:

  service users   $MCP_USER      runs the MCP service, holds the secrets
                  $BROWSER_USER  runs Chrome, holds nothing
  tree            $ROOT, owned $MCP_USER, releases/ plus a current symlink
  units           $APP.service, $APP-browser.service
  listens         127.0.0.1:$MCP_PORT     MCP
                  127.0.0.1:$BROWSER_PORT     browser CDP
                  127.0.0.1:$PROXY_PORT     egress guard
                  all loopback; the reverse proxy is the only public surface
  public at       $VHOST
  database        $DB_NAME, role $DB_ROLE, loopback only
  config          $CONF, dir root:root 0711
                    env, db_password, browser_ws_path  root:$MCP_USER 0640
                    browser.env                        root:$BROWSER_USER 0640
                    oauth_signing_key.pem              $MCP_USER:$MCP_USER 0600
  runtime         vendored Node $NODE_VERSION at $ROOT/runtime
                  google-chrome-stable from Google's apt repository
  hardening       full block on the MCP unit; the browser unit deviates in four
                  places so Chrome's own sandbox can run, each marked in the file

REPORT
