#!/usr/bin/env bash
#
# Deploy Ghost Protocol to its host.
#
#   ./deploy/deploy.sh            # deploy current HEAD
#   ./deploy/deploy.sh --rollback # flip back to the previous release
#
# Ships the committed tree only. The working directory is never uploaded, so an
# accidental local edit cannot reach production. The release is built before the
# symlink moves and the symlink is reverted if the health check fails, so a
# broken build never becomes the live one.
set -euo pipefail

# Host and key come from deploy/deploy.env, which is gitignored. Nothing here
# hardcodes an address: this script is public and that file is not.
ENV_FILE=${GHOST_DEPLOY_ENV:-$(dirname "$0")/deploy.env}
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

HOST=${DEPLOY_HOST:?set DEPLOY_HOST, or copy deploy/deploy.env.example to deploy/deploy.env}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519}
VHOST=${GHOST_VHOST:-}
APP=ghost-protocol
APP_USER=ghostmcp
ROOT=/opt/$APP
RUNTIME=$ROOT/runtime/bin
PORT=17719
KEEP_RELEASES=5

SSH=(ssh -i "$SSH_KEY" -o ConnectTimeout=10 "root@$HOST")

log()  { printf '\033[1;35m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

if [[ ${1:-} == --rollback ]]; then
  log "Rolling back on $HOST"
  "${SSH[@]}" "set -e
    PREV=\$(ls -1dt $ROOT/releases/*/ | sed -n 2p)
    [ -n \"\$PREV\" ] || { echo 'no previous release'; exit 1; }
    sudo -n -u $APP_USER ln -sfn \"\${PREV%/}\" $ROOT/current
    sudo -n systemctl restart $APP-browser
    sudo -n systemctl restart $APP
    echo \"rolled back to \$PREV\""
  exit 0
fi

command -v git >/dev/null || fail "git not found"
[[ -z $(git status --porcelain) ]] || log "WARNING: working tree is dirty; deploying committed HEAD only"

SHA=$(git rev-parse --short HEAD)
REL=$ROOT/releases/$SHA
log "Deploying $SHA to $HOST"

# Grants first, before a byte moves. A deploy that fails halfway through
# because a sudo rule is missing is worse than one that refuses to start.
log "Checking sudo grants"
"${SSH[@]}" "set -e
  sudo -n -l -u $APP_USER true >/dev/null || { echo 'cannot run as $APP_USER'; exit 1; }
  sudo -n -l /usr/bin/systemctl restart $APP >/dev/null || { echo 'cannot restart $APP'; exit 1; }
  sudo -n -l /usr/bin/systemctl restart $APP-browser >/dev/null || { echo 'cannot restart $APP-browser'; exit 1; }
  echo '  grants ok'"

log "Uploading source"
# Runs as $APP_USER rather than root: the tree is owned by that account, so
# creating, extracting into and removing release directories are ordinary file
# operations for it, and files it extracts already belong to it.
git archive --format=tar HEAD | "${SSH[@]}" "set -e
  sudo -n -u $APP_USER mkdir -p '$REL'
  sudo -n -u $APP_USER chmod 0755 '$REL'
  sudo -n -u $APP_USER tar -x -C '$REL'"

log "Installing dependencies and building"
# HOME and the npm cache are forced into the app's own tree. The service account
# is created with --no-create-home, so npm's default cache path under /home does
# not exist and is not writable, and npm fails on the first write rather than
# falling back to anywhere sensible.
"${SSH[@]}" "set -e
  sudo -n -u $APP_USER env PATH=$RUNTIME:\$PATH HOME=$ROOT npm_config_cache=$ROOT/.npm sh -c '
    set -a; . /etc/$APP/env; set +a
    cd $REL
    # --include=dev is required: NODE_ENV=production in the env file otherwise
    # makes npm skip devDependencies, and typescript is one of them.
    npm ci --include=dev --no-audit --no-fund
    npm run build
    # The build output is all the service needs at runtime. Dropping the dev
    # dependencies afterwards keeps the release directory to a sensible size.
    npm prune --omit=dev --no-audit --no-fund
  '" 2>&1 | grep -vE '^npm (warn|notice)' | tail -20

# The browser account reads the built code out of this tree. It never writes to
# it, and a release the browser cannot read is a browser unit that will not
# start.
log "Opening read access for the browser account"
"${SSH[@]}" "sudo -n -u $APP_USER chmod -R a+rX '$REL'"

log "Flipping symlink and restarting"
# readlink WITHOUT -f: it prints a target only when the path really is a
# symlink, and nothing otherwise. `readlink -f` resolves a path that does not
# exist yet and happily returns the link's own location, so on a first deploy
# PREV became \$ROOT/current and the revert below pointed the link at itself.
# That leaves ELOOP on every access and no way back except deleting it by hand.
"${SSH[@]}" "set -e
  PREV=\$(readlink $ROOT/current 2>/dev/null || true)
  sudo -n -u $APP_USER ln -sfn $REL $ROOT/current
  # Browser first: the MCP service reconnects on its own, but starting it
  # against an old browser build wastes a restart.
  sudo -n systemctl restart $APP-browser
  sudo -n systemctl restart $APP

  for i in \$(seq 1 40); do
    body=\$(curl -s --max-time 5 http://127.0.0.1:$PORT/healthz || true)
    case \"\$body\" in
      *'\"ok\":true'*) echo \"  healthy after \${i}s: \$body\"; exit 0 ;;
    esac
    sleep 1
  done

  echo 'health check failed' >&2
  sudo -n journalctl -u $APP -n 30 --no-pager >&2 || true
  if [ -n \"\$PREV\" ] && [ -d \"\$PREV\" ] && [ \"\$PREV\" != $ROOT/current ]; then
    echo \"  reverting to \$PREV\" >&2
    sudo -n -u $APP_USER ln -sfn \"\$PREV\" $ROOT/current
    sudo -n systemctl restart $APP-browser
    sudo -n systemctl restart $APP
  else
    echo '  no previous release to revert to; the new one is left in place' >&2
  fi
  exit 1"

# Computed here, not in the remote shell: expanding it there would leave
# KEEP_RELEASES unset and turn this into `tail -n +1`, which deletes every
# release except the current one and destroys the rollback target.
SKIP_FROM=$((KEEP_RELEASES + 1))

log "Pruning old releases (keeping $KEEP_RELEASES)"
"${SSH[@]}" "set -e
  cd $ROOT/releases
  CURRENT=\$(basename \$(readlink -f $ROOT/current))
  ls -1dt */ | sed 's#/\$##' | tail -n +$SKIP_FROM | while read -r old; do
    [ \"\$old\" = \"\$CURRENT\" ] && continue
    echo \"  removing \$old\"
    sudo -n -u $APP_USER rm -rf \"\$old\"
  done
  echo \"  releases kept: \$(ls -1d */ | wc -l)\""

log "Deployed $SHA${VHOST:+ — https://$VHOST/mcp}"
