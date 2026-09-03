// Operator commands. Everything that needs a database or a key file lives here
// rather than in the service, so the service never grows a code path that
// writes a credential.

import { writeFileSync, chmodSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadConfig } from './config.js';
import { connect, migrate, prune } from './db.js';
import { generateSigningKeyPem, loadSigningKey } from './oauth/jwt.js';
import { hashPassword } from './oauth/passwords.js';
import { setLevel } from './util/log.js';

const HERE = dirname(fileURLToPath(import.meta.url));

const USAGE = `ghost-cli — Ghost Protocol operator commands

  passwd <principal>            set or replace a login password
  oauth keygen <path>           write a new ES256 signing key (refuses to overwrite)
  oauth kid <path>              print the key id a signing key will publish
  oauth clients                 list registered OAuth clients
  oauth revoke <client_id>      delete a client and every grant it holds
  migrate                       apply pending SQL migrations and exit
  prune [days]                  drop expired grants and request log older than N days (default 90)
  log [n]                       show the last N relayed requests (default 20)

Reads GHOST_CONFIG for the config path and DATABASE_URL for the connection.
`;

/** True when there is a person at the other end of stdin. */
function interactive(): boolean {
  return process.stdin.isTTY === true;
}

/**
 * Read the password from stdin when it is a pipe.
 *
 * Provisioning wants to be scriptable, and stdin is the one channel that is
 * safe for it: a password passed as an argument shows up in `ps` output and in
 * shell history, which is why there is no --password flag.
 */
async function readPiped(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8').split('\n')[0]!.replace(/\r$/, '');
}

async function prompt(question: string, hidden: boolean): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  if (!hidden) {
    const answer = await rl.question(question);
    rl.close();
    return answer;
  }
  // readline has no built-in masking. Overriding the interface's own
  // _writeToOutput suppresses the per-keystroke echo, which is what keeps the
  // password off the terminal and out of the scrollback.
  //
  // The override has to go on the Interface, not on its output stream: putting
  // it on the stream does nothing and the password is echoed in full.
  process.stdout.write(question);
  (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = () => {};
  const answer = await rl.question('');
  rl.close();
  process.stdout.write('\n');
  return answer;
}

async function main(): Promise<number> {
  setLevel(process.env.GHOST_LOG_LEVEL ?? 'warn');
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === 'help' || command === '--help') {
    process.stdout.write(USAGE);
    return 0;
  }

  // Key commands touch no database, so they work before the box has one.
  if (command === 'oauth' && rest[0] === 'keygen') {
    const path = rest[1];
    if (!path) {
      process.stderr.write('usage: ghost-cli oauth keygen <path>\n');
      return 2;
    }
    if (existsSync(path)) {
      // Overwriting a signing key invalidates every token it minted and every
      // JWKS entry a client has cached. That is a decision, not a side effect.
      process.stderr.write(`refusing to overwrite ${path}\nMove the old key aside first, and keep it listed in previous_key_paths until its tokens age out.\n`);
      return 1;
    }
    const pem = await generateSigningKeyPem();
    writeFileSync(path, pem, { mode: 0o600 });
    chmodSync(path, 0o600);
    const key = await loadSigningKey(path);
    process.stdout.write(`wrote ${path}\n  alg: ${key.alg}\n  kid: ${key.kid}\n`);
    return 0;
  }

  if (command === 'oauth' && rest[0] === 'kid') {
    const path = rest[1];
    if (!path) {
      process.stderr.write('usage: ghost-cli oauth kid <path>\n');
      return 2;
    }
    const key = await loadSigningKey(path);
    process.stdout.write(`${key.kid}  (${key.alg})\n`);
    return 0;
  }

  const configPath = process.env.GHOST_CONFIG ?? join(HERE, '..', 'config', 'ghost-protocol.toml');
  const cfg = loadConfig(configPath);
  const db = connect(cfg.databaseUrl);

  try {
    switch (command) {
      case 'migrate': {
        await migrate(db, join(HERE, '..', 'sql', 'migrations'));
        process.stdout.write('migrations applied\n');
        return 0;
      }

      case 'passwd': {
        const principal = rest[0];
        if (!principal) {
          process.stderr.write('usage: ghost-cli passwd <principal>\n');
          return 2;
        }
        if (!cfg.auth.principals.some((p) => p.name === principal)) {
          const names = cfg.auth.principals.map((p) => p.name).join(', ') || '(none)';
          process.stderr.write(
            `"${principal}" is not in [[auth.principals]] in ${configPath}.\n` +
              `A password for a principal the server does not know is unusable.\nConfigured: ${names}\n`,
          );
          return 1;
        }
        await migrate(db, join(HERE, '..', 'sql', 'migrations'));

        // Piped stdin gets one line and no confirmation prompt. Asking a script
        // to type it twice is how the earlier version silently did nothing:
        // readline consumed both lines on the first read, the comparison failed,
        // and the credential was never written.
        let first: string;
        if (interactive()) {
          first = await prompt(`password for ${principal}: `, true);
          if (first.length < 12) {
            process.stderr.write('too short: use at least 12 characters\n');
            return 1;
          }
          const second = await prompt('again: ', true);
          if (first !== second) {
            process.stderr.write('they do not match\n');
            return 1;
          }
        } else {
          first = await readPiped();
          if (first.length < 12) {
            process.stderr.write('too short: use at least 12 characters\n');
            return 1;
          }
        }

        const phc = await hashPassword(first, cfg.passwordPepper);
        await db`
          INSERT INTO ghost.principal_credentials (principal, password_phc)
          VALUES (${principal}, ${phc})
          ON CONFLICT (principal)
          DO UPDATE SET password_phc = EXCLUDED.password_phc, updated_at = now()`;
        process.stdout.write(
          `set password for ${principal}${cfg.passwordPepper ? ' (peppered)' : ''}\n`,
        );
        if (!cfg.passwordPepper) {
          process.stdout.write(
            'GHOST_PASSWORD_PEPPER is not set. Setting it and re-running this makes a stolen\n' +
              'credentials table useless on its own.\n',
          );
        }
        return 0;
      }

      case 'oauth': {
        if (rest[0] === 'clients') {
          const rows = await db<
            Array<{
              client_id: string;
              client_name: string | null;
              redirect_uris: string[];
              created_at: Date;
              last_used_at: Date | null;
            }>
          >`
            SELECT client_id, client_name, redirect_uris, created_at, last_used_at
              FROM ghost.oauth_clients ORDER BY created_at`;
          if (rows.length === 0) {
            process.stdout.write('no registered clients\n');
            return 0;
          }
          for (const r of rows) {
            process.stdout.write(
              `${r.client_id}\n` +
                `  name:      ${r.client_name ?? '(unnamed)'}\n` +
                `  redirects: ${r.redirect_uris.join(', ')}\n` +
                `  created:   ${r.created_at.toISOString()}\n` +
                `  last used: ${r.last_used_at ? r.last_used_at.toISOString() : 'never'}\n`,
            );
          }
          return 0;
        }
        if (rest[0] === 'revoke') {
          const id = rest[1];
          if (!id) {
            process.stderr.write('usage: ghost-cli oauth revoke <client_id>\n');
            return 2;
          }
          // Codes and refresh tokens cascade from the client row.
          const deleted = await db`DELETE FROM ghost.oauth_clients WHERE client_id = ${id} RETURNING client_id`;
          process.stdout.write(deleted.length > 0 ? `revoked ${id}\n` : `no such client: ${id}\n`);
          return deleted.length > 0 ? 0 : 1;
        }
        process.stderr.write(USAGE);
        return 2;
      }

      case 'prune': {
        const days = Number(rest[0] ?? 90);
        await prune(db, Number.isFinite(days) ? days : 90);
        process.stdout.write(`pruned; request log kept for ${days} days\n`);
        return 0;
      }

      case 'log': {
        const n = Math.min(Number(rest[0] ?? 20) || 20, 500);
        const rows = await db<
          Array<{
            at: Date;
            principal: string;
            tool: string;
            url: string;
            status: number | null;
            ok: boolean;
            injection_findings: number;
            hidden_elements: number;
          }>
        >`
          SELECT at, principal, tool, url, status, ok, injection_findings, hidden_elements
            FROM ghost.request_log ORDER BY at DESC LIMIT ${n}`;
        for (const r of rows.reverse()) {
          const flags = [
            r.injection_findings > 0 ? `inject:${r.injection_findings}` : '',
            r.hidden_elements > 0 ? `hidden:${r.hidden_elements}` : '',
          ]
            .filter(Boolean)
            .join(' ');
          process.stdout.write(
            `${r.at.toISOString()}  ${r.ok ? 'ok ' : 'ERR'}  ${String(r.status ?? '---').padStart(3)}  ` +
              `${r.principal}  ${r.tool}  ${r.url}${flags ? '  [' + flags + ']' : ''}\n`,
          );
        }
        return 0;
      }

      default:
        process.stderr.write(USAGE);
        return 2;
    }
  } finally {
    await db.end({ timeout: 5 }).catch(() => {});
  }
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  });
