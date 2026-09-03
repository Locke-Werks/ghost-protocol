// One Postgres connection pool, and the migration runner.
//
// The schema is small and the write rate is a handful of rows per fetch, so
// there is nothing here worth an ORM.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import postgres, { type Sql } from 'postgres';
import { log } from './util/log.js';

export type Db = Sql;

export function connect(url: string): Db {
  return postgres(url, {
    max: 6,
    idle_timeout: 60,
    connect_timeout: 10,
    // The default onnotice writes NOTICE lines to stderr, which turns every
    // "already exists, skipping" from a re-run migration into what looks like
    // an error in the journal.
    onnotice: (n) => log.debug('postgres notice', { message: n.message }),
    types: {},
  });
}

/**
 * Apply every .sql file in `dir` in filename order, once each.
 *
 * A plain ledger table rather than a migration framework: the files are
 * idempotent (`CREATE ... IF NOT EXISTS`), so re-running one is harmless, and
 * the ledger exists to keep the log honest about what ran when.
 */
export async function migrate(sql: Db, dir: string): Promise<void> {
  await sql`CREATE SCHEMA IF NOT EXISTS ghost`;
  await sql`
    CREATE TABLE IF NOT EXISTS ghost.migrations (
      name       TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;

  const applied = new Set(
    (await sql<{ name: string }[]>`SELECT name FROM ghost.migrations`).map((r) => r.name),
  );

  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    if (applied.has(file)) continue;
    const body = readFileSync(join(dir, file), 'utf8');
    log.info('applying migration', { file });
    await sql.begin(async (tx) => {
      await tx.unsafe(body);
      await tx`INSERT INTO ghost.migrations (name) VALUES (${file})`;
    });
  }
}

/** Drop rows nobody will read again. Called on a timer by the server. */
export async function prune(sql: Db, requestLogDays: number): Promise<void> {
  await sql`DELETE FROM ghost.oauth_codes WHERE expires_at < now() - interval '1 day'`;
  await sql`DELETE FROM ghost.oauth_refresh_tokens WHERE expires_at < now() - interval '7 days'`;
  await sql`
    DELETE FROM ghost.request_log
    WHERE at < now() - make_interval(days => ${requestLogDays})`;
  await sql`DELETE FROM ghost.audit WHERE at < now() - interval '180 days'`;
}
