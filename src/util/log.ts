// Structured lines to stdout/stderr, which systemd captures into the journal.
// No log files, no rotation, no dependency: journald already does all three.

type Level = 'debug' | 'info' | 'warn' | 'error';

const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let threshold = ORDER.info;

export function setLevel(level: string): void {
  const l = level.toLowerCase() as Level;
  if (l in ORDER) threshold = ORDER[l];
}

function emit(level: Level, msg: string, fields?: Record<string, unknown>): void {
  if (ORDER[level] < threshold) return;
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields });
  if (level === 'error' || level === 'warn') process.stderr.write(line + '\n');
  else process.stdout.write(line + '\n');
}

export const log = {
  debug: (msg: string, f?: Record<string, unknown>) => emit('debug', msg, f),
  info: (msg: string, f?: Record<string, unknown>) => emit('info', msg, f),
  warn: (msg: string, f?: Record<string, unknown>) => emit('warn', msg, f),
  error: (msg: string, f?: Record<string, unknown>) => emit('error', msg, f),
};

// Errors reach the journal as a message plus a type, never a raw object whose
// `cause` chain might carry a page's own text or a connection string.
export function errFields(e: unknown): Record<string, unknown> {
  if (e instanceof Error) return { err: e.message, err_type: e.constructor.name };
  return { err: String(e) };
}
