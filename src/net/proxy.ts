// A forward proxy on loopback that every relayed request must pass through.
//
// Chrome resolves its own DNS, so a check performed in our process before
// handing Chrome a URL proves nothing: the browser will look the name up again
// and may get a different answer. Putting a proxy in the path moves name
// resolution back to us. Chrome sends `CONNECT host:port` (or an absolute-form
// request for plain http) and never resolves anything itself, so the address
// that was checked is the address that gets dialled.
//
// It also gives one place to see and log every host a relayed page reached,
// including the third-party requests a page makes on its own.

// http.createServer, not net.createServer: the CONNECT method arrives as the
// server's 'connect' event and absolute-form plain-http requests as 'request',
// and a bare net.Server emits neither.
import { createServer, type Server } from 'node:http';
import { connect as netConnect, type Socket } from 'node:net';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { log, errFields } from '../util/log.js';
import { EgressDenied, resolveGuarded } from './guard.js';

const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);

export interface ProxyOptions {
  host: string;
  port: number;
  /** Empty set = every public host is fair game. */
  allowHosts: Set<string>;
  /** Called for each connection attempt, allowed or not. */
  onEgress?: (host: string, port: number, allowed: boolean, reason?: string) => void;
}

export class GuardedProxy {
  readonly username = 'ghost';
  readonly password = randomBytes(24).toString('base64url');
  private server: Server | null = null;
  private readonly expected: Buffer;

  constructor(private readonly opts: ProxyOptions) {
    this.expected = Buffer.from(
      'Basic ' + Buffer.from(`${this.username}:${this.password}`).toString('base64'),
      'utf8',
    );
  }

  get url(): string {
    return `http://${this.opts.host}:${this.opts.port}`;
  }

  async listen(): Promise<void> {
    const server = createServer();
    // An idle tunnel is a leaked socket. Both directions of an active pipe
    // reset this, so only a genuinely silent connection is cut.
    server.on('connection', (socket) => {
      socket.setTimeout(300_000, () => socket.destroy());
      socket.on('error', () => socket.destroy());
    });
    server.on('connect', (req, socket, head) => {
      void this.handleConnect(req.url ?? '', req.headers['proxy-authorization'], socket as Socket, head);
    });
    // Absolute-form plain-http requests arrive as ordinary requests on the same
    // listener. Handled by the same guard, then piped byte for byte.
    server.on('request', (req: any, res: any) => {
      void this.handlePlain(req, res);
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.opts.port, this.opts.host, () => {
        server.removeListener('error', reject);
        resolve();
      });
    });
    this.server = server;
    log.info('egress proxy listening', { bind: `${this.opts.host}:${this.opts.port}` });
  }

  async close(): Promise<void> {
    const s = this.server;
    if (!s) return;
    this.server = null;
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }

  private authOk(header: string | string[] | undefined): boolean {
    const value = Array.isArray(header) ? header[0] : header;
    if (!value) return false;
    const got = Buffer.from(value, 'utf8');
    if (got.length !== this.expected.length) return false;
    return timingSafeEqual(got, this.expected);
  }

  private async handleConnect(
    target: string,
    auth: string | string[] | undefined,
    socket: Socket,
    head: Buffer,
  ): Promise<void> {
    if (!this.authOk(auth)) {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="ghost"\r\n\r\n');
      return;
    }
    const sep = target.lastIndexOf(':');
    const host = sep > 0 ? target.slice(0, sep) : target;
    const port = sep > 0 ? Number(target.slice(sep + 1)) : 443;

    try {
      const upstream = await this.dial(host, port);
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
      const kill = () => {
        upstream.destroy();
        socket.destroy();
      };
      upstream.on('error', kill);
      socket.on('error', kill);
      upstream.on('close', kill);
      socket.on('close', kill);
    } catch (e) {
      const reason = e instanceof EgressDenied ? e.reason : 'upstream unreachable';
      socket.end(`HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Ghost-Reason: ${reason.replace(/[^\x20-\x7e]/g, '')}\r\n\r\n`);
    }
  }

  private async handlePlain(req: any, res: any): Promise<void> {
    if (!this.authOk(req.headers['proxy-authorization'])) {
      res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="ghost"' });
      res.end();
      return;
    }
    let url: URL;
    try {
      url = new URL(req.url);
    } catch {
      res.writeHead(400).end();
      return;
    }
    const port = url.port ? Number(url.port) : 80;
    try {
      const upstream = await this.dial(url.hostname, port);
      const path = url.pathname + url.search;
      const headers: string[] = [`${req.method} ${path} HTTP/1.1`];
      // Rewrite to origin form and drop hop-by-hop headers.
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const k = req.rawHeaders[i] as string;
        const v = req.rawHeaders[i + 1] as string;
        if (/^(proxy-authorization|proxy-connection|connection|keep-alive|te|trailer|upgrade)$/i.test(k)) continue;
        headers.push(`${k}: ${v}`);
      }
      headers.push('Connection: close', '', '');
      upstream.write(headers.join('\r\n'));
      req.pipe(upstream);
      upstream.pipe(res.socket);
      const kill = () => upstream.destroy();
      upstream.on('error', kill);
      res.socket?.on('error', kill);
      res.socket?.on('close', kill);
    } catch (e) {
      const reason = e instanceof EgressDenied ? e.reason : 'upstream unreachable';
      res.writeHead(403, { 'Content-Type': 'text/plain' }).end(`ghost: ${reason}\n`);
    }
  }

  /** Guard, then connect to the address that was guarded. */
  private async dial(host: string, port: number): Promise<Socket> {
    if (!ALLOWED_PORTS.has(port)) {
      this.opts.onEgress?.(host, port, false, 'port not allowed');
      throw new EgressDenied(host, `port ${port} is not an http(s) port`);
    }
    let target;
    try {
      target = await resolveGuarded(host, this.opts.allowHosts);
    } catch (e) {
      const reason = e instanceof EgressDenied ? e.reason : 'resolution failed';
      this.opts.onEgress?.(host, port, false, reason);
      log.warn('egress refused', { host, port, reason });
      throw e;
    }
    this.opts.onEgress?.(host, port, true);
    return await new Promise<Socket>((resolve, reject) => {
      // `host` is the pinned literal, so no second lookup happens here.
      const s = netConnect({ host: target.pinned, port, family: target.family });
      const onError = (e: Error) => {
        s.destroy();
        reject(e);
      };
      s.setTimeout(20_000, () => onError(new Error('connect timeout')));
      s.once('error', onError);
      s.once('connect', () => {
        s.removeListener('error', onError);
        s.setTimeout(0);
        s.on('error', () => s.destroy());
        resolve(s);
      });
    });
  }
}

export function proxyErrorFields(e: unknown): Record<string, unknown> {
  return errFields(e);
}
