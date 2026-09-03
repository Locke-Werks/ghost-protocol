// Sliding-window counters for the auth endpoints.
//
// Self-bounding on purpose: an attacker who varies the key (spoofed addresses,
// random principals) would otherwise turn a rate limiter into a memory leak, so
// expired entries are pruned and the number of distinct keys is capped.

const MAX_KEYS = 10_000;

export class SlidingWindow {
  private readonly hits = new Map<string, number[]>();
  private lastSweep = 0;

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  /** True when the key is over its limit. Records the hit when it is not. */
  over(key: string, now = Date.now()): boolean {
    this.maybeSweep(now);

    const cutoff = now - this.windowMs;
    let times = this.hits.get(key);
    if (!times) {
      // A flood of unique keys must not be able to grow this without bound.
      // Refusing at the cap fails closed, which is the right direction for a
      // limiter guarding a login.
      if (this.hits.size >= MAX_KEYS) return true;
      times = [];
      this.hits.set(key, times);
    }
    while (times.length > 0 && times[0]! < cutoff) times.shift();
    if (times.length >= this.max) return true;
    times.push(now);
    return false;
  }

  reset(key: string): void {
    this.hits.delete(key);
  }

  private maybeSweep(now: number): void {
    if (now - this.lastSweep < 60_000) return;
    this.lastSweep = now;
    const cutoff = now - this.windowMs;
    for (const [key, times] of this.hits) {
      while (times.length > 0 && times[0]! < cutoff) times.shift();
      if (times.length === 0) this.hits.delete(key);
    }
  }
}
