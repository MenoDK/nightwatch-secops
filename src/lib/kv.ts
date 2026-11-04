import { randomUUID } from 'node:crypto';
import type { Redis } from 'ioredis';

/**
 * The small slice of Redis this service uses, behind one prefix. Everything that remembers something for a while goes
 * through here: block lists, counters, replay markers. The values hold deadlines in the injected clock's time, and the
 * Redis expiry is only the garbage collector, so a lab that moves the clock sees the same behaviour as a real wait.
 */
export class Kv {
  constructor(
    readonly redis: Redis,
    readonly prefix: string,
  ) {}

  key(...parts: string[]): string {
    return [this.prefix, ...parts].join(':');
  }

  async getJson<T>(key: string): Promise<T | null> {
    const raw = await this.redis.get(key);
    if (raw === null) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  async setJson(key: string, value: unknown, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds === undefined) await this.redis.set(key, JSON.stringify(value));
    else await this.redis.set(key, JSON.stringify(value), 'EX', Math.max(1, Math.ceil(ttlSeconds)));
  }

  /** True the first time a key is seen within its lifetime, false afterwards: SET NX with an expiry, atomically. */
  async claim(key: string, ttlSeconds: number): Promise<boolean> {
    return (await this.redis.set(key, '1', 'EX', Math.max(1, Math.ceil(ttlSeconds)), 'NX')) === 'OK';
  }

  async del(...keys: string[]): Promise<number> {
    return keys.length === 0 ? 0 : this.redis.del(...keys);
  }

  /** Counts events in a sliding window. The window is measured in the caller's time, not Redis's. */
  async slide(key: string, nowMs: number, windowMs: number): Promise<number> {
    const results = await this.redis
      .multi()
      .zadd(key, nowMs, `${nowMs}:${randomUUID()}`)
      .zremrangebyscore(key, '-inf', nowMs - windowMs)
      .zcard(key)
      .pexpire(key, windowMs * 2)
      .exec();
    const card = results?.[2]?.[1];
    return typeof card === 'number' ? card : 0;
  }

  async count(key: string, nowMs: number, windowMs: number): Promise<number> {
    await this.redis.zremrangebyscore(key, '-inf', nowMs - windowMs);
    return this.redis.zcard(key);
  }

  /** Keys under a prefix. SCAN, never KEYS: the latter blocks the server. Capped, because a listing is for people. */
  async list(pattern: string, limit = 200): Promise<string[]> {
    const found: string[] = [];
    let cursor = '0';
    do {
      const [next, batch] = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 200);
      cursor = next;
      found.push(...batch);
    } while (cursor !== '0' && found.length < limit);
    return found.slice(0, limit);
  }

  /** Removes everything under this prefix: the lab's "start over", and the tests' clean slate. */
  async flush(): Promise<void> {
    const keys = await this.list(`${this.prefix}:*`, 100_000);
    for (let i = 0; i < keys.length; i += 500) await this.redis.del(...keys.slice(i, i + 500));
  }
}
