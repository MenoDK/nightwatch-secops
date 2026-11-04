import type { Clock } from '../clock.js';
import type { Kv } from './kv.js';
import { normalizeIp } from './net.js';

export interface Deadline {
  /** Epoch milliseconds in the injected clock's time. */
  until: number | null;
  reason: string;
  by: string;
  at: number;
}

export interface Containment {
  active: boolean;
  /** True when Redis could not be read and the answer is the configured fail-open or fail-closed default. */
  degraded: boolean;
  deadline?: Deadline;
}

/** Reads a deadline; expired means gone, even if Redis has not yet garbage-collected the key. */
async function readDeadline(kv: Kv, clock: Clock, key: string, failClosed: boolean): Promise<Containment> {
  let found: Deadline | null;
  try {
    found = await kv.getJson<Deadline>(key);
  } catch {
    // If the store is down we cannot tell: refuse (fail closed) or let traffic through (fail open). Both are written
    // down in the settings, because "what happens when Redis dies" is a decision and not an accident.
    return { active: failClosed, degraded: true };
  }
  if (!found) return { active: false, degraded: false };
  if (found.until !== null && found.until <= clock.now().getTime()) return { active: false, degraded: false };
  return { active: true, degraded: false, deadline: found };
}

abstract class Containments {
  constructor(
    protected readonly kv: Kv,
    protected readonly clock: Clock,
    protected readonly failClosed: boolean,
  ) {}

  protected async set(key: string, seconds: number | null, reason: string, by: string): Promise<Deadline> {
    const now = this.clock.now().getTime();
    const deadline: Deadline = { until: seconds === null ? null : now + seconds * 1000, reason, by, at: now };
    // Redis expires the key a minute after the deadline: only to tidy up, the deadline itself decides.
    await this.kv.setJson(key, deadline, seconds === null ? undefined : seconds + 60);
    return deadline;
  }

  protected read(key: string): Promise<Containment> {
    return readDeadline(this.kv, this.clock, key, this.failClosed);
  }
}

/** Addresses refused at the door. Keyed by the normalised address, so `::ffff:1.2.3.4` and `1.2.3.4` are one entry. */
export class Blocklist extends Containments {
  async block(ip: string, seconds: number, reason: string, by: string): Promise<Deadline> {
    const normalized = normalizeIp(ip);
    if (!normalized) throw new RangeError('not an IP address');
    return this.set(this.kv.key('block', normalized), seconds, reason, by);
  }

  async check(ip: string | null): Promise<Containment> {
    const normalized = ip ? normalizeIp(ip) : null;
    if (!normalized) return { active: false, degraded: false };
    return this.read(this.kv.key('block', normalized));
  }

  async unblock(ip: string): Promise<boolean> {
    const normalized = normalizeIp(ip);
    return normalized ? (await this.kv.del(this.kv.key('block', normalized))) > 0 : false;
  }

  async list(): Promise<{ ip: string; deadline: Deadline }[]> {
    const prefix = this.kv.key('block', '');
    const out: { ip: string; deadline: Deadline }[] = [];
    for (const key of await this.kv.list(`${prefix}*`, 100)) {
      const state = await this.read(key);
      if (state.active && state.deadline) out.push({ ip: key.slice(prefix.length), deadline: state.deadline });
    }
    return out.sort((a, b) => b.deadline.at - a.deadline.at);
  }
}

/** The panic switch. While it is on the protected application refuses everything; the SOC's own API is never behind it. */
export class Lockdown extends Containments {
  private get key(): string {
    return this.kv.key('lockdown');
  }

  activate(seconds: number, reason: string, by: string): Promise<Deadline> {
    return this.set(this.key, seconds, reason, by);
  }

  status(): Promise<Containment> {
    return this.read(this.key);
  }

  async release(): Promise<boolean> {
    return (await this.kv.del(this.key)) > 0;
  }
}

/** Accounts that may not act, set by a proposal an operator approved or by the travel rule when it is told to. */
export class Suspensions extends Containments {
  suspend(subject: string, reason: string, by: string): Promise<Deadline> {
    return this.set(this.kv.key('suspended', subject.toLowerCase()), null, reason, by);
  }

  status(subject: string): Promise<Containment> {
    return this.read(this.kv.key('suspended', subject.toLowerCase()));
  }

  async release(subject: string): Promise<boolean> {
    return (await this.kv.del(this.kv.key('suspended', subject.toLowerCase()))) > 0;
  }

  async list(): Promise<{ subject: string; deadline: Deadline }[]> {
    const prefix = this.kv.key('suspended', '');
    const out: { subject: string; deadline: Deadline }[] = [];
    for (const key of await this.kv.list(`${prefix}*`, 100)) {
      const state = await this.read(key);
      if (state.active && state.deadline) out.push({ subject: key.slice(prefix.length), deadline: state.deadline });
    }
    return out;
  }
}
