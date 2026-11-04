import type { Clock } from '../clock.js';
import { type GeoProvider, type LastSeen, type TravelLimits, type TravelVerdict, travelVerdict } from './geo.js';
import type { Kv } from './kv.js';

export interface LoginAlarm {
  ipCount: number;
  subjectCount: number;
  /** True only for the first failure past the limit in a window, so one attack raises one alarm and not one per attempt. */
  raised: boolean;
  /** Why: many tries from one address (stuffing), or many tries on one account (brute force from many addresses). */
  pattern: 'none' | 'one_address' | 'one_account';
}

/**
 * Counts failed sign-ins per address and per account over a sliding window. The window is in the injected clock's time.
 * Two counters, because the two attacks look different: stuffing hammers many accounts from one place, brute force
 * hammers one account from many.
 */
export class LoginWatch {
  constructor(
    private readonly kv: Kv,
    private readonly clock: Clock,
    private readonly limits: { max: number; windowSeconds: number },
  ) {}

  async failed(ip: string | null, subject: string | null): Promise<LoginAlarm> {
    const nowMs = this.clock.now().getTime();
    const windowMs = this.limits.windowSeconds * 1000;
    const ipCount = ip ? await this.kv.slide(this.kv.key('lf', 'ip', ip), nowMs, windowMs) : 0;
    const subjectCount = subject
      ? await this.kv.slide(this.kv.key('lf', 'sub', subject.toLowerCase()), nowMs, windowMs)
      : 0;
    const pattern =
      ipCount >= this.limits.max ? 'one_address' : subjectCount >= this.limits.max ? 'one_account' : 'none';
    let raised = false;
    if (pattern !== 'none') {
      const flag = this.kv.key('lf', 'alarm', pattern === 'one_address' ? (ip ?? '') : (subject ?? '').toLowerCase());
      raised = await this.kv.claim(flag, this.limits.windowSeconds);
    }
    return { ipCount, subjectCount, raised, pattern };
  }

  /** A successful sign-in clears that account's count: the legitimate owner typed it right in the end. */
  async succeeded(subject: string | null): Promise<void> {
    if (subject) await this.kv.del(this.kv.key('lf', 'sub', subject.toLowerCase()));
  }
}

export type GeoCheck =
  | { status: 'unknown_address' }
  | { status: 'first_seen' }
  | { status: 'exempt' }
  | { status: 'ok'; verdict: TravelVerdict }
  | { status: 'impossible'; verdict: TravelVerdict; from: LastSeen };

/** Remembers where each account was last seen and asks whether the next sighting could be the same person. */
export class GeoWatch {
  constructor(
    private readonly kv: Kv,
    private readonly clock: Clock,
    private readonly geo: GeoProvider,
    private readonly limits: TravelLimits,
    private readonly isExempt: (ip: string) => boolean,
  ) {}

  async check(subject: string, ip: string): Promise<GeoCheck> {
    // An operator on a known address is not a traveller: the same exemption as the approval allow-list.
    if (this.isExempt(ip)) return { status: 'exempt' };
    const here = await this.geo.lookup(ip);
    if (!here) return { status: 'unknown_address' };
    const key = this.kv.key('geo', subject.toLowerCase());
    const now = this.clock.now().getTime();
    const last = await this.kv.getJson<LastSeen>(key);
    // The baseline moves to the new sighting whatever the verdict: alert-only mode would otherwise alarm on every request.
    await this.kv.setJson(key, { ...here, ts: now }, 30 * 24 * 3600);
    if (!last) return { status: 'first_seen' };
    const verdict = travelVerdict(last, here, now, this.limits);
    return verdict.impossible ? { status: 'impossible', verdict, from: last } : { status: 'ok', verdict };
  }
}
