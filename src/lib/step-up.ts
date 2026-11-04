import type { Clock } from '../clock.js';
import type { Kv } from './kv.js';
import { verifyTotp } from './totp.js';

export type StepUpResult =
  | { ok: true }
  | { ok: false; reason: 'missing' | 'locked' }
  | { ok: false; reason: 'invalid' | 'replayed'; remaining: number }
  | { ok: false; reason: 'lockout' };

export interface StepUpEvents {
  failed(operator: string, detail: { reason: 'invalid' | 'replayed'; remaining: number }): Promise<void>;
  lockedOut(operator: string, detail: { attempts: number; windowSeconds: number }): Promise<void>;
}

/**
 * A second factor for the actions that change the world (approving a proposal, releasing a lockdown, overriding a
 * finding). A stolen API key alone is not enough. Wrong codes are counted in a window; too many lock the operator out
 * until a human releases them, because a lockout that clears itself is a rate limit for the attacker.
 */
export class StepUp {
  constructor(
    private readonly kv: Kv,
    private readonly clock: Clock,
    private readonly settings: { secret: string; maxFails: number; windowSeconds: number },
    private readonly events: StepUpEvents,
  ) {}

  private lockKey = (operator: string) => this.kv.key('stepup', 'locked', operator);

  async isLocked(operator: string): Promise<boolean> {
    return (await this.kv.redis.exists(this.lockKey(operator))) === 1;
  }

  async unlock(operator: string): Promise<void> {
    await this.kv.del(this.lockKey(operator), this.kv.key('stepup', 'fails', operator));
  }

  async verify(operator: string, code: string | undefined): Promise<StepUpResult> {
    if (await this.isLocked(operator)) return { ok: false, reason: 'locked' };
    // A missing or malformed code is a client that forgot, not a guess: it is not counted against the operator.
    if (!code || !/^\d{6}$/.test(code)) return { ok: false, reason: 'missing' };

    const nowMs = this.clock.now().getTime();
    const match = verifyTotp(this.settings.secret, code, nowMs);
    let reason: 'invalid' | 'replayed' | null = null;
    if (!match.ok || match.step === undefined) reason = 'invalid';
    else if (!(await this.kv.claim(this.kv.key('stepup', 'used', operator, String(match.step)), 150)))
      reason = 'replayed'; // a code is good once

    if (reason === null) {
      await this.kv.del(this.kv.key('stepup', 'fails', operator));
      return { ok: true };
    }

    const fails = await this.kv.slide(
      this.kv.key('stepup', 'fails', operator),
      nowMs,
      this.settings.windowSeconds * 1000,
    );
    if (fails >= this.settings.maxFails) {
      await this.kv.redis.set(this.lockKey(operator), '1'); // no expiry: a human releases it
      await this.kv.del(this.kv.key('stepup', 'fails', operator));
      await this.events.lockedOut(operator, { attempts: fails, windowSeconds: this.settings.windowSeconds });
      return { ok: false, reason: 'lockout' };
    }
    const remaining = this.settings.maxFails - fails;
    await this.events.failed(operator, { reason, remaining });
    return { ok: false, reason, remaining };
  }
}
