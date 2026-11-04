import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { INTEGRATION, type Stack, startStack, totpAt } from './harness.js';

describe.skipIf(!INTEGRATION)('step-up', () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack({ STEP_UP_MAX_FAILS: '3', STEP_UP_WINDOW_SECONDS: '900' });
  });
  afterAll(() => s.close());
  beforeEach(() => s.reset());

  const secret = () => s.config.totpSecret;
  const good = () => totpAt(secret(), s.clock.now().getTime());
  /** A six-digit code that is certainly not valid now, or one step either side. */
  const wrong = () => {
    const now = s.clock.now().getTime();
    const valid = new Set([-30_000, 0, 30_000].map((d) => totpAt(secret(), now + d)));
    for (let n = 0; n < 1_000_000; n++) {
      const candidate = String(n).padStart(6, '0');
      if (!valid.has(candidate)) return candidate;
    }
    throw new Error('unreachable');
  };
  const actions = async () => (await s.ctx.chain.recent({ limit: 50 })).map((e) => e.action);

  it('accepts the current code', async () => {
    expect(await s.ctx.stepUp.verify('op', good())).toEqual({ ok: true });
  });

  it('accepts a code one step either side: clocks drift', async () => {
    const now = s.clock.now().getTime();
    expect((await s.ctx.stepUp.verify('op', totpAt(secret(), now - 30_000))).ok).toBe(true);
    expect((await s.ctx.stepUp.verify('op', totpAt(secret(), now + 30_000))).ok).toBe(true);
  });

  it('a code works once: the second use is a replay', async () => {
    const code = good();
    expect((await s.ctx.stepUp.verify('op', code)).ok).toBe(true);
    expect(await s.ctx.stepUp.verify('op', code)).toMatchObject({ ok: false, reason: 'replayed' });
  });

  it('the next code, thirty seconds on, is a different code and works', async () => {
    expect((await s.ctx.stepUp.verify('op', good())).ok).toBe(true);
    s.clock.advance(30);
    expect((await s.ctx.stepUp.verify('op', good())).ok).toBe(true);
  });

  it('a code used by one operator is not burned for another', async () => {
    const code = good();
    expect((await s.ctx.stepUp.verify('op-a', code)).ok).toBe(true);
    expect((await s.ctx.stepUp.verify('op-b', code)).ok).toBe(true);
  });

  it('counts wrong codes, tells how many are left, and writes each to the audit chain', async () => {
    expect(await s.ctx.stepUp.verify('op', wrong())).toEqual({ ok: false, reason: 'invalid', remaining: 2 });
    expect(await s.ctx.stepUp.verify('op', wrong())).toEqual({ ok: false, reason: 'invalid', remaining: 1 });
    expect((await actions()).filter((a) => a === 'step_up_failed')).toHaveLength(2);
  });

  it('the third wrong code locks the operator out, and a correct one no longer helps', async () => {
    await s.ctx.stepUp.verify('op', wrong());
    await s.ctx.stepUp.verify('op', wrong());
    expect(await s.ctx.stepUp.verify('op', wrong())).toEqual({ ok: false, reason: 'lockout' });
    expect(await s.ctx.stepUp.isLocked('op')).toBe(true);
    expect(await s.ctx.stepUp.verify('op', good())).toEqual({ ok: false, reason: 'locked' });
    expect(await actions()).toContain('step_up_lockout');
  });

  it('the lockout does not clear by itself, however long the wait', async () => {
    for (let i = 0; i < 3; i++) await s.ctx.stepUp.verify('op', wrong());
    s.clock.advance(7 * 24 * 3600);
    expect(await s.ctx.stepUp.verify('op', good())).toEqual({ ok: false, reason: 'locked' });
  });

  it('a person releases it, and then the operator can act again', async () => {
    for (let i = 0; i < 3; i++) await s.ctx.stepUp.verify('op', wrong());
    await s.ctx.stepUp.unlock('op');
    expect((await s.ctx.stepUp.verify('op', good())).ok).toBe(true);
  });

  it('locking one operator out leaves the others alone', async () => {
    for (let i = 0; i < 3; i++) await s.ctx.stepUp.verify('op-a', wrong());
    expect((await s.ctx.stepUp.verify('op-b', good())).ok).toBe(true);
  });

  it('a missing or malformed code is a forgetful client, not a guess: it costs nothing', async () => {
    for (const bad of [undefined, '', '12345', '1234567', 'abcdef', '12 456']) {
      expect(await s.ctx.stepUp.verify('op', bad)).toEqual({ ok: false, reason: 'missing' });
    }
    expect((await s.ctx.stepUp.verify('op', good())).ok).toBe(true);
    expect(await actions()).not.toContain('step_up_failed');
  });

  it('failures older than the window are forgotten', async () => {
    await s.ctx.stepUp.verify('op', wrong());
    await s.ctx.stepUp.verify('op', wrong());
    s.clock.advance(901);
    expect(await s.ctx.stepUp.verify('op', wrong())).toMatchObject({ ok: false, reason: 'invalid', remaining: 2 });
  });

  it('a correct code clears the failure count', async () => {
    await s.ctx.stepUp.verify('op', wrong());
    await s.ctx.stepUp.verify('op', wrong());
    expect((await s.ctx.stepUp.verify('op', good())).ok).toBe(true);
    expect(await s.ctx.stepUp.verify('op', wrong())).toMatchObject({ remaining: 2 });
  });
});
