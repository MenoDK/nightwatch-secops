import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createOverride, readRisk } from '../src/lib/risk-query.js';
import { computeRisk } from '../src/lib/risk.js';
import { INTEGRATION, type Stack, startStack } from './harness.js';

describe.skipIf(!INTEGRATION)('risk from the audit chain', () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack({ RISK_WINDOW_HOURS: '24' });
  });
  afterAll(() => s.close());
  beforeEach(() => s.reset());

  const put = (action: Parameters<Stack['ctx']['chain']['append']>[0]['action'], n = 1) =>
    Promise.all(Array.from({ length: n }, () => s.ctx.chain.append({ actor: 'test', action })));
  const risk = () => readRisk(s.ctx.pool, s.ctx.clock, 24);
  const override = (seq: number) =>
    createOverride(s.ctx.pool, s.ctx.chain, s.ctx.clock, { seq, reason: 'known scanner', operator: 'op' });

  it('is calm on an empty chain', async () => {
    expect(await risk()).toMatchObject({ score: 0, level: 'calm', overriddenEvents: 0 });
  });

  it('scores what the chain holds, the same way the pure function does', async () => {
    await put('login_failed', 3);
    await put('ssrf_attempt', 2);
    await put('ip_blocked', 4); // a consequence, not a signal
    const got = await risk();
    const expected = computeRisk({ login_failed: 3, ssrf_attempt: 2 });
    expect(got.score).toBe(expected.score);
    expect(got.level).toBe(expected.level);
  });

  it('counts only the window', async () => {
    await put('honeytoken_trip');
    s.clock.advance(25 * 3600);
    expect((await risk()).score).toBe(0);
    await put('login_failed');
    expect((await risk()).parts.map((p) => p.action)).toEqual(['login_failed']);
  });

  it('a honeytoken alone is already serious', async () => {
    await put('honeytoken_trip');
    expect((await risk()).score).toBeGreaterThanOrEqual(40);
  });

  describe('overrides', () => {
    it('lower the score and leave the original row, and the number nobody can argue down, untouched', async () => {
      const [first] = await put('login_failed');
      await put('login_failed', 4);
      const before = await risk();
      const result = await override(first?.seq ?? 0);
      expect(result.ok).toBe(true);
      const after = await risk();
      expect(after.score).toBeLessThan(before.score);
      expect(after.scoreWithoutOverrides).toBe(before.score);
      expect(after.overriddenEvents).toBe(1);
      expect((await s.sql('SELECT action FROM audit_chain WHERE seq = $1', [first?.seq]))[0]?.action).toBe(
        'login_failed',
      );
    });

    it('are themselves written to the chain, and the chain still verifies', async () => {
      const [first] = await put('login_failed');
      await override(first?.seq ?? 0);
      const [entry] = await s.ctx.chain.recent({ action: 'override_created' });
      expect(entry).toMatchObject({
        actor: 'op',
        metadata: { seq: first?.seq, of: 'login_failed', reason: 'known scanner' },
      });
      expect((await s.ctx.chain.verify()).ok).toBe(true);
    });

    it.each(['audit_integrity_failed', 'honeytoken_trip', 'data_canary_trip', 'step_up_lockout'] as const)(
      'cannot be made on %s: the intruder who stole a session would do exactly that',
      async (action) => {
        const [row] = await put(action);
        expect(await override(row?.seq ?? 0)).toEqual({ ok: false, reason: 'not_overridable' });
        expect((await risk()).overriddenEvents).toBe(0);
      },
    );

    it('cannot be made on something that is not scored, or on something that is not there', async () => {
      const [blocked] = await put('ip_blocked');
      expect(await override(blocked?.seq ?? 0)).toEqual({ ok: false, reason: 'not_scored' });
      expect(await override(999)).toEqual({ ok: false, reason: 'not_found' });
    });

    it('cannot be made twice on one event', async () => {
      const [row] = await put('login_failed');
      expect((await override(row?.seq ?? 0)).ok).toBe(true);
      expect(await override(row?.seq ?? 0)).toEqual({ ok: false, reason: 'already_overridden' });
    });

    it('two operators clicking together: exactly one wins, and the other is told so', async () => {
      const [row] = await put('login_failed');
      const results = await Promise.all([override(row?.seq ?? 0), override(row?.seq ?? 0), override(row?.seq ?? 0)]);
      expect(results.filter((r) => r.ok)).toHaveLength(1);
      expect(results.filter((r) => !r.ok && r.reason === 'already_overridden')).toHaveLength(2);
      expect((await s.ctx.chain.recent({ action: 'override_created' })).length).toBe(1);
      expect((await s.ctx.chain.verify()).ok).toBe(true);
    });
  });
});
