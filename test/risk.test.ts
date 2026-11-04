import { describe, expect, it } from 'vitest';
import { NON_OVERRIDABLE, SIGNALS, computeRisk, levelFor } from '../src/lib/risk.js';

describe('computeRisk', () => {
  it('is zero and calm when nothing happened', () => {
    expect(computeRisk({})).toMatchObject({ score: 0, level: 'calm', parts: [] });
  });

  it('caps a signal: a hundred failed logins are worth the cap, not a hundred times the unit', () => {
    const risk = computeRisk({ login_failed: 100 });
    expect(risk.score).toBe(SIGNALS.login_failed?.cap);
    expect(risk.parts[0]).toMatchObject({ action: 'login_failed', capped: true });
  });

  it('does not report a signal as capped before it reaches the cap', () => {
    expect(computeRisk({ login_failed: 2 }).parts[0]).toMatchObject({ points: 3, capped: false });
  });

  it('treats a single honeytoken trip as a verdict', () => {
    const risk = computeRisk({ honeytoken_trip: 1 });
    expect(risk.score).toBe(40);
    expect(computeRisk({ honeytoken_trip: 1, data_canary_trip: 1 }).level).toBe('critical');
  });

  it('never exceeds 100', () => {
    const everything = Object.fromEntries(Object.keys(SIGNALS).map((action) => [action, 1000]));
    expect(computeRisk(everything).score).toBe(100);
  });

  it('ignores negative and fractional counts instead of producing a negative score', () => {
    expect(computeRisk({ login_failed: -5 }).score).toBe(0);
    expect(computeRisk({ login_failed: 2.9 }).parts[0]?.events).toBe(2);
  });

  it('orders the parts by the points they added', () => {
    const risk = computeRisk({ login_failed: 3, ssrf_attempt: 4, honeytoken_trip: 1 });
    expect(risk.parts.map((part) => part.action)).toEqual(['honeytoken_trip', 'ssrf_attempt', 'login_failed']);
  });

  describe('overrides (an operator marks events as benign)', () => {
    it('lowers the score and still reports what it would have been', () => {
      const risk = computeRisk({ login_failed: 10 }, { login_failed: 10 });
      expect(risk.score).toBe(0);
      expect(risk.scoreWithoutOverrides).toBe(15);
      expect(risk.overriddenEvents).toBe(10);
    });

    it('cannot remove more events than happened', () => {
      expect(computeRisk({ login_failed: 2 }, { login_failed: 50 })).toMatchObject({ score: 0, overriddenEvents: 2 });
    });

    it.each([...NON_OVERRIDABLE])('cannot talk away %s, even if an override row exists', (action) => {
      const risk = computeRisk({ [action]: 1 }, { [action]: 1 });
      expect(risk.score).toBe(risk.scoreWithoutOverrides);
      expect(risk.score).toBeGreaterThan(0);
      expect(risk.overriddenEvents).toBe(0);
    });
  });
});

describe('levelFor', () => {
  it.each([
    [0, 'calm'],
    [24, 'calm'],
    [25, 'elevated'],
    [49, 'elevated'],
    [50, 'high'],
    [74, 'high'],
    [75, 'critical'],
    [100, 'critical'],
  ])('%i is %s', (score, level) => {
    expect(levelFor(score)).toBe(level);
  });
});
