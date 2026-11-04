import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { DEMO_GEO } from '../src/lib/geo.js';
import { INTEGRATION, type Stack, startStack } from './harness.js';

const LISBON = '203.0.113.5';
const TOKYO = '198.51.100.7';
const HONEY = 'backup-admin@example.test';
const CANARY = '00000000-0000-4000-8000-000000000c01';

describe.skipIf(!INTEGRATION)('engine', () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack({ LOGIN_FAIL_MAX: '5' }, { geo: DEMO_GEO });
  });
  afterAll(() => s.close());
  beforeEach(() => s.reset());

  const actions = async () => (await s.ctx.chain.recent({ limit: 100 })).map((e) => e.action).reverse();
  const failLogin = (ip: string, subject: string) => s.ctx.engine.report({ kind: 'login_failed', ip, subject });

  describe('sign-in failures', () => {
    it('records each failure and does nothing else until the limit', async () => {
      for (let i = 0; i < 4; i++) {
        const out = await failLogin('203.0.113.9', `u${i}@example.test`);
        expect(out.contained.ipBlocked).toBe(false);
      }
      expect(await actions()).toEqual(Array(4).fill('login_failed'));
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(false);
    });

    it('the fifth failure from one address is credential stuffing: one alarm, one block', async () => {
      for (let i = 0; i < 5; i++) await failLogin('203.0.113.9', `u${i}@example.test`);
      const sixth = await failLogin('203.0.113.9', 'u6@example.test');
      const seen = await actions();
      expect(seen.filter((a) => a === 'credential_stuffing_suspected')).toHaveLength(1);
      expect(seen.filter((a) => a === 'ip_blocked')).toHaveLength(1);
      expect(sixth.contained.ipBlocked).toBe(false); // already done; not repeated
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(true);
    });

    it('says in words what it did', async () => {
      let last = await failLogin('203.0.113.9', 'u0@example.test');
      for (let i = 1; i < 5; i++) last = await failLogin('203.0.113.9', `u${i}@example.test`);
      expect(last.notes.join(' ')).toMatch(/credential stuffing/);
      expect(last.notes.join(' ')).toMatch(/203\.0\.113\.9 blocked/);
      expect(last.counts?.ip).toBe(5);
    });

    it('a brute force on one account from many addresses is flagged but blocks nobody', async () => {
      for (let i = 0; i < 5; i++) await failLogin(`203.0.113.${30 + i}`, 'ana@example.test');
      const seen = await actions();
      expect(seen).toContain('credential_stuffing_suspected');
      expect(seen).not.toContain('ip_blocked');
      const [alarm] = await s.ctx.chain.recent({ action: 'credential_stuffing_suspected' });
      expect(alarm?.metadata).toMatchObject({ pattern: 'one_account' });
    });

    it('treats an IPv4-mapped address as the plain one', async () => {
      for (let i = 0; i < 5; i++) await failLogin('::ffff:203.0.113.9', `u${i}@example.test`);
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(true);
      const [blocked] = await s.ctx.chain.recent({ action: 'ip_blocked' });
      expect(blocked?.ip).toBe('203.0.113.9');
    });

    it('a successful sign-in is recorded and clears the account’s failures', async () => {
      for (let i = 0; i < 3; i++) await failLogin(`203.0.113.${40 + i}`, 'ana@example.test');
      await s.ctx.engine.report({ kind: 'login_succeeded', ip: LISBON, subject: 'ana@example.test' });
      expect((await actions()).at(-1)).toBe('login_succeeded');
      const next = await failLogin('203.0.113.99', 'ana@example.test');
      expect(next.counts?.subject).toBe(1);
    });
  });

  describe('traps', () => {
    it('a honey account is never typed by a customer: one attempt is the verdict', async () => {
      const out = await failLogin('203.0.113.9', HONEY);
      expect(await actions()).toEqual(['honeytoken_trip', 'ip_blocked']);
      expect(out.contained).toMatchObject({ ipBlocked: true, lockdown: false });
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(true);
    });

    it('matches the honey account whatever its case, and does not also log it as a plain failed login', async () => {
      await failLogin('203.0.113.9', 'Backup-Admin@Example.TEST');
      expect(await actions()).not.toContain('login_failed');
      expect(await actions()).toContain('honeytoken_trip');
    });

    it('blocks the address for the long honey period, not the short stuffing one', async () => {
      await failLogin('203.0.113.9', HONEY);
      const state = await s.ctx.blocklist.check('203.0.113.9');
      expect(
        state.deadline && state.deadline.until !== null ? (state.deadline.until - state.deadline.at) / 1000 : 0,
      ).toBe(s.config.honeyBlockSeconds);
    });

    it('reading a canary record is the same verdict', async () => {
      const out = await s.ctx.engine.report({
        kind: 'record_read',
        ip: '203.0.113.9',
        subject: 'ana@example.test',
        metadata: { id: CANARY },
      });
      expect(await actions()).toEqual(['data_canary_trip', 'ip_blocked']);
      expect(out.contained.ipBlocked).toBe(true);
    });

    it('reading an ordinary record leaves nothing behind', async () => {
      const out = await s.ctx.engine.report({
        kind: 'record_read',
        ip: '203.0.113.9',
        metadata: { id: crypto.randomUUID() },
      });
      expect(out.recorded).toEqual([]);
      expect(await actions()).toEqual([]);
    });

    it('a trap does not switch the lockdown on unless configured to: that is a person’s decision', async () => {
      await failLogin('203.0.113.9', HONEY);
      expect((await s.ctx.lockdown.status()).active).toBe(false);
    });
  });

  describe('impossible travel', () => {
    it('is recorded, with the distance and the time, and by default suspends nobody', async () => {
      await s.ctx.engine.report({ kind: 'login_succeeded', ip: LISBON, subject: 'ana@example.test' });
      s.clock.advance(600);
      const out = await s.ctx.engine.report({ kind: 'login_succeeded', ip: TOKYO, subject: 'ana@example.test' });
      const [event] = await s.ctx.chain.recent({ action: 'api_impossible_travel' });
      expect(event?.metadata).toMatchObject({ minutes: 10 });
      expect(event?.metadata.km).toBeGreaterThan(10_000);
      expect(out.contained.subjectSuspended).toBe(false);
      expect((await s.ctx.suspensions.status('ana@example.test')).active).toBe(false);
    });

    it('is also caught on an ordinary API request, which is not itself written to the chain', async () => {
      await s.ctx.engine.report({ kind: 'api_request', ip: LISBON, subject: 'ana@example.test' });
      expect(await actions()).toEqual([]);
      s.clock.advance(600);
      await s.ctx.engine.report({ kind: 'api_request', ip: TOKYO, subject: 'ana@example.test' });
      expect(await actions()).toEqual(['api_impossible_travel']);
    });

    it('a real journey is not an alert', async () => {
      await s.ctx.engine.report({ kind: 'login_succeeded', ip: LISBON, subject: 'ana@example.test' });
      s.clock.advance(20 * 3600);
      await s.ctx.engine.report({ kind: 'login_succeeded', ip: TOKYO, subject: 'ana@example.test' });
      expect(await actions()).not.toContain('api_impossible_travel');
    });

    it('an operator on the allow-list is exempt', async () => {
      await s.ctx.engine.report({ kind: 'login_succeeded', ip: '10.20.1.2', subject: 'op@example.test' });
      s.clock.advance(5);
      await s.ctx.engine.report({ kind: 'login_succeeded', ip: TOKYO, subject: 'op@example.test' });
      expect(await actions()).not.toContain('api_impossible_travel');
    });
  });

  describe('other observations', () => {
    it('a broken-object-access attempt and a policy violation are recorded as reported', async () => {
      await s.ctx.engine.report({
        kind: 'bola_attempt',
        ip: '203.0.113.9',
        subject: 'ana@example.test',
        metadata: { path: '/invoices/42' },
      });
      await s.ctx.engine.report({ kind: 'csp_violation', ip: '203.0.113.9', metadata: { directive: 'script-src' } });
      expect(await actions()).toEqual(['bola_attempt', 'csp_violation']);
      const [csp] = await s.ctx.chain.recent({ action: 'csp_violation' });
      expect(csp?.metadata).toEqual({ directive: 'script-src' });
    });
  });
});

describe.skipIf(!INTEGRATION)('engine, when told to be stricter', () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack(
      { TRAVEL_SUSPENDS: 'true', HONEY_TRIGGERS_LOCKDOWN: 'true', LOCKDOWN_SECONDS: '900' },
      { geo: DEMO_GEO },
    );
  });
  afterAll(() => s.close());
  beforeEach(() => s.reset());

  it('suspends the account on impossible travel', async () => {
    await s.ctx.engine.report({ kind: 'login_succeeded', ip: LISBON, subject: 'ana@example.test' });
    s.clock.advance(600);
    const out = await s.ctx.engine.report({ kind: 'login_succeeded', ip: TOKYO, subject: 'ana@example.test' });
    expect(out.contained.subjectSuspended).toBe(true);
    expect((await s.ctx.suspensions.status('ana@example.test')).active).toBe(true);
    expect((await s.ctx.chain.recent({ limit: 10 })).map((e) => e.action)).toContain('subject_suspended');
  });

  it('switches the lockdown on when a trap is touched, for the configured time', async () => {
    const out = await s.ctx.engine.report({ kind: 'login_failed', ip: '203.0.113.9', subject: HONEY });
    expect(out.contained).toMatchObject({ ipBlocked: true, lockdown: true });
    const status = await s.ctx.lockdown.status();
    expect(status.active).toBe(true);
    expect(status.deadline?.until).toBe(s.clock.now().getTime() + 900_000);
    expect((await s.ctx.chain.recent({ action: 'lockdown_on' })).length).toBe(1);
  });
});
