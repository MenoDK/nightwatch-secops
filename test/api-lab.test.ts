import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type AppWorld, INTEGRATION, OPERATOR_IP, startApp } from './harness.js';

describe.skipIf(!INTEGRATION)('lab mode: the demo application and the controls', () => {
  let w: AppWorld;
  beforeAll(async () => {
    w = await startApp({ LAB_MODE: 'true', LOGIN_FAIL_MAX: '5' });
  });
  afterAll(() => w.close());
  beforeEach(async () => {
    await w.call('POST', '/v1/lab/reset');
  });

  const as = (ip: string, extra: Record<string, string> = {}) => ({ headers: { 'x-lab-client-ip': ip, ...extra } });
  const login = (ip: string, email: string, password: string) =>
    w.call('POST', '/v1/demo/login', { key: null, body: { email, password }, ...as(ip) });
  const state = async () => (await w.call('GET', '/v1/lab/state')).json();
  const actions = async () => (await w.ctx.chain.recent({ limit: 200 })).map((e) => e.action).reverse();

  it('announces itself, and the key it was started with', async () => {
    const res = await w.call('GET', '/v1/lab/config', { key: null });
    expect(res.json()).toMatchObject({ lab: true, default_key_in_use: false, operator_ip: '10.20.0.10' });
    expect(res.json().scenarios.length).toBeGreaterThan(5);
  });

  it('exposes the operator’s code and the clock only to the key holder', async () => {
    expect((await w.call('GET', '/v1/lab/totp', { key: null })).statusCode).toBe(401);
    const res = await w.call('GET', '/v1/lab/totp');
    expect(res.json()).toMatchObject({ code: w.code(), secret: w.config.totpSecret });
  });

  describe('the demo application', () => {
    it('signs a known user in, and a wrong password out', async () => {
      expect((await login('203.0.113.5', 'ana@example.test', 'demo-password')).json().ok).toBe(true);
      expect((await login('203.0.113.5', 'ana@example.test', 'wrong')).statusCode).toBe(401);
      expect(await actions()).toEqual(['login_succeeded', 'login_failed']);
    });

    it('closes the loop: the verdict on one request changes what the next one gets', async () => {
      const ip = '203.0.113.77';
      for (let i = 0; i < 5; i++) await login(ip, `victim${i}@example.test`, 'guess');
      const after = await w.call('GET', '/v1/demo/resource', { key: null, ...as(ip) });
      expect(after.statusCode).toBe(403);
      expect(after.json().error.code).toBe('blocked');
      const other = await w.call('GET', '/v1/demo/resource', { key: null, ...as('203.0.113.78') });
      expect(other.statusCode).toBe(200);
    });

    it('a honey account trips the first time, and the address is out', async () => {
      const res = await login('203.0.113.88', 'backup-admin@example.test', 'anything');
      expect(res.json().lab.contained.ipBlocked).toBe(true);
      expect((await w.call('GET', '/v1/demo/resource', { key: null, ...as('203.0.113.88') })).statusCode).toBe(403);
    });

    it('reading a canary record looks like reading any record, and then the door closes', async () => {
      const res = await w.call('GET', '/v1/demo/records/00000000-0000-4000-8000-000000000c01', {
        key: null,
        ...as('203.0.113.89'),
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().note).toBe('a fictional record');
      expect((await w.call('GET', '/v1/demo/resource', { key: null, ...as('203.0.113.89') })).statusCode).toBe(403);
    });

    it('a lockdown stops the application and not the SOC', async () => {
      await w.call('POST', '/v1/lockdown', {
        ip: OPERATOR_IP,
        code: w.code(),
        body: { reason: 'drill', seconds: 600 },
      });
      expect((await w.call('GET', '/v1/demo/resource', { key: null, ...as('203.0.113.5') })).statusCode).toBe(503);
      expect((await login('203.0.113.5', 'ana@example.test', 'demo-password')).statusCode).toBe(503);
      expect((await w.call('GET', '/v1/risk')).statusCode).toBe(200);
      expect((await w.call('GET', '/v1/audit/verify')).statusCode).toBe(200);
    });

    it('a suspended account is refused even with the right password', async () => {
      await w.call('POST', '/v1/suspensions', {
        ip: OPERATOR_IP,
        code: w.code(),
        body: { subject: 'ana@example.test', reason: 'drill' },
      });
      const res = await login('203.0.113.5', 'ana@example.test', 'demo-password');
      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('suspended');
    });
  });

  describe('scenarios', () => {
    it('lists them, and an unknown one is a 404', async () => {
      expect((await w.call('POST', '/v1/lab/scenarios/nonsense')).statusCode).toBe(404);
    });

    it.each([
      ['stuffing', 'credential_stuffing_suspected'],
      ['brute-force', 'credential_stuffing_suspected'],
      ['honeytoken', 'honeytoken_trip'],
      ['canary', 'data_canary_trip'],
      ['travel', 'api_impossible_travel'],
      ['probe', 'ssrf_attempt'],
      ['injection', 'prompt_injection_attempt'],
    ])('%s leaves %s in the chain', async (name, expected) => {
      const res = await w.call('POST', `/v1/lab/scenarios/${name}`);
      expect(res.statusCode).toBe(200);
      expect(res.json().steps.length).toBeGreaterThan(0);
      expect(await actions()).toContain(expected);
    });

    it('probe → analyse → approve is the whole loop in three calls', async () => {
      await w.call('POST', '/v1/lab/scenarios/probe');
      const analysis = (await w.call('POST', '/v1/alice/analyze')).json();
      expect(analysis.created[0]).toMatchObject({ kind: 'block_ip', target: '198.51.100.200' });
      const approved = await w.call('POST', `/v1/alice/proposals/${analysis.created[0].id}/approve`, {
        ip: OPERATOR_IP,
        code: w.code(),
      });
      expect(approved.statusCode).toBe(200);
      expect((await w.ctx.blocklist.check('198.51.100.200')).active).toBe(true);
    });

    it('travel is a proposal to suspend, not a suspension', async () => {
      await w.call('POST', '/v1/lab/scenarios/travel');
      const analysis = (await w.call('POST', '/v1/alice/analyze')).json();
      expect(analysis.created.map((p: { kind: string }) => p.kind)).toContain('suspend_subject');
      expect((await w.ctx.suspensions.status('ana@example.test')).active).toBe(false);
    });
  });

  describe('time', () => {
    it('moves forward and expires a block exactly as waiting would', async () => {
      await w.call('POST', '/v1/lab/scenarios/stuffing');
      expect((await state()).blocked).toHaveLength(1);
      const res = await w.call('POST', '/v1/lab/clock', { body: { seconds: 3601 } });
      expect(res.json().offsetSeconds).toBeGreaterThanOrEqual(3601);
      expect((await state()).blocked).toHaveLength(0);
    });

    it('never backwards', async () => {
      expect((await w.call('POST', '/v1/lab/clock', { body: { seconds: -5 } })).statusCode).toBe(400);
      expect((await w.call('POST', '/v1/lab/clock', { body: { seconds: 0 } })).statusCode).toBe(400);
    });

    it('moving it changes the code the operator needs, and the lab hands out the right one', async () => {
      await w.call('POST', '/v1/lab/clock', { body: { seconds: 90 } });
      const { code } = (await w.call('GET', '/v1/lab/totp')).json();
      const res = await w.call('POST', '/v1/lockdown', { ip: OPERATOR_IP, code, body: { reason: 'drill' } });
      expect(res.statusCode).toBe(200);
    });

    it('a reset puts the clock back', async () => {
      await w.call('POST', '/v1/lab/clock', { body: { seconds: 7200 } });
      await w.call('POST', '/v1/lab/reset');
      expect((await state()).offsetSeconds).toBe(0);
    });
  });

  describe('tampering with the audit chain', () => {
    const seed = async () => {
      await w.call('POST', '/v1/lab/scenarios/stuffing');
      await w.call('POST', '/v1/lab/scenarios/probe');
    };

    it('refuses to tamper with nothing', async () => {
      expect((await w.call('POST', '/v1/lab/tamper', { body: { mode: 'edit' } })).statusCode).toBe(409);
    });

    it.each(['edit', 'delete', 'truncate'] as const)(
      '%s is found by verification, written to the chain, and counts in the score',
      async (mode) => {
        await seed();
        expect((await w.call('GET', '/v1/audit/verify')).json().ok).toBe(true);
        await w.call('POST', '/v1/lab/tamper', { body: { mode } });
        const verdict = (await w.call('GET', '/v1/audit/verify')).json();
        expect(verdict.ok).toBe(false);
        expect(verdict.alarmed).toBe(true);
        expect(await actions()).toContain('audit_integrity_failed');
        const { risk, escalation } = (await w.call('GET', '/v1/risk')).json();
        expect(risk.parts.map((p: { action: string }) => p.action)).toContain('audit_integrity_failed');
        expect(escalation.advisories.map((a: { playbookId: string }) => a.playbookId)).toContain('NW-TAMPER-04');
      },
    );

    it('polling a broken chain does not fill it: one alarm in five minutes', async () => {
      await seed();
      await w.call('POST', '/v1/lab/tamper', { body: { mode: 'edit' } });
      const first = (await w.call('GET', '/v1/audit/verify')).json();
      const second = (await w.call('GET', '/v1/audit/verify')).json();
      expect([first.alarmed, second.alarmed]).toEqual([true, false]);
      expect((await actions()).filter((a) => a === 'audit_integrity_failed')).toHaveLength(1);
    });

    it('the damage names the row', async () => {
      await seed();
      await w.call('POST', '/v1/lab/tamper', { body: { mode: 'edit', seq: 3 } });
      expect((await w.call('GET', '/v1/audit/verify')).json().problem).toEqual({ seq: 3, reason: 'row_hash_mismatch' });
    });

    it('a rewrite with the key passes by itself, and fails against a receipt taken before', async () => {
      await seed();
      const receipt = (await w.call('POST', '/v1/audit/anchor')).json();
      await w.call('POST', '/v1/lab/tamper', { body: { mode: 'rewrite', seq: 3 } });
      const alone = (await w.call('GET', '/v1/audit/verify')).json();
      expect(alone.ok).toBe(true);
      const against = (await w.call('POST', '/v1/audit/verify', { body: { anchor: receipt } })).json();
      expect(against).toMatchObject({ ok: false, problem: { reason: 'anchor_mismatch' }, alarmed: true });
    });

    it('a receipt for an honest chain passes, even after the chain has grown', async () => {
      await seed();
      const receipt = (await w.call('POST', '/v1/audit/anchor')).json();
      await w.call('POST', '/v1/lab/scenarios/honeytoken');
      expect((await w.call('POST', '/v1/audit/verify', { body: { anchor: receipt } })).json().ok).toBe(true);
    });

    it('a receipt this service did not sign is refused, not trusted', async () => {
      await seed();
      const forged = { seq: 1, hash: 'f'.repeat(64), at: new Date().toISOString(), mac: '0'.repeat(64) };
      const res = await w.call('POST', '/v1/audit/verify', { body: { anchor: forged } });
      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe('anchor_not_ours');
    });
  });

  it('the step-up lockout can be released from the lab, and only there', async () => {
    for (let i = 0; i < 3; i++)
      await w.call('POST', '/v1/lockdown', { ip: OPERATOR_IP, code: '000000', body: { reason: 'x' } });
    expect((await state()).stepUpLocked).toBe(true);
    await w.call('POST', '/v1/lab/unlock');
    expect((await state()).stepUpLocked).toBe(false);
  });

  it('state is one call that holds everything the page draws', async () => {
    await w.call('POST', '/v1/lab/scenarios/honeytoken');
    expect(await state()).toMatchObject({
      chain: { total: 2 },
      risk: { level: expect.any(String) },
      blocked: [expect.objectContaining({ ip: '203.0.113.88' })],
      recent: expect.any(Array),
      lockdown: { active: false },
      stepUpLocked: false,
    });
  });
});
