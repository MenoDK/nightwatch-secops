import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { signWebhook } from '../src/lib/guards/webhook.js';
import { type AppWorld, INTEGRATION, startApp } from './harness.js';

describe.skipIf(!INTEGRATION)('ingest: signed deliveries from log shippers and scanners', () => {
  let w: AppWorld;
  beforeAll(async () => {
    w = await startApp({ LOGIN_FAIL_MAX: '5' });
  });
  afterAll(() => w.close());
  beforeEach(() => w.reset());

  const secret = () => w.config.webhookSecrets[0] as string;
  const nowS = () => Math.floor(w.ctx.clock.now().getTime() / 1000);
  const send = (
    source: string,
    payload: unknown,
    over: { secret?: string; timestamp?: number; signature?: string; ip?: string; route?: string } = {},
  ) => {
    const raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const ts = over.timestamp ?? nowS();
    const signature =
      over.signature ?? signWebhook(over.secret ?? secret(), over.route ?? `/v1/ingest/${source}`, ts, raw);
    return w.call('POST', `/v1/ingest/${source}`, {
      key: null,
      ip: over.ip ?? '203.0.113.20',
      body: raw,
      headers: { 'content-type': 'application/json', 'x-nw-timestamp': String(ts), 'x-nw-signature': signature },
    });
  };
  const actions = async () => (await w.ctx.chain.recent({ limit: 200 })).map((e) => e.action).reverse();
  const sshd = (verb: 'Failed' | 'Accepted', user: string, ip: string) =>
    `Jan 15 12:00:01 host sshd[1234]: ${verb} password for ${verb === 'Failed' ? 'invalid user ' : ''}${user} from ${ip} port 52311 ssh2`;

  it('turns sshd lines into sign-in observations that the engine acts on', async () => {
    const lines = Array.from({ length: 6 }, (_, i) => sshd('Failed', `user${i}`, '203.0.113.99'));
    const res = await send('host-log', {
      host: 'bastion',
      lines: [...lines, 'Jan 15 12:00:02 host cron[1]: nothing to see'],
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ accepted: true, items: 7, matched: 6 });
    expect(res.json().notes.join(' ')).toMatch(/credential stuffing/);
    expect((await w.ctx.blocklist.check('203.0.113.99')).active).toBe(true);
    expect((await actions()).filter((a) => a === 'ingest_received')).toHaveLength(1);
  });

  it('reads successful sign-ins too, and ignores addresses that are not addresses', async () => {
    const res = await send('host-log', {
      lines: [sshd('Accepted', 'ana', '203.0.113.5'), sshd('Failed', 'x', 'not.an.ip.at.all')],
    });
    expect(res.json()).toMatchObject({ items: 2, matched: 1 });
    expect(await actions()).toEqual(['login_succeeded', 'ingest_received']);
  });

  it('keeps a dependency scan as counted evidence, and scores nothing', async () => {
    const res = await send('dependency-scan', {
      findings: [{ severity: 'HIGH' }, { severity: 'high' }, { severity: 'low' }, {}],
    });
    expect(res.json()).toMatchObject({ accepted: true, items: 4 });
    const [entry] = await w.ctx.chain.recent({ action: 'ingest_received' });
    expect(entry?.metadata).toMatchObject({
      source: 'dependency-scan',
      findings: 4,
      bySeverity: { high: 2, low: 1, unknown: 1 },
    });
    expect((await w.call('GET', '/v1/risk')).json().risk.score).toBe(0);
  });

  it('is bounded: lines past the cap are not read, and a line cannot make the pattern backtrack', async () => {
    const chatter = Array.from({ length: 800 }, () => 'Jan 15 12:00:02 host cron[1]: nothing to see');
    expect((await send('host-log', { lines: chatter })).json()).toMatchObject({ items: 500, matched: 0 });
    const hostile = 'sshd['.repeat(5000);
    const started = Date.now();
    await send('host-log', { lines: [hostile, `${' '.repeat(900)}sshd[1]: Failed password for ${'a'.repeat(500)}`] });
    expect(Date.now() - started).toBeLessThan(1500);
  });

  describe('refusals all look the same from outside', () => {
    it.each([
      ['a wrong signature', () => ({ signature: 'a'.repeat(64) }), 'webhook_bad_signature'],
      ['the wrong secret', () => ({ secret: 'not-the-secret-not-the-secret' }), 'webhook_bad_signature'],
      ['a signature made for another route', () => ({ route: '/v1/ingest/dependency-scan' }), 'webhook_bad_signature'],
      ['a stale timestamp', () => ({ timestamp: nowS() - 3600 }), 'webhook_bad_signature'],
    ])('%s', async (_name, over, recorded) => {
      const res = await send('host-log', { lines: [] }, over());
      expect(res.statusCode).toBe(401);
      expect(res.json().error.code).toBe('unauthorized');
      expect(res.json().error.message).toBe('the signature did not verify');
      expect(await actions()).toEqual([recorded]);
    });

    it('missing headers', async () => {
      const res = await w.call('POST', '/v1/ingest/host-log', {
        key: null,
        body: '{}',
        headers: { 'content-type': 'application/json' },
      });
      expect(res.statusCode).toBe(401);
    });

    it('a captured delivery cannot be replayed, and the replay is recorded as one', async () => {
      const ts = nowS();
      const body = { lines: [sshd('Accepted', 'ana', '203.0.113.5')] };
      expect((await send('host-log', body, { timestamp: ts })).statusCode).toBe(200);
      expect((await send('host-log', body, { timestamp: ts })).statusCode).toBe(401);
      expect(await actions()).toContain('webhook_replay');
    });

    it('the body is covered by the signature: change one byte and it fails', async () => {
      const ts = nowS();
      const good = JSON.stringify({ lines: [] });
      const res = await w.call('POST', '/v1/ingest/host-log', {
        key: null,
        body: good.replace('[]', '[ ]'),
        headers: {
          'content-type': 'application/json',
          'x-nw-timestamp': String(ts),
          'x-nw-signature': signWebhook(secret(), '/v1/ingest/host-log', ts, good),
        },
      });
      expect(res.statusCode).toBe(401);
    });

    it('an unknown source is a 404 before any signature work', async () => {
      expect((await send('nothing', {})).statusCode).toBe(404);
      expect(await actions()).toEqual([]);
    });

    it('a secret that was rotated out keeps working while it is still listed', async () => {
      const old = 'old-rotated-out-secret-0123456789';
      const rotated = await startApp({ WEBHOOK_SECRETS: `${'n'.repeat(24)},${old}` });
      try {
        const raw = JSON.stringify({ lines: [] });
        const ts = Math.floor(rotated.ctx.clock.now().getTime() / 1000);
        const res = await rotated.call('POST', '/v1/ingest/host-log', {
          key: null,
          body: raw,
          headers: {
            'content-type': 'application/json',
            'x-nw-timestamp': String(ts),
            'x-nw-signature': signWebhook(old, '/v1/ingest/host-log', ts, raw),
          },
        });
        expect(res.statusCode).toBe(200);
      } finally {
        await rotated.close();
      }
    });
  });

  describe('noise from strangers is capped, because strangers can write here', () => {
    it('forty forged deliveries from one address leave thirty rows and one “rate_limited”', async () => {
      for (let i = 0; i < 40; i++) await send('host-log', { n: i }, { signature: 'b'.repeat(64), ip: '198.51.100.9' });
      const seen = await actions();
      expect(seen.filter((a) => a === 'webhook_bad_signature')).toHaveLength(30);
      expect(seen.filter((a) => a === 'rate_limited')).toHaveLength(1);
      const [limited] = await w.ctx.chain.recent({ action: 'rate_limited' });
      expect(limited).toMatchObject({ ip: '198.51.100.9', metadata: { of: 'webhook_bad_signature', limit: 30 } });
    });

    it('another address is not affected by the first one’s noise', async () => {
      for (let i = 0; i < 35; i++) await send('host-log', { n: i }, { signature: 'b'.repeat(64), ip: '198.51.100.9' });
      await send('host-log', {}, { signature: 'c'.repeat(64), ip: '198.51.100.10' });
      expect(
        (await w.ctx.chain.recent({ action: 'webhook_bad_signature', limit: 100 })).filter(
          (e) => e.ip === '198.51.100.10',
        ),
      ).toHaveLength(1);
    });

    it('the window passes and the address is heard again', async () => {
      for (let i = 0; i < 35; i++) await send('host-log', { n: i }, { signature: 'b'.repeat(64), ip: '198.51.100.9' });
      w.clock.advance(601);
      await send('host-log', {}, { signature: 'c'.repeat(64), ip: '198.51.100.9' });
      expect((await actions()).filter((a) => a === 'webhook_bad_signature')).toHaveLength(31);
    });
  });
});
