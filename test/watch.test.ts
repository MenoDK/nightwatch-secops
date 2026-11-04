import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { DEMO_GEO } from '../src/lib/geo.js';
import { INTEGRATION, type Stack, startStack } from './harness.js';

const LISBON = '203.0.113.5';
const TOKYO = '198.51.100.7';
const SAO_PAULO = '192.0.2.44';

describe.skipIf(!INTEGRATION)('login watch', () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack({ LOGIN_FAIL_MAX: '5', LOGIN_FAIL_WINDOW_SECONDS: '300' });
  });
  afterAll(() => s.close());
  beforeEach(() => s.reset());

  it('counts failures per address and raises exactly one alarm per attack', async () => {
    const seen = [];
    for (let i = 0; i < 8; i++) seen.push(await s.ctx.loginWatch.failed('203.0.113.9', `user${i}@example.test`));
    expect(seen.map((a) => a.ipCount)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(seen.filter((a) => a.raised)).toHaveLength(1);
    expect(seen[4]).toMatchObject({ raised: true, pattern: 'one_address' });
    expect(seen[5]).toMatchObject({ raised: false, pattern: 'one_address' });
  });

  it('tells a brute force on one account (many addresses) from stuffing (one address)', async () => {
    const seen = [];
    for (let i = 0; i < 5; i++) seen.push(await s.ctx.loginWatch.failed(`203.0.113.${10 + i}`, 'ana@example.test'));
    expect(seen[3]).toMatchObject({ raised: false, pattern: 'none', subjectCount: 4 });
    expect(seen[4]).toMatchObject({ raised: true, pattern: 'one_account', subjectCount: 5 });
  });

  it('forgets failures older than the window', async () => {
    for (let i = 0; i < 4; i++) await s.ctx.loginWatch.failed('203.0.113.9', `u${i}@example.test`);
    s.clock.advance(301);
    const next = await s.ctx.loginWatch.failed('203.0.113.9', 'late@example.test');
    expect(next).toMatchObject({ ipCount: 1, raised: false, pattern: 'none' });
  });

  it('a slow trickle never trips it: four failures, a wait, four more', async () => {
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 4; i++) {
        const a = await s.ctx.loginWatch.failed('203.0.113.9', `u${i}@example.test`);
        expect(a.pattern).toBe('none');
      }
      s.clock.advance(301);
    }
  });

  it('a successful sign-in clears that account’s count, not the address’s', async () => {
    for (let i = 0; i < 3; i++) await s.ctx.loginWatch.failed(`203.0.113.${20 + i}`, 'ana@example.test');
    await s.ctx.loginWatch.succeeded('Ana@Example.test');
    const next = await s.ctx.loginWatch.failed('203.0.113.99', 'ana@example.test');
    expect(next.subjectCount).toBe(1);
    const same = await s.ctx.loginWatch.failed('203.0.113.20', 'bob@example.test');
    expect(same.ipCount).toBe(2);
  });

  it('works without an address or without an account', async () => {
    expect(await s.ctx.loginWatch.failed(null, 'ana@example.test')).toMatchObject({ ipCount: 0, subjectCount: 1 });
    expect(await s.ctx.loginWatch.failed('203.0.113.9', null)).toMatchObject({ ipCount: 1, subjectCount: 0 });
  });
});

describe.skipIf(!INTEGRATION)('geo watch', () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack({ ADMIN_IPS: '10.20.0.0/16' }, { geo: DEMO_GEO });
  });
  afterAll(() => s.close());
  beforeEach(() => s.reset());

  it('the first sighting only sets the baseline', async () => {
    expect(await s.ctx.geoWatch.check('ana@example.test', LISBON)).toEqual({ status: 'first_seen' });
  });

  it('flags Lisbon then Tokyo ten minutes later', async () => {
    await s.ctx.geoWatch.check('ana@example.test', LISBON);
    s.clock.advance(600);
    const result = await s.ctx.geoWatch.check('ana@example.test', TOKYO);
    expect(result.status).toBe('impossible');
    if (result.status === 'impossible') {
      expect(result.verdict.km).toBeGreaterThan(10_000);
      expect(result.verdict.speedKmh).toBeGreaterThan(50_000);
      expect(result.from.lat).toBeCloseTo(38.7, 0);
    }
  });

  it('accepts the same journey with a flight’s worth of time', async () => {
    await s.ctx.geoWatch.check('ana@example.test', LISBON);
    s.clock.advance(20 * 3600);
    expect((await s.ctx.geoWatch.check('ana@example.test', TOKYO)).status).toBe('ok');
  });

  it('moves the baseline even on an alert, so one trip is one alert', async () => {
    await s.ctx.geoWatch.check('ana@example.test', LISBON);
    s.clock.advance(600);
    expect((await s.ctx.geoWatch.check('ana@example.test', TOKYO)).status).toBe('impossible');
    s.clock.advance(60);
    expect((await s.ctx.geoWatch.check('ana@example.test', TOKYO)).status).toBe('ok');
  });

  it('keeps one baseline per account, case-insensitively', async () => {
    await s.ctx.geoWatch.check('Ana@Example.test', LISBON);
    s.clock.advance(600);
    expect((await s.ctx.geoWatch.check('bob@example.test', TOKYO)).status).toBe('first_seen');
    expect((await s.ctx.geoWatch.check('ana@example.test', SAO_PAULO)).status).toBe('impossible');
  });

  it('does not judge an address it cannot place, nor an operator on the allow-list', async () => {
    expect((await s.ctx.geoWatch.check('ana@example.test', '8.8.8.8')).status).toBe('unknown_address');
    expect((await s.ctx.geoWatch.check('ana@example.test', '10.20.1.2')).status).toBe('exempt');
  });
});
