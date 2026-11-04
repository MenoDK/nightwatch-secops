import type { Redis } from 'ioredis';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Blocklist, Lockdown, Suspensions } from '../src/lib/controls.js';
import { Kv } from '../src/lib/kv.js';
import { INTEGRATION, type Stack, TestClock, startStack } from './harness.js';

describe.skipIf(!INTEGRATION)('containments', () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack();
  });
  afterAll(() => s.close());
  beforeEach(() => s.reset());

  describe('blocklist', () => {
    it('blocks an address until its deadline, measured by the injected clock', async () => {
      await s.ctx.blocklist.block('203.0.113.9', 60, 'test', 'tester');
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(true);
      s.clock.advance(59);
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(true);
      s.clock.advance(2);
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(false);
    });

    it('the deadline decides even though Redis still holds the key a minute longer', async () => {
      await s.ctx.blocklist.block('203.0.113.9', 60, 'test', 'tester');
      s.clock.advance(90); // past the deadline, inside the 60 s of garbage-collection slack
      expect(await s.ctx.redis.exists(s.ctx.kv.key('block', '203.0.113.9'))).toBe(1);
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(false);
    });

    it('treats the IPv4-mapped form and the plain form as one address', async () => {
      await s.ctx.blocklist.block('::ffff:203.0.113.9', 600, 'test', 'tester');
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(true);
      expect((await s.ctx.blocklist.check('::ffff:cb00:7109')).active).toBe(true);
    });

    it('and one IPv6 address however it is written', async () => {
      await s.ctx.blocklist.block('2001:DB8:0:0:0:0:0:1', 600, 'test', 'tester');
      expect((await s.ctx.blocklist.check('2001:db8::1')).active).toBe(true);
    });

    it('refuses to block something that is not an address, and ignores a lookup of one', async () => {
      await expect(s.ctx.blocklist.block('not-an-ip', 60, 'x', 'y')).rejects.toBeInstanceOf(RangeError);
      expect((await s.ctx.blocklist.check('not-an-ip')).active).toBe(false);
      expect((await s.ctx.blocklist.check(null)).active).toBe(false);
    });

    it('unblocks, and says whether there was anything to unblock', async () => {
      await s.ctx.blocklist.block('203.0.113.9', 600, 'test', 'tester');
      expect(await s.ctx.blocklist.unblock('203.0.113.9')).toBe(true);
      expect(await s.ctx.blocklist.unblock('203.0.113.9')).toBe(false);
      expect((await s.ctx.blocklist.check('203.0.113.9')).active).toBe(false);
    });

    it('lists only the live entries, newest first', async () => {
      await s.ctx.blocklist.block('203.0.113.1', 30, 'short', 'tester');
      s.clock.advance(5);
      await s.ctx.blocklist.block('203.0.113.2', 600, 'long', 'tester');
      expect((await s.ctx.blocklist.list()).map((e) => e.ip)).toEqual(['203.0.113.2', '203.0.113.1']);
      s.clock.advance(60);
      expect((await s.ctx.blocklist.list()).map((e) => e.ip)).toEqual(['203.0.113.2']);
    });

    it('keeps the reason and the author with the entry', async () => {
      await s.ctx.blocklist.block('203.0.113.9', 600, 'credential stuffing', 'engine');
      const state = await s.ctx.blocklist.check('203.0.113.9');
      expect(state.deadline).toMatchObject({ reason: 'credential stuffing', by: 'engine' });
    });
  });

  describe('lockdown', () => {
    it('is off until switched on, then on until its deadline', async () => {
      expect((await s.ctx.lockdown.status()).active).toBe(false);
      await s.ctx.lockdown.activate(120, 'drill', 'tester');
      expect((await s.ctx.lockdown.status()).active).toBe(true);
      s.clock.advance(121);
      expect((await s.ctx.lockdown.status()).active).toBe(false);
    });

    it('can be released early', async () => {
      await s.ctx.lockdown.activate(3600, 'drill', 'tester');
      expect(await s.ctx.lockdown.release()).toBe(true);
      expect((await s.ctx.lockdown.status()).active).toBe(false);
      expect(await s.ctx.lockdown.release()).toBe(false);
    });
  });

  describe('suspensions', () => {
    it('are per account, case-insensitive, and do not expire by themselves', async () => {
      await s.ctx.suspensions.suspend('Ana@Example.test', 'impossible travel', 'engine');
      expect((await s.ctx.suspensions.status('ana@example.test')).active).toBe(true);
      expect((await s.ctx.suspensions.status('bob@example.test')).active).toBe(false);
      s.clock.advance(30 * 24 * 3600);
      expect((await s.ctx.suspensions.status('ANA@example.test')).active).toBe(true);
      expect((await s.ctx.suspensions.list()).map((e) => e.subject)).toEqual(['ana@example.test']);
      expect(await s.ctx.suspensions.release('ana@example.test')).toBe(true);
      expect((await s.ctx.suspensions.status('ana@example.test')).active).toBe(false);
    });
  });
});

/**
 * "What happens when Redis dies" is a decision, not an accident. These tests use a store that throws, with no server
 * involved, so they run even without the integration stack.
 */
describe('when the store cannot be read', () => {
  const dead = new Kv(
    {
      get: async () => {
        throw new Error('connection refused');
      },
    } as unknown as Redis,
    'x',
  );
  const clock = new TestClock();

  it('fails open when told to: traffic goes through, and the answer says it is a guess', async () => {
    expect(await new Blocklist(dead, clock, false).check('203.0.113.9')).toEqual({ active: false, degraded: true });
    expect(await new Lockdown(dead, clock, false).status()).toEqual({ active: false, degraded: true });
    expect(await new Suspensions(dead, clock, false).status('ana')).toEqual({ active: false, degraded: true });
  });

  it('fails closed when told to: nothing goes through', async () => {
    expect(await new Blocklist(dead, clock, true).check('203.0.113.9')).toEqual({ active: true, degraded: true });
    expect(await new Lockdown(dead, clock, true).status()).toEqual({ active: true, degraded: true });
    expect(await new Suspensions(dead, clock, true).status('ana')).toEqual({ active: true, degraded: true });
  });

  it('an address that is not valid is never "blocked" just because the store is down', async () => {
    expect((await new Blocklist(dead, clock, true).check(null)).active).toBe(false);
    expect((await new Blocklist(dead, clock, true).check('garbage')).active).toBe(false);
  });
});
