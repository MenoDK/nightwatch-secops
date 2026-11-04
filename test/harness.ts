import { randomBytes } from 'node:crypto';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { Redis } from 'ioredis';
import pg from 'pg';
import { type AppOverrides, buildApp } from '../src/app.js';
import type { Clock } from '../src/clock.js';
import { type Config, loadConfig } from '../src/config.js';
import { type Context, type Overrides, buildContext } from '../src/context.js';
import { createPool } from '../src/db.js';
import type { Resolver } from '../src/lib/guards/ssrf.js';
import { newTotpSecret, totpAt } from '../src/lib/totp.js';

export const DATABASE_URL = process.env.DATABASE_URL ?? '';
export const REDIS_URL = process.env.REDIS_URL ?? '';
/** The stateful tests need both stores; without them the files skip, so `pnpm test` still works on a bare checkout. */
export const INTEGRATION = DATABASE_URL !== '' && REDIS_URL !== '';

/** Credentials for tests are made at run time: nothing here is, or ever was, a real secret. */
export const fresh = (bytes = 24): string => randomBytes(bytes).toString('base64url');

/** A clock the tests move by hand. */
export class TestClock implements Clock {
  #ms = Date.parse('2030-01-15T12:00:00Z');
  now(): Date {
    return new Date(this.#ms);
  }
  advance(seconds: number): void {
    this.#ms += seconds * 1000;
  }
}

/** What names resolve to in tests: no DNS, and the interesting cases written down. */
export const TEST_DNS: Record<string, string[]> = {
  'public.example.test': ['1.1.1.1'],
  'internal.example.test': ['10.0.0.8'],
  'rebinding.example.test': ['1.1.1.1', '10.0.0.8'],
  'metadata.example.test': ['169.254.169.254'],
};

export const testResolver: Resolver = async (hostname) => {
  const found = TEST_DNS[hostname];
  if (!found) throw new Error('ENOTFOUND');
  return found;
};

export function testEnv(over: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    DATABASE_URL,
    REDIS_URL,
    APP_ENV: 'test',
    API_KEY: fresh(12),
    AUDIT_CHAIN_SECRET: fresh(),
    WEBHOOK_SECRETS: fresh(),
    TOTP_SECRET: newTotpSecret(),
    ADMIN_IPS: '10.20.0.0/16',
    ...over,
  };
}

export interface Stack {
  ctx: Context;
  config: Config;
  clock: TestClock;
  schema: string;
  /** Raw SQL against this stack's schema. */
  sql: (text: string, values?: unknown[]) => Promise<pg.QueryResultRow[]>;
  /** Empties both stores, keeping the schema: each test starts from nothing. */
  reset: () => Promise<void>;
  close: () => Promise<void>;
}

/** One schema and one Redis prefix per stack, so test files share the two servers and still run in parallel. */
export async function startStack(env: Record<string, string> = {}, overrides: Overrides = {}): Promise<Stack> {
  const suffix = randomBytes(4).toString('hex');
  const schema = `t_${suffix}`;
  const admin = new pg.Pool({ connectionString: DATABASE_URL, max: 1 });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const config = loadConfig(testEnv({ REDIS_PREFIX: `t${suffix}`, ...env }));
  const clock = new TestClock();
  const ctx = await buildContext(config, {
    clock,
    pool: createPool(DATABASE_URL, { schema }),
    resolver: testResolver,
    ...overrides,
  });
  const janitor = new Redis(REDIS_URL);
  return {
    ctx,
    config,
    clock,
    schema,
    sql: async (text, values = []) => (await ctx.pool.query(text, values)).rows,
    reset: async () => {
      await ctx.pool.query('TRUNCATE audit_chain, overrides, proposals RESTART IDENTITY CASCADE');
      await ctx.pool.query("UPDATE chain_head SET last_seq = 0, last_hash = '' WHERE id = 1");
      await ctx.kv.flush();
    },
    close: async () => {
      await ctx.kv.flush().catch(() => undefined);
      await ctx.close();
      await admin.query(`DROP SCHEMA ${schema} CASCADE`).catch(() => undefined);
      await admin.end();
      await janitor.quit().catch(() => undefined);
    },
  };
}

/** The six-digit code the operator's authenticator would show right now. */
export { totpAt };

/** An address inside the allow-listed operators' network (ADMIN_IPS in {@link testEnv}). */
export const OPERATOR_IP = '10.20.1.2';
/** Anyone else. */
export const OUTSIDER_IP = '203.0.113.200';

export interface Call {
  /** The peer address the request appears to come from. */
  ip?: string;
  body?: unknown;
  /** The six-digit second factor, sent as x-totp. */
  code?: string;
  /** Override the API key; `null` sends none. */
  key?: string | null;
  headers?: Record<string, string>;
}

export interface AppWorld extends Stack {
  app: FastifyInstance;
  apiKey: string;
  call: (method: 'GET' | 'POST' | 'DELETE', url: string, options?: Call) => Promise<LightMyRequestResponse>;
  /** The code the operator's authenticator would show at the service's own time. */
  code: (offsetSteps?: number) => string;
}

/** The whole service over HTTP (`inject`, no sockets), on its own schema and Redis prefix. */
export async function startApp(env: Record<string, string> = {}, overrides: AppOverrides = {}): Promise<AppWorld> {
  const suffix = randomBytes(4).toString('hex');
  const schema = `t_${suffix}`;
  const admin = new pg.Pool({ connectionString: DATABASE_URL, max: 1 });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const config = loadConfig(testEnv({ REDIS_PREFIX: `t${suffix}`, ...env }));
  const testClock = new TestClock();
  // In lab mode the app builds its own movable clock; otherwise the test moves time by hand.
  const clockOverride = config.labMode ? {} : { clock: testClock };
  const built = await buildApp(config, {
    pool: createPool(DATABASE_URL, { schema }),
    resolver: testResolver,
    ...clockOverride,
    ...overrides,
  });
  const { ctx, app } = built;
  return {
    ctx,
    config,
    clock: testClock,
    schema,
    app,
    apiKey: config.apiKey,
    sql: async (text, values = []) => (await ctx.pool.query(text, values)).rows,
    reset: async () => {
      await ctx.pool.query('TRUNCATE audit_chain, overrides, proposals RESTART IDENTITY CASCADE');
      await ctx.pool.query("UPDATE chain_head SET last_seq = 0, last_hash = '' WHERE id = 1");
      await ctx.kv.flush();
    },
    code: (offsetSteps = 0) => totpAt(config.totpSecret, ctx.clock.now().getTime() + offsetSteps * 30_000),
    call: (method, url, options = {}) =>
      app.inject({
        method,
        url,
        remoteAddress: options.ip ?? OUTSIDER_IP,
        headers: {
          ...(options.key === null ? {} : { 'x-api-key': options.key ?? config.apiKey }),
          ...(options.code ? { 'x-totp': options.code } : {}),
          ...options.headers,
        },
        ...(options.body === undefined ? {} : { payload: options.body as object | string }),
      }),
    close: async () => {
      await ctx.kv.flush().catch(() => undefined);
      await app.close();
      await ctx.close();
      await admin.query(`DROP SCHEMA ${schema} CASCADE`).catch(() => undefined);
      await admin.end();
    },
  };
}
