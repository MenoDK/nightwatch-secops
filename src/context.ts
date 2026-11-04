import { Redis } from 'ioredis';
import { type Clock, systemClock } from './clock.js';
import type { Config } from './config.js';
import { type Pool, createPool, migrate } from './db.js';
import { AuditChain } from './lib/audit-chain.js';
import { Blocklist, Lockdown, Suspensions } from './lib/controls.js';
import { Engine } from './lib/engine.js';
import { DEMO_GEO, type GeoProvider } from './lib/geo.js';
import type { Resolver } from './lib/guards/ssrf.js';
import { Kv } from './lib/kv.js';
import { matchesAny } from './lib/net.js';
import { Shield } from './lib/shield.js';
import { StepUp } from './lib/step-up.js';
import { GeoWatch, LoginWatch } from './lib/watch.js';

export interface Overrides {
  clock?: Clock;
  pool?: Pool;
  redis?: Redis;
  geo?: GeoProvider;
  resolver?: Resolver;
}

/** Every long-lived object, built once and handed around. Nothing in the tree reaches for a global. */
export interface Context {
  config: Config;
  clock: Clock;
  pool: Pool;
  redis: Redis;
  kv: Kv;
  chain: AuditChain;
  blocklist: Blocklist;
  lockdown: Lockdown;
  suspensions: Suspensions;
  loginWatch: LoginWatch;
  geoWatch: GeoWatch;
  stepUp: StepUp;
  engine: Engine;
  shield: Shield;
  geo: GeoProvider;
  isAdminIp: (ip: string | null) => boolean;
  close: () => Promise<void>;
}

/** The name server is only asked in production; tests and the demo hand in a table of their own. */
async function systemResolver(hostname: string): Promise<string[]> {
  const { lookup } = await import('node:dns/promises');
  return (await lookup(hostname, { all: true })).map((r) => r.address);
}

export async function buildContext(config: Config, overrides: Overrides = {}): Promise<Context> {
  const clock = overrides.clock ?? systemClock;
  const pool = overrides.pool ?? createPool(config.databaseUrl);
  const redis =
    overrides.redis ??
    new Redis(config.redisUrl, { maxRetriesPerRequest: 1, enableOfflineQueue: false, lazyConnect: false });
  // A Redis that is down must be an answer ("degraded"), not an unhandled event.
  redis.on('error', () => undefined);
  await migrate(pool);

  const kv = new Kv(redis, config.redisPrefix);
  const chain = new AuditChain(pool, clock, config.auditChainSecret);
  const blocklist = new Blocklist(kv, clock, config.failClosed);
  const lockdown = new Lockdown(kv, clock, config.failClosed);
  const suspensions = new Suspensions(kv, clock, config.failClosed);
  const geo = overrides.geo ?? DEMO_GEO;
  const isAdminIp = (ip: string | null): boolean => ip !== null && matchesAny(ip, config.adminIps);

  const loginWatch = new LoginWatch(kv, clock, {
    max: config.loginFailMax,
    windowSeconds: config.loginFailWindowSeconds,
  });
  const geoWatch = new GeoWatch(kv, clock, geo, config.travel, (ip) => isAdminIp(ip));
  const stepUp = new StepUp(
    kv,
    clock,
    { secret: config.totpSecret, ...config.stepUp },
    {
      failed: async (operator, detail) => {
        await chain.append({ actor: operator, action: 'step_up_failed', metadata: detail });
      },
      lockedOut: async (operator, detail) => {
        await chain.append({ actor: operator, action: 'step_up_lockout', metadata: detail });
      },
    },
  );
  const engine = new Engine({ chain, clock, config, blocklist, lockdown, suspensions, loginWatch, geoWatch });
  const shield = new Shield(chain, kv, clock, config, overrides.resolver ?? systemResolver);

  return {
    config,
    clock,
    pool,
    redis,
    kv,
    chain,
    blocklist,
    lockdown,
    suspensions,
    loginWatch,
    geoWatch,
    stepUp,
    engine,
    shield,
    geo,
    isAdminIp,
    close: async () => {
      await redis.quit().catch(() => undefined);
      await pool.end().catch(() => undefined);
    },
  };
}
