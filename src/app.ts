import { resolve } from 'node:path';
import fastifyStatic from '@fastify/static';
import Fastify, { type FastifyInstance } from 'fastify';
import { RemoteAnalyst } from './alice/remote.js';
import type { Analyst } from './alice/types.js';
import { type Clock, OffsetClock, systemClock } from './clock.js';
import type { Config } from './config.js';
import { type Context, type Overrides, buildContext } from './context.js';
import { registerDemo } from './lab/demo.js';
import { registerLab } from './lab/routes.js';
import { installHttp } from './lib/http.js';
import { registerAlice } from './routes/alice.js';
import { registerControls } from './routes/controls.js';
import { registerCore } from './routes/core.js';
import { registerGuards } from './routes/guards.js';
import { registerIngest } from './routes/ingest.js';
import { installCaller } from './routes/support.js';

export interface Built {
  app: FastifyInstance;
  ctx: Context;
  close: () => Promise<void>;
}

export interface AppOverrides extends Overrides {
  logger?: boolean;
  fetchImpl?: typeof fetch;
}

/** The scripts and styles of the site are all same-origin files: nothing inline, nothing from elsewhere. */
export const SITE_CSP =
  "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

export async function buildApp(config: Config, overrides: AppOverrides = {}): Promise<Built> {
  const clock: Clock = overrides.clock ?? (config.labMode ? new OffsetClock() : systemClock);
  const ctx = await buildContext(config, { ...overrides, clock });

  const app = Fastify({
    logger: overrides.logger ?? false,
    bodyLimit: 1024 * 1024,
    // Forwarding headers are read by hand, from the right, against an explicit list of proxies (see resolveClientIp).
    trustProxy: false,
  });
  installHttp(app);
  installCaller(app, ctx);

  app.get('/health/live', async () => ({ status: 'ok' }));
  app.get('/health/ready', async (_request, reply) => {
    try {
      await ctx.pool.query('SELECT 1');
      await ctx.redis.ping();
      return { status: 'ok', lab: config.labMode };
    } catch {
      return reply.status(503).send({ status: 'unavailable' });
    }
  });

  // The analyst is optional. Without a model endpoint the local rules do the work, and say so.
  const remote: Analyst | null = config.analyst
    ? new RemoteAnalyst(config.analyst, {
        ...(overrides.fetchImpl ? { fetchImpl: overrides.fetchImpl } : {}),
        guard: async (serialized) => (await ctx.shield.model(serialized, { ip: null, userAgent: 'analyst' })).ok,
      })
    : null;

  registerCore(app, ctx);
  registerControls(app, ctx);
  registerAlice(app, ctx, remote);
  registerGuards(app, ctx);
  registerIngest(app, ctx);
  if (config.labMode) {
    registerDemo(app, ctx);
    registerLab(app, ctx);
  }

  if (!config.siteDir) {
    // A service with no page of its own still answers its root, so opening its port in a browser explains itself.
    app.get('/', async () => ({
      service: 'nightwatch-secops',
      message: 'This is an API with no page of its own. The demo site and the lab are served when SITE_DIR is set.',
      health: '/health/ready',
    }));
  } else {
    app.addHook('onSend', async (request, reply) => {
      if (!request.url.startsWith('/v1/') && !request.url.startsWith('/health/')) {
        reply.header('content-security-policy', SITE_CSP);
      }
    });
    await app.register(fastifyStatic, {
      root: resolve(process.cwd(), config.siteDir), // resolve, not join: SITE_DIR may be absolute (/app/site)
      index: ['index.html'],
      wildcard: false,
    });
  }

  return {
    app,
    ctx,
    close: async () => {
      await app.close();
      if (!overrides.pool) await ctx.pool.end().catch(() => undefined);
      if (!overrides.redis) await ctx.redis.quit().catch(() => undefined);
    },
  };
}
