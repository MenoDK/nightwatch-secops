import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Context } from '../context.js';
import { errorBody } from '../lib/http.js';

/** The only credential of the demo application. It protects a fictional app that exists to be attacked in the lab. */
export const DEMO_PASSWORD = 'demo-password';
const DEMO_USERS = new Set(['ana@example.test', 'bob@example.test']);

/**
 * A stand-in for "the application being protected", so the whole loop can be seen in one browser tab: a request comes in,
 * is checked against the containments, is reported to the engine, and the engine's verdict changes what the next request
 * gets. Registered only in lab mode - a production deployment protects someone else's application, not its own.
 */
export function registerDemo(app: FastifyInstance, ctx: Context): void {
  /** True when the request may proceed. Otherwise the reply has been sent and says which containment stopped it. */
  async function admitted(request: FastifyRequest, reply: FastifyReply, subject?: string): Promise<boolean> {
    const blocked = await ctx.blocklist.check(request.caller.ip);
    if (blocked.active) {
      await reply.status(403).send(errorBody('blocked', 'this address is blocked'));
      return false;
    }
    const lockdown = await ctx.lockdown.status();
    if (lockdown.active) {
      await reply.status(503).send(errorBody('lockdown', 'the application is in lockdown'));
      return false;
    }
    if (subject) {
      const suspended = await ctx.suspensions.status(subject);
      if (suspended.active) {
        await reply.status(403).send(errorBody('suspended', 'this account is suspended'));
        return false;
      }
    }
    return true;
  }

  const subjectOf = (request: FastifyRequest): string | undefined => {
    const header = request.headers['x-subject'];
    return typeof header === 'string' && header.length <= 200 ? header.toLowerCase() : undefined;
  };

  app.post('/v1/demo/login', async (request, reply) => {
    const body = z.object({ email: z.string().min(1).max(200), password: z.string().max(200) }).parse(request.body);
    const email = body.email.toLowerCase();
    if (!(await admitted(request, reply, email))) return reply;
    const ok = DEMO_USERS.has(email) && body.password === DEMO_PASSWORD;
    const outcome = await ctx.engine.report({
      kind: ok ? 'login_succeeded' : 'login_failed',
      ip: request.caller.ip ?? '0.0.0.0',
      subject: email,
      userAgent: request.caller.userAgent,
    });
    return reply.status(ok ? 200 : 401).send({ ok, lab: { notes: outcome.notes, contained: outcome.contained } });
  });

  app.get('/v1/demo/resource', async (request, reply) => {
    const subject = subjectOf(request);
    if (!(await admitted(request, reply, subject))) return reply;
    const outcome = subject
      ? await ctx.engine.report({
          kind: 'api_request',
          ip: request.caller.ip ?? '0.0.0.0',
          subject,
          userAgent: request.caller.userAgent,
        })
      : null;
    return {
      ok: true,
      resource: 'quarterly-report (fictional)',
      subject: subject ?? null,
      lab: { notes: outcome?.notes ?? [] },
    };
  });

  app.get<{ Params: { id: string } }>('/v1/demo/records/:id', async (request, reply) => {
    const subject = subjectOf(request);
    if (!(await admitted(request, reply, subject))) return reply;
    const id = request.params.id.slice(0, 80);
    const outcome = await ctx.engine.report({
      kind: 'record_read',
      ip: request.caller.ip ?? '0.0.0.0',
      ...(subject ? { subject } : {}),
      userAgent: request.caller.userAgent,
      metadata: { id },
    });
    // The decoy answers like any record: a canary that behaves differently is a canary that is noticed.
    return { id, owner: 'someone@example.test', note: 'a fictional record', lab: { notes: outcome.notes } };
  });
}
