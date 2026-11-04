import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../context.js';
import { HttpError } from '../lib/http.js';
import { createOverride } from '../lib/risk-query.js';
import { authenticated, ipField, requireHuman } from './support.js';

const reason = z.string().min(1).max(300);

/**
 * Reading is open to anyone with the API key. Changing what the protected application lets through is not: every route
 * below that writes goes through the human gate (operator network + a code from the operator's authenticator). A stolen
 * API key can see everything and change nothing.
 */
export function registerControls(app: FastifyInstance, ctx: Context): void {
  const guard = { preHandler: authenticated(ctx) };

  app.get('/v1/blocklist', guard, async () => ({ blocked: await ctx.blocklist.list() }));

  app.post('/v1/blocklist', guard, async (request, reply) => {
    const body = z
      .object({ ip: ipField, seconds: z.number().int().min(60).max(604_800).default(3600), reason })
      .parse(request.body);
    const actor = await requireHuman(ctx, request, reply, 'block_ip');
    if (!actor) return reply;
    if (ctx.isAdminIp(body.ip))
      throw new HttpError(409, 'protected_address', 'the operators’ own network cannot be blocked from here');
    await ctx.blocklist.block(body.ip, body.seconds, body.reason, actor);
    await ctx.chain.append({
      actor,
      action: 'ip_blocked',
      ip: body.ip,
      metadata: { reason: body.reason, seconds: body.seconds, manual: true },
    });
    return { ok: true };
  });

  app.delete<{ Params: { ip: string } }>('/v1/blocklist/:ip', guard, async (request, reply) => {
    const ip = ipField.safeParse(decodeURIComponent(request.params.ip));
    if (!ip.success) throw new HttpError(400, 'invalid_request', 'invalid: ip');
    const actor = await requireHuman(ctx, request, reply, 'unblock_ip');
    if (!actor) return reply;
    const removed = await ctx.blocklist.unblock(ip.data);
    if (removed) await ctx.chain.append({ actor, action: 'ip_unblocked', ip: ip.data, metadata: {} });
    return { ok: true, removed };
  });

  app.get('/v1/lockdown', guard, async () => ctx.lockdown.status());

  app.post('/v1/lockdown', guard, async (request, reply) => {
    const body = z
      .object({ seconds: z.number().int().min(60).max(86_400).default(ctx.config.lockdownSeconds), reason })
      .parse(request.body);
    const actor = await requireHuman(ctx, request, reply, 'lockdown_on');
    if (!actor) return reply;
    const deadline = await ctx.lockdown.activate(body.seconds, body.reason, actor);
    await ctx.chain.append({
      actor,
      action: 'lockdown_on',
      metadata: { reason: body.reason, seconds: body.seconds, manual: true },
    });
    return { ok: true, deadline };
  });

  app.delete('/v1/lockdown', guard, async (request, reply) => {
    const actor = await requireHuman(ctx, request, reply, 'lockdown_off');
    if (!actor) return reply;
    const released = await ctx.lockdown.release();
    if (released) await ctx.chain.append({ actor, action: 'lockdown_off', metadata: {} });
    return { ok: true, released };
  });

  app.get('/v1/suspensions', guard, async () => ({ suspended: await ctx.suspensions.list() }));

  app.post('/v1/suspensions', guard, async (request, reply) => {
    const body = z.object({ subject: z.string().min(1).max(200), reason }).parse(request.body);
    const actor = await requireHuman(ctx, request, reply, 'suspend_subject');
    if (!actor) return reply;
    await ctx.suspensions.suspend(body.subject, body.reason, actor);
    await ctx.chain.append({
      actor,
      action: 'subject_suspended',
      subject: body.subject.toLowerCase(),
      metadata: { reason: body.reason, manual: true },
    });
    return { ok: true };
  });

  app.delete<{ Params: { subject: string } }>('/v1/suspensions/:subject', guard, async (request, reply) => {
    const subject = decodeURIComponent(request.params.subject).slice(0, 200);
    const actor = await requireHuman(ctx, request, reply, 'release_subject');
    if (!actor) return reply;
    const released = await ctx.suspensions.release(subject);
    if (released)
      await ctx.chain.append({ actor, action: 'subject_released', subject: subject.toLowerCase(), metadata: {} });
    return { ok: true, released };
  });

  app.post('/v1/overrides', guard, async (request, reply) => {
    const body = z.object({ seq: z.number().int().positive(), reason }).parse(request.body);
    const actor = await requireHuman(ctx, request, reply, 'override');
    if (!actor) return reply;
    const result = await createOverride(ctx.pool, ctx.chain, ctx.clock, {
      seq: body.seq,
      reason: body.reason,
      operator: actor,
    });
    if (result.ok) return { ok: true, id: result.id };
    const status = result.reason === 'not_found' ? 404 : 409;
    throw new HttpError(
      status,
      result.reason,
      {
        not_found: 'no such audit entry',
        not_scored: 'that kind of event does not count towards the score, so there is nothing to override',
        not_overridable:
          'this kind of event cannot be reclassified: it is the evidence of tampering, not an alert about it',
        already_overridden: 'this event was already reclassified',
      }[result.reason],
    );
  });
}
