import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Context } from '../context.js';
import { type GateResult, type Human, authorizeHuman, operatorLabel } from '../lib/gate.js';
import { resolveClientIp } from '../lib/guards/client-ip.js';
import { apiKeyGuard, errorBody } from '../lib/http.js';
import { normalizeIp } from '../lib/net.js';

export interface Caller {
  ip: string | null;
  userAgent: string;
  /** Who the caller says they are. Attribution only. */
  operator: string;
  /** Header names that claimed to carry a client address but came from a peer we do not trust. */
  spoofed: string[];
}

declare module 'fastify' {
  interface FastifyRequest {
    caller: Caller;
  }
}

/** The caller's address, resolved once per request. In lab mode a header may stand in for it, so one browser can play many callers. */
export function installCaller(app: FastifyInstance, ctx: Context): void {
  app.decorateRequest('caller', undefined as unknown as Caller);
  app.addHook('onRequest', async (request) => {
    const resolved = resolveClientIp({
      remoteAddress: request.socket.remoteAddress ?? '',
      headers: request.headers,
      trustedProxies: ctx.config.trustedProxies,
    });
    let ip = resolved.ip;
    if (ctx.config.labMode) {
      const pretend = request.headers['x-lab-client-ip'];
      const normalized = typeof pretend === 'string' ? normalizeIp(pretend) : null;
      if (normalized) ip = normalized;
    }
    request.caller = {
      ip,
      userAgent: String(request.headers['user-agent'] ?? '').slice(0, 300),
      operator: operatorLabel(request.headers['x-operator']),
      spoofed: resolved.spoofed,
    };
  });
}

/**
 * The API-key check. A forged forwarding header is recorded only for callers who passed it: an unauthenticated stranger
 * must not be able to make the audit chain grow just by sending a header.
 */
export function authenticated(ctx: Context) {
  const check = apiKeyGuard(ctx.config.apiKey);
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    await check(request, reply);
    if (reply.sent) return;
    if (request.caller.spoofed.length > 0) {
      await ctx.shield.clientIp(request.socket.remoteAddress ?? '', request.headers, {
        ip: request.caller.ip,
        userAgent: request.caller.userAgent,
      });
    }
  };
}

export const humanOf = (request: FastifyRequest): Human => ({
  label: request.caller.operator,
  ip: request.caller.ip,
  userAgent: request.caller.userAgent,
  code: typeof request.headers['x-totp'] === 'string' ? request.headers['x-totp'] : undefined,
});

/** Runs the human gate and answers the request itself when it refuses. Returns the actor on success. */
export async function requireHuman(
  ctx: Context,
  request: FastifyRequest,
  reply: FastifyReply,
  what: string,
): Promise<string | null> {
  const gate = await authorizeHuman(ctx, humanOf(request), what);
  if (gate.ok) return gate.actor;
  await refuse(reply, gate);
  return null;
}

export async function refuse(
  reply: FastifyReply,
  gate: Extract<GateResult, { ok: false }> | { status: number; code: string; message: string; remaining?: number },
) {
  const body = errorBody(gate.code, gate.message);
  return reply
    .status(gate.status)
    .send(
      'remaining' in gate && gate.remaining !== undefined
        ? { error: { ...body.error, remaining: gate.remaining } }
        : body,
    );
}

export const ipField = z
  .string()
  .max(64)
  .refine((v) => normalizeIp(v) !== null, 'not an IP address')
  .transform((v) => normalizeIp(v) as string);

export const entryJson = (e: {
  seq: number;
  id: string;
  at: Date;
  actor: string;
  action: string;
  subject: string | null;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  rowHash: string;
}) => ({
  seq: e.seq,
  id: e.id,
  at: e.at.toISOString(),
  actor: e.actor,
  action: e.action,
  subject: e.subject,
  ip: e.ip,
  userAgent: e.userAgent,
  metadata: e.metadata,
  hash: e.rowHash.slice(0, 16),
});
