import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../context.js';
import { authenticated, ipField } from './support.js';

/**
 * The guards as a service: a protected application asks "may I fetch this URL / redirect here / send this to a model?"
 * and gets a verdict. Every refusal is evidence in the audit chain. These are also what the lab's "try the hard things"
 * panel calls.
 */
export function registerGuards(app: FastifyInstance, ctx: Context): void {
  const guard = { preHandler: authenticated(ctx) };
  /**
   * Whom a refusal is held against. The caller of this API is the protected application, so by default the evidence
   * would name the application's own address; `ip` lets it name the person on whose behalf it is asking.
   */
  const behalf = z.object({ ip: ipField.optional(), userAgent: z.string().max(300).optional() });
  const who = (request: { caller: { ip: string | null; userAgent: string } }, body: z.infer<typeof behalf>) => ({
    ip: body.ip ?? request.caller.ip,
    userAgent: body.userAgent ?? request.caller.userAgent,
  });

  app.post('/v1/guards/url', guard, async (request) => {
    const body = behalf.extend({ url: z.string().min(1).max(2048) }).parse(request.body);
    return ctx.shield.url(body.url, who(request, body));
  });

  app.post('/v1/guards/redirect', guard, async (request) => {
    const body = behalf.extend({ target: z.unknown() }).parse(request.body);
    return ctx.shield.redirect(body.target, who(request, body));
  });

  app.post('/v1/guards/model', guard, async (request) => {
    const body = behalf.extend({ text: z.string().min(1).max(130_000) }).parse(request.body);
    return ctx.shield.model(body.text, who(request, body));
  });

  app.post('/v1/guards/client-ip', guard, async (request) => {
    const body = behalf
      .extend({
        remoteAddress: z.string().max(64),
        headers: z.record(z.union([z.string().max(500), z.array(z.string().max(500)).max(10)])).default({}),
      })
      .parse(request.body);
    const lowered = Object.fromEntries(Object.entries(body.headers).map(([k, v]) => [k.toLowerCase(), v]));
    return ctx.shield.clientIp(body.remoteAddress, lowered, who(request, body));
  });
}
