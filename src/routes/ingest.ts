import type { FastifyInstance } from 'fastify';
import type { Context } from '../context.js';
import { errorBody } from '../lib/http.js';
import { isIngestSource, normalize } from '../lib/ingest.js';

/**
 * Where log shippers and scanners deliver. There is no API key here: the sender proves itself with a signature over the
 * time, the route and the exact bytes, so a captured request cannot be replayed or pointed at another route. Every
 * refusal looks the same from outside; the reason goes to the audit chain.
 */
export function registerIngest(app: FastifyInstance, ctx: Context): void {
  app.post<{ Params: { source: string } }>('/v1/ingest/:source', async (request, reply) => {
    const source = request.params.source;
    if (!isIngestSource(source)) return reply.status(404).send(errorBody('not_found', 'no such source'));

    const route = `/v1/ingest/${source}`;
    const header = (name: string) =>
      typeof request.headers[name] === 'string' ? (request.headers[name] as string) : undefined;
    const verdict = await ctx.shield.webhook(
      {
        route,
        rawBody: request.rawBody?.toString('utf8') ?? '',
        timestamp: header('x-nw-timestamp'),
        signature: header('x-nw-signature'),
      },
      { ip: request.caller.ip, userAgent: request.caller.userAgent },
    );
    if (!verdict.ok) return reply.status(401).send(errorBody('unauthorized', 'the signature did not verify'));

    const normalized = normalize(source, request.body);
    const notes: string[] = [];
    let contained = 0;
    for (const report of normalized.reports) {
      const outcome = await ctx.engine.report(report);
      notes.push(...outcome.notes);
      if (outcome.contained.ipBlocked || outcome.contained.subjectSuspended || outcome.contained.lockdown)
        contained += 1;
    }
    await ctx.chain.append({
      actor: `ingest:${source}`,
      action: 'ingest_received',
      ip: request.caller.ip,
      metadata: { source, items: normalized.items, matched: normalized.matched, contained, ...normalized.summary },
    });
    return {
      accepted: true,
      items: normalized.items,
      matched: normalized.matched,
      notes: [...new Set(notes)].slice(0, 20),
    };
  });
}
