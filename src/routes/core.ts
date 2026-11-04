import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { windowEntries } from '../alice/runner.js';
import type { Context } from '../context.js';
import { evaluateEscalation } from '../lib/escalation.js';
import { AUDIT_ACTIONS, REPORT_KINDS } from '../lib/events.js';
import { HttpError } from '../lib/http.js';
import { readRisk } from '../lib/risk-query.js';
import { authenticated, entryJson, ipField } from './support.js';

const event = z.object({
  kind: z.enum(REPORT_KINDS),
  /** The end user's address, as the protected application saw it. */
  ip: ipField,
  subject: z.string().min(1).max(200).optional(),
  userAgent: z.string().max(300).optional(),
  metadata: z
    .record(z.unknown())
    .optional()
    .refine((m) => m === undefined || JSON.stringify(m).length <= 4096, 'metadata is limited to 4 KB'),
});

const auditQuery = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  action: z.enum(AUDIT_ACTIONS).optional(),
  sinceSeq: z.coerce.number().int().min(0).default(0),
});

const anchor = z.object({
  seq: z.number().int().min(0),
  hash: z.string().length(64),
  at: z.string().max(40),
  mac: z.string().length(64),
});

export function registerCore(app: FastifyInstance, ctx: Context): void {
  const guard = { preHandler: authenticated(ctx) };

  app.post('/v1/events', guard, async (request) => {
    const body = event.parse(request.body);
    return ctx.engine.report({
      kind: body.kind,
      ip: body.ip,
      subject: body.subject,
      userAgent: body.userAgent,
      metadata: body.metadata,
    });
  });

  app.get('/v1/audit', guard, async (request) => {
    const q = auditQuery.parse(request.query);
    const entries = await ctx.chain.recent({
      limit: q.limit,
      sinceSeq: q.sinceSeq,
      ...(q.action ? { action: q.action } : {}),
    });
    return { total: await ctx.chain.count(), entries: entries.map(entryJson) };
  });

  /**
   * A chain that does not verify is itself an event: it is written to the chain (once in five minutes, so polling a
   * broken chain does not fill it) and feeds the risk score, where nobody can mark it a false positive.
   */
  const verify = async (receipt?: z.infer<typeof anchor>) => {
    const result = await ctx.chain.verify(receipt ? { anchor: receipt } : {});
    let alarmed = false;
    if (!result.ok && (await ctx.kv.claim(ctx.kv.key('integrity-alarm'), 300))) {
      await ctx.chain.append({
        actor: 'engine',
        action: 'audit_integrity_failed',
        metadata: { problem: result.problem ?? null, checked: result.checked },
      });
      alarmed = true;
    }
    return { ...result, alarmed };
  };

  app.get('/v1/audit/verify', guard, async () => verify());

  app.post('/v1/audit/verify', guard, async (request) => {
    const body = z.object({ anchor }).parse(request.body);
    if (!ctx.chain.isOurAnchor(body.anchor)) {
      throw new HttpError(400, 'anchor_not_ours', 'that receipt was not signed by this service, so it proves nothing');
    }
    return verify(body.anchor);
  });

  app.post('/v1/audit/anchor', guard, async () => ctx.chain.anchor());

  app.get('/v1/risk', guard, async () => {
    const risk = await readRisk(ctx.pool, ctx.clock, ctx.config.riskWindowHours);
    const entries = await windowEntries(ctx);
    const escalation = evaluateEscalation(entries.map((e) => ({ id: String(e.seq), action: e.action })));
    return { risk, escalation };
  });
}
