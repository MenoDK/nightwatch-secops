import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { approveProposal, rejectProposal } from '../alice/approval.js';
import { listProposals } from '../alice/proposals.js';
import { analyze } from '../alice/runner.js';
import type { Analyst } from '../alice/types.js';
import type { Context } from '../context.js';
import { authenticated, humanOf, refuse } from './support.js';

/** "Alice" reads the evidence and proposes. These routes are the whole of what she can do; none of them changes the protected application. */
export function registerAlice(app: FastifyInstance, ctx: Context, remote: Analyst | null): void {
  const guard = { preHandler: authenticated(ctx) };

  app.get('/v1/alice/status', guard, async () => ({
    analyst: remote ? 'remote' : 'local',
    model: remote ? (ctx.config.analyst?.model ?? null) : null,
    note: 'The analyst proposes. Approving a proposal needs the operators’ network and a code from the authenticator.',
  }));

  app.get('/v1/alice/proposals', guard, async (request) => {
    const { status } = z
      .object({ status: z.enum(['pending', 'executed', 'rejected', 'failed']).optional() })
      .parse(request.query);
    return { proposals: await listProposals(ctx.pool, status) };
  });

  app.post('/v1/alice/analyze', guard, async () => analyze(ctx, remote));

  app.post<{ Params: { id: string } }>('/v1/alice/proposals/:id/approve', guard, async (request, reply) => {
    const result = await approveProposal(ctx, request.params.id, humanOf(request));
    return result.ok ? result : refuse(reply, result);
  });

  app.post<{ Params: { id: string } }>('/v1/alice/proposals/:id/reject', guard, async (request, reply) => {
    const body = z.object({ note: z.string().max(500).optional() }).parse(request.body ?? {});
    const { code: _code, ...human } = humanOf(request);
    const result = await rejectProposal(ctx, request.params.id, human, body.note);
    return result.ok ? result : refuse(reply, result);
  });
}
