import type { Context } from '../context.js';
import { type GateResult, type Human, authorizeHuman } from '../lib/gate.js';
import { execute } from './actions.js';
import { getProposal, toProposal } from './proposals.js';
import type { Proposal } from './types.js';

export type DecisionResult =
  | { ok: true; proposal: Proposal }
  | Extract<GateResult, { ok: false }>
  | { ok: false; status: 404 | 409; code: 'not_found' | 'not_pending'; message: string };

/**
 * Approval is where a suggestion becomes a change. Three gates in a row: the network, the second factor, and an atomic
 * claim on the proposal - `UPDATE … WHERE status = 'pending'` - so that two operators approving at once cannot both
 * execute it. The claim comes before the effect and the effect before the final audit row; if the effect fails the
 * proposal is marked failed rather than left looking done.
 */
export async function approveProposal(ctx: Context, id: string, human: Human): Promise<DecisionResult> {
  const before = await getProposal(ctx.pool, id);
  if (!before) return { ok: false, status: 404, code: 'not_found', message: 'no such proposal' };

  const gate = await authorizeHuman(ctx, human, `approve:${before.kind}`);
  if (!gate.ok) return gate;

  const claimed = await ctx.pool.query(
    `UPDATE proposals SET status = 'executed', decided_at = $2, decided_by = $3
      WHERE id = $1 AND status = 'pending' RETURNING *`,
    [id, ctx.clock.now(), gate.actor],
  );
  const row = claimed.rows[0];
  if (!row) return { ok: false, status: 409, code: 'not_pending', message: 'this proposal was already decided' };
  const proposal = toProposal(row);

  await ctx.chain.append({
    actor: gate.actor,
    action: 'proposal_approved',
    ip: human.ip,
    userAgent: human.userAgent ?? null,
    metadata: { id, kind: proposal.kind, target: proposal.target },
  });
  try {
    await execute(ctx, proposal, gate.actor);
    await ctx.chain.append({ actor: 'engine', action: 'proposal_executed', metadata: { id, ok: true } });
    return { ok: true, proposal };
  } catch (error) {
    await ctx.pool.query(`UPDATE proposals SET status = 'failed', decision_note = $2 WHERE id = $1`, [
      id,
      'the action could not be carried out',
    ]);
    await ctx.chain.append({
      actor: 'engine',
      action: 'proposal_executed',
      metadata: { id, ok: false, error: (error as Error).name },
    });
    return {
      ok: true,
      proposal: { ...proposal, status: 'failed', decisionNote: 'the action could not be carried out' },
    };
  }
}

/** Saying no changes nothing in the world, so it needs the network gate but not the second factor. */
export async function rejectProposal(
  ctx: Context,
  id: string,
  human: Omit<Human, 'code'>,
  note?: string,
): Promise<DecisionResult> {
  const before = await getProposal(ctx.pool, id);
  if (!before) return { ok: false, status: 404, code: 'not_found', message: 'no such proposal' };
  if (!ctx.isAdminIp(human.ip)) {
    await ctx.chain.append({
      actor: human.label,
      action: 'approval_denied',
      ip: human.ip,
      userAgent: human.userAgent ?? null,
      metadata: { reason: 'ip_not_allowed', attempted: `reject:${before.kind}` },
    });
    return {
      ok: false,
      status: 403,
      code: 'ip_not_allowed',
      message: 'this action is only accepted from the operators’ network',
    };
  }
  const result = await ctx.pool.query(
    `UPDATE proposals SET status = 'rejected', decided_at = $2, decided_by = $3, decision_note = $4
      WHERE id = $1 AND status = 'pending' RETURNING *`,
    [id, ctx.clock.now(), human.label, note?.slice(0, 500) ?? null],
  );
  const row = result.rows[0];
  if (!row) return { ok: false, status: 409, code: 'not_pending', message: 'this proposal was already decided' };
  await ctx.chain.append({
    actor: human.label,
    action: 'proposal_rejected',
    ip: human.ip,
    metadata: { id, kind: before.kind, target: before.target },
  });
  return { ok: true, proposal: toProposal(row) };
}
