import type { Clock } from '../clock.js';
import { type Pool, transaction } from '../db.js';
import type { AuditChain } from '../lib/audit-chain.js';
import type { Draft, Proposal, ProposalStatus } from './types.js';

interface Row {
  id: string;
  kind: Proposal['kind'];
  target: string;
  rationale: string;
  evidence: number[];
  severity: Proposal['severity'];
  source: Proposal['source'];
  status: ProposalStatus;
  created_at: Date;
  decided_at: Date | null;
  decided_by: string | null;
  decision_note: string | null;
}

export const toProposal = (r: Row): Proposal => ({
  id: r.id,
  kind: r.kind,
  target: r.target,
  rationale: r.rationale,
  evidence: r.evidence,
  severity: r.severity,
  source: r.source,
  status: r.status,
  createdAt: r.created_at.toISOString(),
  decidedAt: r.decided_at?.toISOString() ?? null,
  decidedBy: r.decided_by,
  decisionNote: r.decision_note,
});

/** Stores drafts as pending proposals. The same proposal is not queued twice: the unique index decides, not a SELECT. */
export async function createProposals(
  pool: Pool,
  chain: AuditChain,
  clock: Clock,
  drafts: readonly Draft[],
  source: Proposal['source'],
): Promise<Proposal[]> {
  const created: Proposal[] = [];
  for (const draft of drafts) {
    const row = await transaction(pool, async (client) => {
      const inserted = await client.query<Row>(
        `INSERT INTO proposals (id, kind, target, rationale, evidence, severity, source, status, created_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, 'pending', $7)
         ON CONFLICT (kind, target) WHERE status = 'pending' DO NOTHING RETURNING *`,
        [
          draft.kind,
          draft.target,
          draft.rationale,
          JSON.stringify(draft.evidence),
          draft.severity,
          source,
          clock.now(),
        ],
      );
      const found = inserted.rows[0];
      if (!found) return null;
      await chain.appendIn(client, {
        actor: `analyst:${source}`,
        action: 'proposal_created',
        metadata: {
          id: found.id,
          kind: draft.kind,
          target: draft.target,
          severity: draft.severity,
          evidence: draft.evidence,
        },
      });
      return found;
    });
    if (row) created.push(toProposal(row));
  }
  return created;
}

export async function listProposals(pool: Pool, status?: ProposalStatus): Promise<Proposal[]> {
  const result = await pool.query<Row>(
    'SELECT * FROM proposals WHERE ($1::text IS NULL OR status = $1) ORDER BY created_at DESC, id LIMIT 200',
    [status ?? null],
  );
  return result.rows.map(toProposal);
}

export async function getProposal(pool: Pool, id: string): Promise<Proposal | null> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
  const result = await pool.query<Row>('SELECT * FROM proposals WHERE id = $1', [id]);
  const row = result.rows[0];
  return row ? toProposal(row) : null;
}
