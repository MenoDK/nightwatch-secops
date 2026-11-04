import type { Clock } from '../clock.js';
import { type Pool, transaction } from '../db.js';
import type { AuditChain } from './audit-chain.js';
import type { AuditAction } from './events.js';
import { type Counts, NON_OVERRIDABLE, type Risk, SIGNALS, computeRisk } from './risk.js';

const SCORED = Object.keys(SIGNALS) as AuditAction[];

export interface RiskReport extends Risk {
  since: string;
  windowHours: number;
}

/** Counts what happened in the window, and how much of it an operator has reclassified, then lets the pure function score it. */
export async function readRisk(pool: Pool, clock: Clock, windowHours: number): Promise<RiskReport> {
  const since = new Date(clock.now().getTime() - windowHours * 3600_000);
  const totals = await pool.query<{ action: AuditAction; n: number }>(
    'SELECT action, count(*)::int AS n FROM audit_chain WHERE at >= $1 AND action = ANY($2::text[]) GROUP BY action',
    [since, SCORED],
  );
  const overridden = await pool.query<{ action: AuditAction; n: number }>(
    `SELECT a.action, count(*)::int AS n
       FROM audit_chain a JOIN overrides o ON o.audit_seq = a.seq AND o.status = 'active'
      WHERE a.at >= $1 AND a.action = ANY($2::text[]) GROUP BY a.action`,
    [since, SCORED],
  );
  const toCounts = (rows: { action: AuditAction; n: number }[]): Counts =>
    Object.fromEntries(rows.map((r) => [r.action, r.n]));
  return { ...computeRisk(toCounts(totals.rows), toCounts(overridden.rows)), since: since.toISOString(), windowHours };
}

export type OverrideResult =
  | { ok: true; id: number }
  | { ok: false; reason: 'not_found' | 'not_scored' | 'not_overridable' | 'already_overridden' };

/**
 * "This one was benign." The audit row is never touched: the override sits beside it and only changes how the score
 * counts it. The refusal list lives in the risk module and is applied here too, so it holds even if a client skips the UI.
 */
export async function createOverride(
  pool: Pool,
  chain: AuditChain,
  clock: Clock,
  input: { seq: number; reason: string; operator: string },
): Promise<OverrideResult> {
  return transaction(pool, async (client) => {
    const found = await client.query<{ action: AuditAction }>('SELECT action FROM audit_chain WHERE seq = $1', [
      input.seq,
    ]);
    const action = found.rows[0]?.action;
    if (!action) return { ok: false, reason: 'not_found' };
    if (NON_OVERRIDABLE.has(action)) return { ok: false, reason: 'not_overridable' };
    if (!SCORED.includes(action)) return { ok: false, reason: 'not_scored' };
    // The partial unique index decides, not a SELECT before it: two operators clicking at once cannot both win.
    const created = await client.query<{ id: string }>(
      `INSERT INTO overrides (audit_seq, action, reason, operator, created_at) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (audit_seq) WHERE status = 'active' DO NOTHING RETURNING id`,
      [input.seq, action, input.reason, input.operator, clock.now()],
    );
    if (created.rowCount === 0) return { ok: false, reason: 'already_overridden' };
    await chain.appendIn(client, {
      actor: input.operator,
      action: 'override_created',
      metadata: { seq: input.seq, of: action, reason: input.reason },
    });
    return { ok: true, id: Number(created.rows[0]?.id) };
  });
}
