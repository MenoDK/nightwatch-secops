import { randomUUID } from 'node:crypto';
import type { Clock } from '../clock.js';
import { type Pool, type Queryable, transaction } from '../db.js';
import { hmacHex, safeEqual, sha256, stableJson } from './crypto.js';
import type { AuditAction } from './events.js';

export interface NewEntry {
  actor: string;
  action: AuditAction;
  subject?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown>;
}

export interface Entry {
  seq: number;
  id: string;
  at: Date;
  actor: string;
  action: AuditAction;
  subject: string | null;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  prevHash: string;
  rowHash: string;
}

export const GENESIS_HASH = sha256('nightwatch:audit-chain:genesis:v1');

/**
 * What the hash covers, as a JSON array so no field can bleed into the next (a `|`-joined string lets "a|b","c" and
 * "a","b|c" collide). Includes the previous row's hash: that is the chain.
 */
export function canonical(row: Omit<Entry, 'rowHash' | 'seq'> & { seq: number }): string {
  return stableJson([
    row.seq,
    row.id,
    row.at.toISOString(),
    row.actor,
    row.action,
    row.subject,
    row.ip,
    row.userAgent,
    row.metadata,
    row.prevHash,
  ]);
}

export const rowHashOf = (secret: string, row: Omit<Entry, 'rowHash'>): string => hmacHex(secret, canonical(row));

export type Problem =
  | { seq: number; reason: 'row_hash_mismatch' }
  | { seq: number; reason: 'prev_hash_mismatch' }
  | { seq: number; reason: 'seq_gap'; expected: number }
  | { seq: number; reason: 'head_mismatch' }
  | { seq: number; reason: 'anchor_mismatch' };

export interface VerifyResult {
  ok: boolean;
  checked: number;
  head: { seq: number; hash: string };
  problem?: Problem;
}

/** A receipt for "the chain looked like this at this moment", kept somewhere an attacker with the database cannot reach. */
export interface Anchor {
  seq: number;
  hash: string;
  at: string;
  mac: string;
}

interface Row {
  seq: string;
  id: string;
  at: Date;
  actor: string;
  action: AuditAction;
  subject: string | null;
  ip: string | null;
  user_agent: string | null;
  metadata: Record<string, unknown>;
  prev_hash: string;
  row_hash: string;
}

const toEntry = (r: Row): Entry => ({
  seq: Number(r.seq),
  id: r.id,
  at: r.at,
  actor: r.actor,
  action: r.action,
  subject: r.subject,
  ip: r.ip,
  userAgent: r.user_agent,
  metadata: r.metadata,
  prevHash: r.prev_hash,
  rowHash: r.row_hash,
});

export class AuditChain {
  constructor(
    private readonly pool: Pool,
    private readonly clock: Clock,
    private readonly secret: string,
  ) {}

  /** Appends in its own transaction. */
  append(entry: NewEntry): Promise<Entry> {
    return transaction(this.pool, (client) => this.appendIn(client, entry));
  }

  /**
   * Appends inside the caller's transaction, so a change and its audit row commit or roll back together. The head row is
   * locked for the rest of that transaction: writers take turns, and each one sees the previous writer's last hash.
   */
  async appendIn(db: Queryable, entry: NewEntry): Promise<Entry> {
    const head = await db.query<{ last_seq: string; last_hash: string }>(
      'SELECT last_seq, last_hash FROM chain_head WHERE id = 1 FOR UPDATE',
    );
    const row = head.rows[0];
    if (!row) throw new Error('chain_head is missing: run the migration');
    const seq = Number(row.last_seq) + 1;
    const prevHash = seq === 1 ? GENESIS_HASH : row.last_hash;
    // What is hashed is what comes back from the database: a JSON round-trip drops `undefined` and normalises numbers.
    const metadata = JSON.parse(JSON.stringify(entry.metadata ?? {})) as Record<string, unknown>;
    const unsealed = {
      seq,
      id: randomUUID(),
      at: this.clock.now(),
      actor: entry.actor,
      action: entry.action,
      subject: entry.subject ?? null,
      ip: entry.ip ?? null,
      userAgent: entry.userAgent ?? null,
      metadata,
      prevHash,
    };
    const rowHash = rowHashOf(this.secret, unsealed);
    await db.query(
      `INSERT INTO audit_chain (seq, id, at, actor, action, subject, ip, user_agent, metadata, prev_hash, row_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        seq,
        unsealed.id,
        unsealed.at,
        unsealed.actor,
        unsealed.action,
        unsealed.subject,
        unsealed.ip,
        unsealed.userAgent,
        JSON.stringify(metadata),
        prevHash,
        rowHash,
      ],
    );
    await db.query('UPDATE chain_head SET last_seq = $1, last_hash = $2 WHERE id = 1', [seq, rowHash]);
    return { ...unsealed, rowHash };
  }

  /**
   * Walks the whole chain and reports the first thing wrong. It looks for four kinds of damage: a row whose content was
   * edited (hash mismatch), a row that was removed from the middle (the next row points at something that is not there),
   * rows cut off the end (the head says more than the table holds), and, with an anchor kept elsewhere, a rewrite of
   * everything, which only a witness outside the database can expose.
   */
  async verify(options: { anchor?: Anchor } = {}): Promise<VerifyResult> {
    let after = 0;
    let previousHash = GENESIS_HASH;
    let previousSeq = 0;
    let checked = 0;
    const anchorHashes = new Map<number, string>();
    for (;;) {
      const page = await this.pool.query<Row>('SELECT * FROM audit_chain WHERE seq > $1 ORDER BY seq LIMIT 1000', [
        after,
      ]);
      if (page.rows.length === 0) break;
      for (const raw of page.rows) {
        const entry = toEntry(raw);
        const fail = (problem: Problem): VerifyResult => ({
          ok: false,
          checked,
          head: { seq: previousSeq, hash: previousHash },
          problem,
        });
        if (entry.seq !== previousSeq + 1)
          return fail({ seq: entry.seq, reason: 'seq_gap', expected: previousSeq + 1 });
        if (!safeEqual(entry.prevHash, previousHash)) return fail({ seq: entry.seq, reason: 'prev_hash_mismatch' });
        if (!safeEqual(entry.rowHash, rowHashOf(this.secret, entry)))
          return fail({ seq: entry.seq, reason: 'row_hash_mismatch' });
        previousHash = entry.rowHash;
        previousSeq = entry.seq;
        checked += 1;
        if (options.anchor && entry.seq === options.anchor.seq) anchorHashes.set(entry.seq, entry.rowHash);
      }
      after = previousSeq;
    }
    const head = await this.pool.query<{ last_seq: string; last_hash: string }>(
      'SELECT last_seq, last_hash FROM chain_head WHERE id = 1',
    );
    const stored = head.rows[0];
    const headOk =
      stored !== undefined &&
      Number(stored.last_seq) === previousSeq &&
      (previousSeq === 0 || safeEqual(stored.last_hash, previousHash));
    const result: VerifyResult = { ok: true, checked, head: { seq: previousSeq, hash: previousHash } };
    if (!headOk) return { ...result, ok: false, problem: { seq: previousSeq, reason: 'head_mismatch' } };
    if (options.anchor) {
      const seen = anchorHashes.get(options.anchor.seq);
      if (seen === undefined || !safeEqual(seen, options.anchor.hash)) {
        return { ...result, ok: false, problem: { seq: options.anchor.seq, reason: 'anchor_mismatch' } };
      }
    }
    return result;
  }

  /** A signed receipt of the current head. Keep it somewhere the database's owner cannot write. */
  async anchor(): Promise<Anchor> {
    const head = await this.pool.query<{ last_seq: string; last_hash: string }>(
      'SELECT last_seq, last_hash FROM chain_head WHERE id = 1',
    );
    const row = head.rows[0];
    const seq = Number(row?.last_seq ?? 0);
    const hash = seq === 0 ? GENESIS_HASH : (row?.last_hash ?? GENESIS_HASH);
    const at = this.clock.now().toISOString();
    return { seq, hash, at, mac: hmacHex(this.secret, `anchor:${seq}:${hash}:${at}`) };
  }

  /** Is this receipt one we issued? A forged anchor cannot be used to "prove" a chain intact. */
  isOurAnchor(anchor: Anchor): boolean {
    return safeEqual(anchor.mac, hmacHex(this.secret, `anchor:${anchor.seq}:${anchor.hash}:${anchor.at}`));
  }

  async recent(options: { limit?: number; action?: AuditAction; sinceSeq?: number } = {}): Promise<Entry[]> {
    const limit = Math.min(Math.max(options.limit ?? 50, 1), 500);
    const result = await this.pool.query<Row>(
      `SELECT * FROM audit_chain
        WHERE ($1::text IS NULL OR action = $1) AND seq > $2
        ORDER BY seq DESC LIMIT $3`,
      [options.action ?? null, options.sinceSeq ?? 0, limit],
    );
    return result.rows.map(toEntry);
  }

  async count(): Promise<number> {
    const result = await this.pool.query<{ n: string }>('SELECT count(*) AS n FROM audit_chain');
    return Number(result.rows[0]?.n ?? 0);
  }
}
