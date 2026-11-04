import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { transaction } from '../src/db.js';
import { rowHashOf } from '../src/lib/audit-chain.js';
import { INTEGRATION, type Stack, startStack } from './harness.js';

describe.skipIf(!INTEGRATION)('audit chain', () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack();
  });
  afterAll(() => s.close());
  beforeEach(() => s.reset());

  const add = (n: number) =>
    Array.from({ length: n }, (_, i) =>
      s.ctx.chain.append({ actor: 'test', action: 'login_failed', ip: '203.0.113.9', metadata: { i } }),
    );

  async function fill(n: number) {
    for (let i = 0; i < n; i++)
      await s.ctx.chain.append({ actor: 'test', action: 'login_failed', ip: '203.0.113.9', metadata: { i } });
  }

  it('an empty chain verifies', async () => {
    expect(await s.ctx.chain.verify()).toMatchObject({ ok: true, checked: 0 });
  });

  it('numbers entries 1, 2, 3 and links each to the one before', async () => {
    await fill(3);
    const rows = await s.sql('SELECT seq, prev_hash, row_hash FROM audit_chain ORDER BY seq');
    expect(rows.map((r) => Number(r.seq))).toEqual([1, 2, 3]);
    expect(rows[1]?.prev_hash).toBe(rows[0]?.row_hash);
    expect(rows[2]?.prev_hash).toBe(rows[1]?.row_hash);
    expect(await s.ctx.chain.verify()).toMatchObject({ ok: true, checked: 3 });
  });

  it('forty writers at once still make one gap-free chain', async () => {
    await Promise.all(add(40));
    const rows = await s.sql('SELECT seq FROM audit_chain ORDER BY seq');
    expect(rows.map((r) => Number(r.seq))).toEqual(Array.from({ length: 40 }, (_, i) => i + 1));
    expect(await s.ctx.chain.verify()).toMatchObject({ ok: true, checked: 40 });
  });

  it('a failed transaction leaves no hole: the number is taken back with the row', async () => {
    await fill(2);
    await expect(
      transaction(s.ctx.pool, async (client) => {
        await s.ctx.chain.appendIn(client, { actor: 'test', action: 'ip_blocked' });
        throw new Error('the change this audit row belonged to failed');
      }),
    ).rejects.toThrow('failed');
    const next = await s.ctx.chain.append({ actor: 'test', action: 'ip_blocked' });
    expect(next.seq).toBe(3);
    expect(await s.ctx.chain.verify()).toMatchObject({ ok: true, checked: 3 });
  });

  it('notices an edited row', async () => {
    await fill(5);
    await s.sql("UPDATE audit_chain SET ip = '198.51.100.1' WHERE seq = 3");
    const result = await s.ctx.chain.verify();
    expect(result.ok).toBe(false);
    expect(result.problem).toEqual({ seq: 3, reason: 'row_hash_mismatch' });
    expect(result.checked).toBe(2);
  });

  it('notices an edit to the metadata, however small', async () => {
    await fill(3);
    await s.sql(`UPDATE audit_chain SET metadata = '{"i":99}' WHERE seq = 2`);
    expect((await s.ctx.chain.verify()).problem).toEqual({ seq: 2, reason: 'row_hash_mismatch' });
  });

  it('notices a row removed from the middle', async () => {
    await fill(5);
    await s.sql('DELETE FROM audit_chain WHERE seq = 3');
    expect((await s.ctx.chain.verify()).problem).toEqual({ seq: 4, reason: 'seq_gap', expected: 3 });
  });

  it('notices rows cut off the end, which no hash can show: the head row remembers', async () => {
    await fill(5);
    await s.sql('DELETE FROM audit_chain WHERE seq IN (4, 5)');
    const result = await s.ctx.chain.verify();
    expect(result.ok).toBe(false);
    expect(result.problem?.reason).toBe('head_mismatch');
  });

  it('notices the whole table emptied: with nothing left to hash, only the head row knows there was something', async () => {
    await fill(4);
    await s.sql('DELETE FROM audit_chain');
    const result = await s.ctx.chain.verify();
    expect(result.ok).toBe(false);
    expect(result.problem?.reason).toBe('head_mismatch');
  });

  it('notices a swapped pair of rows', async () => {
    await fill(4);
    await s.sql('UPDATE audit_chain SET seq = 100 WHERE seq = 2');
    await s.sql('UPDATE audit_chain SET seq = 2 WHERE seq = 3');
    await s.sql('UPDATE audit_chain SET seq = 3 WHERE seq = 100');
    expect((await s.ctx.chain.verify()).ok).toBe(false);
  });

  describe('someone who holds the signing key and rewrites everything', () => {
    // They edit row 3, then recompute every hash after it and the head row. The chain is internally consistent again:
    // no check made from inside the database can tell. Only a receipt kept elsewhere can.
    async function rewriteFrom(seq: number, edit: (row: Record<string, unknown>) => void) {
      const raw = await s.sql('SELECT * FROM audit_chain ORDER BY seq');
      let previous = raw[seq - 2]?.row_hash as string;
      let last = previous;
      for (const r of raw.filter((row) => Number(row.seq) >= seq)) {
        const entry = {
          seq: Number(r.seq),
          id: r.id as string,
          at: r.at as Date,
          actor: r.actor as string,
          action: r.action,
          subject: r.subject as string | null,
          ip: r.ip as string | null,
          userAgent: r.user_agent as string | null,
          metadata: r.metadata as Record<string, unknown>,
          prevHash: previous,
        };
        if (entry.seq === seq) edit(entry);
        const rowHash = rowHashOf(s.config.auditChainSecret, entry as Parameters<typeof rowHashOf>[1]);
        await s.sql('UPDATE audit_chain SET ip = $1, metadata = $2, prev_hash = $3, row_hash = $4 WHERE seq = $5', [
          entry.ip,
          JSON.stringify(entry.metadata),
          entry.prevHash,
          rowHash,
          entry.seq,
        ]);
        previous = rowHash;
        last = rowHash;
      }
      await s.sql('UPDATE chain_head SET last_hash = $1 WHERE id = 1', [last]);
    }

    it('passes verification on its own, and fails against a receipt taken earlier', async () => {
      await fill(5);
      const receipt = await s.ctx.chain.anchor();
      await rewriteFrom(3, (row) => {
        row.ip = '198.51.100.99';
      });
      expect(await s.ctx.chain.verify()).toMatchObject({ ok: true, checked: 5 });
      const against = await s.ctx.chain.verify({ anchor: receipt });
      expect(against.ok).toBe(false);
      expect(against.problem?.reason).toBe('anchor_mismatch');
    });

    it('a receipt for an untouched chain still passes', async () => {
      await fill(4);
      const receipt = await s.ctx.chain.anchor();
      await fill(2);
      expect(await s.ctx.chain.verify({ anchor: receipt })).toMatchObject({ ok: true, checked: 6 });
    });
  });

  describe('receipts', () => {
    it('are signed, so a made-up one proves nothing', async () => {
      await fill(2);
      const receipt = await s.ctx.chain.anchor();
      expect(s.ctx.chain.isOurAnchor(receipt)).toBe(true);
      expect(s.ctx.chain.isOurAnchor({ ...receipt, seq: receipt.seq - 1 })).toBe(false);
      expect(s.ctx.chain.isOurAnchor({ ...receipt, hash: 'f'.repeat(64) })).toBe(false);
      expect(s.ctx.chain.isOurAnchor({ ...receipt, mac: '0'.repeat(64) })).toBe(false);
    });

    it('of an empty chain are valid and say seq 0', async () => {
      const receipt = await s.ctx.chain.anchor();
      expect(receipt.seq).toBe(0);
      expect(s.ctx.chain.isOurAnchor(receipt)).toBe(true);
    });
  });

  it('reads recent entries newest first, filtered by action', async () => {
    await fill(3);
    await s.ctx.chain.append({ actor: 'test', action: 'ip_blocked' });
    const all = await s.ctx.chain.recent({ limit: 10 });
    expect(all.map((e) => e.seq)).toEqual([4, 3, 2, 1]);
    const blocked = await s.ctx.chain.recent({ action: 'ip_blocked' });
    expect(blocked.map((e) => e.seq)).toEqual([4]);
    expect(await s.ctx.chain.count()).toBe(4);
  });
});
