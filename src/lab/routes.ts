import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { analyze, windowEntries } from '../alice/runner.js';
import { OffsetClock } from '../clock.js';
import { isDefaultApiKey } from '../config.js';
import type { Context } from '../context.js';
import { rowHashOf } from '../lib/audit-chain.js';
import { evaluateEscalation } from '../lib/escalation.js';
import { HttpError } from '../lib/http.js';
import { sampleAddress } from '../lib/net.js';
import { readRisk } from '../lib/risk-query.js';
import { totpAt } from '../lib/totp.js';
import { authenticated, entryJson } from '../routes/support.js';
import { SCENARIOS, runScenario } from './scenarios.js';

/**
 * Laboratory mode: makes the defences observable. It is refused when APP_ENV=production (config.ts), and these routes
 * only exist when the flag is on. They expose the operator's TOTP seed, move the clock and edit the audit chain behind
 * its back - each exactly what must never exist on a real deployment and exactly what a demonstration needs.
 */
export function registerLab(app: FastifyInstance, ctx: Context): void {
  const guard = { preHandler: authenticated(ctx) };
  const clock = ctx.clock instanceof OffsetClock ? ctx.clock : null;
  const adminAddress = ctx.config.adminIps[0] ? sampleAddress(ctx.config.adminIps[0]) : null;

  app.get('/v1/lab/config', async () => ({
    lab: true,
    default_key_in_use: isDefaultApiKey(ctx.config.apiKey),
    operator_ip: adminAddress,
    scenarios: SCENARIOS,
  }));

  app.get('/v1/lab/state', guard, async () => {
    const [risk, entries, blocked, suspended, lockdown, pending, total, head] = await Promise.all([
      readRisk(ctx.pool, ctx.clock, ctx.config.riskWindowHours),
      windowEntries(ctx),
      ctx.blocklist.list(),
      ctx.suspensions.list(),
      ctx.lockdown.status(),
      ctx.pool.query("SELECT count(*)::int AS n FROM proposals WHERE status = 'pending'"),
      ctx.chain.count(),
      ctx.pool.query<{ last_seq: string; last_hash: string }>(
        'SELECT last_seq, last_hash FROM chain_head WHERE id = 1',
      ),
    ]);
    const escalation = evaluateEscalation(entries.map((e) => ({ id: String(e.seq), action: e.action })));
    return {
      now: ctx.clock.now().toISOString(),
      offsetSeconds: clock?.offsetSeconds ?? 0,
      chain: {
        total,
        headSeq: Number(head.rows[0]?.last_seq ?? 0),
        headHash: (head.rows[0]?.last_hash ?? '').slice(0, 16),
      },
      risk,
      escalation,
      recent: entries.slice(-25).reverse().map(entryJson),
      blocked,
      suspended,
      lockdown,
      pendingProposals: pending.rows[0]?.n ?? 0,
      stepUpLocked: await ctx.stepUp.isLocked('soc'),
    };
  });

  app.get('/v1/lab/totp', guard, async () => {
    const nowMs = ctx.clock.now().getTime();
    return {
      code: totpAt(ctx.config.totpSecret, nowMs),
      secret: ctx.config.totpSecret,
      secondsLeft: 30 - (Math.floor(nowMs / 1000) % 30),
      note: 'In a real deployment this seed lives in the operator’s authenticator and nowhere else.',
    };
  });

  app.post('/v1/lab/clock', guard, async (request) => {
    if (!clock) throw new HttpError(409, 'no_clock', 'this service is not running on a movable clock');
    const { seconds } = z
      .object({
        seconds: z
          .number()
          .int()
          .min(1)
          .max(30 * 86_400),
      })
      .parse(request.body);
    clock.advance(seconds);
    return { now: ctx.clock.now().toISOString(), offsetSeconds: clock.offsetSeconds };
  });

  app.post('/v1/lab/unlock', guard, async () => {
    await ctx.stepUp.unlock('soc');
    return { ok: true };
  });

  app.post('/v1/lab/reset', guard, async () => {
    await ctx.pool.query('TRUNCATE audit_chain, overrides, proposals RESTART IDENTITY CASCADE');
    await ctx.pool.query("UPDATE chain_head SET last_seq = 0, last_hash = '' WHERE id = 1");
    await ctx.kv.flush();
    clock?.reset();
    return { ok: true };
  });

  /**
   * Plays the part of someone with access to the database. `rewrite` is the worst case: they hold the signing key too and
   * redo every hash after the edit, so the chain verifies on its own and only a receipt taken earlier can expose it.
   */
  app.post('/v1/lab/tamper', guard, async (request) => {
    const body = z
      .object({ mode: z.enum(['edit', 'delete', 'truncate', 'rewrite']), seq: z.number().int().positive().optional() })
      .parse(request.body);
    const head = Number(
      (await ctx.pool.query<{ last_seq: string }>('SELECT last_seq FROM chain_head WHERE id = 1')).rows[0]?.last_seq ??
        0,
    );
    if (head < 3)
      throw new HttpError(409, 'chain_too_short', 'run a scenario first: there is not enough history to tamper with');
    const seq = body.seq ?? Math.max(2, Math.floor(head / 2));
    if (body.mode === 'truncate') {
      await ctx.pool.query('DELETE FROM audit_chain WHERE seq = $1', [head]);
      return { done: `removed the last entry (#${head}); nothing after it points back to it`, seq: head };
    }
    if (body.mode === 'delete') {
      await ctx.pool.query('DELETE FROM audit_chain WHERE seq = $1', [seq]);
      return { done: `removed entry #${seq} from the middle`, seq };
    }
    if (body.mode === 'edit') {
      await ctx.pool.query("UPDATE audit_chain SET ip = '198.51.100.250' WHERE seq = $1", [seq]);
      return { done: `changed the address in entry #${seq}`, seq };
    }
    // rewrite: edit, then recompute every hash from there on and the head row, with the key
    const rows = (await ctx.pool.query('SELECT * FROM audit_chain WHERE seq >= $1 ORDER BY seq', [seq])).rows;
    const before = (await ctx.pool.query('SELECT row_hash FROM audit_chain WHERE seq = $1', [seq - 1])).rows[0]
      ?.row_hash as string | undefined;
    let previous = before ?? rows[0]?.prev_hash;
    for (const r of rows) {
      const entry = {
        seq: Number(r.seq),
        id: r.id,
        at: r.at,
        actor: r.actor,
        action: r.action,
        subject: r.subject,
        ip: Number(r.seq) === seq ? '198.51.100.250' : r.ip,
        userAgent: r.user_agent,
        metadata: r.metadata,
        prevHash: previous,
      };
      const rowHash = rowHashOf(ctx.config.auditChainSecret, entry);
      await ctx.pool.query('UPDATE audit_chain SET ip = $1, prev_hash = $2, row_hash = $3 WHERE seq = $4', [
        entry.ip,
        entry.prevHash,
        rowHash,
        entry.seq,
      ]);
      previous = rowHash;
    }
    await ctx.pool.query('UPDATE chain_head SET last_hash = $1 WHERE id = 1', [previous]);
    return { done: `edited entry #${seq} and recomputed every hash after it, with the signing key`, seq };
  });

  app.post<{ Params: { name: string } }>('/v1/lab/scenarios/:name', guard, async (request) => {
    const result = await runScenario(ctx, request.params.name);
    if (!result) throw new HttpError(404, 'not_found', 'no such scenario');
    return result;
  });

  app.post('/v1/lab/analyze-now', guard, async () => analyze(ctx, null));
}
