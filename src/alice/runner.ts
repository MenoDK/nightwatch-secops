import type { Context } from '../context.js';
import type { Entry } from '../lib/audit-chain.js';
import { evaluateEscalation } from '../lib/escalation.js';
import { normalizeIp } from '../lib/net.js';
import { readRisk } from '../lib/risk-query.js';
import { LocalAnalyst } from './local.js';
import { createProposals } from './proposals.js';
import { RemoteUnavailable } from './remote.js';
import type { AnalysisInput, Analyst, Draft, Proposal } from './types.js';

export interface AnalysisReport {
  source: 'local' | 'remote';
  /** Set when a remote analyst was configured but this run used the local rules, and why. */
  fellBackBecause: string | null;
  considered: number;
  created: Proposal[];
  /** Drafts dropped because a person already said no and nothing new has happened since. */
  suppressed: number;
}

/** The audit entries inside the risk window, oldest first. Capped: an analysis is a summary, not an export. */
export async function windowEntries(ctx: Context): Promise<Entry[]> {
  const since = ctx.clock.now().getTime() - ctx.config.riskWindowHours * 3600_000;
  const recent = await ctx.chain.recent({ limit: 500 });
  return recent.filter((e) => e.at.getTime() >= since).reverse();
}

/** Everything an analyst may look at, gathered once: the window's evidence, the verdicts computed from it, and what is already done. */
export async function gather(ctx: Context): Promise<AnalysisInput> {
  const entries = await windowEntries(ctx);
  const [risk, blocked, suspended, lockdown] = await Promise.all([
    readRisk(ctx.pool, ctx.clock, ctx.config.riskWindowHours),
    ctx.blocklist.list(),
    ctx.suspensions.list(),
    ctx.lockdown.status(),
  ]);
  return {
    entries,
    risk,
    escalation: evaluateEscalation(entries.map((e) => ({ id: String(e.seq), action: e.action }))),
    state: {
      blockedIps: new Set(blocked.map((b) => b.ip)),
      suspended: new Set(suspended.map((s) => s.subject)),
      lockdownActive: lockdown.active,
    },
    isAdminIp: (ip) => ctx.isAdminIp(normalizeIp(ip) ?? ip),
  };
}

/** A "no" is remembered until there is something new to say: a draft is suppressed unless it cites evidence newer than the rejection. */
async function withoutRejected(ctx: Context, drafts: Draft[]): Promise<{ kept: Draft[]; suppressed: number }> {
  const rejected = await ctx.pool.query<{ kind: string; target: string; evidence: number[] }>(
    "SELECT kind, target, evidence FROM proposals WHERE status = 'rejected'",
  );
  const newest = new Map<string, number>();
  for (const r of rejected.rows) {
    const key = `${r.kind}:${r.target}`;
    newest.set(key, Math.max(newest.get(key) ?? 0, ...r.evidence));
  }
  const kept = drafts.filter((d) => {
    const seen = newest.get(`${d.kind}:${d.target}`);
    return seen === undefined || d.evidence.some((seq) => seq > seen);
  });
  return { kept, suppressed: drafts.length - kept.length };
}

/** Runs the analysis and queues what it suggests. Nothing here changes the protected application. */
export async function analyze(ctx: Context, remote: Analyst | null): Promise<AnalysisReport> {
  const input = await gather(ctx);
  let analyst: Analyst = new LocalAnalyst();
  let fellBackBecause: string | null = null;
  let drafts: Draft[];
  if (remote) {
    try {
      drafts = await remote.analyze(input);
      analyst = remote;
    } catch (error) {
      fellBackBecause = error instanceof RemoteUnavailable ? error.why : 'error';
      drafts = await analyst.analyze(input);
    }
  } else {
    drafts = await analyst.analyze(input);
  }
  drafts = drafts.filter((d) => d.evidence.length > 0);
  const { kept, suppressed } = await withoutRejected(ctx, drafts);
  const created = await createProposals(ctx.pool, ctx.chain, ctx.clock, kept, analyst.name);
  return { source: analyst.name, fellBackBecause, considered: input.entries.length, created, suppressed };
}
