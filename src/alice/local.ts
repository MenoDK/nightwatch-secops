import type { AuditAction } from '../lib/events.js';
import { normalizeIp } from '../lib/net.js';
import type { AnalysisInput, Analyst, Draft, Severity } from './types.js';

interface IpRule {
  actions: readonly AuditAction[];
  min: number;
  severity: Severity;
}

/**
 * What it takes, from one address, for the analyst to suggest closing the door. The engine has already blocked the
 * unambiguous cases (stuffing, traps); these are the slower ones - probing that is only convincing in aggregate.
 */
const IP_RULES: readonly IpRule[] = [
  { actions: ['honeytoken_trip', 'data_canary_trip'], min: 1, severity: 'critical' },
  { actions: ['credential_stuffing_suspected'], min: 1, severity: 'high' },
  { actions: ['ssrf_attempt'], min: 3, severity: 'high' },
  { actions: ['bola_attempt'], min: 3, severity: 'high' },
  { actions: ['prompt_injection_attempt'], min: 2, severity: 'medium' },
  { actions: ['webhook_bad_signature', 'webhook_replay'], min: 3, severity: 'medium' },
  { actions: ['open_redirect_attempt', 'header_spoof_attempt'], min: 3, severity: 'medium' },
];

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const MAX_EVIDENCE = 20;

/** The analyst that needs no model: plain rules over the same evidence. Deterministic, so it is also the test oracle. */
export class LocalAnalyst implements Analyst {
  readonly name = 'local' as const;

  async analyze(input: AnalysisInput): Promise<Draft[]> {
    const drafts: Draft[] = [];

    const byIp = new Map<string, typeof input.entries>();
    for (const entry of input.entries) {
      const ip = entry.ip ? normalizeIp(entry.ip) : null;
      if (ip) byIp.set(ip, [...(byIp.get(ip) ?? []), entry]);
    }
    for (const [ip, entries] of byIp) {
      if (input.state.blockedIps.has(ip) || input.isAdminIp(ip)) continue;
      const reasons: string[] = [];
      const evidence: number[] = [];
      let severity: Severity = 'low';
      for (const rule of IP_RULES) {
        const hits = entries.filter((e) => rule.actions.includes(e.action));
        if (hits.length < rule.min) continue;
        reasons.push(`${hits.length} × ${[...new Set(hits.map((h) => h.action))].join(' / ')}`);
        evidence.push(...hits.map((h) => h.seq));
        if (RANK[rule.severity] > RANK[severity]) severity = rule.severity;
      }
      if (reasons.length === 0) continue;
      drafts.push({
        kind: 'block_ip',
        target: ip,
        rationale: `From ${ip} in the window: ${reasons.join('; ')}. Nothing on the allow-list; not blocked yet.`,
        evidence: [...new Set(evidence)].sort((a, b) => a - b).slice(0, MAX_EVIDENCE),
        severity,
      });
    }

    const travellers = new Map<string, typeof input.entries>();
    for (const entry of input.entries) {
      if (entry.action === 'api_impossible_travel' && entry.subject) {
        const subject = entry.subject.toLowerCase();
        travellers.set(subject, [...(travellers.get(subject) ?? []), entry]);
      }
    }
    for (const [subject, entries] of travellers) {
      if (input.state.suspended.has(subject)) continue;
      drafts.push({
        kind: 'suspend_subject',
        target: subject,
        rationale: `${subject} appeared in places no one could travel between (${entries.length} time${entries.length === 1 ? '' : 's'}). The session or the credentials may be in two hands.`,
        evidence: entries.map((e) => e.seq).slice(0, MAX_EVIDENCE),
        severity: 'high',
      });
    }

    if (!input.state.lockdownActive && input.escalation.lockdownRisk === 'critical') {
      const critical = input.escalation.advisories.filter((a) => a.tier === 'CRITICAL');
      const ids = new Set(critical.flatMap((a) => a.evidence));
      drafts.push({
        kind: 'lockdown',
        target: 'all',
        rationale:
          `${critical.map((a) => a.playbookId).join(', ')} matched. ${critical[0]?.message ?? ''} A lockdown refuses all traffic to the protected application until it is lifted.`.trim(),
        evidence: input.entries
          .filter((e) => ids.has(String(e.seq)))
          .map((e) => e.seq)
          .slice(0, MAX_EVIDENCE),
        severity: 'critical',
      });
    }

    return drafts.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  }
}
