import type { AuditAction } from './events.js';

export type Tier = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** A known attack, described by the kinds of event it leaves behind. */
export interface Playbook {
  id: string;
  title: string;
  tier: Tier;
  signatures: readonly AuditAction[];
}

/**
 * The doctrine: what each attack looks like in the audit trail. A CRITICAL entry fires on a single matching event
 * (waiting for the second sign of a stolen database is too late); the others need most of their signature, so a lone
 * failed login does not call for a lockdown.
 */
export const PLAYBOOKS: readonly Playbook[] = [
  {
    id: 'NW-CRED-01',
    title: 'Credential stuffing against sign-in',
    tier: 'HIGH',
    signatures: ['login_failed', 'credential_stuffing_suspected', 'rate_limited', 'ip_blocked', 'step_up_failed'],
  },
  {
    id: 'NW-ATO-02',
    title: 'Account takeover',
    tier: 'CRITICAL',
    signatures: ['api_impossible_travel', 'step_up_lockout'],
  },
  {
    id: 'NW-EXFIL-03',
    title: 'Data theft: a trap or a canary was touched',
    tier: 'CRITICAL',
    signatures: ['honeytoken_trip', 'data_canary_trip'],
  },
  {
    id: 'NW-TAMPER-04',
    title: 'The audit trail was altered',
    tier: 'CRITICAL',
    signatures: ['audit_integrity_failed'],
  },
  {
    id: 'NW-RECON-05',
    title: 'Web reconnaissance and injection probing',
    tier: 'HIGH',
    signatures: ['ssrf_attempt', 'bola_attempt', 'prompt_injection_attempt', 'csp_violation', 'open_redirect_attempt'],
  },
  {
    id: 'NW-WEBHOOK-06',
    title: 'Webhook forgery and replay',
    tier: 'MEDIUM',
    signatures: ['webhook_bad_signature', 'webhook_replay', 'header_spoof_attempt'],
  },
];

/** At or above this share of a playbook's signature, a non-critical playbook fires. */
export const CORRELATION_THRESHOLD = 0.8;

export interface EscalationEvent {
  id: string;
  action: AuditAction;
}

export interface Advisory {
  playbookId: string;
  title: string;
  tier: Tier;
  correlation: number;
  matched: AuditAction[];
  evidence: string[];
  message: string;
}

export type LockdownRisk = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface Escalation {
  lockdownRisk: LockdownRisk;
  maxCorrelation: number;
  advisories: Advisory[];
}

const RANK: Record<Tier, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const RISK_BY_RANK: LockdownRisk[] = ['none', 'low', 'medium', 'high', 'critical'];

/** Pure and I/O-free. It produces advice with the evidence attached; an operator decides what to do with it. */
export function evaluateEscalation(
  events: readonly EscalationEvent[],
  playbooks: readonly Playbook[] = PLAYBOOKS,
): Escalation {
  const advisories: Advisory[] = [];
  let maxCorrelation = 0;
  let top = 0;
  for (const playbook of playbooks) {
    const matched = playbook.signatures.filter((signature) => events.some((event) => event.action === signature));
    const correlation = playbook.signatures.length === 0 ? 0 : matched.length / playbook.signatures.length;
    maxCorrelation = Math.max(maxCorrelation, correlation);
    const fires = (playbook.tier === 'CRITICAL' && matched.length > 0) || correlation >= CORRELATION_THRESHOLD;
    if (!fires) continue;
    const evidence = events.filter((event) => matched.includes(event.action)).map((event) => event.id);
    top = Math.max(top, RANK[playbook.tier]);
    advisories.push({
      playbookId: playbook.id,
      title: playbook.title,
      tier: playbook.tier,
      correlation,
      matched,
      evidence,
      message: `${playbook.id} (${playbook.tier}): ${playbook.title}. Matched ${matched.join(', ')}. Recommend an operator review lockdown.`,
    });
  }
  advisories.sort((a, b) => RANK[b.tier] - RANK[a.tier] || b.correlation - a.correlation);
  return { lockdownRisk: RISK_BY_RANK[top] ?? 'none', maxCorrelation, advisories };
}
