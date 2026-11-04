import type { AuditAction } from './events.js';

/**
 * One row per signal: each event is worth `unit` points, and a signal can never contribute more than `cap`. The cap is
 * the point. Typing a password wrong is human, so a hundred failures are worth little more than twenty; a honeytoken
 * tripped once is already a verdict. The weights are a contract in one place, not scattered through the code.
 */
export const SIGNALS: Partial<Record<AuditAction, { unit: number; cap: number; label: string }>> = {
  audit_integrity_failed: { unit: 60, cap: 100, label: 'The audit chain does not verify' },
  honeytoken_trip: { unit: 40, cap: 80, label: 'A honeytoken was touched' },
  data_canary_trip: { unit: 40, cap: 80, label: 'A canary record was read' },
  step_up_lockout: { unit: 35, cap: 70, label: 'An operator was locked out of step-up' },
  api_impossible_travel: { unit: 25, cap: 60, label: 'Impossible travel' },
  credential_stuffing_suspected: { unit: 20, cap: 40, label: 'Credential stuffing suspected' },
  ssrf_attempt: { unit: 6, cap: 24, label: 'Server-side request forgery attempts' },
  bola_attempt: { unit: 5, cap: 20, label: 'Access to other people’s objects' },
  prompt_injection_attempt: { unit: 4, cap: 16, label: 'Prompt injection attempts' },
  webhook_replay: { unit: 4, cap: 12, label: 'Replayed webhooks' },
  webhook_bad_signature: { unit: 3, cap: 12, label: 'Webhooks with a bad signature' },
  step_up_failed: { unit: 3, cap: 12, label: 'Wrong step-up codes' },
  approval_denied: { unit: 5, cap: 15, label: 'Approvals attempted from outside the allow-list' },
  header_spoof_attempt: { unit: 3, cap: 9, label: 'Spoofed forwarding headers' },
  secret_leak_blocked: { unit: 2, cap: 8, label: 'Secrets caught leaving' },
  open_redirect_attempt: { unit: 2, cap: 6, label: 'Open-redirect attempts' },
  login_failed: { unit: 1.5, cap: 15, label: 'Failed sign-ins' },
  csp_violation: { unit: 0.5, cap: 5, label: 'Content-security-policy reports' },
};

/**
 * What an operator may not talk away. Marking a failed login a false positive is routine; marking a broken audit chain
 * or a tripped honeytoken a false positive is exactly what an intruder who stole an operator's session would do.
 */
export const NON_OVERRIDABLE: ReadonlySet<AuditAction> = new Set<AuditAction>([
  'audit_integrity_failed',
  'honeytoken_trip',
  'data_canary_trip',
  'step_up_lockout',
]);

export type Counts = Partial<Record<AuditAction, number>>;
export type RiskLevel = 'calm' | 'elevated' | 'high' | 'critical';

export interface RiskPart {
  action: AuditAction;
  label: string;
  events: number;
  counted: number;
  points: number;
  capped: boolean;
}

export interface Risk {
  score: number;
  level: RiskLevel;
  parts: RiskPart[];
  /** What the score would be if no operator had reclassified anything: the number that cannot be argued down. */
  scoreWithoutOverrides: number;
  overriddenEvents: number;
}

export const levelFor = (score: number): RiskLevel =>
  score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'elevated' : 'calm';

function score(counts: Counts): { score: number; parts: RiskPart[] } {
  const parts: RiskPart[] = [];
  let raw = 0;
  for (const [action, signal] of Object.entries(SIGNALS) as [
    AuditAction,
    { unit: number; cap: number; label: string },
  ][]) {
    const events = Math.max(0, Math.floor(counts[action] ?? 0));
    if (events === 0) continue;
    const uncapped = events * signal.unit;
    const points = Math.min(signal.cap, uncapped);
    raw += points;
    parts.push({ action, label: signal.label, events, counted: events, points, capped: uncapped > signal.cap });
  }
  parts.sort((a, b) => b.points - a.points);
  return { score: Math.min(100, Math.round(raw)), parts };
}

/**
 * `counts` is what happened; `overridden` is how many of each an operator has reclassified as benign. A non-overridable
 * signal ignores the second argument even if it is given one: the rule is enforced here as well as where overrides are made.
 */
const whole = (counts: Counts): Counts =>
  Object.fromEntries(Object.entries(counts).map(([action, n]) => [action, Math.max(0, Math.floor(n ?? 0))]));

export function computeRisk(rawCounts: Counts, rawOverridden: Counts = {}): Risk {
  const counts = whole(rawCounts);
  const overridden = whole(rawOverridden);
  const effective: Counts = {};
  let overriddenEvents = 0;
  for (const action of Object.keys(counts) as AuditAction[]) {
    const total = counts[action] ?? 0;
    const removed = NON_OVERRIDABLE.has(action) ? 0 : Math.min(total, Math.max(0, overridden[action] ?? 0));
    overriddenEvents += removed;
    effective[action] = total - removed;
  }
  const after = score(effective);
  const parts = after.parts.map((part) => ({
    ...part,
    events: counts[part.action] ?? 0,
    counted: effective[part.action] ?? 0,
  }));
  return {
    score: after.score,
    level: levelFor(after.score),
    parts,
    scoreWithoutOverrides: score(counts).score,
    overriddenEvents,
  };
}
