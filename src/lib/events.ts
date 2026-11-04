/** Everything the engine can write to the audit chain. One list, so a typo cannot create a new kind of event. */
export const AUDIT_ACTIONS = [
  'login_failed',
  'login_succeeded',
  'credential_stuffing_suspected',
  'rate_limited',
  'api_impossible_travel',
  'honeytoken_trip',
  'data_canary_trip',
  'step_up_failed',
  'step_up_lockout',
  'audit_integrity_failed',
  'ssrf_attempt',
  'bola_attempt',
  'csp_violation',
  'prompt_injection_attempt',
  'secret_leak_blocked',
  'webhook_bad_signature',
  'webhook_replay',
  'header_spoof_attempt',
  'open_redirect_attempt',
  'ip_blocked',
  'ip_unblocked',
  'subject_suspended',
  'subject_released',
  'lockdown_on',
  'lockdown_off',
  'override_created',
  'proposal_created',
  'proposal_approved',
  'proposal_rejected',
  'proposal_executed',
  'approval_denied',
  'ingest_received',
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export const isAuditAction = (value: string): value is AuditAction =>
  (AUDIT_ACTIONS as readonly string[]).includes(value);

/**
 * What the protected application (or a log shipper) may tell us it saw. These are observations, not conclusions: the
 * engine decides what they mean. A caller can never write `honeytoken_trip` or `ip_blocked` itself; those exist only
 * as things the engine concluded.
 */
export const REPORT_KINDS = [
  'login_failed',
  'login_succeeded',
  'api_request',
  'record_read',
  'bola_attempt',
  'csp_violation',
] as const;

export type ReportKind = (typeof REPORT_KINDS)[number];
