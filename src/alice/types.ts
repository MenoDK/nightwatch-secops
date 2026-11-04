import type { Entry } from '../lib/audit-chain.js';
import type { Escalation } from '../lib/escalation.js';
import type { RiskReport } from '../lib/risk-query.js';

export const PROPOSAL_KINDS = ['block_ip', 'suspend_subject', 'lockdown'] as const;
export type ProposalKind = (typeof PROPOSAL_KINDS)[number];
export const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];
export type ProposalStatus = 'pending' | 'executed' | 'rejected' | 'failed';

/** What an analyst hands back: a suggestion with its reasons and the audit rows it rests on. It changes nothing. */
export interface Draft {
  kind: ProposalKind;
  target: string;
  rationale: string;
  /** Audit sequence numbers. A proposal with no evidence is not a proposal. */
  evidence: number[];
  severity: Severity;
}

export interface Proposal extends Draft {
  id: string;
  source: 'local' | 'remote';
  status: ProposalStatus;
  createdAt: string;
  decidedAt: string | null;
  decidedBy: string | null;
  decisionNote: string | null;
}

export interface AnalysisInput {
  /** The window's audit entries, oldest first. */
  entries: Entry[];
  escalation: Escalation;
  risk: RiskReport;
  /** What is already done, so the analyst does not propose it again. */
  state: { blockedIps: ReadonlySet<string>; suspended: ReadonlySet<string>; lockdownActive: boolean };
  isAdminIp: (ip: string) => boolean;
}

export interface Analyst {
  readonly name: 'local' | 'remote';
  analyze(input: AnalysisInput): Promise<Draft[]>;
}
