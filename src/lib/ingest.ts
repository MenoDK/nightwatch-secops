import type { Report } from './engine.js';
import { normalizeIp } from './net.js';

export const INGEST_SOURCES = ['host-log', 'dependency-scan'] as const;
export type IngestSource = (typeof INGEST_SOURCES)[number];
export const isIngestSource = (value: string): value is IngestSource =>
  (INGEST_SOURCES as readonly string[]).includes(value);

export interface Normalized {
  reports: Report[];
  /** How many items the payload held, and how many of those meant anything to us. */
  items: number;
  matched: number;
  summary: Record<string, unknown>;
}

const MAX_LINES = 500;
const MAX_LINE = 1000;

// Bounded quantifiers throughout: a line is attacker-controlled text, so the pattern must not be able to backtrack badly.
const SSHD =
  /^.{0,80}?sshd\[\d{1,7}\]: (Failed|Accepted) (?:password|publickey) for (?:invalid user )?(\S{1,64}) from ([0-9a-fA-F:.]{2,45}) port \d{1,5}/;

/** `sshd` lines in, sign-in observations out. Everything else in the log is none of our business. */
export function parseHostLog(body: unknown): Normalized {
  const lines = Array.isArray((body as { lines?: unknown })?.lines)
    ? (body as { lines: unknown[] }).lines.filter((l): l is string => typeof l === 'string').slice(0, MAX_LINES)
    : [];
  const reports: Report[] = [];
  for (const raw of lines) {
    const hit = SSHD.exec(raw.slice(0, MAX_LINE));
    if (!hit) continue;
    const ip = normalizeIp(hit[3] as string);
    if (!ip) continue;
    reports.push({
      kind: hit[1] === 'Failed' ? 'login_failed' : 'login_succeeded',
      ip,
      subject: hit[2] as string,
      metadata: { via: 'host-log' },
    });
  }
  return {
    reports,
    items: lines.length,
    matched: reports.length,
    summary: { lines: lines.length, signIns: reports.length },
  };
}

interface Finding {
  severity: string;
}

/** A dependency scan is inventory, not an attack: it is kept as evidence, with counts, and scores nothing. */
export function parseDependencyScan(body: unknown): Normalized {
  const raw = (body as { findings?: unknown })?.findings;
  const findings = Array.isArray(raw) ? raw.slice(0, 2000) : [];
  const bySeverity: Record<string, number> = {};
  for (const f of findings as Finding[]) {
    const severity = typeof f?.severity === 'string' ? f.severity.toLowerCase().slice(0, 16) : 'unknown';
    bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
  }
  return {
    reports: [],
    items: findings.length,
    matched: findings.length,
    summary: { findings: findings.length, bySeverity },
  };
}

export function normalize(source: IngestSource, body: unknown): Normalized {
  return source === 'host-log' ? parseHostLog(body) : parseDependencyScan(body);
}
