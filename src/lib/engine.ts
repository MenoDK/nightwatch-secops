import type { Clock } from '../clock.js';
import type { Config } from '../config.js';
import type { AuditChain, Entry, NewEntry } from './audit-chain.js';
import type { Blocklist, Lockdown, Suspensions } from './controls.js';
import type { ReportKind } from './events.js';
import { normalizeIp } from './net.js';
import type { GeoCheck, GeoWatch, LoginWatch } from './watch.js';

export interface Report {
  kind: ReportKind;
  subject?: string | undefined;
  ip: string;
  userAgent?: string | undefined;
  metadata?: Record<string, unknown> | undefined;
}

export interface Outcome {
  /** Audit sequence numbers written for this report, including the ones the engine derived. */
  recorded: number[];
  /** Plain-language notes on what the engine decided, in order. Safe to show to an operator. */
  notes: string[];
  contained: { ipBlocked: boolean; subjectSuspended: boolean; lockdown: boolean };
  counts?: { ip: number; subject: number };
}

const emptyOutcome = (): Outcome => ({
  recorded: [],
  notes: [],
  contained: { ipBlocked: false, subjectSuspended: false, lockdown: false },
});

export interface EngineDeps {
  chain: AuditChain;
  clock: Clock;
  config: Config;
  blocklist: Blocklist;
  lockdown: Lockdown;
  suspensions: Suspensions;
  loginWatch: LoginWatch;
  geoWatch: GeoWatch;
}

/**
 * Turns "the application saw this" into evidence in the chain and, where a rule is unambiguous, into containment.
 * Containment here is deliberately narrow and reversible: block one address for a while, suspend an account only when
 * told to. Anything wider (a lockdown, in most cases) is proposed to a person, not done.
 */
export class Engine {
  constructor(private readonly d: EngineDeps) {}

  private async write(out: Outcome, entry: NewEntry): Promise<Entry> {
    const written = await this.d.chain.append(entry);
    out.recorded.push(written.seq);
    return written;
  }

  async report(report: Report): Promise<Outcome> {
    const out = emptyOutcome();
    const ip = normalizeIp(report.ip) ?? report.ip;
    const subject = report.subject ?? null;
    const base = { subject, ip, userAgent: report.userAgent ?? null };

    switch (report.kind) {
      case 'login_failed': {
        if (subject && this.d.config.honeyAccounts.includes(subject.toLowerCase())) {
          await this.trap('honeytoken_trip', { ...base, trap: 'honey account', detail: { attempted: subject } }, out);
          break;
        }
        await this.write(out, { actor: 'app', action: 'login_failed', ...base, metadata: report.metadata ?? {} });
        const alarm = await this.d.loginWatch.failed(ip, subject);
        out.counts = { ip: alarm.ipCount, subject: alarm.subjectCount };
        if (alarm.raised) {
          await this.write(out, {
            actor: 'engine',
            action: 'credential_stuffing_suspected',
            ...base,
            metadata: {
              pattern: alarm.pattern,
              ipCount: alarm.ipCount,
              subjectCount: alarm.subjectCount,
              limit: this.d.config.loginFailMax,
            },
          });
          out.notes.push(
            alarm.pattern === 'one_address'
              ? `${alarm.ipCount} failed sign-ins from one address in the window: credential stuffing suspected.`
              : `${alarm.subjectCount} failed sign-ins on one account in the window: brute force suspected.`,
          );
          if (alarm.pattern === 'one_address') {
            await this.block(ip, this.d.config.stuffingBlockSeconds, 'credential stuffing', out);
          }
        }
        break;
      }
      case 'login_succeeded': {
        await this.write(out, { actor: 'app', action: 'login_succeeded', ...base, metadata: report.metadata ?? {} });
        await this.d.loginWatch.succeeded(subject);
        if (subject) await this.travel(subject, ip, base, out);
        break;
      }
      case 'api_request': {
        // Not audited: a request is not an event. Only a request that trips a rule becomes one.
        if (subject) await this.travel(subject, ip, base, out);
        break;
      }
      case 'record_read': {
        const id = typeof report.metadata?.id === 'string' ? report.metadata.id : null;
        if (id && this.d.config.canaryIds.includes(id)) {
          await this.trap('data_canary_trip', { ...base, trap: 'canary record', detail: { id } }, out);
        }
        break;
      }
      case 'bola_attempt':
      case 'csp_violation': {
        await this.write(out, { actor: 'app', action: report.kind, ...base, metadata: report.metadata ?? {} });
        break;
      }
    }
    return out;
  }

  private async travel(
    subject: string,
    ip: string,
    base: { subject: string | null; ip: string; userAgent: string | null },
    out: Outcome,
  ): Promise<GeoCheck> {
    const check = await this.d.geoWatch.check(subject, ip);
    if (check.status !== 'impossible') return check;
    const { verdict, from } = check;
    await this.write(out, {
      actor: 'engine',
      action: 'api_impossible_travel',
      ...base,
      metadata: {
        km: Math.round(verdict.km),
        minutes: Math.round(verdict.minutes * 10) / 10,
        speedKmh: Math.round(verdict.speedKmh),
        from: { lat: from.lat, lon: from.lon },
      },
    });
    out.notes.push(
      `${subject} moved ${Math.round(verdict.km)} km in ${Math.round(verdict.minutes)} minutes: impossible travel.`,
    );
    if (this.d.config.travel.suspends) {
      await this.d.suspensions.suspend(subject, 'impossible travel', 'engine');
      await this.write(out, {
        actor: 'engine',
        action: 'subject_suspended',
        ...base,
        metadata: { reason: 'impossible travel' },
      });
      out.contained.subjectSuspended = true;
    }
    return check;
  }

  private async block(ip: string, seconds: number, reason: string, out: Outcome): Promise<void> {
    await this.d.blocklist.block(ip, seconds, reason, 'engine');
    await this.write(out, { actor: 'engine', action: 'ip_blocked', ip, metadata: { reason, seconds } });
    out.contained.ipBlocked = true;
    out.notes.push(`Address ${ip} blocked for ${Math.round(seconds / 60)} minutes (${reason}).`);
  }

  /** A trap was touched. Nothing legitimate ever does that, so the verdict does not wait for a second sign. */
  private async trap(
    action: 'honeytoken_trip' | 'data_canary_trip',
    info: {
      subject: string | null;
      ip: string;
      userAgent: string | null;
      trap: string;
      detail: Record<string, unknown>;
    },
    out: Outcome,
  ): Promise<void> {
    await this.write(out, {
      actor: 'engine',
      action,
      subject: info.subject,
      ip: info.ip,
      userAgent: info.userAgent,
      metadata: { trap: info.trap, ...info.detail },
    });
    out.notes.push(`A ${info.trap} was touched from ${info.ip}.`);
    await this.block(info.ip, this.d.config.honeyBlockSeconds, info.trap, out);
    if (this.d.config.honeyTriggersLockdown) {
      await this.d.lockdown.activate(this.d.config.lockdownSeconds, `${info.trap} touched`, 'engine');
      await this.write(out, {
        actor: 'engine',
        action: 'lockdown_on',
        metadata: { reason: `${info.trap} touched`, seconds: this.d.config.lockdownSeconds },
      });
      out.contained.lockdown = true;
      out.notes.push('Lockdown switched on (configured to follow a trap).');
    }
  }
}
