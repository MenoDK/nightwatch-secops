import { describe, expect, it } from 'vitest';
import { CORRELATION_THRESHOLD, PLAYBOOKS, evaluateEscalation } from '../src/lib/escalation.js';
import type { AuditAction } from '../src/lib/events.js';

const events = (...actions: AuditAction[]) => actions.map((action, i) => ({ id: `e${i}`, action }));

describe('evaluateEscalation', () => {
  it('has nothing to say about a quiet system', () => {
    expect(evaluateEscalation([])).toEqual({ lockdownRisk: 'none', maxCorrelation: 0, advisories: [] });
    expect(evaluateEscalation(events('login_succeeded')).advisories).toEqual([]);
  });

  it('does not call for a lockdown over a lone failed login', () => {
    const result = evaluateEscalation(events('login_failed'));
    expect(result.advisories).toEqual([]);
    expect(result.maxCorrelation).toBeCloseTo(1 / 5);
  });

  it('fires a CRITICAL playbook on a single matching event, and cites it', () => {
    const result = evaluateEscalation(events('login_succeeded', 'honeytoken_trip'));
    expect(result.lockdownRisk).toBe('critical');
    expect(result.advisories[0]).toMatchObject({
      playbookId: 'NW-EXFIL-03',
      matched: ['honeytoken_trip'],
      evidence: ['e1'],
    });
  });

  it('fires a non-critical playbook only at 80% of its signature', () => {
    const cred = PLAYBOOKS.find((p) => p.id === 'NW-CRED-01');
    expect(cred?.signatures.length).toBe(5);
    expect(evaluateEscalation(events('login_failed', 'rate_limited', 'ip_blocked')).advisories).toEqual([]);
    const four = evaluateEscalation(
      events('login_failed', 'rate_limited', 'ip_blocked', 'credential_stuffing_suspected'),
    );
    expect(four.advisories).toHaveLength(1);
    expect(four.advisories[0]).toMatchObject({ playbookId: 'NW-CRED-01', tier: 'HIGH' });
    expect(four.advisories[0]?.correlation).toBeGreaterThanOrEqual(CORRELATION_THRESHOLD);
    expect(four.lockdownRisk).toBe('high');
  });

  it('reports the worst tier and orders advisories by it', () => {
    const result = evaluateEscalation(
      events('webhook_bad_signature', 'webhook_replay', 'header_spoof_attempt', 'audit_integrity_failed'),
    );
    expect(result.lockdownRisk).toBe('critical');
    expect(result.advisories.map((a) => a.tier)).toEqual(['CRITICAL', 'MEDIUM']);
  });

  it('counts each signature once however many events carry it', () => {
    const many = evaluateEscalation(events(...Array<AuditAction>(50).fill('login_failed')));
    expect(many.advisories).toEqual([]);
    expect(many.maxCorrelation).toBeCloseTo(1 / 5);
  });

  it('every playbook signature is a known audit action (the catalogue cannot drift from the event list)', async () => {
    const { AUDIT_ACTIONS } = await import('../src/lib/events.js');
    for (const playbook of PLAYBOOKS) {
      for (const signature of playbook.signatures)
        expect({ [playbook.id]: AUDIT_ACTIONS.includes(signature) }).toEqual({ [playbook.id]: true });
    }
  });
});
