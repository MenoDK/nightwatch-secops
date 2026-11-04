import type { Context } from '../context.js';

export interface Human {
  /** Who is asking, as they say so. It is attribution in the audit chain, never an authority. */
  label: string;
  ip: string | null;
  userAgent?: string | null;
  /** The six-digit code from the operator's authenticator. */
  code: string | undefined;
}

export type GateResult =
  | { ok: true; actor: string }
  | {
      ok: false;
      status: 401 | 403 | 423;
      code: 'ip_not_allowed' | 'step_up_required' | 'step_up_invalid' | 'operator_locked';
      message: string;
      remaining?: number;
    };

/** The single bucket the second factor is counted in. See {@link authorizeHuman}. */
const BUCKET = 'soc';

export const operatorLabel = (raw: string | string[] | undefined): string => {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' && /^[A-Za-z0-9._@-]{1,64}$/.test(value) ? value : 'operator';
};

/**
 * The line between "can look and report" and "can change the world". An API key is enough for the first; the second
 * needs a person: on a network that was written down in advance, with a code from a device only they hold.
 *
 * Order matters. The network check is first so that someone outside it cannot spend the operator's attempts at the
 * code and lock them out. The code is counted in ONE bucket, not per label: the label is a header the caller chooses,
 * and a lockout keyed on it is a lockout the attacker can walk around by changing it.
 */
export async function authorizeHuman(ctx: Context, human: Human, what: string): Promise<GateResult> {
  if (!ctx.isAdminIp(human.ip)) {
    await ctx.chain.append({
      actor: human.label,
      action: 'approval_denied',
      ip: human.ip,
      userAgent: human.userAgent ?? null,
      metadata: { reason: 'ip_not_allowed', attempted: what },
    });
    return {
      ok: false,
      status: 403,
      code: 'ip_not_allowed',
      message: 'this action is only accepted from the operators’ network',
    };
  }
  const result = await ctx.stepUp.verify(BUCKET, human.code);
  if (result.ok) return { ok: true, actor: human.label };
  if (result.reason === 'invalid' || result.reason === 'replayed') {
    return {
      ok: false,
      status: 401,
      code: 'step_up_invalid',
      message:
        result.reason === 'replayed' ? 'that code was already used; wait for the next one' : 'that code is not valid',
      remaining: result.remaining,
    };
  }
  if (result.reason === 'missing') {
    return {
      ok: false,
      status: 401,
      code: 'step_up_required',
      message: 'send the six-digit code from your authenticator in the x-totp header',
    };
  }
  return {
    ok: false,
    status: 423,
    code: 'operator_locked',
    message: 'too many wrong codes; a person must release the lockout',
  };
}
