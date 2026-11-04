import type { Clock } from '../clock.js';
import type { Config } from '../config.js';
import type { AuditChain } from './audit-chain.js';
import { type Headers, resolveClientIp } from './guards/client-ip.js';
import { guardModelInput } from './guards/prompt.js';
import { safeCallbackUrl } from './guards/redirect.js';
import { type OutboundVerdict, type Resolver, checkOutboundUrl } from './guards/ssrf.js';
import { type ReplayStore, type WebhookVerdict, verifyWebhook } from './guards/webhook.js';
import type { Kv } from './kv.js';

const NOISE_WINDOW_MS = 600_000;

export interface Ctx {
  ip: string | null;
  userAgent?: string | null;
}

/** A URL goes into the log, but never the password someone put in it. */
export function redactUrl(raw: string): string {
  try {
    const url = new URL(raw);
    url.username = '';
    url.password = '';
    return url.toString().slice(0, 300);
  } catch {
    return raw.slice(0, 300);
  }
}

/**
 * The guards, each wrapped so that a refusal becomes evidence. The refusal itself is a cheap pure function; what this
 * adds is that an attack that fails still leaves a mark in the chain, which is what lets the risk score notice a pattern.
 */
export class Shield {
  readonly replay: ReplayStore;

  constructor(
    private readonly chain: AuditChain,
    private readonly kv: Kv,
    private readonly clock: Clock,
    private readonly config: Config,
    private readonly resolver: Resolver,
    private readonly noiseLimit = 30,
  ) {
    this.replay = { claim: (key, ttl) => this.kv.claim(this.kv.key('replay', key), ttl) };
  }

  /**
   * Evidence from callers nobody has authenticated (a bad webhook, a forged header) is the one thing an outsider can make
   * us write. So it is capped per address: past the limit the chain gets one `rate_limited` row saying so, and then
   * nothing, until the window passes. The attack is still visible; the disk is not the thing under attack.
   */
  private async note(
    ctx: Ctx,
    action: Parameters<AuditChain['append']>[0]['action'],
    metadata: Record<string, unknown>,
  ) {
    const nowMs = this.clock.now().getTime();
    const seen = await this.kv.slide(this.kv.key('noise', action, ctx.ip ?? 'unknown'), nowMs, NOISE_WINDOW_MS);
    if (seen > this.noiseLimit) {
      if (seen === this.noiseLimit + 1) {
        await this.chain.append({
          actor: 'shield',
          action: 'rate_limited',
          ip: ctx.ip,
          userAgent: ctx.userAgent ?? null,
          metadata: { of: action, limit: this.noiseLimit, windowSeconds: NOISE_WINDOW_MS / 1000 },
        });
      }
      return;
    }
    await this.chain.append({ actor: 'shield', action, ip: ctx.ip, userAgent: ctx.userAgent ?? null, metadata });
  }

  async url(raw: string, ctx: Ctx): Promise<OutboundVerdict> {
    const verdict = await checkOutboundUrl(raw, { resolver: this.resolver });
    // A string that is not a URL, or a name that does not exist, is a typo as often as an attack. The rest is not.
    if (!verdict.ok && verdict.reason !== 'invalid_url' && verdict.reason !== 'unresolvable') {
      await this.note(ctx, 'ssrf_attempt', {
        url: redactUrl(raw),
        reason: verdict.reason,
        ...(verdict.detail ? { detail: verdict.detail } : {}),
      });
    }
    return verdict;
  }

  async redirect(raw: unknown, ctx: Ctx) {
    const verdict = safeCallbackUrl(raw, { allowedOrigins: this.config.allowedRedirectOrigins });
    if (!verdict.ok && verdict.reason !== 'not_a_string') {
      await this.note(ctx, 'open_redirect_attempt', {
        reason: verdict.reason,
        value: typeof raw === 'string' ? raw.slice(0, 200) : null,
      });
    }
    return verdict;
  }

  async webhook(
    input: { route: string; rawBody: string; timestamp: string | undefined; signature: string | undefined },
    ctx: Ctx,
  ): Promise<WebhookVerdict> {
    const verdict = await verifyWebhook({
      secrets: this.config.webhookSecrets,
      route: input.route,
      rawBody: input.rawBody,
      timestamp: input.timestamp,
      signature: input.signature,
      now: this.clock.now(),
      replay: this.replay,
    });
    if (!verdict.ok) {
      if (verdict.reason === 'replay') await this.note(ctx, 'webhook_replay', { route: input.route });
      else await this.note(ctx, 'webhook_bad_signature', { route: input.route, reason: verdict.reason });
    }
    return verdict;
  }

  /** The gate in front of anything that will be sent to a language model. Never put the offending text itself in the log. */
  async model(text: string, ctx: Ctx) {
    const verdict = guardModelInput(text);
    if (!verdict.ok) {
      if (verdict.reason === 'adversarial_prompt')
        await this.note(ctx, 'prompt_injection_attempt', { patterns: verdict.patterns });
      else await this.note(ctx, 'secret_leak_blocked', { kinds: verdict.kinds });
    }
    return verdict;
  }

  async clientIp(remoteAddress: string, headers: Headers, ctx: Ctx) {
    const result = resolveClientIp({ remoteAddress, headers, trustedProxies: this.config.trustedProxies });
    if (result.spoofed.length > 0) {
      const claimed = Object.fromEntries(
        result.spoofed.map((name) => [name, String(headers[name] ?? '').slice(0, 120)]),
      );
      await this.note({ ...ctx, ip: result.ip ?? ctx.ip }, 'header_spoof_attempt', {
        headers: result.spoofed,
        claimed,
      });
    }
    return result;
  }
}
