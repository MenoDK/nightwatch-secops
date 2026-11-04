import { hmacHex, safeEqual, sha256 } from '../crypto.js';

/** `claim` is true the first time it sees a key and false afterwards: an atomic "set if absent" with an expiry. */
export interface ReplayStore {
  claim(key: string, ttlSeconds: number): Promise<boolean>;
}

export type WebhookVerdict =
  | { ok: true }
  | { ok: false; reason: 'missing_headers' | 'bad_timestamp' | 'stale' | 'bad_signature' | 'replay' };

/** The signature covers the time, the route and the exact bytes: change any of them and it no longer matches. */
export const signWebhook = (secret: string, route: string, timestampSeconds: number, rawBody: string): string =>
  hmacHex(secret, `${timestampSeconds}.${route}.${rawBody}`);

export interface WebhookInput {
  /** Current secret first; older ones stay valid until they are removed, so a rotation needs no downtime. */
  secrets: readonly string[];
  route: string;
  rawBody: string;
  timestamp: string | undefined;
  signature: string | undefined;
  now: Date;
  maxSkewSeconds?: number;
  replay: ReplayStore;
}

/**
 * Order matters. Time and signature are checked first, and only a message that authenticates is remembered: if
 * remembering came first, anyone could fill the replay store with junk, or burn the id of a real message before it arrived.
 * The caller answers every refusal the same way and keeps the reason for its own log.
 */
export async function verifyWebhook(input: WebhookInput): Promise<WebhookVerdict> {
  const { timestamp, signature } = input;
  if (!timestamp || !signature) return { ok: false, reason: 'missing_headers' };
  if (!/^\d{1,12}$/.test(timestamp)) return { ok: false, reason: 'bad_timestamp' };
  const maxSkew = input.maxSkewSeconds ?? 300;
  const sent = Number(timestamp);
  if (Math.abs(input.now.getTime() / 1000 - sent) > maxSkew) return { ok: false, reason: 'stale' };

  // Compare against every secret without stopping at the first match, so the time taken does not say which one it was.
  let matched = false;
  for (const secret of input.secrets) {
    if (safeEqual(signature, signWebhook(secret, input.route, sent, input.rawBody))) matched = true;
  }
  if (!matched) return { ok: false, reason: 'bad_signature' };

  const first = await input.replay.claim(`webhook:${input.route}:${sha256(signature)}`, maxSkew * 2);
  return first ? { ok: true } : { ok: false, reason: 'replay' };
}
