import { createHmac, randomBytes } from 'node:crypto';
import { safeEqual } from './crypto.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.replace(/[\s=]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) throw new RangeError('not a base32 string');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export const newTotpSecret = (): string => base32Encode(randomBytes(20));

/** RFC 4226: HMAC-SHA1 of the counter, dynamically truncated. */
export function hotp(secret: Buffer, counter: number, digits = 6): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', secret).update(message).digest();
  const offset = (hmac[hmac.length - 1] ?? 0) & 0x0f;
  const binary =
    (((hmac[offset] ?? 0) & 0x7f) << 24) |
    (((hmac[offset + 1] ?? 0) & 0xff) << 16) |
    (((hmac[offset + 2] ?? 0) & 0xff) << 8) |
    ((hmac[offset + 3] ?? 0) & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export const stepAt = (timeMs: number, stepSeconds = 30): number => Math.floor(timeMs / 1000 / stepSeconds);

/** RFC 6238: the HOTP of the current 30-second step. */
export const totpAt = (secretBase32: string, timeMs: number, digits = 6, stepSeconds = 30): string =>
  hotp(base32Decode(secretBase32), stepAt(timeMs, stepSeconds), digits);

export interface TotpMatch {
  ok: boolean;
  /** The step the code belongs to. The caller remembers it, because a code is good once. */
  step?: number;
}

/**
 * Accepts the current step and `window` steps either side (clock drift). Every step in the window is compared, with no
 * early exit, so the time taken does not reveal which step a nearly-right code belonged to.
 */
export function verifyTotp(secretBase32: string, code: string, timeMs: number, window = 1, digits = 6): TotpMatch {
  if (!new RegExp(`^\\d{${digits}}$`).test(code)) return { ok: false };
  const secret = base32Decode(secretBase32);
  const now = stepAt(timeMs);
  let matched: number | undefined;
  for (let offset = -window; offset <= window; offset++) {
    const step = now + offset;
    if (step >= 0 && safeEqual(code, hotp(secret, step, digits))) matched = step;
  }
  return matched === undefined ? { ok: false } : { ok: true, step: matched };
}
