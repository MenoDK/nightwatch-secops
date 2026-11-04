import { describe, expect, it } from 'vitest';
import { base32Decode, base32Encode, hotp, newTotpSecret, totpAt, verifyTotp } from '../src/lib/totp.js';

// RFC 6238, appendix B: the SHA-1 seed is the ASCII string "12345678901234567890"; the vectors use 8 digits.
const rfcSecret = base32Encode(Buffer.from('12345678901234567890'));

describe('TOTP (RFC 6238 and RFC 4226 test vectors)', () => {
  it.each([
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ])('at %i seconds the code is %s', (seconds, code) => {
    expect(totpAt(rfcSecret, seconds * 1000, 8)).toBe(code);
  });

  it('matches the RFC 4226 HOTP sequence', () => {
    const secret = Buffer.from('12345678901234567890');
    const expected = [
      '755224',
      '287082',
      '359152',
      '969429',
      '338314',
      '254676',
      '287922',
      '162583',
      '399871',
      '520489',
    ];
    expect(expected.map((_, counter) => hotp(secret, counter))).toEqual(expected);
  });
});

describe('base32', () => {
  it('round-trips arbitrary bytes', () => {
    for (const length of [1, 5, 10, 20, 33]) {
      const bytes = Buffer.from(Array.from({ length }, (_, i) => (i * 37 + 11) & 255));
      expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
    }
  });

  it('ignores case, spaces and padding, and refuses other characters', () => {
    expect(base32Decode('mfrg gzdf ====')).toEqual(Buffer.from('abcde'));
    expect(() => base32Decode('MFRG1')).toThrow(RangeError);
  });

  it('makes secrets that are long enough and different each time', () => {
    const a = newTotpSecret();
    expect(a).toMatch(/^[A-Z2-7]{32}$/);
    expect(a).not.toBe(newTotpSecret());
  });
});

describe('verifyTotp', () => {
  const secret = rfcSecret;
  const now = 1_700_000_010_000;
  const code = (offsetSteps: number) => totpAt(secret, now + offsetSteps * 30_000);

  it('accepts the current code and reports its step', () => {
    expect(verifyTotp(secret, code(0), now)).toEqual({ ok: true, step: Math.floor(now / 30_000) });
  });

  it('allows one step of clock drift either way, and no more', () => {
    expect(verifyTotp(secret, code(-1), now).ok).toBe(true);
    expect(verifyTotp(secret, code(1), now).ok).toBe(true);
    expect(verifyTotp(secret, code(-2), now).ok).toBe(false);
    expect(verifyTotp(secret, code(2), now).ok).toBe(false);
  });

  it.each(['', '12345', '1234567', 'abcdef', '12 345', '１２３４５６'])('refuses the malformed code %j', (bad) => {
    expect(verifyTotp(secret, bad, now)).toEqual({ ok: false });
  });

  it('refuses a code for a different secret', () => {
    expect(verifyTotp(base32Encode(Buffer.from('another secret!!!!!!!')), code(0), now).ok).toBe(false);
  });
});
