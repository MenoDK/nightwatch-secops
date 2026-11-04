import { describe, expect, it } from 'vitest';
import { safeCallbackUrl } from '../src/lib/guards/redirect.js';

const allowedOrigins = ['https://app.example.com'];
const check = (raw: unknown) => safeCallbackUrl(raw, { allowedOrigins });

describe('safeCallbackUrl', () => {
  it.each([
    ['/dashboard', '/dashboard'],
    ['/a/b?x=1#top', '/a/b?x=1#top'],
    ['/', '/'],
    ['https://app.example.com/next?x=1', 'https://app.example.com/next?x=1'],
  ])('allows %s', (raw, url) => {
    expect(check(raw)).toEqual({ ok: true, url });
  });

  it.each([
    ['//evil.example', 'origin'],
    ['///evil.example', 'origin'],
    ['/\\evil.example', 'backslash'],
    ['\\\\evil.example', 'backslash'],
    ['/\t/evil.example', 'control_characters'],
    ['/\n/evil.example', 'control_characters'],
    ['javascript:alert(1)', 'scheme'],
    ['data:text/html,<script>', 'scheme'],
    ['https://evil.example/', 'origin'],
    ['https://app.example.com.evil.example/', 'origin'],
    ['https://app.example.com@evil.example/', 'userinfo'],
    ['https://user:pass@app.example.com/', 'userinfo'],
    ['http://app.example.com/', 'origin'], // same host, different scheme: not the origin we allowed
    ['next', 'invalid'],
    ['', 'invalid'],
  ])('refuses %j (%s)', (raw, reason) => {
    expect(check(raw)).toEqual({ ok: false, reason });
  });

  it('refuses what is not text and what is absurdly long', () => {
    expect(check(undefined)).toEqual({ ok: false, reason: 'not_a_string' });
    expect(check({ toString: () => '/x' })).toEqual({ ok: false, reason: 'not_a_string' });
    expect(check(`/${'a'.repeat(3000)}`)).toEqual({ ok: false, reason: 'too_long' });
  });
});
