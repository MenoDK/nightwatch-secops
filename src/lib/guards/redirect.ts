export type RedirectVerdict =
  | { ok: true; url: string }
  | {
      ok: false;
      reason:
        | 'not_a_string'
        | 'too_long'
        | 'control_characters'
        | 'backslash'
        | 'invalid'
        | 'scheme'
        | 'userinfo'
        | 'origin';
    };

const PLACEHOLDER = 'http://placeholder.invalid';

/**
 * Where may a "return to" or "callback" parameter send a visitor? Only somewhere on this site, or to an origin that was
 * written down in advance. Browsers are forgiving about what a URL looks like (they drop tabs and newlines, treat `\`
 * as `/`), so the rule is applied to what the URL *parses to* rather than to how the text looks.
 */
export function safeCallbackUrl(raw: unknown, options: { allowedOrigins: readonly string[] }): RedirectVerdict {
  if (typeof raw !== 'string') return { ok: false, reason: 'not_a_string' };
  if (raw.length > 2048) return { ok: false, reason: 'too_long' };
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (/[\u0000-\u001f\u007f]/.test(raw)) return { ok: false, reason: 'control_characters' };
  if (raw.includes('\\')) return { ok: false, reason: 'backslash' };

  if (raw.startsWith('/')) {
    // `//host` is a scheme-relative URL: it leaves the site.
    if (raw.startsWith('//')) return { ok: false, reason: 'origin' };
    let parsed: URL;
    try {
      parsed = new URL(raw, PLACEHOLDER);
    } catch {
      return { ok: false, reason: 'invalid' };
    }
    if (parsed.origin !== PLACEHOLDER) return { ok: false, reason: 'origin' };
    return { ok: true, url: `${parsed.pathname}${parsed.search}${parsed.hash}` };
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid' };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return { ok: false, reason: 'scheme' };
  if (parsed.username !== '' || parsed.password !== '') return { ok: false, reason: 'userinfo' };
  if (!options.allowedOrigins.includes(parsed.origin)) return { ok: false, reason: 'origin' };
  return { ok: true, url: parsed.toString() };
}
