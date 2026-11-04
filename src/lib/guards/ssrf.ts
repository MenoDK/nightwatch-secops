import { isPublicAddress, normalizeIp, parseIp } from '../net.js';

/** Turns a name into addresses. Injected, so a test (and the lab) can decide what a name resolves to without a network. */
export type Resolver = (hostname: string) => Promise<string[]>;

export interface OutboundPolicy {
  resolver: Resolver;
  schemes?: readonly ('http' | 'https')[];
  /** Ports that may be dialled. Default: the scheme's own (80, 443). */
  ports?: readonly number[];
  /** When set, only these exact host names may be fetched: the strongest form of the rule. */
  allowHosts?: readonly string[];
}

export type OutboundVerdict =
  | {
      ok: true;
      url: string;
      host: string /** Connect to this address, not to the name: it closes the DNS-rebinding gap. */;
      address: string;
      addresses: string[];
    }
  | {
      ok: false;
      reason:
        | 'invalid_url'
        | 'scheme'
        | 'userinfo'
        | 'port'
        | 'host_not_allowed'
        | 'reserved_name'
        | 'unresolvable'
        | 'non_public_address';
      detail?: string;
    };

const RESERVED_SUFFIXES = ['.localhost', '.local', '.internal', '.localdomain', '.home.arpa'];

/**
 * May the server fetch this URL on someone's behalf? Every address the name resolves to must be public: a name with one
 * public and one private record is how a check made on the first is defeated at connect time on the second. The caller
 * should connect to `address`, not resolve the name again.
 *
 * `new URL` already turns `2130706433`, `0x7f.1` and `017700000001` into `127.0.0.1`, so numeric disguises reach the
 * range check in their plain form.
 */
export async function checkOutboundUrl(raw: string, policy: OutboundPolicy): Promise<OutboundVerdict> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid_url' };
  }
  const schemes = policy.schemes ?? ['https', 'http'];
  const scheme = url.protocol.replace(':', '');
  if (scheme !== 'http' && scheme !== 'https') return { ok: false, reason: 'scheme', detail: scheme };
  if (!schemes.includes(scheme)) return { ok: false, reason: 'scheme', detail: scheme };
  if (url.username !== '' || url.password !== '') return { ok: false, reason: 'userinfo' };

  const port = url.port === '' ? (scheme === 'https' ? 443 : 80) : Number(url.port);
  const allowedPorts = policy.ports ?? [80, 443];
  if (!allowedPorts.includes(port)) return { ok: false, reason: 'port', detail: String(port) };

  const host = url.hostname
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
    .toLowerCase();
  if (policy.allowHosts && !policy.allowHosts.includes(host)) return { ok: false, reason: 'host_not_allowed' };

  const literal = parseIp(host);
  if (literal) {
    const address = normalizeIp(host) ?? host;
    return isPublicAddress(address)
      ? { ok: true, url: url.toString(), host, address, addresses: [address] }
      : { ok: false, reason: 'non_public_address', detail: address };
  }

  if (host === 'localhost' || RESERVED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    return { ok: false, reason: 'reserved_name', detail: host };
  }

  let resolved: string[];
  try {
    resolved = (await policy.resolver(host)).map((a) => normalizeIp(a)).filter((a): a is string => a !== null);
  } catch {
    return { ok: false, reason: 'unresolvable' };
  }
  const first = resolved[0];
  if (first === undefined) return { ok: false, reason: 'unresolvable' };
  const bad = resolved.find((address) => !isPublicAddress(address));
  if (bad !== undefined) return { ok: false, reason: 'non_public_address', detail: bad };
  return { ok: true, url: url.toString(), host, address: first, addresses: resolved };
}

const DANGEROUS_CONTENT: readonly RegExp[] = [
  /<\s*iframe\b/i,
  /<\s*object\b/i,
  /<\s*embed\b/i,
  /<\s*script\b/i,
  /<\s*img\b[^>]*\bsrc\s*=\s*["']?\s*file:/i,
  /\bfile:\/\//i,
  /\b169\.254\.169\.254\b/,
  /\bmetadata\.google\.internal\b/i,
  /\bgopher:\/\//i,
  /\bdict:\/\//i,
  /\bldap:\/\//i,
];

/**
 * For text that a renderer (a PDF or an e-mail pipeline) may one day interpret: markup that fetches things, and the
 * addresses cloud metadata services live at. A second line of defence behind {@link checkOutboundUrl}, not a substitute.
 */
export function findDangerousContent(text: string | null | undefined): string | null {
  if (!text) return null;
  const hit = DANGEROUS_CONTENT.find((pattern) => pattern.test(text));
  return hit ? hit.source : null;
}
