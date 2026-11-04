import { isIP } from 'node:net';

/** An address as a number, so a range check is arithmetic and not string matching (which is how `10.0.0.1.evil.com` gets through). */
export interface ParsedIp {
  version: 4 | 6;
  value: bigint;
}

function parseIpv4(text: string): bigint | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function parseIpv6(text: string): bigint | null {
  let address = text;
  // An embedded IPv4 tail (::ffff:1.2.3.4) is two groups.
  const tail = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
  if (tail?.[1]) {
    const v4 = parseIpv4(tail[1]);
    if (v4 === null) return null;
    address = `${address.slice(0, address.length - tail[1].length)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = halves.length === 1 ? head : [...head, ...Array<string>(missing).fill('0'), ...rest];
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    value = (value << 16n) | BigInt(Number.parseInt(group, 16));
  }
  return value;
}

/** An IPv4-mapped IPv6 address is an IPv4 address in disguise (`::ffff:7f00:1` is `127.0.0.1`), so it is judged as one. */
export function parseIp(raw: string): ParsedIp | null {
  let text = raw.trim();
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);
  const kind = isIP(text);
  if (kind === 4) {
    const value = parseIpv4(text);
    return value === null ? null : { version: 4, value };
  }
  if (kind === 6) {
    const value = parseIpv6(text);
    if (value === null) return null;
    if (value >> 32n === 0xffffn) return { version: 4, value: value & 0xffffffffn };
    return { version: 6, value };
  }
  return null;
}

/** One canonical spelling per address, or null when the text is not an address at all. */
export function normalizeIp(raw: string): string | null {
  const parsed = parseIp(raw);
  return parsed ? formatIp(parsed) : null;
}

export function formatIp(parsed: ParsedIp): string {
  if (parsed.version === 4) {
    const v = parsed.value;
    return [24n, 16n, 8n, 0n].map((shift) => Number((v >> shift) & 0xffn)).join('.');
  }
  const groups: string[] = [];
  for (let i = 7n; i >= 0n; i--) groups.push(Number((parsed.value >> (i * 16n)) & 0xffffn).toString(16));
  // Compress the longest run of zero groups, as RFC 5952 asks.
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== '0') {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  if (bestLength < 2) return groups.join(':');
  const left = groups.slice(0, bestStart).join(':');
  const right = groups.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

export interface Cidr {
  version: 4 | 6;
  base: bigint;
  bits: number;
}

export function parseCidr(text: string): Cidr | null {
  const [address, length, ...extra] = text.trim().split('/');
  if (extra.length > 0 || address === undefined) return null;
  const parsed = parseIp(address);
  if (!parsed) return null;
  const max = parsed.version === 4 ? 32 : 128;
  const bits = length === undefined ? max : /^\d{1,3}$/.test(length) ? Number(length) : Number.NaN;
  if (!Number.isInteger(bits) || bits < 0 || bits > max) return null;
  const hostBits = BigInt(max - bits);
  return { version: parsed.version, base: (parsed.value >> hostBits) << hostBits, bits };
}

/** A concrete address inside a range. The lab uses it to play an operator on the allow-listed network. */
export function sampleAddress(cidr: Cidr): string {
  const max = cidr.version === 4 ? 32 : 128;
  const roomForHost = max - cidr.bits >= 4;
  return formatIp({ version: cidr.version, value: roomForHost ? cidr.base + 10n : cidr.base });
}

export function inCidr(ip: ParsedIp, cidr: Cidr): boolean {
  if (ip.version !== cidr.version) return false;
  const max = ip.version === 4 ? 32 : 128;
  const hostBits = BigInt(max - cidr.bits);
  return (ip.value >> hostBits) << hostBits === cidr.base;
}

export function matchesAny(ip: string, ranges: readonly Cidr[]): boolean {
  const parsed = parseIp(ip);
  return parsed !== null && ranges.some((range) => inCidr(parsed, range));
}

/** What a server must never be talked into fetching: loopback, private, link-local (cloud metadata), reserved, multicast. */
const NON_PUBLIC = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
  '::/128',
  '::1/128',
  '64:ff9b::/96', // NAT64 wraps an IPv4 address; a server has no business connecting through it
  '100::/64',
  '2001:db8::/32',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8',
]
  .map(parseCidr)
  .filter((cidr): cidr is Cidr => cidr !== null);

export function isPublicAddress(raw: string): boolean {
  const parsed = parseIp(raw);
  return parsed !== null && !NON_PUBLIC.some((range) => inCidr(parsed, range));
}
