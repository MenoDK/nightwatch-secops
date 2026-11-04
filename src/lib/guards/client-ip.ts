import { type Cidr, matchesAny, normalizeIp } from '../net.js';

export type Headers = Record<string, string | string[] | undefined>;

export interface ClientIpResult {
  /** The address to rate-limit, block and log; null only when the socket address itself is unusable. */
  ip: string | null;
  via: 'socket' | 'cf-connecting-ip' | 'x-forwarded-for';
  /** Forwarding headers that arrived from a peer we do not trust, or that held garbage: a spoofing attempt, or a bug. */
  spoofed: string[];
}

const FORWARDING = ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip', 'forwarded'] as const;

const first = (value: string | string[] | undefined): string | undefined => (Array.isArray(value) ? value[0] : value);

/**
 * Who is really calling. A forwarding header is a claim made by whoever sent it, so it counts only when the peer that
 * delivered the request is a proxy we run. From a trusted proxy, `X-Forwarded-For` is read from the right: the proxy
 * appended the address it saw, and everything to the left of that is what the client chose to write.
 */
export function resolveClientIp(input: {
  remoteAddress: string;
  headers: Headers;
  trustedProxies: readonly Cidr[];
}): ClientIpResult {
  const peer = normalizeIp(input.remoteAddress);
  const present = FORWARDING.filter((name) => first(input.headers[name]) !== undefined);
  if (!peer) return { ip: null, via: 'socket', spoofed: [...present] };
  if (!matchesAny(peer, input.trustedProxies)) return { ip: peer, via: 'socket', spoofed: [...present] };

  const connecting = first(input.headers['cf-connecting-ip']);
  if (connecting !== undefined) {
    const ip = normalizeIp(connecting);
    if (ip) return { ip, via: 'cf-connecting-ip', spoofed: [] };
    return { ip: peer, via: 'socket', spoofed: ['cf-connecting-ip'] };
  }

  const chain = first(input.headers['x-forwarded-for']);
  if (chain !== undefined) {
    const hops = chain.split(',').map((hop) => hop.trim());
    for (let i = hops.length - 1; i >= 0; i--) {
      const hop = normalizeIp(hops[i] ?? '');
      if (!hop) return { ip: peer, via: 'socket', spoofed: ['x-forwarded-for'] };
      if (!matchesAny(hop, input.trustedProxies)) return { ip: hop, via: 'x-forwarded-for', spoofed: [] };
    }
  }
  return { ip: peer, via: 'socket', spoofed: [] };
}
