import { describe, expect, it } from 'vitest';
import { resolveClientIp } from '../src/lib/guards/client-ip.js';
import { type Cidr, parseCidr } from '../src/lib/net.js';

const trusted = ['10.0.0.0/8', '172.18.0.0/16'].map((c) => parseCidr(c) as Cidr);
const call = (remoteAddress: string, headers: Record<string, string> = {}) =>
  resolveClientIp({ remoteAddress, headers, trustedProxies: trusted });

describe('resolveClientIp', () => {
  it('uses the socket when nothing is forwarded', () => {
    expect(call('203.0.113.9')).toEqual({ ip: '203.0.113.9', via: 'socket', spoofed: [] });
  });

  it('ignores every forwarding header from a peer that is not a proxy of ours, and says so', () => {
    const result = call('203.0.113.9', {
      'x-forwarded-for': '1.1.1.1',
      'cf-connecting-ip': '2.2.2.2',
      'x-real-ip': '3.3.3.3',
    });
    expect(result.ip).toBe('203.0.113.9');
    expect(result.spoofed.sort()).toEqual(['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip']);
  });

  it('reads X-Forwarded-For from the right: what the client wrote on the left is not trusted', () => {
    // The client claimed to be 6.6.6.6; our proxy appended the address it actually saw.
    const result = call('10.0.0.2', { 'x-forwarded-for': '6.6.6.6, 198.51.100.7' });
    expect(result).toEqual({ ip: '198.51.100.7', via: 'x-forwarded-for', spoofed: [] });
  });

  it('skips our own proxies in the chain', () => {
    expect(call('10.0.0.2', { 'x-forwarded-for': '198.51.100.7, 10.0.0.5, 172.18.0.3' }).ip).toBe('198.51.100.7');
  });

  it('falls back to the proxy and flags a chain with garbage in it', () => {
    const result = call('10.0.0.2', { 'x-forwarded-for': '198.51.100.7, not-an-ip' });
    expect(result).toEqual({ ip: '10.0.0.2', via: 'socket', spoofed: ['x-forwarded-for'] });
  });

  it('prefers a valid cf-connecting-ip from a trusted proxy, and flags an invalid one', () => {
    expect(call('10.0.0.2', { 'cf-connecting-ip': '198.51.100.7', 'x-forwarded-for': '9.9.9.9' }).ip).toBe(
      '198.51.100.7',
    );
    expect(call('10.0.0.2', { 'cf-connecting-ip': 'junk' })).toEqual({
      ip: '10.0.0.2',
      via: 'socket',
      spoofed: ['cf-connecting-ip'],
    });
  });

  it('recognises a trusted proxy that arrives as an IPv4-mapped IPv6 address', () => {
    expect(call('::ffff:10.0.0.2', { 'x-forwarded-for': '198.51.100.7' }).ip).toBe('198.51.100.7');
  });

  it('normalises the address it returns', () => {
    expect(call('10.0.0.2', { 'x-forwarded-for': '::ffff:198.51.100.7' }).ip).toBe('198.51.100.7');
  });

  it('has no address when the socket address is not one', () => {
    expect(call('').ip).toBeNull();
  });
});
