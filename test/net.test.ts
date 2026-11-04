import { describe, expect, it } from 'vitest';
import { inCidr, isPublicAddress, normalizeIp, parseCidr, parseIp } from '../src/lib/net.js';

describe('normalizeIp', () => {
  it.each([
    ['1.2.3.4', '1.2.3.4'],
    [' 1.2.3.4 ', '1.2.3.4'],
    ['::ffff:1.2.3.4', '1.2.3.4'],
    ['::ffff:7f00:1', '127.0.0.1'],
    ['[2001:DB8:0:0:0:0:0:1]', '2001:db8::1'],
    ['fe80::1%eth0', 'fe80::1'],
    ['0:0:0:0:0:0:0:1', '::1'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeIp(input)).toBe(expected);
  });

  it.each(['', 'hello', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.-4', '::g', '1::2::3', '10.0.0.1.evil.com'])(
    'rejects %j',
    (input) => {
      expect(normalizeIp(input)).toBeNull();
    },
  );
});

describe('CIDR ranges', () => {
  it('matches on the network bits only', () => {
    const range = parseCidr('10.0.0.0/8');
    expect(range && inCidr(parseIp('10.255.255.255') ?? { version: 4, value: 0n }, range)).toBe(true);
    expect(range && inCidr(parseIp('11.0.0.0') ?? { version: 4, value: 0n }, range)).toBe(false);
  });

  it('never matches across IP versions', () => {
    const range = parseCidr('0.0.0.0/0');
    expect(range && inCidr(parseIp('::1') ?? { version: 6, value: 0n }, range)).toBe(false);
  });

  it.each(['10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0/8/8', 'nope/8', '::/129'])('rejects the range %s', (text) => {
    expect(parseCidr(text)).toBeNull();
  });
});

describe('isPublicAddress', () => {
  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.35', '2606:4700:4700::1111'])('%s is public', (ip) => {
    expect(isPublicAddress(ip)).toBe(true);
  });

  it.each([
    '127.0.0.1',
    '127.255.255.254',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254', // cloud metadata
    '100.64.0.1', // carrier-grade NAT
    '0.0.0.0',
    '224.0.0.1',
    '255.255.255.255',
    '198.18.0.1',
    '203.0.113.5', // documentation range
    '::1',
    '::',
    'fe80::1',
    'fc00::1',
    'fd12:3456::1',
    'ff02::1',
    '2001:db8::1',
    '::ffff:127.0.0.1', // IPv4-mapped loopback
    '::ffff:a00:1', // IPv4-mapped 10.0.0.1, hex form
    '64:ff9b::7f00:1', // NAT64 wrapping loopback
  ])('%s is not public', (ip) => {
    expect(isPublicAddress(ip)).toBe(false);
  });

  it('treats text that is not an address as not public', () => {
    expect(isPublicAddress('example.com')).toBe(false);
    expect(isPublicAddress('')).toBe(false);
  });

  it('judges the boundary of 172.16.0.0/12 exactly', () => {
    expect(isPublicAddress('172.15.255.255')).toBe(true);
    expect(isPublicAddress('172.32.0.0')).toBe(true);
  });
});
