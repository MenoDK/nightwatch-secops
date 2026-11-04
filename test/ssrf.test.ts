import { describe, expect, it } from 'vitest';
import { type Resolver, checkOutboundUrl, findDangerousContent } from '../src/lib/guards/ssrf.js';

const table: Record<string, string[]> = {
  'files.partner.test': ['8.8.8.8'],
  'rebind.test': ['8.8.8.8', '10.0.0.5'], // one public record, one private
  'internal-only.test': ['10.1.2.3'],
  'mapped.test': ['::ffff:127.0.0.1'],
  'empty.test': [],
};
const resolver: Resolver = async (host) => {
  const found = table[host];
  if (!found) throw new Error('NXDOMAIN');
  return found;
};
const check = (url: string, extra = {}) => checkOutboundUrl(url, { resolver, ...extra });

describe('checkOutboundUrl', () => {
  it('allows a public host and says which address to connect to', async () => {
    expect(await check('https://files.partner.test/doc.pdf')).toMatchObject({
      ok: true,
      host: 'files.partner.test',
      address: '8.8.8.8',
    });
  });

  it('allows a public address literal', async () => {
    expect(await check('http://8.8.8.8/x')).toMatchObject({ ok: true, address: '8.8.8.8' });
  });

  it.each([
    ['http://127.0.0.1/', 'non_public_address'],
    ['http://169.254.169.254/latest/meta-data/', 'non_public_address'],
    ['http://[::1]/', 'non_public_address'],
    ['http://[::ffff:127.0.0.1]/', 'non_public_address'],
    ['http://[::ffff:7f00:1]/', 'non_public_address'],
    ['http://2130706433/', 'non_public_address'], // 127.0.0.1 as one decimal number
    ['http://0x7f000001/', 'non_public_address'], // ... as hex
    ['http://0x7f.1/', 'non_public_address'],
    ['http://017700000001/', 'non_public_address'], // ... as octal
    ['http://127.1/', 'non_public_address'], // short form
    ['http://0/', 'non_public_address'],
    ['http://192.168.0.1:80/', 'non_public_address'],
    ['http://localhost/', 'reserved_name'],
    ['http://localhost./', 'reserved_name'],
    ['http://service.localhost/', 'reserved_name'],
    ['http://metadata.google.internal/', 'reserved_name'],
    ['http://printer.local/', 'reserved_name'],
  ])('refuses %s (%s)', async (url, reason) => {
    expect(await check(url)).toMatchObject({ ok: false, reason });
  });

  it('refuses a name that resolves to a private address', async () => {
    expect(await check('https://internal-only.test/')).toMatchObject({
      ok: false,
      reason: 'non_public_address',
      detail: '10.1.2.3',
    });
  });

  it('refuses a name with one public and one private record (DNS rebinding by multiple answers)', async () => {
    expect(await check('https://rebind.test/')).toMatchObject({
      ok: false,
      reason: 'non_public_address',
      detail: '10.0.0.5',
    });
  });

  it('judges an IPv4-mapped answer as the IPv4 address it is', async () => {
    expect(await check('https://mapped.test/')).toMatchObject({ ok: false, reason: 'non_public_address' });
  });

  it('refuses names that do not resolve, or resolve to nothing', async () => {
    expect(await check('https://nx.test/')).toMatchObject({ ok: false, reason: 'unresolvable' });
    expect(await check('https://empty.test/')).toMatchObject({ ok: false, reason: 'unresolvable' });
  });

  it.each([
    ['file:///etc/passwd', 'scheme'],
    ['gopher://8.8.8.8/', 'scheme'],
    ['ftp://8.8.8.8/', 'scheme'],
    ['https://user:pw@files.partner.test/', 'userinfo'],
    ['https://files.partner.test:8080/', 'port'],
    ['https://files.partner.test:22/', 'port'],
    ['not a url', 'invalid_url'],
    ['', 'invalid_url'],
  ])('refuses %s (%s)', async (url, reason) => {
    expect(await check(url)).toMatchObject({ ok: false, reason });
  });

  it('honours the scheme, port and host allow-lists when they are given', async () => {
    expect(await check('http://files.partner.test/', { schemes: ['https'] })).toMatchObject({
      ok: false,
      reason: 'scheme',
    });
    expect(await check('https://files.partner.test:8443/', { ports: [8443] })).toMatchObject({ ok: true });
    expect(await check('https://files.partner.test/', { allowHosts: ['other.test'] })).toMatchObject({
      ok: false,
      reason: 'host_not_allowed',
    });
  });

  it('a host that merely starts or ends like a private address is judged as a name', async () => {
    expect(await check('http://10.0.0.1.files.partner.test/')).toMatchObject({ ok: false, reason: 'unresolvable' });
  });
});

describe('findDangerousContent', () => {
  it.each([
    '<iframe src="http://x">',
    '<  script>alert(1)</script>',
    '<img src="file:///etc/passwd">',
    'see file:///etc/hosts',
    'curl http://169.254.169.254/latest',
    'http://metadata.google.internal/computeMetadata',
    'gopher://127.0.0.1:6379/_FLUSHALL',
  ])('flags %j', (text) => {
    expect(findDangerousContent(text)).not.toBeNull();
  });

  it('lets ordinary text, and the word "filesystem", through', () => {
    expect(findDangerousContent('Quarterly report: the filesystem was migrated on 2026-01-05.')).toBeNull();
    expect(findDangerousContent('')).toBeNull();
    expect(findDangerousContent(null)).toBeNull();
  });
});
