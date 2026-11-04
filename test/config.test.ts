import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { fresh, testEnv } from './harness.js';

const base = () => testEnv({ DATABASE_URL: 'postgres://u@db/app', REDIS_URL: 'redis://redis:6379' });
const prod = (over: Record<string, string> = {}) => ({
  ...base(),
  APP_ENV: 'production',
  API_KEY: fresh(12),
  ADMIN_IPS: '10.20.0.0/16',
  ...over,
});

describe('configuration', () => {
  it('loads a complete development environment', () => {
    const config = loadConfig(base());
    expect(config).toMatchObject({ appEnv: 'test', loginFailMax: 5, failClosed: false, labMode: false });
    expect(config.adminIps).toHaveLength(1);
  });

  it('treats an empty optional setting as not set, which is what Compose passes for an unset variable', () => {
    const config = loadConfig({ ...base(), ANALYST_URL: '', ANALYST_KEY: '  ' });
    expect(config.analyst).toBeNull();
    expect(() => loadConfig({ ...base(), ANALYST_URL: 'not a url' })).toThrow(/ANALYST_URL/);
  });

  it('production accepts a sound configuration', () => {
    expect(() => loadConfig(prod())).not.toThrow();
  });

  describe('production refuses to start with', () => {
    it.each([
      ['the default API key', { API_KEY: 'change-me' }, 'API_KEY'],
      ['lab mode, which hands out the TOTP seed and edits the chain', { LAB_MODE: 'true' }, 'LAB_MODE'],
      ['no operator network, which would leave approval open to everyone', { ADMIN_IPS: '' }, 'ADMIN_IPS'],
    ])('%s', (_name, over, field) => {
      expect(() => loadConfig(prod(over))).toThrow(new RegExp(field));
    });
  });

  describe('any environment refuses', () => {
    it.each([
      ['a short chain secret', { AUDIT_CHAIN_SECRET: 'short' }, 'AUDIT_CHAIN_SECRET'],
      ['a short webhook secret', { WEBHOOK_SECRETS: 'short' }, 'WEBHOOK_SECRETS'],
      ['one short secret among several', { WEBHOOK_SECRETS: `${fresh()},short` }, 'WEBHOOK_SECRETS'],
      ['a TOTP seed that is not base32', { TOTP_SECRET: '1111111111111111!' }, 'TOTP_SECRET'],
      ['an operator range that is not one', { ADMIN_IPS: '10.20.0.0/99' }, 'ADMIN_IPS'],
      ['a proxy that is not an address', { TRUSTED_PROXIES: 'proxy.example.test' }, 'TRUSTED_PROXIES'],
      ['a login limit of one, which would block every typo', { LOGIN_FAIL_MAX: '1' }, 'LOGIN_FAIL_MAX'],
      ['a missing database', { DATABASE_URL: '' }, 'DATABASE_URL'],
    ])('%s', (_name, over, field) => {
      expect(() => loadConfig({ ...base(), ...over })).toThrow(new RegExp(field));
    });
  });

  it('names the setting that is wrong and never repeats its value', () => {
    const secret = fresh(8);
    try {
      loadConfig({ ...base(), TOTP_SECRET: `${secret}!!!!!!!!!!!!!!!!` });
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).toContain('TOTP_SECRET');
      expect((error as Error).message).not.toContain(secret);
    }
  });

  it('parses lists, ranges and flags', () => {
    const config = loadConfig({
      ...base(),
      TRUSTED_PROXIES: '10.0.0.0/8, 192.0.2.1',
      HONEY_ACCOUNTS: 'Root@Example.test, ',
      FAIL_CLOSED: 'true',
      ANALYST_URL: 'http://localhost:11434/v1',
    });
    expect(config.trustedProxies).toHaveLength(2);
    expect(config.honeyAccounts).toEqual(['root@example.test']);
    expect(config.failClosed).toBe(true);
    expect(config.analyst).toMatchObject({ url: 'http://localhost:11434/v1', model: 'local-model' });
  });

  it('flags are exactly "true" or "false": a typo is an error, not a silent no', () => {
    expect(() => loadConfig({ ...base(), FAIL_CLOSED: 'yes' })).toThrow(/FAIL_CLOSED/);
  });
});
