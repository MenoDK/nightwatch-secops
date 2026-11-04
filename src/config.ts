import { z } from 'zod';
import { type Cidr, parseCidr } from './lib/net.js';
import { base32Decode } from './lib/totp.js';

const DEFAULT_API_KEY = 'change-me';

const flag = z
  .enum(['true', 'false'])
  .default('false')
  .transform((v) => v === 'true');

/** Docker Compose passes `VAR=` for a variable that is declared but unset; for an optional setting that means "not set". */
const optional = <T extends z.ZodTypeAny>(schema: T) =>
  z.preprocess((v) => (typeof v === 'string' && v.trim() === '' ? undefined : v), schema.optional());

const list = (raw: string): string[] =>
  raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

const schema = z
  .object({
    PORT: z.coerce.number().int().min(1).max(65535).default(8000),
    APP_ENV: z.enum(['development', 'test', 'production']).default('development'),
    DATABASE_URL: z.string().min(1),
    REDIS_URL: z.string().min(1),
    /** Prefix for every Redis key, so two deployments (or two test files) can share one server. */
    REDIS_PREFIX: z.string().min(1).default('nw'),
    API_KEY: z.string().min(8).default(DEFAULT_API_KEY),

    /** Keys the audit chain. Whoever holds it can rewrite history, so it is a secret and nothing else uses it. */
    AUDIT_CHAIN_SECRET: z.string().min(32),
    /** Secrets that sign inbound webhooks (log shippers, scanners). Current first; the rest are still accepted (rotation). */
    WEBHOOK_SECRETS: z.string().min(16),
    /** The operator's TOTP seed, base32. Step-up needs it for every action that changes the world. */
    TOTP_SECRET: z.string().min(16),

    /** Addresses an operator may approve from (CIDR, comma-separated). Required in production. */
    ADMIN_IPS: z.string().default(''),
    /** Reverse proxies whose forwarding headers are believed. Anyone else's are claims, logged as such. */
    TRUSTED_PROXIES: z.string().default(''),
    ALLOWED_REDIRECT_ORIGINS: z.string().default(''),
    /** Names that sign-in forms must never receive: whoever tries one is not a customer. */
    HONEY_ACCOUNTS: z.string().default('backup-admin@example.test,root-recovery@example.test'),
    /** Record ids that no legitimate screen shows. Reading one is the alarm. */
    CANARY_IDS: z.string().default('00000000-0000-4000-8000-000000000c01'),

    LOGIN_FAIL_MAX: z.coerce.number().int().min(2).max(100).default(5),
    LOGIN_FAIL_WINDOW_SECONDS: z.coerce.number().int().min(10).max(86_400).default(300),
    TRAVEL_MAX_SPEED_KMH: z.coerce.number().min(100).max(5000).default(900),
    TRAVEL_MIN_KM: z.coerce.number().min(10).max(5000).default(300),
    /** Alert only by default (VPNs and mobile carriers give false positives); the analyst then proposes the suspension. */
    TRAVEL_SUSPENDS: flag,
    STUFFING_BLOCK_SECONDS: z.coerce.number().int().min(60).default(3600),
    APPROVED_BLOCK_SECONDS: z.coerce.number().int().min(60).default(86_400),
    HONEY_BLOCK_SECONDS: z.coerce.number().int().min(60).default(172_800),
    HONEY_TRIGGERS_LOCKDOWN: flag,
    LOCKDOWN_SECONDS: z.coerce.number().int().min(60).default(3600),
    STEP_UP_MAX_FAILS: z.coerce.number().int().min(2).max(10).default(3),
    STEP_UP_WINDOW_SECONDS: z.coerce.number().int().min(60).max(86_400).default(900),
    /** What a dead Redis means for the blocklist and the lockdown flag: let traffic through, or refuse it. */
    FAIL_CLOSED: flag,
    RISK_WINDOW_HOURS: z.coerce.number().int().min(1).max(168).default(24),

    /** An OpenAI-compatible chat endpoint for the analyst. Without it the local rules do the analysis. */
    ANALYST_URL: optional(z.string().url()),
    ANALYST_MODEL: z.string().default('local-model'),
    ANALYST_KEY: optional(z.string()),
    ANALYST_TIMEOUT_MS: z.coerce.number().int().min(500).max(60_000).default(8000),

    LAB_MODE: flag,
    SITE_DIR: z.string().default(''),
  })
  .superRefine((env, ctx) => {
    const issue = (path: string, message: string) => ctx.addIssue({ code: 'custom', path: [path], message });
    const production = env.APP_ENV === 'production';
    if (production && env.API_KEY === DEFAULT_API_KEY) issue('API_KEY', 'must not be the default in production');
    if (production && env.LAB_MODE) {
      issue(
        'LAB_MODE',
        'exposes the TOTP seed, a movable clock and a way to tamper with the audit chain; refused in production',
      );
    }
    if (production && list(env.ADMIN_IPS).length === 0) issue('ADMIN_IPS', 'is required in production');
    for (const range of list(env.ADMIN_IPS))
      if (!parseCidr(range)) issue('ADMIN_IPS', `${range} is not an address or a CIDR range`);
    for (const range of list(env.TRUSTED_PROXIES))
      if (!parseCidr(range)) issue('TRUSTED_PROXIES', `${range} is not an address or a CIDR range`);
    for (const secret of list(env.WEBHOOK_SECRETS))
      if (secret.length < 16) issue('WEBHOOK_SECRETS', 'every secret needs 16+ characters');
    try {
      if (base32Decode(env.TOTP_SECRET).length < 10) issue('TOTP_SECRET', 'must decode to at least 10 bytes');
    } catch {
      issue('TOTP_SECRET', 'must be base32');
    }
  });

export interface Config {
  port: number;
  appEnv: 'development' | 'test' | 'production';
  databaseUrl: string;
  redisUrl: string;
  redisPrefix: string;
  apiKey: string;
  auditChainSecret: string;
  webhookSecrets: string[];
  totpSecret: string;
  adminIps: Cidr[];
  trustedProxies: Cidr[];
  allowedRedirectOrigins: string[];
  honeyAccounts: string[];
  canaryIds: string[];
  loginFailMax: number;
  loginFailWindowSeconds: number;
  travel: { maxSpeedKmh: number; minKm: number; suspends: boolean };
  stuffingBlockSeconds: number;
  approvedBlockSeconds: number;
  honeyBlockSeconds: number;
  honeyTriggersLockdown: boolean;
  lockdownSeconds: number;
  stepUp: { maxFails: number; windowSeconds: number };
  failClosed: boolean;
  riskWindowHours: number;
  analyst: { url: string; model: string; key: string | undefined; timeoutMs: number } | null;
  labMode: boolean;
  siteDir: string;
}

const cidrs = (items: string[]): Cidr[] => items.map(parseCidr).filter((c): c is Cidr => c !== null);

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join('.') || 'env'}: ${i.message}`).join('; ');
    throw new Error(`invalid configuration: ${problems}`);
  }
  const e = parsed.data;
  return {
    port: e.PORT,
    appEnv: e.APP_ENV,
    databaseUrl: e.DATABASE_URL,
    redisUrl: e.REDIS_URL,
    redisPrefix: e.REDIS_PREFIX,
    apiKey: e.API_KEY,
    auditChainSecret: e.AUDIT_CHAIN_SECRET,
    webhookSecrets: list(e.WEBHOOK_SECRETS),
    totpSecret: e.TOTP_SECRET.replace(/\s/g, '').toUpperCase(),
    adminIps: cidrs(list(e.ADMIN_IPS)),
    trustedProxies: cidrs(list(e.TRUSTED_PROXIES)),
    allowedRedirectOrigins: list(e.ALLOWED_REDIRECT_ORIGINS),
    honeyAccounts: list(e.HONEY_ACCOUNTS).map((a) => a.toLowerCase()),
    canaryIds: list(e.CANARY_IDS),
    loginFailMax: e.LOGIN_FAIL_MAX,
    loginFailWindowSeconds: e.LOGIN_FAIL_WINDOW_SECONDS,
    travel: { maxSpeedKmh: e.TRAVEL_MAX_SPEED_KMH, minKm: e.TRAVEL_MIN_KM, suspends: e.TRAVEL_SUSPENDS },
    stuffingBlockSeconds: e.STUFFING_BLOCK_SECONDS,
    approvedBlockSeconds: e.APPROVED_BLOCK_SECONDS,
    honeyBlockSeconds: e.HONEY_BLOCK_SECONDS,
    honeyTriggersLockdown: e.HONEY_TRIGGERS_LOCKDOWN,
    lockdownSeconds: e.LOCKDOWN_SECONDS,
    stepUp: { maxFails: e.STEP_UP_MAX_FAILS, windowSeconds: e.STEP_UP_WINDOW_SECONDS },
    failClosed: e.FAIL_CLOSED,
    riskWindowHours: e.RISK_WINDOW_HOURS,
    analyst: e.ANALYST_URL
      ? { url: e.ANALYST_URL, model: e.ANALYST_MODEL, key: e.ANALYST_KEY, timeoutMs: e.ANALYST_TIMEOUT_MS }
      : null,
    labMode: e.LAB_MODE,
    siteDir: e.SITE_DIR,
  };
}

export const isDefaultApiKey = (key: string): boolean => key === DEFAULT_API_KEY;
