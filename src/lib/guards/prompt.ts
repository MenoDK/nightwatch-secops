/**
 * Logs are written by attackers. Before text that came from outside reaches a language model it is cleaned, and text that
 * tries to talk to the model is refused outright: the model is a reader of untrusted input, never a source of authority.
 */

const MARKER = '[SANITIZED]';
const MAX_TEXT = 120_000;

const NEUTRALISE: readonly RegExp[] = [
  /<\s*(tool_call|script|system|instruction|assistant|function)[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi,
  /<\s*tool_call\b[\s\S]*?(<\/\s*tool_call\s*>|$)/gi,
  /<\s*(tool_call|script|system|instruction|assistant|function)[^>]*>/gi,
  /\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?\b/gi,
  /"name"\s*:\s*"run_sql"/gi,
];

export function sanitizeForModel(text: string): { text: string; mutated: boolean } {
  let out = text;
  let mutated = false;
  for (const pattern of NEUTRALISE) {
    const next = out.replace(pattern, MARKER);
    if (next !== out) mutated = true;
    out = next;
  }
  if (out.length > MAX_TEXT) {
    out = out.slice(0, MAX_TEXT);
    mutated = true;
  }
  return { text: out, mutated };
}

/** Walks any JSON value and cleans every string in it; keys are left alone. */
export function sanitizeJsonForModel(value: unknown): { value: unknown; mutated: boolean } {
  let mutated = false;
  const walk = (node: unknown): unknown => {
    if (typeof node === 'string') {
      const cleaned = sanitizeForModel(node);
      if (cleaned.mutated) mutated = true;
      return cleaned.text;
    }
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === 'object') {
      return Object.fromEntries(Object.entries(node as Record<string, unknown>).map(([key, v]) => [key, walk(v)]));
    }
    return node;
  };
  return { value: walk(value), mutated };
}

const ADVERSARIAL: readonly { id: string; pattern: RegExp }[] = [
  { id: 'ignore_previous', pattern: /\bignore\s+(all\s+)?(previous|prior)\s+instructions?\b/i },
  { id: 'disregard_above', pattern: /\bdisregard\s+(the\s+)?(above|prior)\b/i },
  { id: 'role_override', pattern: /\bsystem\s*:\s*you\s+are\s+now\b/i },
  { id: 'developer_mode', pattern: /\bdeveloper\s+mode\s+enabled\b/i },
  { id: 'jailbreak', pattern: /\bDAN\b.*\bjailbreak\b|\bjailbreak\b.*\bDAN\b/i },
  { id: 'fake_tool_markup', pattern: /<\s*tool(_call)?\b[^>]*>/i },
  { id: 'end_of_system', pattern: /<\s*\/\s*system\s*>\s*<\s*user\b/i },
  {
    id: 'reveal_instructions',
    pattern:
      /\b(reveal|show|print|dump|output|leak|expose|send|paste)\b[^.\n]{0,96}\b(system|developer|hidden|initial)\s*(prompt|instruction|directive|message)s?\b/i,
  },
  { id: 'repeat_instructions', pattern: /\brepeat\s+(your|the)\s+system\s+(prompt|message)\s+verbatim\b/i },
  { id: 'sandbox_escape', pattern: /\b(break|escape)\s+(out\s+of\s+)?(the\s+)?sandbox\b/i },
  { id: 'sql_tool', pattern: /"name"\s*:\s*"run_sql"/i },
];

/** The ids of every adversarial pattern found in the text. */
export function detectAdversarial(text: string): string[] {
  const head = text.slice(0, MAX_TEXT);
  return ADVERSARIAL.filter(({ pattern }) => pattern.test(head)).map(({ id }) => id);
}

const SECRET_PATTERNS: readonly { name: string; pattern: RegExp; placeholder: string }[] = [
  { name: 'openai_key', pattern: /\bsk-[A-Za-z0-9]{20,}\b/g, placeholder: '[REDACTED_API_KEY]' },
  { name: 'groq_key', pattern: /\bgsk_[A-Za-z0-9]{20,}\b/g, placeholder: '[REDACTED_API_KEY]' },
  { name: 'aws_access_key', pattern: /\bAKIA[0-9A-Z]{16}\b/g, placeholder: '[REDACTED_AWS_KEY]' },
  { name: 'stripe_live', pattern: /\bsk_live_[0-9a-zA-Z]{20,}\b/g, placeholder: '[REDACTED_PAYMENT_KEY]' },
  { name: 'github_token', pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, placeholder: '[REDACTED_GITHUB_TOKEN]' },
  { name: 'github_fine_grained', pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, placeholder: '[REDACTED_GITHUB_TOKEN]' },
  { name: 'bearer_token', pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/g, placeholder: 'Bearer [REDACTED]' },
  {
    name: 'webhook_secret',
    pattern: /\bx-webhook-secret\b\s*[:=]\s*['"]?[\w+/=-]{12,}/gi,
    placeholder: '[REDACTED_WEBHOOK_SECRET]',
  },
  {
    name: 'private_key',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{10,4000}?-----END [A-Z ]*PRIVATE KEY-----/g,
    placeholder: '[REDACTED_PRIVATE_KEY]',
  },
];

/** A heuristic, deliberately conservative. It is a seatbelt for logs and prompts, not a substitute for a secret scanner. */
export function redactSecrets(text: string): { text: string; found: string[] } {
  const found: string[] = [];
  let out = text;
  for (const { name, pattern, placeholder } of SECRET_PATTERNS) {
    out = out.replace(pattern, () => {
      if (!found.includes(name)) found.push(name);
      return placeholder;
    });
  }
  return { text: out, found };
}

export type ModelInputVerdict =
  | { ok: true; text: string }
  | { ok: false; reason: 'adversarial_prompt'; patterns: string[] }
  | { ok: false; reason: 'secret_in_input'; kinds: string[]; preview: string };

/** The gate in front of any model call that includes text a user or a log supplied. */
export function guardModelInput(text: string): ModelInputVerdict {
  const patterns = detectAdversarial(text);
  if (patterns.length > 0) return { ok: false, reason: 'adversarial_prompt', patterns };
  const secrets = redactSecrets(text);
  if (secrets.found.length > 0) {
    return { ok: false, reason: 'secret_in_input', kinds: secrets.found, preview: secrets.text.slice(0, 200) };
  }
  return { ok: true, text: sanitizeForModel(text).text };
}
