import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const sha256 = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

export const hmacHex = (secret: string, data: string): string =>
  createHmac('sha256', secret).update(data, 'utf8').digest('hex');

/**
 * Compares two strings in constant time whatever their lengths: both sides are hashed first, so `timingSafeEqual`
 * always sees 32 bytes and a wrong length cannot be told apart from a wrong value by timing.
 */
export function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(
    createHash('sha256').update(a, 'utf8').digest(),
    createHash('sha256').update(b, 'utf8').digest(),
  );
}

/**
 * JSON with sorted keys and no insignificant whitespace. Two equal values always give the same bytes, whatever order
 * a database or a client put the keys in: the property a hash over structured data needs.
 */
export function stableJson(value: unknown): string {
  if (value === undefined || value === null) return 'null';
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value !== 'object') return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item)).join(',')}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
}
