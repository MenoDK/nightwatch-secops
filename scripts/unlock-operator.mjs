#!/usr/bin/env node
/**
 * Releases the step-up lockout. It talks to Redis, not to the API, on purpose: a lockout exists because someone guessed
 * wrong codes, and "whoever can call the API can lift it" would hand the guesser the key to their own cell. Needing
 * access to the store means needing access to the infrastructure.
 *
 *   REDIS_URL=redis://... REDIS_PREFIX=nw node scripts/unlock-operator.mjs
 */
import { Redis } from 'ioredis';

const url = process.env.REDIS_URL;
if (!url) {
  console.error('REDIS_URL is required.');
  process.exit(2);
}
const prefix = process.env.REDIS_PREFIX || 'nw';
const redis = new Redis(url, { maxRetriesPerRequest: 1 });
try {
  const removed = await redis.del(`${prefix}:stepup:locked:soc`, `${prefix}:stepup:fails:soc`);
  console.log(removed > 0 ? 'The operator lockout was released.' : 'There was no lockout to release.');
} finally {
  await redis.quit();
}
