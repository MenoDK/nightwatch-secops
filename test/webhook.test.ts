import { describe, expect, it } from 'vitest';
import { type ReplayStore, signWebhook, verifyWebhook } from '../src/lib/guards/webhook.js';

const secret = ['whs', 'a'.repeat(24)].join('_'); // built at run time: nothing in the file looks like a credential
const oldSecret = ['whs', 'b'.repeat(24)].join('_');
const route = '/v1/ingest/sentry';
const body = '{"level":"error","message":"boom"}';
const now = new Date('2026-11-01T12:00:00Z');
const nowSeconds = now.getTime() / 1000;

const memoryReplay = (): ReplayStore => {
  const seen = new Set<string>();
  return {
    async claim(key) {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
};

const send = (over: Partial<Parameters<typeof verifyWebhook>[0]> = {}, replay = memoryReplay()) =>
  verifyWebhook({
    secrets: [secret],
    route,
    rawBody: body,
    timestamp: String(nowSeconds),
    signature: signWebhook(secret, route, nowSeconds, body),
    now,
    replay,
    ...over,
  });

describe('verifyWebhook', () => {
  it('accepts a correctly signed, fresh message', async () => {
    expect(await send()).toEqual({ ok: true });
  });

  it('refuses the second delivery of the same message (replay)', async () => {
    const replay = memoryReplay();
    expect(await send({}, replay)).toEqual({ ok: true });
    expect(await send({}, replay)).toEqual({ ok: false, reason: 'replay' });
  });

  it('refuses a body that was changed after signing, even by one byte', async () => {
    expect(await send({ rawBody: `${body} ` })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('refuses the same body on another route: the route is part of what is signed', async () => {
    expect(await send({ route: '/v1/ingest/other' })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('refuses a timestamp changed after signing', async () => {
    expect(await send({ timestamp: String(nowSeconds + 1) })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('refuses a message older or newer than the window, even if the signature is right', async () => {
    const old = nowSeconds - 301;
    expect(await send({ timestamp: String(old), signature: signWebhook(secret, route, old, body) })).toEqual({
      ok: false,
      reason: 'stale',
    });
    const future = nowSeconds + 301;
    expect(await send({ timestamp: String(future), signature: signWebhook(secret, route, future, body) })).toEqual({
      ok: false,
      reason: 'stale',
    });
    const edge = nowSeconds - 300;
    expect(await send({ timestamp: String(edge), signature: signWebhook(secret, route, edge, body) })).toEqual({
      ok: true,
    });
  });

  it.each(['', 'abc', '1.5', '-5', '1e9', '12345678901234'])('refuses the timestamp %j', async (timestamp) => {
    expect(await send({ timestamp })).toMatchObject({ ok: false });
  });

  it('needs both headers', async () => {
    expect(await send({ timestamp: undefined })).toEqual({ ok: false, reason: 'missing_headers' });
    expect(await send({ signature: undefined })).toEqual({ ok: false, reason: 'missing_headers' });
  });

  it('accepts the previous secret during a rotation, and not one that was never configured', async () => {
    const signedWithOld = signWebhook(oldSecret, route, nowSeconds, body);
    expect(await send({ secrets: [secret, oldSecret], signature: signedWithOld })).toEqual({ ok: true });
    expect(await send({ secrets: [secret], signature: signedWithOld })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('does not remember a message that failed to authenticate, so junk cannot burn a real one', async () => {
    const replay = memoryReplay();
    const real = signWebhook(secret, route, nowSeconds, body);
    expect(await send({ signature: 'f'.repeat(64) }, replay)).toEqual({ ok: false, reason: 'bad_signature' });
    expect(await send({ signature: real }, replay)).toEqual({ ok: true });
  });
});
