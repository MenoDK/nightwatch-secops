/**
 * Records the output shown in the landing page's tour by driving the real service (a Fastify app, a real PostgreSQL, a
 * real Redis) and writing what it answered. Nothing on that page is typed by hand: `test/transcripts.test.ts` records
 * again and fails when `site/transcripts.js` no longer matches, so the page cannot drift away from the code.
 *
 *   DATABASE_URL=postgresql://... REDIS_URL=redis://... npx tsx scripts/record-transcripts.ts
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { signWebhook } from '../src/lib/guards/webhook.js';
import { type AppWorld, OPERATOR_IP, TestClock, startApp } from '../test/harness.js';

type Reply = { statusCode: number; body: string };

const escapeHtml = (text: string): string =>
  text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

/**
 * What the landing page's tour shows. The kit inserts a transcript as HTML, so every character is escaped here and the
 * four classes it styles (`tok-dim` for the story, `tok-k` for a request, `tok-ok` and `tok-bad` for the answer) are
 * added around whole lines. A placeholder such as `<id-1>` therefore reaches the reader as text, not as a tag.
 */
class Tape {
  readonly #entries: { cls?: string; text: string }[] = [];
  say(text: string): void {
    if (this.#entries.length > 0) this.#entries.push({ text: '' });
    this.#entries.push({ cls: 'tok-dim', text: `# ${text}` });
  }
  call(request: string, reply: Reply, shown?: (json: any) => unknown): void {
    this.#entries.push({ cls: 'tok-k', text: `→ ${request}` });
    this.#entries.push({ cls: reply.statusCode < 400 ? 'tok-ok' : 'tok-bad', text: `← ${reply.statusCode}` });
    let body: unknown = reply.body;
    try {
      body = JSON.parse(reply.body);
    } catch {
      /* not JSON: keep the text */
    }
    const content = shown && typeof body === 'object' ? shown(body) : body;
    this.#entries.push({ text: typeof content === 'string' ? content : JSON.stringify(content, null, 2) });
  }
  raw(line: string): void {
    this.#entries.push({ text: line });
  }
  render(transform: (text: string) => string): string {
    return this.#entries
      .map(({ cls, text }) => {
        const shown = escapeHtml(transform(text));
        return cls ? `<span class="${cls}">${shown}</span>` : shown;
      })
      .join('\n');
  }
}

/** Ids and hashes change on every run; what they mean does not. Replace them, in order of appearance. */
function normaliser(): (text: string) => string {
  const seen = new Map<string, string>();
  return (text) =>
    text
      .replace(/[0-9a-f]{64}/g, '<hash>')
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, (id) => {
        if (id === '00000000-0000-4000-8000-000000000c01') return id; // the canary's id is a setting, not a secret
        if (!seen.has(id)) seen.set(id, `<id-${seen.size + 1}>`);
        return seen.get(id) ?? id;
      });
}

const ATTACKER = '198.51.100.200';
const OTHER = '203.0.113.50';
const CANARY = '00000000-0000-4000-8000-000000000c01';

const pick = (source: Record<string, unknown>, ...keys: string[]) =>
  Object.fromEntries(keys.filter((k) => k in source).map((k) => [k, source[k]]));

async function newWorld(): Promise<{ w: AppWorld; clock: TestClock }> {
  const clock = new TestClock();
  // Fixed settings, so what is recorded does not depend on the machine it was recorded on.
  const w = await startApp(
    {
      LAB_MODE: 'true',
      LOGIN_FAIL_MAX: '5',
      ADMIN_IPS: '10.20.0.0/16',
      HONEY_ACCOUNTS: 'backup-admin@example.test',
      CANARY_IDS: CANARY,
    },
    { clock },
  );
  return { w, clock };
}

const wrongCode = (w: AppWorld): string => {
  const valid = new Set([-1, 0, 1].map((n) => w.code(n)));
  for (let n = 0; n < 1000; n++) {
    const candidate = String(n).padStart(6, '0');
    if (!valid.has(candidate)) return candidate;
  }
  throw new Error('unreachable');
};

async function chainTab(): Promise<string> {
  const { w } = await newWorld();
  const tape = new Tape();
  try {
    const events = async () => {
      for (const [ip, subject] of [
        ['203.0.113.9', 'ana@example.test'],
        ['203.0.113.9', 'bob@example.test'],
        ['203.0.113.10', 'ana@example.test'],
      ] as const) {
        await w.call('POST', '/v1/events', { body: { kind: 'login_failed', ip, subject } });
      }
    };
    tape.say(
      'Three failed sign-ins are reported. The service writes each one down; every row carries a keyed hash of the row before it.',
    );
    await events();
    tape.call('GET /v1/audit/verify', await w.call('GET', '/v1/audit/verify'), (j) =>
      pick(j, 'ok', 'checked', 'problem'),
    );

    tape.say('Someone with access to the database edits one address.');
    tape.raw("UPDATE audit_chain SET ip = '198.51.100.250' WHERE seq = 2;");
    await w.sql("UPDATE audit_chain SET ip = '198.51.100.250' WHERE seq = 2");
    tape.call('GET /v1/audit/verify', await w.call('GET', '/v1/audit/verify'), (j) =>
      pick(j, 'ok', 'checked', 'problem', 'alarmed'),
    );

    tape.say('Worse: they delete a row, or cut the end off. Each leaves a different mark.');
    await w.reset();
    await events();
    await w.sql('DELETE FROM audit_chain WHERE seq = 2');
    tape.raw('DELETE FROM audit_chain WHERE seq = 2;');
    tape.call('GET /v1/audit/verify', await w.call('GET', '/v1/audit/verify'), (j) => pick(j, 'ok', 'problem'));
    await w.reset();
    await events();
    await w.sql('DELETE FROM audit_chain WHERE seq = 3');
    tape.raw('DELETE FROM audit_chain WHERE seq = 3;   -- the last row');
    tape.call('GET /v1/audit/verify', await w.call('GET', '/v1/audit/verify'), (j) => pick(j, 'ok', 'problem'));

    tape.say(
      'The worst case: they also hold the signing key. They edit row 2 and recompute every hash after it. A receipt was taken earlier and kept elsewhere.',
    );
    await w.reset();
    await events();
    const receipt = (await w.call('POST', '/v1/audit/anchor')).json();
    tape.call('POST /v1/audit/anchor   (kept outside the database)', await w.call('POST', '/v1/audit/anchor'), (j) =>
      pick(j, 'seq', 'hash'),
    );
    tape.call(
      'POST /v1/lab/tamper   {"mode":"rewrite","seq":2}',
      await w.call('POST', '/v1/lab/tamper', { body: { mode: 'rewrite', seq: 2 } }),
    );
    tape.say('On its own, the chain is consistent again: nothing inside the database can tell.');
    tape.call('GET /v1/audit/verify', await w.call('GET', '/v1/audit/verify'), (j) => pick(j, 'ok', 'checked'));
    tape.say('Against the receipt, it is not.');
    tape.call(
      'POST /v1/audit/verify   {"anchor": <the receipt>}',
      await w.call('POST', '/v1/audit/verify', { body: { anchor: receipt } }),
      (j) => pick(j, 'ok', 'problem', 'alarmed'),
    );
  } finally {
    await w.close();
  }
  return tape.render(normaliser());
}

async function trapsTab(): Promise<string> {
  const { w } = await newWorld();
  const tape = new Tape();
  const from = (ip: string) => ({ key: null as null, ip });
  try {
    tape.say('An ordinary visit to the demo application.');
    tape.call(`GET /v1/demo/resource   (from ${OTHER})`, await w.call('GET', '/v1/demo/resource', from(OTHER)), (j) =>
      pick(j, 'ok', 'resource'),
    );

    tape.say(
      'Someone signs in as an account no customer has ever heard of. Nothing legitimate does that, so once is enough.',
    );
    tape.call(
      `POST /v1/demo/login   (${ATTACKER}, backup-admin@example.test)`,
      await w.call('POST', '/v1/demo/login', {
        ...from(ATTACKER),
        body: { email: 'backup-admin@example.test', password: 'x' },
      }),
      (j) => ({ ok: j.ok, notes: j.lab.notes }),
    );
    tape.say('The same address, a moment later. A different address is untouched.');
    tape.call(`GET /v1/demo/resource   (from ${ATTACKER})`, await w.call('GET', '/v1/demo/resource', from(ATTACKER)));
    tape.call(`GET /v1/demo/resource   (from ${OTHER})`, await w.call('GET', '/v1/demo/resource', from(OTHER)), (j) =>
      pick(j, 'ok'),
    );

    tape.say(
      'A canary: a record that looks like any other and that no screen links to. Reading it answers like any record, and then the door closes.',
    );
    tape.call(
      `GET /v1/demo/records/${CANARY}   (from 203.0.113.89)`,
      await w.call('GET', `/v1/demo/records/${CANARY}`, from('203.0.113.89')),
      (j) => pick(j, 'id', 'note'),
    );
    tape.call(
      'GET /v1/demo/resource   (from 203.0.113.89)',
      await w.call('GET', '/v1/demo/resource', from('203.0.113.89')),
      (j) => j.error,
    );

    tape.say('What the audit chain recorded, oldest first.');
    const trail = (await w.ctx.chain.recent({ limit: 20 }))
      .reverse()
      .map((e) => `${e.action}${e.ip ? `  ${e.ip}` : ''}`);
    tape.raw(trail.join('\n'));
  } finally {
    await w.close();
  }
  return tape.render(normaliser());
}

async function gateTab(): Promise<string> {
  const { w } = await newWorld();
  const tape = new Tape();
  const block = (over: Parameters<AppWorld['call']>[2] = {}) =>
    w.call('POST', '/v1/blocklist', { body: { ip: '203.0.113.99', seconds: 600, reason: 'drill' }, ...over });
  const errorOf = (j: any) => j.error;
  try {
    tape.say('The API key can report and read. It cannot change what the application lets through.');
    tape.call(
      `POST /v1/blocklist   (API key, from the operators' network, no code)`,
      await block({ ip: OPERATOR_IP }),
      errorOf,
    );

    tape.say(
      'From the internet, even with a correct code: refused before the code is looked at, and the attempt is evidence.',
    );
    tape.call('POST /v1/blocklist   (API key + code, from 203.0.113.200)', await block({ code: w.code() }), errorOf);

    tape.say("From the operators' network with a correct code.");
    tape.call(
      'POST /v1/blocklist   (API key + code, from 10.20.1.2)',
      await block({ ip: OPERATOR_IP, code: w.code() }),
    );

    tape.say('A code works once. The replay is refused, and it counts as the first of three failed attempts.');
    tape.call('POST /v1/blocklist   (the same code again)', await block({ ip: OPERATOR_IP, code: w.code() }), errorOf);

    tape.say(
      'Wrong codes are counted too. The third failure locks the operator out, and calling oneself something else does not help.',
    );
    tape.call('POST /v1/blocklist   (wrong code)', await block({ ip: OPERATOR_IP, code: wrongCode(w) }), errorOf);
    tape.call('POST /v1/blocklist   (wrong code)', await block({ ip: OPERATOR_IP, code: wrongCode(w) }), errorOf);
    tape.call(
      'POST /v1/blocklist   (a correct code, x-operator: someone-new)',
      await block({ ip: OPERATOR_IP, code: w.code(1), headers: { 'x-operator': 'someone-new' } }),
      errorOf,
    );
    tape.say(
      'Only a person with access to the infrastructure releases it: pnpm unlock, which talks to Redis and not to this API.',
    );
  } finally {
    await w.close();
  }
  return tape.render(normaliser());
}

async function guardsTab(): Promise<string> {
  const { w, clock } = await newWorld();
  const tape = new Tape();
  const url = async (target: string, note?: string) =>
    tape.call(
      `POST /v1/guards/url   ${note ?? target}`,
      await w.call('POST', '/v1/guards/url', { body: { url: target, ip: ATTACKER } }),
      (j) => pick(j, 'ok', 'reason', 'detail', 'address'),
    );
  const redirect = async (target: string) =>
    tape.call(
      `POST /v1/guards/redirect   ${target}`,
      await w.call('POST', '/v1/guards/redirect', { body: { target, ip: ATTACKER } }),
      (j) => pick(j, 'ok', 'reason', 'url'),
    );
  try {
    tape.say('May the server fetch this? The rule is applied to what the address parses to, not to how it is written.');
    await url('https://public.example.test/hook');
    await url('http://169.254.169.254/latest/meta-data/', 'the cloud metadata address');
    await url('http://2130706433/', 'an address written as one integer');
    await url('http://[::ffff:7f00:1]/', '127.0.0.1 inside an IPv6 address');
    await url('https://rebinding.example.test/', 'a name with one public record and one private one');

    tape.say('Where may a “return to” link send the visitor?');
    await redirect('/dashboard?tab=1');
    await redirect('//evil.example.test/login');
    await redirect('https://app.example.test@evil.example.test/');
    await redirect('/\\evil.example.test');

    tape.say('A signed delivery from a log shipper. The signature covers the time, the route and the exact bytes.');
    const raw = JSON.stringify({ lines: [] });
    const ts = Math.floor(clock.now().getTime() / 1000);
    const secret = w.config.webhookSecrets[0] as string;
    const deliver = (signature: string, label: string) =>
      w
        .call('POST', '/v1/ingest/host-log', {
          key: null,
          body: raw,
          headers: { 'content-type': 'application/json', 'x-nw-timestamp': String(ts), 'x-nw-signature': signature },
        })
        .then((reply) =>
          tape.call(`POST /v1/ingest/host-log   (${label})`, reply, (j) => j.error ?? pick(j, 'accepted', 'items')),
        );
    await deliver(signWebhook(secret, '/v1/ingest/host-log', ts, raw), 'signed');
    await deliver(signWebhook(secret, '/v1/ingest/host-log', ts, raw), 'the same request captured and sent again');
    await deliver(signWebhook(secret, '/v1/ingest/dependency-scan', ts, raw), 'signed for another route');

    tape.say(
      'What was recorded, oldest first. A typo or a name that does not exist would have been recorded as nothing.',
    );
    const trail = (await w.ctx.chain.recent({ limit: 30 }))
      .reverse()
      .map((e) => `${e.action}${e.ip ? `  ${e.ip}` : ''}`);
    tape.raw(trail.join('\n'));
  } finally {
    await w.close();
  }
  return tape.render(normaliser());
}

async function analystTab(): Promise<string> {
  const { w } = await newWorld();
  const tape = new Tape();
  try {
    tape.say('Four requests from one address that try to make the server fetch things it should not.');
    for (const target of [
      'http://169.254.169.254/',
      'http://10.0.0.5/admin',
      'http://127.0.0.1:8080/',
      'http://[::1]/',
    ]) {
      await w.call('POST', '/v1/guards/url', { body: { url: target, ip: ATTACKER } });
    }
    tape.raw(`ssrf_attempt × 4 from ${ATTACKER}`);

    tape.say('The analyst reads the evidence and proposes. It changes nothing.');
    const analysis = await w.call('POST', '/v1/alice/analyze');
    tape.call('POST /v1/alice/analyze', analysis, (j) => ({
      source: j.source,
      created: j.created.map((p: any) => pick(p, 'kind', 'target', 'severity', 'rationale', 'evidence', 'status')),
    }));
    tape.call(
      `GET /v1/demo/resource   (from ${ATTACKER}, still allowed)`,
      await w.call('GET', '/v1/demo/resource', { key: null, ip: ATTACKER }),
      (j) => pick(j, 'ok'),
    );

    tape.say('A person approves: from the operators’ network, with a code from the authenticator.');
    const id = analysis.json().created[0].id as string;
    tape.call(
      'POST /v1/alice/proposals/<id>/approve   (from 10.20.1.2, x-totp)',
      await w.call('POST', `/v1/alice/proposals/${id}/approve`, {
        ip: OPERATOR_IP,
        code: w.code(),
        headers: { 'x-operator': 'dana' },
      }),
      (j) => ({
        status: j.proposal.status,
        kind: j.proposal.kind,
        target: j.proposal.target,
        decidedBy: j.proposal.decidedBy,
      }),
    );
    tape.call(
      `GET /v1/demo/resource   (from ${ATTACKER})`,
      await w.call('GET', '/v1/demo/resource', { key: null, ip: ATTACKER }),
      (j) => j.error,
    );
    tape.say('Approving it again, or by someone else a moment later, finds it already decided.');
    tape.call(
      'POST /v1/alice/proposals/<id>/approve   (again)',
      await w.call('POST', `/v1/alice/proposals/${id}/approve`, { ip: OPERATOR_IP, code: w.code(1) }),
      (j) => j.error,
    );

    tape.say('The trail of the decision, oldest first.');
    const trail = (await w.ctx.chain.recent({ limit: 30 }))
      .reverse()
      .map((e) => `${e.action}${e.actor && !['shield', 'engine'].includes(e.actor) ? `  (${e.actor})` : ''}`);
    tape.raw(trail.join('\n'));
  } finally {
    await w.close();
  }
  return tape.render(normaliser());
}

export async function record(): Promise<Record<string, string>> {
  return {
    chain: await chainTab(),
    traps: await trapsTab(),
    gate: await gateTab(),
    guards: await guardsTab(),
    analyst: await analystTab(),
  };
}

export function render(tabs: Record<string, string>): string {
  return `/* Recorded from the running service by scripts/record-transcripts.ts. Do not edit: a test re-records and compares. */\nwindow.TRANSCRIPTS = ${JSON.stringify(tabs, null, 2)};\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const target = fileURLToPath(new URL('../site/transcripts.js', import.meta.url));
  writeFileSync(target, render(await record()));
  console.log(`wrote ${target}`);
}
