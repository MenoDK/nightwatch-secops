#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
/**
 * Breaks each critical rule on purpose, one at a time, and runs the test suite. A mutant that the suite does not notice
 * means a rule that nothing is guarding, so the script exits non-zero when any mutant survives (or cannot be applied).
 *
 *   DATABASE_URL=postgresql://... REDIS_URL=redis://... node scripts/mutation-check.mjs [name fragment...]
 *
 * Each source file is restored afterwards, also on Ctrl-C.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
if (!process.env.DATABASE_URL || !process.env.REDIS_URL) {
  console.error('DATABASE_URL and REDIS_URL are required: most of the rules under test live in the two stores.');
  process.exit(2);
}

/** [name, file, exact text to find, replacement] */
const MUTANTS = [
  // --- the audit chain
  [
    'chain: a tail cut off is not noticed',
    'src/lib/audit-chain.ts',
    'Number(stored.last_seq) === previousSeq &&',
    'true &&',
  ],
  [
    'chain: a missing row is not named as a gap',
    'src/lib/audit-chain.ts',
    'if (entry.seq !== previousSeq + 1)',
    'if (false as boolean)',
  ],
  [
    'chain: an edited row is not noticed',
    'src/lib/audit-chain.ts',
    'if (!safeEqual(entry.rowHash, rowHashOf(this.secret, entry)))',
    'if (false as boolean)',
  ],
  ['chain: writers are not serialised', 'src/lib/audit-chain.ts', "WHERE id = 1 FOR UPDATE'", "WHERE id = 1'"],
  [
    'chain: the receipt is not compared',
    'src/lib/audit-chain.ts',
    'if (seen === undefined || !safeEqual(seen, options.anchor.hash))',
    'if (false as boolean)',
  ],
  [
    'chain: any receipt is accepted as ours',
    'src/lib/audit-chain.ts',
    'return safeEqual(anchor.mac, hmacHex(',
    'return true || safeEqual(anchor.mac, hmacHex(',
  ],
  // --- containments
  [
    'controls: a block never expires by the clock',
    'src/lib/controls.ts',
    'if (found.until !== null && found.until <= clock.now().getTime())',
    'if (false as boolean)',
  ],
  [
    'controls: a dead store fails open when told to fail closed',
    'src/lib/controls.ts',
    'return { active: failClosed, degraded: true };',
    'return { active: false, degraded: true };',
  ],
  // --- watching
  [
    'watch: one alarm per attack becomes one per attempt',
    'src/lib/watch.ts',
    'raised = await this.kv.claim(flag, this.limits.windowSeconds);',
    'raised = true;',
  ],
  [
    'step-up: a code can be used twice',
    'src/lib/step-up.ts',
    "!(await this.kv.claim(this.kv.key('stepup', 'used', operator, String(match.step)), 150))",
    'false as boolean',
  ],
  [
    'step-up: a wrong code is not counted',
    'src/lib/step-up.ts',
    'const fails = await this.kv.slide(',
    'const fails = 0 * (await this.kv.slide(',
  ],
  // --- the engine
  [
    'engine: a honey account needs a second attempt',
    'src/lib/engine.ts',
    'if (subject && this.d.config.honeyAccounts.includes(subject.toLowerCase())) {',
    'if (false as boolean) {',
  ],
  [
    'engine: a brute force on one account blocks an address',
    'src/lib/engine.ts',
    "if (alarm.pattern === 'one_address') {",
    'if (true as boolean) {',
  ],
  [
    'engine: a canary read is ignored',
    'src/lib/engine.ts',
    'if (id && this.d.config.canaryIds.includes(id)) {',
    'if (false as boolean) {',
  ],
  [
    'engine: travel is never checked on a request',
    'src/lib/engine.ts',
    "if (subject) await this.travel(subject, ip, base, out);\n        break;\n      }\n      case 'record_read'",
    "break;\n      }\n      case 'record_read'",
  ],
  // --- the guards
  [
    'ssrf: only the first resolved address is checked',
    'src/lib/guards/ssrf.ts',
    'const bad = resolved.find((address) => !isPublicAddress(address));',
    'const bad = isPublicAddress(first) ? undefined : first;',
  ],
  ['shield: a password in a url reaches the log', 'src/lib/shield.ts', "url.password = '';", ''],
  [
    'shield: strangers can fill the chain',
    'src/lib/shield.ts',
    'if (seen > this.noiseLimit) {',
    'if (false as boolean) {',
  ],
  // --- who may change the world
  ['gate: the network is not checked', 'src/lib/gate.ts', 'if (!ctx.isAdminIp(human.ip)) {', 'if (false as boolean) {'],
  [
    'gate: attempts are counted per label, not per operator seat',
    'src/lib/gate.ts',
    'ctx.stepUp.verify(BUCKET, human.code)',
    'ctx.stepUp.verify(human.label, human.code)',
  ],
  [
    'approval: two operators can both execute',
    'src/alice/approval.ts',
    "WHERE id = $1 AND status = 'pending' RETURNING *`,\n    [id, ctx.clock.now(), gate.actor],",
    'WHERE id = $1 RETURNING *`,\n    [id, ctx.clock.now(), gate.actor],',
  ],
  [
    'overrides: the evidence of tampering can be talked away',
    'src/lib/risk-query.ts',
    'if (NON_OVERRIDABLE.has(action))',
    'if (false as boolean)',
  ],
  [
    'overrides: one event can be overridden twice',
    'src/lib/risk-query.ts',
    "ON CONFLICT (audit_seq) WHERE status = 'active' DO NOTHING RETURNING id",
    'RETURNING id',
  ],
  [
    'risk: the score honours an override on a trap',
    'src/lib/risk.ts',
    'NON_OVERRIDABLE.has(action) ? 0 :',
    'false ? 0 :',
  ],
  // --- the analyst
  [
    'analyst: a made-up target is believed',
    'src/alice/remote.ts',
    'if (!events.some((e) => e.ip !== null && normalizeIp(e.ip) === ip)) return null;',
    '',
  ],
  [
    'analyst: the operators’ network can be proposed for a block',
    'src/alice/remote.ts',
    'if (!ip || input.isAdminIp(ip) ||',
    'if (!ip ||',
  ],
  [
    'analyst: a no is forgotten',
    'src/alice/runner.ts',
    'return seen === undefined || d.evidence.some((seq) => seq > seen);',
    'return true;',
  ],
  // --- routes
  [
    'api: the API key is not required for reading',
    'src/lib/http.ts',
    'if (!ok) await reply.status(401)',
    'if (false as boolean) await reply.status(401)',
  ],
  ['api: a stranger can make the chain grow with a header', 'src/routes/support.ts', 'if (reply.sent) return;', ''],
  [
    'api: the lab’s address header works everywhere',
    'src/routes/support.ts',
    'if (ctx.config.labMode) {',
    'if (true as boolean) {',
  ],
  [
    'api: a broken chain raises an alarm on every poll',
    'src/routes/core.ts',
    "(await ctx.kv.claim(ctx.kv.key('integrity-alarm'), 300))",
    'true',
  ],
  [
    'guards: the evidence names the application, not the person it asked on behalf of',
    'src/routes/guards.ts',
    'ip: body.ip ?? request.caller.ip,',
    'ip: request.caller.ip,',
  ],
  [
    'ingest: a bad signature is accepted',
    'src/routes/ingest.ts',
    'if (!verdict.ok) return reply.status(401)',
    'if (false as boolean) return reply.status(401)',
  ],
];

const filters = process.argv.slice(2);
const selected = MUTANTS.filter(([name]) => filters.length === 0 || filters.some((f) => name.includes(f)));
const originals = new Map();
const restore = () => {
  for (const [file, text] of originals) writeFileSync(file, text);
  originals.clear();
};
process.on('SIGINT', () => {
  restore();
  process.exit(130);
});

const problems = [];
for (const [name, rel, find, replacement] of selected) {
  const file = new URL(`../${rel}`, import.meta.url).pathname;
  const source = readFileSync(file, 'utf8');
  if (!source.includes(find)) {
    console.log(`CANNOT APPLY  ${name}  (the code moved: update scripts/mutation-check.mjs)`);
    problems.push(name);
    continue;
  }
  originals.set(file, source);
  writeFileSync(file, source.replace(find, replacement));
  try {
    const run = spawnSync('npx', ['vitest', 'run', '--reporter=dot'], {
      cwd: root,
      encoding: 'utf8',
      timeout: 170_000,
    });
    const caught = run.status !== 0;
    console.log(`${caught ? 'caught   ' : 'SURVIVED '} ${name}`);
    if (!caught) problems.push(name);
  } finally {
    restore();
  }
}
console.log(
  `\n${selected.length - problems.length}/${selected.length} caught${problems.length ? `; not caught: ${problems.join('; ')}` : ''}`,
);
process.exit(problems.length ? 1 : 0);
