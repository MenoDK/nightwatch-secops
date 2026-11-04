# nightwatch-secops

A security-operations engine for web applications: a hash-chained audit log that notices when it is edited, traps and
guards, a risk score with caps, and an analyst that proposes while a person with a second factor decides. Node 22,
TypeScript (strict), Fastify 5, PostgreSQL 16, Redis 7, no ORM.

## Start here

- Map of every document: [docs/00-READ-FIRST.md](docs/00-READ-FIRST.md). Open a document only when the map says to.
- Resuming work: `docs/HANDOFF.md` first; rewrite it before you stop.
- Commands and definition of done: @AGENTS.md

## Layout

- `src/lib/`: the building blocks, each small and testable alone: `audit-chain`, `risk`, `engine`, `controls`, `watch`,
  `step-up`, `gate`, `shield`, `guards/` (SSRF, redirect, webhook, prompt, client address), `net`, `geo`, `totp`.
- `src/alice/`: the analyst. It reads the audit rows and proposes; `approval.ts` is the only place a proposal becomes a change.
- `src/routes/`: the HTTP surface. `src/lab/` is lab mode, off by default and refused in production (ADR 0007).
- `src/context.ts` builds everything once; `src/config.ts` is the only reader of the environment.
- `site/`: landing page and lab UI, plain JS and CSS served when `SITE_DIR` is set. `e2e/`: Playwright tests.
- `scripts/record-transcripts.ts` writes `site/transcripts.js` from the running code; `scripts/mutation-check.mjs` breaks the rules on purpose.

## Rules that apply to every task

1. **The chain's hash covers the previous row's hash, and appends lock the head row.** Do not add a write path that skips
   `AuditChain.appendIn`. See ADR 0001.
2. **Tampering is never an override target.** `audit_integrity_failed`, `honeytoken_trip`, `data_canary_trip` and
   `step_up_lockout` cannot be reclassified by anyone. See ADR 0002.
3. **An API key reads and reports; changing the world goes through `authorizeHuman`**: the operators' network first, then
   the code, counted in one bucket whatever the caller calls themselves. See ADR 0003.
4. **Guards decide on what the input parses to**, and typos (`invalid_url`, `unresolvable`) are not recorded. See ADR 0004.
5. **The analyst only proposes.** It never receives free text from logs, a draft must cite audit rows that exist, and
   approval is an atomic claim. See ADR 0005.
6. **Deadlines are stored in the injected clock's time.** Never read `Date.now()` for a containment. See ADR 0006.
7. **Lab mode never reaches production.** The settings validator refuses it; do not add another way in. See ADR 0007.
8. **Tests build their own secrets at run time** and use fictitious data only; addresses come from RFC 5737 ranges.
9. **The site loads nothing from another origin** and keeps inline script and style out (strict CSP); `make e2e` checks it.
10. **Docs are code.** A new document is added to the map in the same commit; `docsguard check` must pass.

Advice versus enforcement: this file is advice. If `docsguard` is installed, `.claude/settings.json` turns the key rules
into hooks (destructive git is refused, and so are writes to secrets and keys).
