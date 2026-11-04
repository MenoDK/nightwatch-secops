# Handoff

Updated: 2026-11-04

Rewritten at the end of every session. A fresh session must be able to resume from disk alone.

## 1. What is live

Nothing is deployed. `make demo` runs the stack locally (the service with the site on :8000, one PostgreSQL, one Redis)
with the lab on. Plain `docker compose up` without `LAB_MODE`/`SITE_DIR` would run the service as it would run for real,
and the application refuses to start with `LAB_MODE=true` and `APP_ENV=production`.

## 2. Where we stopped

The service (audit chain, risk engine, human gate, guards, analyst), the landing page and lab UI (`site/`, six lab tabs,
14 languages), the browser tests (`e2e/`), the mutation check, delivery files and documentation are complete and
verified; the numbers are in section 8. Open items are in the checklist.

## 3. What the owner does now

Push to GitHub and enable Actions: the workflow in `.github/workflows/ci.yml` is linted but had not run there when this
was written. Translations of the landing page were written by the assistant (machine quality); ask a native speaker to read
Hindi, Bengali, Urdu and Arabic before the repository is shown to anyone who reads them.

## 4. Deadlines

None.

## 5. What NOT to do

- Do not make the audit chain depend on anything but what is in the row and the previous hash, and do not claim it proves more than it does: a full rewrite with the key is only exposed by a receipt kept elsewhere: [ADR 0001](adr/0001-a-hash-chain-and-what-it-cannot-prove.md).
- Do not let an event that records tampering be reclassified or overridden, not even by an administrator: [ADR 0002](adr/0002-risk-with-caps-and-overrides-that-cannot-hide-tampering.md).
- Do not count wrong codes per label or per address: one `'soc'` bucket per operator seat, and the lockout does not clear itself; a person releases it: [ADR 0003](adr/0003-the-human-gate.md).
- Do not decide a guard on the text of an input (decide on what it parses to), and do not let a guard be a way for strangers to fill the log: [ADR 0004](adr/0004-guards-and-the-noise-they-must-not-make.md).
- Do not keep a containment's deadline in Redis's clock instead of the application's, and do not hard-code what happens when the store cannot be read (it is a setting): [ADR 0006](adr/0006-containments-time-and-failure.md).
- Do not give the analyst a path that acts: it proposes with the rows it cites, a person approves, and a made-up target is dropped: [ADR 0005](adr/0005-the-analyst-proposes-and-never-acts.md).
- Do not allow `LAB_MODE` with `APP_ENV=production`, and do not honour `x-lab-client-ip` anywhere else: it is what lets one browser play several people: [ADR 0007](adr/0007-a-lab-mode-that-cannot-reach-production.md).
- Do not edit `site/transcripts.js` by hand: `make transcripts` records it from the running code, and a test compares them.
- Do not add a script, font or stylesheet from another origin to `site/`; the Content Security Policy and the e2e suite refuse it.
- Do not hand-edit one language table to "fix" a string and leave the others: `site/i18n/<code>.js` mirrors `content.js` key for key (English is the source and the fallback), and `scripts/check-i18n.mjs` plus `e2e/tests/i18n.spec.ts` read the tables. Strings that quote the lab's English buttons stay English on purpose.
- Do not run another test suite against the same database while `scripts/mutation-check.mjs` runs: it rewrites `src/` in place and restores it, and it uses the dev database.
- Do not use a bare `ls` in this environment's shell (it is aliased and hangs); use `command ls`.
- Do not use port 16379 for the dev Redis: it belongs to another project on this machine; `compose.dev.yml` uses 16390 (PostgreSQL 15434).

## 6. Decisions

- Chain, risk, human gate, guards, analyst, containments, lab mode: [ADR 0001](adr/0001-a-hash-chain-and-what-it-cannot-prove.md) to [ADR 0007](adr/0007-a-lab-mode-that-cannot-reach-production.md).

## 7. Learned, not in the code

- `docker compose` passes `VAR=` (an empty string) for a variable that is declared in the file but unset on the host. The
  first Docker boot of this service crash-looped because `ANALYST_URL=""` failed `z.string().url()`. Optional settings now go
  through `optional()` in `src/config.ts`, and `test/config.test.ts` covers it. The same class of bug can exist in any repo that
  reads optional settings through a strict schema; only a real container boot finds it.
- `@fastify/static` is registered with `wildcard: false`, which lists the files in `site/` at boot. A file added while a native
  server is running 404s until it restarts. In Docker this does not matter, the image is rebuilt.
- A test that sets up concurrency can pass without the protection being there, because pooled connections open lazily and
  never overlap. Hold the lock yourself and assert on the outcome; then mutate the code to prove it (`approval: two operators
  can both execute` and `chain: writers are not serialised` do this).
- A mutant that only breaks syntax proves nothing. Each entry in `scripts/mutation-check.mjs` removes one rule and must fail
  one test; the script reports a mutant it can no longer apply instead of skipping it. An early run left one survivor (a tail
  cut off the chain went unnoticed by the suite) and the 33rd mutant (the evidence names the application instead of the
  person it asked on behalf of) was added later; the current run catches all 33.
- A TOTP code is good once. Approving twice with the same code answers 401 and that is correct; in the lab, press "Fill in
  the current code" or move the clock in the Time tab before the next change.
- The injection scenario also queues a second, weaker proposal (a block for the probing address) next to the one the
  Analyst tab is about; the impossible-travel scenario queues a suspension and a lockdown. Tests filter by target.
- In the browser tests `latest()` must look only at the visible tab panel and skip "Played:" cards, and a test that presses
  "Start over" must wait for its toast before continuing (`startOver()` in `e2e/tests/helpers.ts`), or it races the reset.
- `hadolint` flagged `USER node` (DL3066/DL3025 style findings) and a shell-form `HEALTHCHECK`; the Dockerfile uses
  `USER 1000:1000` and the exec form.
- `kit.css`, `kit.js` and `i18n/ui.js` (the page chrome in 14 languages) are shared with the other showcase repositories;
  the canonical copy is in the first one and `scripts/sync-kit.sh` copies it. Change a shared style there, not here.
- The browser container shares the app's network namespace so the page is `http://localhost:3000`, a secure context (the
  lab signs with WebCrypto) without a browser flag; it runs as the caller's user so files are deletable.
- The remote analyst (an OpenAI-compatible endpoint) has only been exercised against a fake endpoint in the tests, never
  against a real model.

## 8. Suite state

Measured on 2026-11-04: 476 tests in 23 files (pure logic and integration against a real PostgreSQL and Redis);
58 browser tests (`make e2e`, against the Compose stack: axe scans of the landing page and every lab tab in both themes, and
24 language tests), plus 4 screenshot tests that are skipped unless `SHOTS=1`; 33 of 33 mutants caught (`make mutate`);
`biome` and `tsc --strict` clean; `hadolint` and `actionlint` clean. The GitHub Actions workflow had not run when this was written.
