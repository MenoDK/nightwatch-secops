# Master checklist

_What_ and _when_. The _how_ lives in the code and tests, the _why_ in the [ADRs](adr/README.md).

| #   | Item                                                                             | Status  | Evidence                                                                                         |
| --- | -------------------------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------ |
| 1   | HMAC hash chain: edit, delete, cut-off and gap are named; head row; signed receipts | done | [ADR 0001](adr/0001-a-hash-chain-and-what-it-cannot-prove.md), `test/audit-chain.test.ts`        |
| 2   | Risk score with caps; overrides that cannot hide tampering                         | done    | [ADR 0002](adr/0002-risk-with-caps-and-overrides-that-cannot-hide-tampering.md), `test/risk-query.test.ts` |
| 3   | Human gate: operators' network, then a one-time code, one bucket, lockout by hand  | done    | [ADR 0003](adr/0003-the-human-gate.md), `test/step-up.test.ts`, `test/api-gate.test.ts`           |
| 4   | Guards: SSRF, redirect, signed webhook, prompt, client address; noise limiter      | done    | [ADR 0004](adr/0004-guards-and-the-noise-they-must-not-make.md), `test/shield.test.ts`            |
| 5   | Engine: stuffing, brute force, honeytoken, canary, impossible travel               | done    | `test/engine.test.ts`, `test/watch.test.ts`                                                       |
| 6   | Analyst proposes; evidence check; atomic approval; rejected is not re-proposed     | done    | [ADR 0005](adr/0005-the-analyst-proposes-and-never-acts.md), `test/api-alice.test.ts`             |
| 7   | Containments in the injected clock; `FAIL_CLOSED` for a dead Redis                 | done    | [ADR 0006](adr/0006-containments-time-and-failure.md), `test/controls.test.ts`                    |
| 8   | Signed ingest of log lines and scanner output                                      | done    | `test/api-ingest.test.ts`                                                                         |
| 9   | Lab mode, landing page and lab UI in 14 languages, refused in production            | done    | [ADR 0007](adr/0007-a-lab-mode-that-cannot-reach-production.md), `test/api-lab.test.ts`, `site/`  |
| 10  | Landing page tour recorded from the running code, with a drift test                | done    | `scripts/record-transcripts.ts`, `test/transcripts.test.ts`                                       |
| 11  | Mutation check of the critical rules                                               | done    | `scripts/mutation-check.mjs`, `make mutate`                                                       |
| 12  | Containers and health-gated compose                                                | done    | `Dockerfile`, `docker-compose.yml`                                                                |
| 13  | Browser tests with accessibility scans, against the real stack                     | done    | `e2e/`, `make e2e`                                                                                |
| 14  | CI workflow                                                                        | done    | `.github/workflows/ci.yml`: actionlint clean; green on GitHub on 2026-11-04 (six jobs)             |
| 15  | A seat per operator (own TOTP seed and lockout bucket)                             | todo    | README "Limitations", ADR 0003                                                                    |
| 16  | An "is this address blocked?" endpoint for integrators                             | todo    | README "Limitations"                                                                              |
| 17  | Receipts written to write-once storage                                             | todo    | ADR 0001                                                                                          |
| 18  | Key id on every row so the chain's signing key can rotate                          | todo    | ADR 0001                                                                                          |
| 19  | One chain per tenant                                                               | todo    | README "Limitations"                                                                              |
| 20  | The remote analyst tested against a real model                                     | todo    | README "Limitations"                                                                              |

Status is one of `todo`, `doing`, `done`, `written` (exists, not yet exercised where it will run), `dropped`.
