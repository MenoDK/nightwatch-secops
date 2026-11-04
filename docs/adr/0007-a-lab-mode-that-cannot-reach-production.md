# ADR 0007: A lab that makes defence visible, and cannot be switched on in production

Status: Accepted

## Context
A security engine is hard to judge from a diagram. The useful demonstration is one where a visitor attacks something and
watches the defences respond, which needs things that must never exist on a real deployment: a demo application to attack,
scripted attacks, the operator's TOTP seed on screen, a clock that moves, and a way to edit the audit chain behind its back.

## Decision
- `LAB_MODE=true` mounts `/v1/lab/*` (state, the TOTP code and seed, the clock, a step-up unlock, reset, tamper, scenarios) and
  `/v1/demo/*` (a stand-in application: sign-in, a resource, records, one of which is a canary). Without the flag the routes do
  not exist: they answer 404.
- **The settings validator refuses `LAB_MODE` when `APP_ENV=production`.** There is no second way in; a test pins that.
- The same validator refuses the default API key and an empty `ADMIN_IPS` in production.
- `x-lab-client-ip` (so one browser can play several callers) is honoured **only in lab mode**; a test checks it means nothing outside it.
- Scenarios run through the same engine and guards a real caller reaches. They use RFC 5737 documentation addresses.
- The lab's `tamper` plays an attacker with database access in four strengths: edit, delete, truncate, and `rewrite` - edit, then
  recompute every hash with the key - which is the case only a receipt can expose ([ADR 0001](0001-a-hash-chain-and-what-it-cannot-prove.md)).
- The demo application's only credential is `demo-password`. It protects a fictional app that exists to be attacked.
- The site is served with a strict content-security-policy: same-origin scripts and styles only, nothing inline.

## Rejected alternatives
- **A separate "demo" build.** Two builds drift; one build with a refused flag is the same code that is tested.
- **Screenshots and a video instead of a lab.** Easy to make, impossible to trust.
- **Hiding the seed and the clock behind a debug header.** Hidden is not absent.

## Consequences
- (+) `test/config.test.ts` pins the production refusals; `test/api-gate.test.ts` checks the lab routes do not exist without the flag;
  `test/api-lab.test.ts` plays every scenario and every tamper.
- (−) The demo deliberately shows what an operator's authenticator would hide. Anyone reading the lab should read this record first.
