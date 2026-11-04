# Agent contract

Tool-neutral: what any engineer or coding agent needs to work here without asking.

## Commands

| Task                                                              | Command                                                                       |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Install                                                           | `make install`                                                                |
| Lint, types, tests                                                | `make check` (starts the PostgreSQL and Redis the tests use: `make stores`)   |
| Run the service with the lab on                                   | `make demo` (then http://localhost:8000); `make down` to stop                 |
| Browser tests and accessibility scans                             | `make e2e` (Playwright in a container, against the real stack)                |
| Break each critical rule on purpose and confirm a test notices    | `make mutate` (rewrites `src/` while it runs: do not edit `src/` or `test/` meanwhile) |
| Re-record the landing page's sample output                        | `make transcripts`                                                            |
| Documentation guards                                              | `docsguard check`                                                             |

## Definition of done

1. A test covers it and fails without the change; a security rule gets an adversarial test (try to break it) and, if it
   is one of the critical rules, a mutant in `scripts/mutation-check.mjs`.
2. `make check` passes and you can quote its output; anything that touches SQL or Redis runs against the real thing.
3. An ADR exists for any decision a newcomer would have to reverse-engineer, with the rejected alternatives.
4. `docs/HANDOFF.md` carries the numbers that were printed, not the ones that were expected.

## Boundaries

- Do not weaken the hash chain, the human gate, the guards' parsing or the analyst's evidence check to make a test pass.
- Ask before adding a dependency or changing a public route, an error code or a configuration key.
- Anything outside the task goes into `docs/CHECKLIST.md`, not into this change.

## Reporting

Say what happened, not what was expected. A failed test, a skipped check or an unverified claim goes in the report as it is.
