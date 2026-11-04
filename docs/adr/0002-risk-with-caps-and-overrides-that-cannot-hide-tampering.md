# ADR 0002: Score risk with a capped weights table, and let operators override noise but never tampering

Status: Accepted

## Context
A single number ("how worried should I be?") is useful on a dashboard and dangerous in a rule: it hides what it counts.
Two failure modes show up in every scoring scheme. One noisy signal drowns the rest (a hundred typos at a login form read
as an attack), and the people who handle false positives learn to wave things away, which an intruder with a stolen
operator session will do first.

## Decision
- **A table, not code.** `SIGNALS` maps each event kind to `{unit, cap, label}`. Each event is worth `unit` points and a
  kind can never contribute more than `cap`. The weights are a contract in one file, readable in a review.
- **Caps are the point.** Failed sign-ins are 1.5 each up to 15: a hundred of them are worth little more than ten. A touched
  honeytoken is 40 on its own, because no legitimate user ever touches one.
- **Levels.** `calm` < 25 ≤ `elevated` < 50 ≤ `high` < 75 ≤ `critical`.
- **Overrides sit beside the evidence.** An operator can reclassify an event as benign; the audit row is never touched.
  `scoreWithoutOverrides` is returned next to `score`, so the number nobody can argue down is always visible.
- **Some events cannot be overridden** (`NON_OVERRIDABLE`): `audit_integrity_failed`, `honeytoken_trip`, `data_canary_trip`,
  `step_up_lockout`. They are the evidence of tampering, not alerts about it. The refusal is applied in the score *and* in
  the route that creates the override, so it holds even if a client skips the UI.
- **One override per event**, enforced by a partial unique index and `INSERT … ON CONFLICT DO NOTHING`, so two operators
  clicking together cannot both win.
- Creating an override takes the human gate ([ADR 0003](0003-the-human-gate.md)) and is itself written to the chain.

## Rejected alternatives
- **A rolling average or a model.** Better at ranking, worse at being argued with. The reason for a number must be
  something a person can check against the events behind it.
- **No cap, "more is worse".** Rewards the noisy attacker and punishes the typist.
- **Deleting false positives.** Destroys the evidence that one was ever there. An override is an opinion with a name on it.
- **Letting an admin override anything.** The one who needs to is the one who should not be able to.

## Consequences
- (+) Tested as a pure function (`test/risk.test.ts`: caps, normalisation of fractional and hostile counts, the refusal list)
  and against the database (`test/risk-query.test.ts`: the window, overrides, the race, the refusals).
- (−) The weights are judgement. They are explicit so that disagreeing with them is a diff, not an investigation.
