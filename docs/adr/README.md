# Architecture decision records

Each record states the problem, what was chosen, **what was rejected and why**, and the cost that was accepted.

| # | Decision |
|---|----------|
| [0001](0001-a-hash-chain-and-what-it-cannot-prove.md) | Chain the audit log with an HMAC, and say plainly what that does and does not prove |
| [0002](0002-risk-with-caps-and-overrides-that-cannot-hide-tampering.md) | Score risk with a capped weights table; overrides for noise, never for tampering |
| [0003](0003-the-human-gate.md) | An API key can read and report; changing the world takes a person, a network and a second factor |
| [0004](0004-guards-and-the-noise-they-must-not-make.md) | Guards that decide on what an input parses to, and that cannot be used to fill the log |
| [0005](0005-the-analyst-proposes-and-never-acts.md) | The analyst proposes; it never acts, and nothing it says is believed without the evidence |
| [0006](0006-containments-time-and-failure.md) | Containments keep their deadlines in the application's clock; "Redis is down" is a setting |
| [0007](0007-a-lab-mode-that-cannot-reach-production.md) | A lab that makes defence visible and cannot be switched on in production |

A record is never rewritten to hide a reversal: a new record supersedes it and the old one says so
(`Superseded by: ADR NNNN`). Template and rules: the `adr` skill in `.claude/skills/adr/`.
