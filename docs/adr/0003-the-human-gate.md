# ADR 0003: An API key can read and report; changing the world takes a person, on a known network, with a second factor

Status: Accepted

## Context
The protected application needs to push events in and read verdicts out, so it holds an API key. If that key could also
block addresses, lift a lockdown, suspend accounts or approve a proposal, then stealing it would be enough to switch the
defences off. The actions that matter most should not be reachable with the credential that is most likely to leak.

## Decision
- **Two classes of route.** With the API key: report events, read the chain, the score, the blocklist, the proposals; ask
  the guards a question; run an analysis. With the **human gate**: block or unblock, switch the lockdown on or off, suspend or
  release an account, create an override, approve a proposal.
- **The gate is two checks, in this order:** the caller's address must be inside `ADMIN_IPS` (the operators' network), then
  the request must carry a valid TOTP code (RFC 6238, `x-totp`).
- **The network is checked first.** Someone outside it cannot spend the operator's attempts at the code and lock them out.
  The refusal is evidence (`approval_denied`).
- **Wrong codes are counted in one bucket, not per `x-operator` label.** The label is a header the caller chooses; a
  lockout keyed on it is a lockout the attacker walks around by changing it. A test does exactly that.
- **A code works once** (replay marker per step), a code one step either side is accepted (clocks drift), and a malformed or
  missing code is a forgetful client, not a guess, so it costs nothing.
- **A lockout does not clear by itself.** A lockout that expires is a rate limit for the attacker. A person releases it (in
  the lab: a button; in production: `scripts/unlock-operator.mjs`, which needs access to Redis, not to the API).
- **Rejecting a proposal needs the network but not the code.** Saying no changes nothing in the world; making it as hard as
  saying yes would only teach operators to approve.
- Proxy headers are believed only from `TRUSTED_PROXIES`, read from the right; anything else is recorded as a spoof attempt
  (`header_spoof_attempt`), and only for callers who passed the API-key check, so a stranger cannot make the chain grow by
  sending a header.
- `ADMIN_IPS` is required in production (the settings validator refuses to start without it).

## Rejected alternatives
- **Roles on the API key.** Still one secret to steal per role, and no second factor.
- **A session cookie after a login form.** A better UX, and a login system is a project of its own. This repository
  protects *someone else's* application; accounts for the SOC's operators belong in a platform (see `bulkhead-saas`).
- **Per-operator TOTP seeds.** The right production shape, and it would turn the single bucket into one bucket per seed. The
  seam is one function (`authorizeHuman`).
- **Counting wrong codes per IP.** An attacker with many addresses gets many attempts.

## Consequences
- (+) `test/api-gate.test.ts` covers each branch, including "a stolen key can read everything and change nothing", the
  header-spoofing attempts and the label-switching lockout. Mutants remove the network check and the single bucket.
- (−) One shared seed means the audit trail knows who *said* they acted (`x-operator`), not who proved it. It is
  attribution, not authentication, and the code says so.
- (−) An operator on a phone network cannot approve. That is the trade being made.
