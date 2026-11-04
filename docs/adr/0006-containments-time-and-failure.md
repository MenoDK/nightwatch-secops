# ADR 0006: Containments keep their deadlines in the application's clock, and "Redis is down" is a setting

Status: Accepted

## Context
Blocks, the lockdown and suspensions live in Redis because they have to be fast and shared. Two questions come with that: what
does "for an hour" mean when a demo (or a test) moves time, and what should happen when the store cannot be read?

## Decision
- **The value holds the deadline**, as epoch milliseconds in the injected clock's time (`{until, reason, by, at}`). Redis's own
  expiry is set a minute later and is only the garbage collector; the deadline decides. A test that advances the clock sees
  exactly what a real wait would show, and so does the lab.
- **Time is an input.** Every rule that depends on "now" takes a `Clock`. The lab uses an `OffsetClock` that can only move
  forward: going back would resurrect expired links.
- **Addresses are keyed in one spelling** (`::ffff:203.0.113.9` and `203.0.113.9` are one entry; IPv6 in RFC 5952 form).
- **When the store cannot be read, a setting decides:** `FAIL_CLOSED=false` lets traffic through (a monitoring outage does not
  become a customer outage), `FAIL_CLOSED=true` refuses it (a security tool that fails open is a door left unlocked). The answer
  carries `degraded: true`, so the caller can tell a verdict from a guess. Neither is right everywhere, which is why it is written down.
- Redis is append-only in the Compose file: a lockdown that evaporates when Redis reboots is not a lockdown.
- The SOC's own API is never behind its lockdown. A lockdown that locks the people who would lift it is a self-inflicted outage.

## Rejected alternatives
- **Trust Redis TTLs.** Simple, and impossible to test without sleeping or to demonstrate with a movable clock.
- **Keep blocks in PostgreSQL.** Durable, and a query on every request.
- **Fail open silently.** The default of most code, chosen by nobody.

## Consequences
- (+) `test/controls.test.ts` covers expiry by the clock with Redis still holding the key, address normalisation, and both failure
  policies against a store that throws, without a server.
- (−) The deadline is trusted as stored: whoever can write to Redis can edit it. Redis is inside the trust boundary here.
