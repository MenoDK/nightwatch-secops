# ADR 0001: Chain the audit log with an HMAC, and say plainly what that does and does not prove

Status: Accepted

## Context
After a break-in the first question is "what did they do, and can I trust the log that says so?". An audit table in the
same database as everything else is the first thing an intruder with database access edits. The log has to make editing it
*noticeable*, and the design has to be honest about the point where noticing stops being possible.

## Decision
- Every row stores `row_hash = HMAC-SHA256(key, canonical(row))`, and the canonical form **includes the previous row's
  hash**. Change any field of any row and its hash no longer matches; remove or reorder rows and the next row no longer
  points at what is there.
- The canonical form is a **JSON array** (`[seq, id, at, actor, action, subject, ip, user_agent, metadata, prev_hash]`) with
  keys sorted inside objects. A string joined with `|` lets `"a|b","c"` and `"a","b|c"` collide.
- `seq` is assigned as **previous + 1 under a row lock** (`SELECT … FROM chain_head FOR UPDATE`), not by a sequence. A
  sequence skips numbers when a transaction rolls back; here a missing number is *evidence*, so there must be none that
  are innocent. A change and its audit row commit or roll back together (`appendIn(client, …)`).
- A one-row table, `chain_head`, remembers where the chain ends. Verification compares it with the table. This is what
  catches **rows cut off the end**, which no hash can show: a shorter chain is still a valid chain.
- `verify()` reports the first thing wrong, by name: `row_hash_mismatch`, `prev_hash_mismatch`, `seq_gap`,
  `head_mismatch`, `anchor_mismatch`.
- **Receipts.** `POST /v1/audit/anchor` returns `{seq, hash, at, mac}`, signed with the same key. Kept somewhere the
  database's owner cannot write (a ticket, a mailbox, a bucket with object lock), it is what exposes a rewrite. A receipt
  this service did not sign is refused (`anchor_not_ours`), so a forged one cannot "prove" a chain intact.
- A chain that fails verification is itself an event (`audit_integrity_failed`), written once per five minutes so that
  polling a broken chain does not fill it. It is **not overridable** in the risk score ([ADR 0002](0002-risk-with-caps-and-overrides-that-cannot-hide-tampering.md)).

## What it proves, and what it does not
| An intruder who can… | Is… |
| --- | --- |
| edit, delete or reorder rows, without the key | caught by `verify()` |
| cut the tail off | caught by the head row |
| empty the table | caught by the head row (`last_seq` is no longer 0) |
| edit the database **and** hold `AUDIT_CHAIN_SECRET` | **not caught by the chain alone**: they can recompute every hash and the head. Caught only by a receipt taken earlier (`anchor_mismatch`) |
| edit the database, hold the key **and** the receipts | not caught. A witness the attacker cannot write to is the whole requirement |

The lab has a button for the fourth row (`rewrite`): the chain verifies on its own and fails against the receipt.

## Rejected alternatives
- **A plain hash chain (SHA-256, no key).** An intruder can recompute it. HMAC with a key that is not in the database
  forces them to find the key as well.
- **Hash only the row, not the previous hash.** Rows can then be removed or reordered undetected.
- **A database sequence for `seq`.** Gaps from rollbacks are indistinguishable from deletions.
- **Triggers that forbid `UPDATE`/`DELETE`.** Worth having, and cheap, but an intruder with owner rights drops the trigger.
  It is defence in depth, not a substitute for being able to *detect*.
- **Anchoring on a public blockchain or a transparency log.** Strong, and far more than a demo needs; the receipt format
  would not change if one were added.
- **Write-once storage only.** The right production answer for the receipts, and an infrastructure choice rather than code.

## Consequences
- (+) Every kind of damage above has a test that causes it and a mutant that removes the check (`test/audit-chain.test.ts`,
  `make mutate`). One mutant ("a tail cut off is not noticed") survived the first version of the tests and found a real gap:
  an *emptied* table was not caught because the hash comparison is skipped for an empty chain. It has its own test now.
- (−) Appends are serialised by the head lock. Throughput is one chain, one writer at a time; fine for security events,
  wrong for a request log. Sharding by tenant is the way out and is listed under "Not built yet".
- (−) The key is a single point of trust. Rotation (a key id on each row) is not built.
