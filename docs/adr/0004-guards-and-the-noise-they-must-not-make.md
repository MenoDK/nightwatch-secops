# ADR 0004: Guards that decide on what an input parses to, and that cannot be used to fill the log

Status: Accepted

## Context
Five attacks recur in web applications that fetch URLs, redirect visitors, accept webhooks, call language models and sit
behind proxies. Each has a well-known wrong fix (a regular expression on the text) and a right one (decide on what the input
*means* once parsed). Each guard also has a second job: a refusal is evidence that someone is probing.

## Decision
- **Outbound URLs (SSRF).** Parse with `new URL`, which already turns `2130706433`, `0x7f.1` and `017700000001` into
  `127.0.0.1`. Check scheme, userinfo and port. Resolve the name and require that **every** address it resolves to is public:
  a name with one public and one private record is how a check on the first is defeated at connect time on the second.
  Return the address to connect to, so the caller does not resolve again (DNS rebinding). Ranges are compared as numbers
  (IPv4-mapped IPv6 is judged as IPv4; NAT64 and documentation ranges are non-public), never as strings.
- **Redirects.** Only a path on this site, or an origin written down in advance. Browsers drop tabs and newlines and treat `\`
  as `/`, so control characters and backslashes are refused outright and `//host` is treated as leaving the site.
- **Webhooks.** `HMAC(secret, "<ts>.<route>.<raw body>")`: the route is in it, so a capture cannot be pointed at another
  endpoint. A skew window; the replay marker is claimed **only after the signature verifies**, so junk cannot fill the store or
  burn the id of a real message before it arrives. Several secrets verify at once (rotation). Every refusal is one generic 401.
- **Text for a language model.** Logs are written by attackers. Text addressed to the model (`ignore previous instructions`,
  fake tool markup, "reveal the system prompt") is refused outright and logged by *pattern name*, never by content; text with
  a secret in it is refused and logged by *kind*. See [ADR 0005](0005-the-analyst-proposes-and-never-acts.md).
- **Client address.** Forwarding headers are believed only from listed proxies, read from the right (the last hop you trust
  wrote the rightmost entry; everything to its left is a claim).
- **A typo is not an attack.** A string that is not a URL, or a name that does not exist, is not written to the chain.
- **Strangers can write here, so it is capped.** A bad webhook signature comes from someone nobody authenticated. Per
  (event kind, address) the shield writes at most 30 rows in ten minutes, then **one** `rate_limited` row saying so, then
  nothing until the window passes. The attack is still visible; the disk is not the thing under attack.
- Secrets in a logged URL (`http://user:pw@host/`) are removed before the URL is written.

## Rejected alternatives
- **A blocklist of "bad" hostnames or a regex for `127.0.0.1`.** There are hundreds of spellings.
- **Checking the name, then letting the HTTP client resolve it again.** The two lookups can disagree.
- **Claiming the replay marker before verifying the signature.** Lets anyone exhaust the store.
- **Logging every refusal.** Turns a probe into a denial of service on the audit table.

## Consequences
- (+) The guards are pure functions with table-driven tests (`test/ssrf.test.ts`, `redirect`, `webhook`, `prompt`, `client-ip`,
  `net`) and a wrapper that audits them (`test/shield.test.ts`, `test/api-ingest.test.ts`).
- (−) The prompt-injection patterns are a list, and a list is never complete. They are a seatbelt in front of a design that
  does not depend on them: the model can only propose, and every proposal is checked ([ADR 0005](0005-the-analyst-proposes-and-never-acts.md)).
