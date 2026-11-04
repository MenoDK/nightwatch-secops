# ADR 0005: The analyst proposes; it never acts, and nothing it says is believed without the evidence

Status: Accepted

## Context
A language model is good at reading a pile of events and saying what looks wrong. It is also a reader of untrusted text (the
events contain strings an attacker chose), it can be confidently wrong, and it does not carry responsibility for a blocked
customer. Handing it the ability to block, suspend or lock down would make the most manipulable component the most powerful.

## Decision
- **Three kinds of suggestion, no more:** `block_ip`, `suspend_subject`, `lockdown`. A suggestion is a row with a rationale, a
  severity and **the audit sequence numbers it rests on**. It changes nothing by itself.
- **Two analysts behind one interface.** The *local* analyst is a table of rules (an address that tripped a trap, three SSRF
  attempts from one address, impossible travel, a critical playbook matched). It needs no model, is deterministic, and is the
  test oracle. The *remote* analyst talks to any OpenAI-compatible endpoint, and is optional.
- **The remote analyst gets less than the local one sees.** Event metadata is left out entirely (that is where free text from
  outside lives); the one free-text field that remains, the account name, is stripped of control characters and clipped to 80.
  The serialised evidence goes through the model gate first; if it contains text addressed to the model, **the model is not
  called**, the run falls back to the local rules, and the attempt is itself evidence (`prompt_injection_attempt`).
- **Nothing the model says is believed.** Each proposal is validated against the input it was given: the target must appear in
  the events it cites (an address, an account), the cited events must exist, the operators' own network can never be proposed,
  and what is already done is not proposed again. A made-up target is dropped, not queued. The whole answer is rejected if it is
  not JSON of the right shape; any failure (HTTP, timeout, shape) falls back to the local rules and the response says why.
- **Approval is the human gate** ([ADR 0003](0003-the-human-gate.md)): the network, a code, and an atomic claim on the proposal
  (`UPDATE … WHERE status = 'pending'`) so that two operators approving together execute it once. Execution is idempotent.
- **A "no" is remembered until there is something new to say.** A rejected proposal is not queued again unless a draft cites
  evidence newer than the rejection.
- The same proposal is not queued twice (partial unique index on `(kind, target)` where pending).

## Rejected alternatives
- **Letting the model call tools that block or suspend.** The usual shape of agent frameworks, and the one this is built to avoid.
- **Trusting a model's own "confidence".** It is text the model produced.
- **Auto-approval above a severity.** Every incident review ever held starts with "the automation did what?".
- **Sending the raw events and asking the model to "ignore any instructions in them".** That is the problem, restated as a request.

## Consequences
- (+) `test/api-alice.test.ts` has table tests for every way a model's answer can be wrong (`validateDraft`), a fake endpoint for
  the five ways it can fail, and the end-to-end case where text in the logs keeps the model out of the loop.
- (−) The local rules are blunt and will miss what a model would catch. That is the cost of a proposer with no authority.
- (−) The remote analyst has not been run against a real model in this repository's tests, only against a fake endpoint with the
  same wire format.
