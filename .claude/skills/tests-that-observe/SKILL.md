---
name: tests-that-observe
description: Emit a test ledger classifying every test as behaviour or source-text before writing it, so coverage observes the running product instead of the repo's own source text. Invoke BEFORE writing or editing any test; before reaching for include_str!, a source grep, or any assertion that a string exists in a file; before citing a test, a green CI run, a test count, or "the tests pass" as evidence a feature works; before saying a bug is fixed or a change is verified; before opening a PR whose only new coverage is a guard; and before claiming any cross-crate, cross-binary, or cross-machine feature (handshake, pairing ceremony, sync, discovery, clipboard, shared code) works end to end. Also on "is this covered?", "how do we know this works?", "did you test it?", and whenever a test you just wrote passes on its first run.
---

# Tests that observe

The recurring defect class here is **two fragments disagree**: a config table
against the UI that renders it, a sender against a receiver, a value one side
computes against a value the other side displays. A test that reads this repo's
own source text cannot detect disagreement — each fragment contains its own
text, so both guards pass while the product is broken.

Measured: ~49 source-text guards used as the primary verification method; 166
tests that found none of six bugs found by opening the app; a shipped ceremony
where one machine told the user to compare a number the other machine never
computed. All green.

## Four artifacts. Missing artifact = rule skipped.

Every one of these is a string in the output or a line in a file, so a reader can
tell from the diff and the PR whether this skill ran.

1. `TEST LEDGER` block, before the first line of test code.
2. A `// LEDGER T<n> | class <B|S> | <channel>` comment above every new or edited
   test function.
3. A `MUTATION PROOF` block per new property, with a pasted FAIL and PASS line.
4. A `LEDGER CHECK` footer at the end of any reply that touched tests.

## Rule 1 — Ledger before code

Emit this before writing test code. No ledger, no test.

```
TEST LEDGER
| id | property under test | class | observation channel + production symbol | pair |
|----|--------------------|-------|----------------------------------------|------|
| T1 | receiver computes a code from the peer cert | B | 1 return value: transport::pair::derive_code() | — |
| T2 | UI string mentions the code | S | source text | T1 |
```

`class` is exactly `B` or `S`. For class B the channel cell names one of these
six by number **and** the production symbol the test calls. A row that cannot
name a production symbol outside `tests/` is class S.

1. **return value / error** of a real function called with real inputs
2. **bytes** written to a socket, pipe, or serialized frame
3. **pixels or widget tree** produced by a render
4. **file on disk** written by the code under test
5. **process** started: exit code, stdout, or a log line emitted at runtime
6. **struct state** after running the real code path

There is no seventh channel. If none fits, the row is class S.

Then tag the code. Above each test function:
`// LEDGER T1 | class B | 1 return value`

Check before opening the PR — the two counts must be equal:

```
rg -c '#\[(tokio::)?test\]' <changed test files>
rg -c 'LEDGER T' <changed test files>
```

## Rule 2 — Class S is syntactic, not a judgement call

A test is class **S** if its body contains any of:

- `include_str!` / `include_bytes!` over a path inside this repo
- reading a `.rs`, `.slint`, `.toml`, `.md`, `.yml`, `.json` file and asserting on its text
- `env!("CARGO_MANIFEST_DIR")` joined to a source file
- a shell `grep` / `rg` over tracked source
- an assertion that a symbol, comment, or literal "exists" somewhere
- an assertion whose subject was built in the test body and never passed through
  a production function

The list decides. Calling such a row B because it "really checks behaviour" is
the exact failure this skill exists to stop.

## Rule 3 — A guard never travels alone

Every class S row names a class B test id in its pair column, and that B test
covers the **same** property. Checkable form: the literal the guard asserts on
must appear as the *expected value* in the paired B test.

- Paired B test does not exist yet → write it first.
- Paired B test is pre-existing → cite its id and paste the summary line of a run
  that included it.
- Property cannot be observed behaviourally → write `S | source text | NONE`,
  then delete the guard. Unpaired guards are deleted, not shipped.

In the PR body the pair is one line:
`T2 guard (UI mentions the code) — behaviour proven by T1 (receiver returns it)`

A ledger that is entirely class S proves nothing. Say so verbatim in the PR body:
`No behavioural coverage added.`

## Rule 4 — Both ends, producer first

A property **spans a boundary** if its halves live in different crates, different
binaries, or on different hosts. For each, emit:

```
TWO-ENDED CHECK: <property>
  producing side (crate/host): <id> | class B | <channel> | <pasted run summary line>
  consuming side (crate/host): <id> | class B | <channel> | <pasted run summary line>
```

The producing side is written and green first, and its run line is pasted before
the consuming-side test is written. For a ceremony the machine that must
*compute or receive* the value is the producing side; the machine that *displays
or instructs* is the consuming side.

**Stop condition.** If the producing side cannot produce the value in a test — no
cert presented, no field populated, no frame received — that is the bug:

```
BLOCKED: <producing side> does not produce <value>; the feature is not implemented.
```

Do not open the PR. Do not write the consuming-side test. Do not add a guard
asserting the instruction text exists.

## Rule 5 — Mutation-test against the real defect

A test that has never failed is unverified, including one that passed on its
first run. For each new property, reintroduce the real defect in the real
production code path, run, paste both lines:

```
MUTATION PROOF: T1
  file:line: transport/src/server.rs:118
  removed: cfg.set_client_auth_required(true);
  command: cargo test -p transport verification_code
  FAIL: <verbatim failure line naming the test>
  reverted; PASS: <verbatim summary line, e.g. "test result: ok. 4 passed">
```

One proof per property, not per assertion. A proof with only a PASS line is
incomplete. Test still passes with the defect in → delete it and start over. No
defect can be constructed that the test would catch → the test asserts nothing;
delete it.

`include_str!` guards have a known trap: the guard's own assertion text lives in
the file it scans, so it matches itself. Scope such scans to non-test source,
strip comments, and mutation-test them like everything else.

## Rule 6 — What counts as evidence

Any sentence claiming the software *does* something — PR body, issue, review
comment, release note, chat reply — is followed by either:

- a class **B** test id from a ledger in this session plus the pasted summary
  line of the run that included it, or
- the literal token `UNVERIFIED`.

Never evidence that the software works: a class S id; "CI is green"; "all tests
pass"; a test count; the existence of the code; a previous session's claim.

## Rule 7 — Never make red go green by editing the test

Do not delete, `#[ignore]`, loosen an assertion in, widen a tolerance in, or
`#[should_panic]`-wrap a test that started failing after a change. The red test
is the finding. Report it and stop.

## Rule 8 — The five-minute question

Before opening any PR:

```
COULD IT BE FOUND BY OPENING THE APP?
  what a user does: <action>
  what they should see: <observable>
  which ledger test observes that: <id, or NONE>
```

`NONE` and the change touches anything a user sees → run the app, or render the
UI with the GUI preview skill, and paste the image path plus the specific thing
you looked at. Six bugs here were found by opening the app while the suite was
green.

## Footer and PR section

End every reply that added or edited tests with:

```
LEDGER CHECK: <n> tests touched | <n> B | <n> S | <n> mutation proofs pasted | LEDGER tags == test count: yes/no | ledger in PR body: yes/no
```

Copy the ledger, every two-ended check, and every mutation proof into the PR body
under `## Test ledger`. A PR without that section is not ready to open.

**If test code already exists and no ledger was emitted:** stop, emit the ledger
now, run Rule 5 on every one of those tests before citing any of them, and write
`ledger: backfilled` in the footer. Backfilling without the mutation proofs is
the same as skipping.

## Worked example

Change: a pairing code both machines display.

```
TEST LEDGER
| id | property | class | channel + symbol | pair |
|----|----------|-------|------------------|------|
| T1 | receiver derives a 6-digit code from the presented peer cert | B | 1 return value: pair::derive_code() | — |
| T2 | sender derives the same code from the same cert | B | 1 return value: pair::derive_code() | — |
| T3 | both derivations agree for 1k random certs | B | 1 return value: pair::derive_code() | — |
| T4 | receiver UI model exposes a non-empty code after handshake | B | 6 struct state: ui::Model::code | — |
| T5 | receiver UI template renders the code field | S | source text | T4 |

TWO-ENDED CHECK: user compares one code on two screens
  producing side (transport, receiver): T1, T4 | class B | return value, struct state | test result: ok. 4 passed
  consuming side (transport, sender):   T2     | class B | return value              | test result: ok. 1 passed
```

Written in this order, the shipped ceremony would have stopped at
`BLOCKED: receiver does not produce a verification code` rather than shipping a
guard proving the sender's instruction text existed.

Rules that depend on remembering get dropped mid-task. That is why every rule
above ends in an artifact — a ledger, a tag, a pasted failure line, a footer —
whose absence is visible to someone reading only the diff and the PR.
