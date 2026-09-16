---
name: raise-the-decision
description: Fires on checkable conditions, not on judgment. (1) The draft reply is about to contain "I recommend", "we should", "the real fix is", "this is an architecture problem", or any recommendation touching more than one module, crate, message type, trait, process boundary, or config key. (2) The draft proposes shipping with a known defect, gap, over-grant or "documented limitation", or contains any of "release note", "known limitation", "for now", "acceptable risk", "caveat", "disclose", "we'll note". (3) A fourth or later PR is about to be opened on one branch or theme. (4) The repo owner asked what to do and the draft holds more than one option, or new research or a subagent is about to be commissioned. Puts one numbered decision with a recommendation into the TL;DR, and the grep, gate keys and disclosure test into a short Provenance section at the very bottom. Read before writing the reply, not after.
---

# Raise the decision

Three failures share one defect: the work was done, the text was written, and nobody had to decide anything. Architecture-level findings get buried in issue bodies. Known defects get proposed for release with a disclosure attached. PR series accumulate individually-defensible changes that do not add up to a design.

This skill puts **one numbered decision line, with a recommendation, into the
TL;DR's `Decisions needed`** — never in an issue body, PR body, commit message,
or code comment — and everything mechanical into a **`Provenance` section at the
very bottom** of the same reply.

## The top of the reply is scarce; the bottom is where receipts live

`reply-tldr` owns the top: decisions, what the reader gets, next steps, blocked. This
skill adds **nothing** there except the decision line itself. Grep output, gate
keys, disclosure tests and series claims all go to `Provenance`, last.

## Provenance is not optional

Once this file is in context, a reply that raises a decision, makes a
recommendation, or asserts what the record says ends with `Provenance`, however
short. Its absence is what makes a skipped gate invisible. Earlier compliance
does not carry forward; each such reply gets its own.

A reply with no decision, no recommendation and no claim about the record — a
one-line factual answer, a conversational aside — needs none of it. Do not pad a
chat with receipts.

## Fire the gates when any of these is true

- The draft reply contains `I recommend`, `we should`, `the real fix is`, `this is an architecture problem`, or a change touching more than one module, crate, message type, trait, process boundary, or config key.
- The draft proposes shipping with a known defect, gap, over-grant, or documented limitation.
- A fourth or later PR is about to be opened on one branch or theme.
- The repo owner asked what to do and the draft holds more than one option.
- New research, a subagent, or a fresh investigation is about to be commissioned.

If none are true, no decision line and no Provenance section are needed. This is not a preamble for every reply.

## Gate 1 — Read the record before writing the recommendation

Resolve the decision record's path once per session from the project's own instructions. Then run, with two or three terms that literally appear in the change (a file name, a type name, a config key, a protocol message):

```
grep -rn -i -e "<term1>" -e "<term2>" -e "<term3>" <record-path> | head -20
```

Paste the command and its output into Provenance, **including a zero-match result** as the literal line `no matches`. A reader must be able to re-run it. If no decision record exists, paste `DECISION RECORD: none — searched <paths tried>` and continue with the invariant half.

Then emit exactly one of:

- `DECISION IMPACT: none — grep above returns no related entry, and the change contradicts no stated invariant.`
- `DECISION IMPACT: depends on <entry id/title> — the change assumes it and does not alter it.`
- `DECISION IMPACT: contradicts <entry id/title or invariant> — this is a DECISION, numbered below.`

The recommendation goes in the TL;DR as a numbered line naming one option. It does not also go into an issue body as a paragraph; a one-line pointer there is fine, the reasoning belongs in the reply.

Before commissioning any new research or subagent, add to Provenance:

```
PRIOR ART: <paths searched> — <what each contained, one clause each> | none exist
```

Generating output resembles progress. Reading your own prior output does not, and is usually the shorter path.

Checkable: the grep command and its output are pasted, or they are not.

## Gate 2 — Is disclosure standing in for a fix?

Two tests. Run both.

1. Search the draft, case-insensitive, for: `release note`, `known limitation`, `document that`, `we'll note`, `disclose`, `caveat`, `for now`, `acceptable risk`, `ship it with`.
2. Answer: **after the change you are proposing, does the shipped artifact still contain the defect?**

If test 1 hits next to a defect, **or** test 2 is yes — wording aside — emit all five lines, keys verbatim:

```
DISCLOSURE-INSTEAD-OF-FIX: yes
DEFECT: <one sentence: what is wrong, and what a user or attacker hits>
INVARIANT AT RISK: <the stated product invariant it breaks, or "none stated">
FIX LANDS: <absolute date, e.g. 2026-09-12, or "unestimated">
SHIP IMPACT: <what slips and from which absolute date, or "no date was set">
```

Otherwise emit `DISCLOSURE-INSTEAD-OF-FIX: no` and move on.

Disclosure is not a mitigation. A deferred security defect is a rejected plan, not a shipped one. The recommendation is either `fix first, ship slips` or `this is not a defect, and here is the evidence`. Never offer "ship and disclose" as a third option, and never present the two as a menu.

Checkable: five lines are present, or the `no` line is.

## Gate 3 — PR 4 or later in a series

Get N mechanically and paste the count:

```
gh pr list --state merged --search "head:<branch>" --json number | jq length
```

Then emit:

```
SERIES: <branch or theme>, PR <N> of <planned total or "unplanned">
SERIES CLAIM: <one sentence>
FALSIFIER PR: <a real PR number, or a named unopened PR>
CLAIM STATUS: <verified by <command, screenshot, or manual step> | UNVERIFIED>
```

Rules that make this checkable:

- The claim is one sentence naming an observable and the condition under which it is observed. `A device that stops sharing shows as stopped in the UI within one second` is a claim. `The source contains a comment explaining X` and `the code now does X` are not.
- The falsifier is a single PR. `All of them` is not an answer; if every PR is equally load-bearing, the series is a list, not a design.
- `verified by` names the thing that ran. A guard test asserting its own text exists does not verify a claim — source-text greps cannot detect two fragments disagreeing, which is the defect class these series keep producing. That is `UNVERIFIED`.

**If the one sentence cannot be written, do not open the PR.** Emit instead:

```
SERIES CLAIM: CANNOT STATE — the series has no design.
BLOCKED: next PR held. The design question is raised as a numbered decision in the TL;DR.
```

That is the finding. Raise it as the decision.

## Where the output goes — the top stays scarce

The reply has one shape, set by `reply-tldr`: decisions, what the reader gets,
next steps, blocked — then the reasoning. **Nothing from this skill goes above
that, and no second block competes with it.** Two placements, and only two:

**1. The decision itself → `Decisions needed`, in the TL;DR.** One numbered line
per decision: the question in one sentence, then the recommendation, one option
named. Nothing else — no options list, no "if deferred", no grep, no gate keys.

```
1. **Clipboard between paired machines.** Asked at pairing, off by default.
```

**2. The machinery → a `Provenance` section, the LAST thing in the reply.**
Below every detail section. It is evidence the gates ran, written for scanning
past, and it is the only place the mechanical keys appear.

```
### Provenance

- **Record:** depends on 2026-08-05 "Persist revocation…" — the change assumes it.
  `grep -rn -i -e "revocation" DECISIONS.md | head -5` → 657, 659, 661
- **Disclosure instead of fix:** no
- **Decisions:** D12 tell-and-learn, over learn-only. Deferred: delete stays one-sided.
- **Gates:** 1 ran · 2 ran · 3 n/a · 1 recommendation for 1 decision · dates absolute
```

Constraints:

- **120 words maximum in Provenance.** Reasoning belongs in the detail sections above it.
- **Every decision line carries one recommendation, never a menu**, and the option named
  there is the option the reply actually ends on. The `Decisions:` line in Provenance
  echoes the chosen option token, so a drift between the two is visible.
- **The alternatives and the cost of deferring** are detail, not TL;DR: put them in a
  detail section when they need saying at all.
- **Absolute dates only.** `2026-09-12`, never `today`, `next week`, `soon`.
- **When no gate fired**, Provenance is one line: `**Gates:** none fired — no
  recommendation, no defect deferred, no PR series.` Keep it; its absence is what
  makes a skipped gate invisible. Drop it entirely only in a reply with no decision,
  no recommendation and no claim about the record — a one-line factual answer or a
  conversational aside.
- **Gate 3's series block** goes in Provenance too, on one line.

## What must not happen

- Any of this appears in an issue body, PR body, commit message, or code comment. Public artifacts get the outcome only — never the owner's name, private paths, quoted messages, or first-person narration.
- A decision is raised as prose inside a long issue and treated as raised. It is not raised until it is a numbered line in `Decisions needed`.
- The reply recommends one option in the TL;DR and drifts to another below it.
- The decision is skipped because the news was good. Good news with an architectural implication is still a decision.
- **Provenance grows.** It is a receipt, not a section anyone reads twice. Over 120 words means reasoning leaked into it.
