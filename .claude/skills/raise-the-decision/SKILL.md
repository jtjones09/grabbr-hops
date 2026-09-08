---
name: raise-the-decision
description: Fires on checkable conditions, not on judgment. (1) The draft reply is about to contain "I recommend", "we should", "the real fix is", "this is an architecture problem", or any recommendation touching more than one module, crate, message type, trait, process boundary, or config key. (2) The draft proposes shipping with a known defect, gap, over-grant or "documented limitation", or contains any of "release note", "known limitation", "for now", "acceptable risk", "caveat", "disclose", "we'll note". (3) A fourth or later PR is about to be opened on one branch or theme. (4) The repo owner asked what to do and the draft holds more than one option, or new research or a subagent is about to be commissioned. Produces a DECISIONS BLOCK at the top of the reply and a four-line gate footer at the bottom. Read before writing the reply, not after.
---

# Raise the decision

Three failures share one defect: the work was done, the text was written, and nobody had to decide anything. Architecture-level findings get buried in issue bodies. Known defects get proposed for release with a disclosure attached. PR series accumulate individually-defensible changes that do not add up to a design.

This skill produces a **DECISIONS BLOCK** in the reply to the repo owner — never in an issue body, PR body, commit message, or code comment — plus a four-line footer that makes skipping visible.

## The footer is not optional

Once this file is in context, **every** reply to the repo owner ends with the four-line footer in the last section, including replies where no gate fires. A reply without it is a skipped skill, and any reader can see that.

Do not drop the footer because the reply is short, because the news is good, because the gates found nothing, or because you emitted one earlier in the session. Earlier compliance does not carry forward. Each reply gets its own.

## Fire the gates when any of these is true

- The draft reply contains `I recommend`, `we should`, `the real fix is`, `this is an architecture problem`, or a change touching more than one module, crate, message type, trait, process boundary, or config key.
- The draft proposes shipping with a known defect, gap, over-grant, or documented limitation.
- A fourth or later PR is about to be opened on one branch or theme.
- The repo owner asked what to do and the draft holds more than one option.
- New research, a subagent, or a fresh investigation is about to be commissioned.

If none are true, skip to the footer. This is not a preamble for every reply.

## Gate 1 — Read the record before writing the recommendation

Resolve the decision record's path once per session from the project's own instructions. Then run, with two or three terms that literally appear in the change (a file name, a type name, a config key, a protocol message):

```
grep -rn -i -e "<term1>" -e "<term2>" -e "<term3>" <record-path> | head -20
```

Paste the command and its output into the reply, **including a zero-match result** as the literal line `no matches`. A reader must be able to re-run it. If no decision record exists, paste `DECISION RECORD: none — searched <paths tried>` and continue with the invariant half.

Then emit exactly one of:

- `DECISION IMPACT: none — grep above returns no related entry, and the change contradicts no stated invariant.`
- `DECISION IMPACT: depends on <entry id/title> — the change assumes it and does not alter it.`
- `DECISION IMPACT: contradicts <entry id/title or invariant> — this is a DECISION, numbered below.`

On the third line, the recommendation goes in the block with a number and one recommended option. It does not also go into an issue body as a paragraph; a one-line pointer there is fine, the reasoning belongs in the reply.

Before commissioning any new research or subagent, also emit:

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
BLOCKED: next PR held. Raising the design question below as DECISION <n>.
```

That is the finding. Raise it as the decision.

## The DECISIONS BLOCK

Emit at the top of the reply, above the summary and above everything else. When the reply also carries a decisions/next-steps summary, that summary points at this block rather than restating it.

```
=== DECISIONS BLOCK ===
DECISION IMPACT: <one of the three Gate-1 lines>
<grep command>
<grep output, or "no matches">
DISCLOSURE-INSTEAD-OF-FIX: <no | the five-line form>
<Gate-3 block, only when opening PR N>3>

DECISION 1 — <short title>
  What: <one sentence>
  Options: <a, b>
  Recommend: <a or b, named verbatim, with one clause of why>
  If deferred: <what breaks or what stays blocked>
=== END ===
```

Constraints:

- **200 words maximum inside the block.** Reasoning over that goes below the block, not inside it.
- **A recommendation, never a menu.** `grep -c "Recommend:"` on the draft equals the decision count, and each `Recommend:` names one option verbatim from that decision's `Options:` line. Two options with no choice delegates the thinking back.
- **Absolute dates only.** `2026-09-12`, never `today`, `next week`, `soon`.
- **Zero decisions is a valid block.** Impact line, grep, `DISCLOSURE-INSTEAD-OF-FIX: no`, nothing else. That is evidence the gates ran.

## What must not happen

- The block, or any part of it, appears in an issue body, PR body, commit message, or code comment. Public artifacts get the outcome only — never the owner's name, private paths, quoted messages, or first-person narration.
- A decision is raised as prose inside a long issue and treated as raised. It is not raised until it is numbered in a block in a reply.
- The reply recommends one option in the block and drifts to another below it. The footer's `RECOMMEND` line is the check: the token it echoes must be the option the reply actually ends on.
- The block is skipped because the news was good. Good news with an architectural implication is still a decision.

## Footer — every reply, last four lines

```
GATES: 1 <ran|n/a> · 2 <ran|n/a> · 3 <ran|n/a>
BLOCK: <emitted | none — no gate fired | none — <reason>>
RECOMMEND: <count> lines for <count> decisions — <chosen option token per decision>
DATES: <absolute | none used>
```

The two counts on the `RECOMMEND` line must be equal. If they are not, a decision was raised as a menu — go back and choose one.
