---
name: public-writing
description: >-
  Write anything that leaves this session: a GitHub issue or bug report, a PR
  body, a commit message, an issue or PR comment, a release note, a README or
  docs change, a prompt handed to another agent, or the reply that closes a
  working turn. Invoke BEFORE drafting, not as a review afterwards, and always
  before running `gh issue create/edit/comment`, `gh pr create/edit/comment`,
  `gh release create`, or `git commit`. This repository is public and permanent:
  issues and pull requests are read by strangers who were not in the session and
  do not know the maintainer, so absolute paths, personal names, machine
  addresses, quoted chat and first-person narration must never appear, and every
  artifact has a word ceiling, a fixed shape, and a gate that runs at send time.
  Also use when correcting a claim that is already published, when closing an
  issue other issues depend on, and when a draft has run long.
---

# public-writing — the artifact, not the session

Everything named above is read by someone who was not here, does not know who
wrote it, and is deciding whether to trust software that sits between a keyboard
and every machine on a network. Write for that reader.

Reading a template has twice failed to produce a conforming artifact inside a
single session. So nothing here is remembered — it is **emitted**. A publish with
no scrub output and no gate block in the transcript has not been checked.

## 1. Rule 0 — no inline bodies, ever

Write the draft to a file **outside the repository**, gate the file, publish from
the file. Inline body text cannot be counted, scanned, diffed, or corrected.

```
DRAFT="${TMPDIR:-/tmp}/publish/$(date +%Y%m%d-%H%M)-issue.md"

gh issue create  --body-file "$DRAFT"   ✅   gh issue create  --body "…"   ❌
gh issue edit N  --body-file "$DRAFT"   ✅   gh issue comment N --body "…" ❌
gh pr create     --body-file "$DRAFT"   ✅   gh pr create     --body "…"   ❌
git commit -F    "$DRAFT"               ✅   git commit -m "<long body>"   ❌
```

The published command is itself the trace: a `--body` in the transcript is a
skipped gate, visible after the fact.

## 2. The scrub — run it, paste the whole output

```bash
D="$DRAFT"
echo "WORDS: $(wc -w < "$D" | tr -d ' ')  LINES: $(wc -l < "$D" | tr -d ' ')"
grep -nEiw "i|i'm|i've|i'll|my|me|we|we've|our|us|you|your|let me" "$D" || echo "PERSON: clean"
grep -nE  '/Users/|/home/[a-z]|[A-Za-z]:\\Users|~/(Documents|Desktop)|\.claude/' "$D" || echo "PATHS: clean"
grep -nEiw 'today|yesterday|tomorrow|this morning|last night|this week|recently|just now|earlier' "$D" || echo "DATES: clean"
grep -nE  '^>|\b(said|asked|wanted|mentioned|confirmed|agreed)\b' "$D" || echo "QUOTES: clean"
grep -nE  '([0-9]{1,3}\.){3}[0-9]{1,3}|[A-Za-z0-9-]+\.local\b' "$D" || echo "HOSTS: clean"
for s in "$(git config user.name)" "$(git config user.email | cut -d@ -f1)" \
         "$(whoami)" "$(hostname -s)"; do
  [ "${#s}" -ge 4 ] && { grep -niF -- "$s" "$D" || :; }
done; echo "IDENTITY: checked"
[ -f ~/.claude/publish-denylist.txt ] && { grep -nFf ~/.claude/publish-denylist.txt "$D" || echo "DENYLIST: clean"; } || echo "DENYLIST: absent"
grep -nE 'UNVERIFIED' "$D" || echo "UNVERIFIED: none marked"
```

Every hit is a rewrite. A hit that is genuinely a false positive is not silently
ignored — it is recorded in the gate as `PERSON L12 ok:<reason>`. `UNVERIFIED`
hits are never failures; they are the mechanism working.

`~/.claude/publish-denylist.txt` is optional, lives outside every repository, and
is never committed: one term per line — personal and family names, private
repository and project names, employer names, machine names, internal codenames,
private URLs.

## 3. The gate block — emit verbatim, filled in, then publish

```
PUBLISH GATE
target:      issue | pr-body | comment | commit | release-note | doc
command:     gh issue create --body-file /tmp/publish/20260905-1140-issue.md
scrub:       PERSON clean · PATHS clean · DATES clean · QUOTES clean · HOSTS clean · IDENTITY clean
length:      287 words (ceiling 300)
shape:       symptom L1 · evidence L7 (crates/net/src/listener.rs:212) · repro L15 · scope L24 · options L29
claims:      6 factual — 5 with pasted evidence, 1 marked UNVERIFIED
behaviour:   proved by running the built binary, output at L9 | n/a — no behaviour claim
recommend:   L30 "→ request client certificates" | n/a — single option
corrections: n/a | body edited, not commented
stranger:    <the one sentence a reader who was not here leaves with>
```

Every field carries a value copied out of the draft — a count, a line number, a
`path:line`. None can be filled in without opening the draft, and a skipped item
shows up as a blank. A missing or empty field is a failed gate: do not publish.

**The stranger field is the last check.** Reread the draft as someone who has
never met the maintainer, does not know an AI wrote it, and was not in the
session. Write the one sentence they leave with. If that sentence is not the
finding — if it is "someone was working on something here" — the draft fails,
whatever the other fields say.

## 4. Ceilings

| Artifact | Ceiling |
|---|---|
| Issue / bug report body | 300 words |
| PR body | 400 words |
| Issue, PR or review comment | 120 words |
| Commit body | 15 lines, wrapped at 72 |
| Release-note entry | 40 words per item |
| Any title | 70 characters |
| Reply that closes a turn | 200 words |

`wc -w` counts the whole file; pasted evidence gets no exemption. Over the
ceiling means narration, restated context, or two artifacts in one — trim the log
excerpt to the smallest span that proves the claim (3–10 lines), cut, or split.
Moving prose into a `<details>` block is not cutting.

## 5. Shape

**Issue / bug report — five headings, this order, nothing else.**

1. **Symptom** — what a user sees or loses. One or two sentences. Not a cause.
2. **Evidence** — `path/to/file.rs:212` plus the 3–6 lines that matter, or a
   verbatim log excerpt ≤10 lines. Every line here is a locator or a quote.
3. **Repro** — numbered, starting from the state the reader's machine is actually
   in. Never assume a fresh install unless a fresh install is what was observed;
   a long-lived setup is the normal case and the one that breaks. The last step
   states observed against expected.
4. **Scope** — affected and not affected, platforms, versions, dependent issue
   numbers. One line each.
5. **Options** — two or three, one line each, the default marked `→`.

**PR body** swaps Repro for **Change** (what the diff does, by file group) and
Scope for **Fits with** (the issue it closes and the sibling PRs it composes
with; `standalone` if none), and adds **Not fixed**.

No section may be called Background, Context, Summary, Investigation, or What
changed in this session. A heading that describes the work rather than the
software is narration. Delete it.

### Worked example — narration replaced by a finding

BEFORE, opening a 1,400-word issue:

> I started by looking at the connection path end to end. Discovery looked fine,
> so I moved on to the handshake. After a lot of back and forth about whether
> this was even a transport problem […900 words…] so in conclusion the
> certificate is never requested.

AFTER, 94 words, gate clean:

> **Symptom** — During pairing the receiving machine shows no verification code,
> while the sending machine shows one and instructs the user to compare them.
>
> **Evidence** — `crates/net/src/listener.rs:212` builds the server config with
> `with_no_client_auth()`, so no client certificate is ever requested. Receiver
> log during pairing: `peer_certificates: none`.
>
> **Repro** — Pair two machines. Sender displays a 6-digit code; receiver
> displays nothing.
>
> **Scope** — Every pairing since 0.11.0. The documented ceremony cannot be
> completed.
>
> **Options** — → request client certificates and derive the code from both
> fingerprints; or remove the compare-codes instruction until that lands.

## 6. Evidence

- Every factual sentence carries one of: pasted command output, a `path:line`, or
  the literal word `UNVERIFIED` in that same sentence. The gate counts them.
- **Source text is not behaviour.** A test that greps the project's own source
  proves a string exists — it cannot detect two fragments disagreeing, which is
  this project's dominant defect class. To claim a user-visible behaviour, paste
  output from running the built product on the platform named, including the
  receiving end of any two-machine ceremony. A ceremony has shipped that one side
  could not perform, because only the sending side was ever run.
- Stronger, where it applies: `mutation: reverted <change> at file.rs:line,
  <test> failed: <pasted output>`. A count of passing tests is not verification.
  If the only evidence is a green suite, the line reads `NOT VERIFIED IN THE APP`
  — an acceptable thing to write and an unacceptable thing to imply otherwise.
- Name a device, host, service or network only from output that identifies it —
  a MAC OUI, an open port, a banner string. Inference from an address or a
  behaviour is `UNVERIFIED`. A consumer peripheral was once described as
  corporate network infrastructure, and the claim propagated through three
  documents before anyone opened it.
- Version numbers come from the binary (`--version`), never a manifest, never
  recall.
- Absence is not proof: a command that returns nothing over a non-interactive
  shell has proved something about the shell, not about the machine.
- A causal claim linking two events needs both timestamps, pasted. Without them
  write "A and B both occurred; the link is UNVERIFIED" — an invented interval is
  worse than no claim, because it reads as a measurement.
- Dates are absolute (`2026-09-05`). The date grep enforces this.

## 7. What may never appear in a public artifact

| Never | Instead |
|---|---|
| Personal names, handles, email addresses | `the maintainer`, or nothing |
| Absolute paths outside this repo | a repo-relative path, or omit |
| Any reference to a private repository or notes system | state the conclusion, drop the citation |
| Machine names, LAN addresses, hostnames | `the test rig`, `a receiving machine` |
| Quoted chat — direction, praise, criticism, decisions | the resulting decision, unattributed |
| First-person narration of process | the finding |
| Context recoverable from the repository | delete it |

One quotation is allowed: a **symptom** report, unattributed, because a user's
own words are evidence — `reported from the test rig: "copy paste is now
broken"`. Direction, opinion, criticism and approval are never quoted.

## 8. Voice — the position, and the defence

**Write as the project's maintainer describing the software to a stranger, not as
an assistant reporting to the person who asked.** Four consequences, each
checkable:

1. The subject of every sentence is the software, the user, or the evidence —
   never the writer, never the work. Zero first-person pronouns in a public body
   (`PERSON clean`).
2. Report the finding, not the search. The investigation is a receipt; only its
   load-bearing line survives.
3. Uncertainty is a bounded claim plus the next measurement, not hedged prose:
   "cause unknown; two candidates, separated by whether the timeout fires."
   Confidence is marked — `MEASURED`, `UNVERIFIED`, `ASSUMED` — not performed.
4. No praise, apology, thanks, or self-assessment in a public artifact. No staged
   reveals, no bolded punchlines, no "turns out", no "interestingly". Finding
   first, evidence underneath it.

Why this and not a warmer, collaborative register: these artifacts outlive the
relationship that produced them. A public issue is read by a contributor
triaging, by a future maintainer bisecting, and by the maintainer's own future
self — none of whom were in the room. First person imports the session into a
document that will be read without it; every "I found" is a sentence the stranger
must translate before reaching the finding. Excess length is the same failure in
different clothes: restating shared context writes to the one reader who does not
need it, in front of everyone who does. This voice is not colder. It is addressed
to the actual audience. Warmth is not banned — it is relocated to §11, the only
artifact here with an audience of one.

## 9. Judgement

- **Recommend, never enumerate.** More than one option requires the `→` marker on
  exactly one line. A menu is a decision handed back unmade to the one person who
  cannot delegate it further.
- **Disclosure is not a mitigation.** A release note containing "known
  limitation", "currently grants", or "will be fixed in a later release" about a
  defect that over-grants privilege, weakens a check, or fails silently is not a
  note — it is a blocker. Stop, and put it under Decisions needed with a
  recommendation to hold the release.
- **Architecture goes at the top or nowhere.** Once the same root cause has
  produced a third artifact, its third mention is a decision issue whose title
  and first sentence are the recommendation — not a paragraph in someone else's
  bug. Before writing a fourth, paste `gh issue list --state all --search
  "<cause>"`.
- **Closing an issue** requires pasting both (a) output showing the behaviour
  works end to end and (b) `gh issue list --state all --search "#<n>" --state
  all`, so dependents are visible. No paste, no close. An issue whose second step
  was never built is not closed.
- **Reread prior output before generating new output.** Before commissioning
  research, paste `gh issue list --state all --search "<topic>"` and `grep -ril
  "<topic>" docs/`. Generating resembles progress; rereading usually is progress.
- **When the maintainer localises a symptom, start there.** Overriding a stated
  localisation to inspect elsewhere has cost three round trips for nothing.

## 10. Corrections outrank comments

The first thing a reader sees is the body. A wrong claim is fixed in the body.

1. `gh issue edit <n> --body-file <new draft>`, gated like any other publish.
2. The corrected claim goes in the first 40 words, prefixed
   `**Corrected 2026-09-05:** <what was wrong, one line>`.
3. Then, optionally, one comment: "Body corrected — <claim> was wrong because
   <evidence>." Nothing else.
4. Verify: `gh issue view <n> --json body -q .body | grep -i '<keyword of the
   wrong claim>'` — the only permitted hit is the dated correction line.

Gate field `corrections:` reads `body edited` or `n/a`. `commented only` fails.

## 11. Commits, agent prompts, and the closing reply

**Commits.** Subject `type(scope): what changed for the user`, imperative, ≤70
chars, no trailing period — someone who has never opened the file must be able to
tell what got better. Body ≤15 lines: what was wrong, the mechanism, what is
still not fixed. Before every commit, including conflict resolutions:

```bash
git diff --cached -U0 | grep -E '^-.*(assert|panic!|expect\(|debug_assert|guard|unwrap)' || echo "REMOVALS: none"
```

Every hit is named in the commit body with its issue number, or restored. A crash
guard has been deleted during a conflict resolution and mentioned nowhere. Chain
the test itself — `cargo test --workspace && git commit -F "$DRAFT" && git push`
— and paste the final line; a commit has landed with a failing test because the
`&&` started one command too late.

**Prompts naming a machine** must carry this literal line, and be grepped for it
before sending: `SCOPE: read-only. Do not install, compile, execute, write, or
restart anything. Report and stop.` An agent handed an address without it
attempted to compile and run a native probe on a personal computer. Never put a
hostname or address in a prompt whose output becomes public.

**The reply that closes a turn** is the one unpublished artifact, and the one
place courtesy belongs. Emit all four headings, in this order, every time — a
heading with nothing under it gets the word `None.`; deleting it is the failure
mode, and this template has decayed twice inside one session, once when the news
was good and once by dissolving into prose. Count the headings before sending:
four.

```
**Decisions needed** — each with one recommendation marked `→`. If nothing: None.
**What you get** — the change in the user's own words, not the code's.
**Next steps** — numbered; each a verb with an owner.
**Blocked** — what is stopping, and on whom. If nothing: None.
```
