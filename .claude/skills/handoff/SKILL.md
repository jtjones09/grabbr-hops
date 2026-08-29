---
name: handoff
description: >-
  Write a post-compaction handoff so the next context window can resume without
  re-deriving what this one already learned. Use when the session is 70-80% full,
  when the user says "handoff" / "we're running out of context" / "compact soon",
  or before deliberately ending a long working session. Updates nisaba first
  (the permanent record), then writes HandoffSessionCompact.md (volatile working
  state). ALSO use at the START of a session when HandoffSessionCompact.md exists
  and is recent — read it before doing anything else.
---

# handoff — survive the compaction

A compaction summary preserves *narrative*. It reliably loses the things that
actually cost time to rediscover: which build is on which machine, what was
already tried and rejected, what the user corrected you about, and what you are
waiting on them for.

This skill writes those down.

## When invoked at session START (the file already exists)

If `HandoffSessionCompact.md` exists, **read it before anything else**, then:

1. Check its `Written` timestamp against `date`. If it is more than ~2 days old,
   treat every "current state" claim as suspect and re-verify — this project has
   multi-day gaps between sessions.
2. **Re-verify live state anyway** (cheap): `git log --oneline -1`, `gh pr list`,
   `gh run list --workflow check --branch main --limit 1`. The file records what
   *was* true.
3. Do NOT re-derive anything in "Already tried — do not redo".

## When invoked to WRITE a handoff

### Step 1 — nisaba first, and validate rather than assume

The permanent record lives in
`/Users/scorndraco/Documents/GitHub/nisaba/projects/grabbr-hops/`.
Do this BEFORE writing the handoff, so the handoff can point at it.

- `git -C <nisaba> log --oneline -5` and `git status --porcelain` — is it current?
- Compare the newest `JOURNAL.md` entry date against the newest grabbr-hops
  commit date. If work has landed since the last journal entry, **write the
  entry now**.
- Any *decision* made this session (a call with a rationale and a reversibility
  cost) belongs in `DECISIONS.md`, not just the journal.
- If a previous entry was contradicted by something learned this session,
  **correct it in place with a pointer forward**. A stale record that reads as
  current is worse than no record — this project has been burned by exactly that.
- Commit nisaba. Never leave it dirty.

Respect nisaba's `CLAUDE.md`: do not rename/move/delete files under `projects/`,
`atoms/`, `positions/`; no new root-level dirs; do not touch root canon unless
explicitly asked.

### Step 2 — gather live state, do not recall it

Run these; do not write from memory:

```bash
date '+%Y-%m-%d %H:%M %A'
git log --oneline -5 ; git status --porcelain ; git branch -vv
gh pr list --state open --json number,title
gh run list --workflow check --branch main --limit 1 --json conclusion
gh issue list --state open --milestone v0.13 --json number,title
# which build is on which machine — got this wrong twice, verify every time
ps -eo pid,command | grep -E "hops (daemon|gui)" | grep -v grep
~/grabbr-hop/hops --version ; target/release/hops --version
```

### Step 3 — write `HandoffSessionCompact.md` at the repo root

Use the structure below. Be specific: file:line, commit SHAs, issue numbers.
Vague handoffs are worse than none because they invite re-derivation.

```markdown
# Handoff — post-compaction session state

**Written:** <YYYY-MM-DD HH:MM> · **main:** <sha> · **CI:** <status>
> Re-verify anything below before relying on it. Sessions here are days apart.

## Right now
One paragraph: what we are in the middle of, and the immediate next action.

## Live state
- branch / dirty files / unpushed branches
- open PRs, with CI status
- rig: which build (commit) is running on Mac / Windows / Linux, and when built

## Waiting on Jeremy
Blocking questions, decisions, and any test only he can run. Say WHY each is blocked.

## Already tried — do not redo
The single highest-value section. Approaches attempted and rejected, with the
reason. Include things *I* got wrong and had to retract, so they are not
re-derived from scratch.

## Corrections made this session
Where the record (nisaba, an issue, a code comment) was wrong and is now fixed —
and where it is still wrong and known to be.

## Landed this session
Commits/PRs merged, with issue numbers.

## Next, in order
Ranked, with what each needs (nothing / a machine / a decision).

## Pointers
nisaba entries written, issues filed, memories saved.
```

### Step 4 — keep it out of git

`HandoffSessionCompact.md` is volatile working state, not project history — it
belongs in `.gitignore`. The durable record is nisaba. If Jeremy wants it
versioned, that is his call to make explicitly.

## Quality bar

- **Dates are absolute**, never "today" or "yesterday". This session narrated
  "shipped today" about work that was six days old.
- **Machine state is verified, never assumed.** Which binary is running has been
  wrong twice; check the process and its `--version`.
- **Record retractions.** When a claim was made and withdrawn, write down the
  withdrawal. Otherwise the next window re-derives the wrong answer.
- **Prefer "unverified" over a confident guess.** Mark anything not measured.
