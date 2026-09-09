---
name: reply-tldr
description: >-
  Structure any substantial reply to the maintainer — the message that closes a
  working turn, a status update, a summary of what landed, an answer to "what is
  next", a plan, a recommendation, or a handoff. Invoke BEFORE writing that
  reply, not as a review afterwards. Every such reply opens with a four-part
  TL;DR (decisions needed, what you're getting in user terms, next steps,
  blocked), then the detail. Use it especially when the news is good, when a
  list of green PRs or landed commits is the obvious thing to lead with, or when
  the turn was long and eventful — those are exactly the conditions under which
  this format has repeatedly decayed. Not for one-line factual answers.
---

# reply-tldr — decisions first, always

He has asked for this format three times and it has decayed three times, twice
inside a single session. It is not a preference about tidiness. He is running a
project and needs to know what he must decide, what the work is worth to a
person using hops, and what he is waiting on — without mining a long answer for
them.

## The four headings, in this order

Every one is mandatory. If a section is empty, write "none" — do not drop it.

### 1. Decisions needed
Numbered. One sentence each. **Give a recommendation, not a menu.** A decision
he has already made never reappears as a question. This section goes first even
when the answer is "none", because its absence is what he notices.

### 2. What you're getting
What a *person using hops* experiences differently, in their words.

- Not "carried `AttemptOrigin` through the wire" — "the prompt now tells you
  whether a machine knocked, or whether hops went looking."
- Say plainly which items are invisible to a user.
- **Always include what they are NOT getting yet**: unmerged, unreleased, not on
  their machines, code-verified but never run.

If a change cannot be written as a sentence a user would say, you do not yet
know what it is worth — say that out loud rather than hiding it in jargon.

### 3. Next steps
What *you* do next, ordered.

### 4. Blocked / waiting
On him, on hardware, on a run. Say why each is blocked. If you are waiting on
him for anything, it appears here **and** in the first five lines — never
discovered at the bottom.

Then the detail, under headings. **Keep the detail.** He has said explicitly he
wants it. The problem was never volume; it was decisions buried in narrative.

## The detail below the TL;DR is EXPLANATION ONLY

Nothing below the four headings may require him to do, decide, or notice
anything. If a detail section contains something he must act on, that thing is
in the wrong place — lift it into Decisions, Next steps, or Blocked, and leave
only the explanation behind.

This is the failure mode in practice: the four headings get written correctly,
and then a long, satisfying write-up follows with new asks embedded in it — an
open question, an unresolved caveat, a heads-up about another project. Every one
of those is something he has to hunt for, which is what the format was created
to stop. He named it directly: *"you put decisions and content all over in your
readouts, stop that."*

Do not invent new top-level sections that compete with the four. Detail headings
are subordinate and descriptive ("why the naive version fails"), never a second
place where status or asks live.

## The failure mode to watch for

**This format decays under good news.** When there are five green PRs and a
crash finally fixed, the pull is to lead with the scoreboard and let the
decisions drift to the bottom or vanish. That is precisely what happened every
time it has failed. Before sending, check all four headings are present, in
order, and that section 2 is in a user's words rather than a changelog.

Composes with `public-writing` (that one governs artifacts that leave the
session; this one governs the reply itself) and with the house style: plain
statements, no hooks, no staged reveals — a status block, not a pitch.

## Gate before sending

- [ ] All four headings present, in order
- [ ] Decisions numbered, one sentence, each with a recommendation
- [ ] "What you're getting" is in user language, and names what is NOT there yet
- [ ] Anything you are waiting on him for is in the first five lines
- [ ] Claims are marked as verified or not — do not imply a fix has run when it
      has only compiled
- [ ] **Re-read every line below the four headings.** If any of it asks him to
      do, decide, or notice something, move it up. Explanation stays; asks do not.
