---
name: verified-claims
description: Use before writing any claim about state you cannot see in the file in front of you — what version is on which machine, what a device on the network is, whether a repo, file or toolchain exists on a remote box, what caused what, how long something took, or the starting state a hardware test plan assumes. Also fires on handoffs, test plans, issue and PR bodies, release notes, status updates, and any answer of the form "that's already there", "that's missing", or "that's still broken". Output carries an evidence block; every such claim carries a pasted command, a file:line, or the literal word UNVERIFIED.
---

# Verified claims

Every sentence is either about the file in front of you, or about the world.
Claims about the world are wrong at a rate that has cost this repo real artifacts.

Defect classes this exists to stop, each of which has shipped here at least once:

- a version number asserted twice without opening the binary
- a device on the LAN named by what its traffic resembled, not by its record
- a remote machine declared to have no repo, no toolchain and no compiler when it
  had all three, because `~` did not expand over SSH
- a causal story with invented durations between two events minutes apart
- a hardware test plan whose step 1 said "fresh install" on a rig paired for months

None of those felt like guesses. They felt like knowing. That feeling is not a signal.

## What is an outside-state claim

Anything you cannot point at in a file you read this session: versions, machines,
binaries, processes, devices, networks, what exists on another box, what caused
what, when something happened, how long it took, and every "already / still /
never / no longer" about any of them.

Not an outside-state claim: the contents of the file open in front of you, and
your own reasoning presented as reasoning.

## The tag rule

Each outside-state claim gets exactly one of three tags. There is no fourth.
`presumably`, `should be`, `I believe`, `as of last session`, `per the earlier
check`, and `still` are all spelled UNVERIFIED.

| Tag | Form | Use when |
|---|---|---|
| **CMD** | the command, and its output pasted verbatim | the claim is about a machine, binary, device, or network |
| **SRC** | `path/to/file.rs:412`, or a doc URL with the date fetched | the claim is about text you read this session |
| **UNVERIFIED** | the literal word, adjacent to the claim | you did not run it or read it, and are writing anyway |

UNVERIFIED is legal and costs nothing: `UNVERIFIED: the Windows box is probably
still on 0.11.x` is never wrong. Asserting it without opening it is how the list
above was written.

The one limit: if verifying is a single read-only command you can already run,
run it. UNVERIFIED is for what needs a human, an unreachable machine, or a write.

## The evidence block

Any output carrying outside-state claims opens with a fenced block. Lines are
numbered; every claim in the prose ends with its ref.

```
EVIDENCE
E1 CMD  ssh user@host '/Users/user/hop/hops.exe --version'
        hops 0.12.1
E2 SRC  src/config.rs:88 — default port 4242
E3 CMD  ssh user@host 'ls -d /Users/user/.cargo/bin/cargo'
        ls: /Users/user/.cargo/bin/cargo: No such file or directory
E4 UNVERIFIED  the receiver has been restarted since the config edit
AUDIT  4 outside-state claims / 4 E-refs in the prose
```

Prose then reads: `The Windows sender runs 0.12.1 [E1] on the default port [E2].`

Rules, all of them grep-checkable:

- Every outside-state claim in the prose ends with `[E#]`. The count of `[E` in
  the prose equals the AUDIT number. Write the AUDIT line last, by counting.
- A CMD line pastes characters that were on the terminal. If you are typing words
  that were not ("returned the version", "confirmed present"), it is an
  UNVERIFIED line in a costume — retag it.
- Empty output is pasted as `<empty>` and is never upgraded to a fact.
- Ran nothing? The block is one line: `EVIDENCE: none — everything below is
  UNVERIFIED.` That is a complete, valid output.
- One or two claims may be tagged inline instead — `hops 0.12.1 (CMD: hops
  --version → hops 0.12.1)` — but the tag word is not optional. Skipping the
  block is a style choice; skipping the tag is the violation, and an untagged
  machine claim is the visible signal that this skill was not run.

**Position.** The block goes at the top of the body. If another skill prescribes
the opening section (a handoff's decisions-and-next-steps TL;DR, a findings
summary), that section stays first and the block goes immediately after it — the
claims in it still carry their `[E#]`.

**Structured output.** When the output is JSON, a findings list, or anything a
script parses, do not prepend the block or break the schema. Tags go inside the
fields.

## Four traps, as procedure

Each is a command you run instead of a conclusion you draw.

### 1. An empty path is not a missing thing

`$HOME`, `~`, and `%USERPROFILE%` do not expand over non-interactive SSH. A lookup
that returns nothing has told you about the shell, not the disk.

Before writing that anything is absent on a remote machine, re-run with an
absolute path and paste both lines:

```
ssh user@host 'ls -d /Users/user/repo'
ssh user@host 'ls -d /Users/user/.cargo/bin/cargo'
```

Only `No such file or directory` from an absolute path supports "absent",
"missing", or "not installed". A blank line supports nothing.

### 2. A device is its record, not its resemblance

Never infer what a machine on the network is from its traffic, its port, its
vendor-ish hostname, or the shape of its packets. Run the lookup:

```
dns-sd -B _services._dns-sd._udp        # or: avahi-browse -art
arp -n 10.0.0.4                         # MAC -> OUI vendor
```

Any noun naming a device kind needs an mDNS or OUI E-line behind it. The only
permitted alternative is the sentence `unidentified device at 10.0.0.4`. Nothing
in between. Traffic that resembles an enterprise tunnel has here been a consumer
camera, and the guess survived a PR, a journal entry and a handoff untagged.

### 3. Two timestamps are not a cause

Before writing "because", "caused", or "led to", write the mechanism in one
sentence naming the code path or system behaviour that carries the effect, and
put a SRC or CMD tag on that sentence.

If you cannot name it, the only permitted sentence is:

> A at 14:02 and B at 14:07 are correlated; mechanism unknown.

Never a narrative — a causal story invents its own supporting durations, retries
and timeouts, and those get quoted back as if measured. Every reported timing
carries a CMD tag (the log line, the timestamps) or is UNVERIFIED, including
timings you computed from two other numbers.

### 4. A test plan's step 0 is read off the rig

A hardware test plan may not assume a starting state. Step 0 is read-only
commands whose pasted output establishes it, and it ships inside the plan so the
person at the rig can confirm it still holds:

```
STEP 0 — rig state (read-only, paste output before continuing)
hops --version
ls -l ~/.config/hops/config.toml     # exists? mtime?
hops trust list                       # existing pairings
```

Any step saying "fresh install", "first run", "before pairing", or "with no trust
entries" is preceded by output showing that is true, or rewritten to work on a rig
paired for months — which is what the rig actually is. A wrong test plan walks a
human to a machine.

## Evidence expires

A CMD line is true as of when it ran. After any build, install, restart, config
edit, reboot, or reconnect touching that thing, earlier evidence about it is
UNVERIFIED again. Re-run it or retag it. Evidence from a previous session is
always UNVERIFIED.

## Read-only on machines that are not yours

Verification commands on someone else's box are limited to reads: `--version`,
`ls`, `stat`, `cat`, `arp`, `dns-sd`, a log tail, a read-only subcommand. Never
compile, install, start or kill a process, or run a probe to settle a claim — ask
the owner to run it. If verifying requires writing to a machine, the claim stays
UNVERIFIED until a human runs it.

## Artifacts

- **Handoffs, issues, PR bodies, release notes.** Dense with outside claims and
  read later by someone who cannot re-derive them. They get the block. A version
  number in a release note without a CMD tag is the failure that shipped twice.
- **Correcting a published claim.** Edit the body. A correction added as a comment
  while the wrong sentence stays in the body leaves the error as the first thing a
  reader sees. Fix the body, then optionally note the change in a comment.
- **Public repo.** Blocks belong only in artifacts already about machines. Strip
  hostnames to roles ("the Windows sender"), keep LAN IPs and personal paths out
  of public bodies: retag as `CMD (output withheld: local paths)` with the command
  and the finding.

## Before sending

The AUDIT line is the emitted proof that you did this; write it by counting, not
by estimating.

1. Does every `[E#]` in the prose resolve, and does the count match AUDIT?
2. Does every CMD line hold pasted characters, not a description of them?
3. Any "absent / missing / not installed" about a remote box → absolute-path
   command in the block?
4. Any device named by kind → mDNS or OUI line?
5. Any "because / caused / led to" → tagged mechanism sentence, or the word
   "correlated, mechanism unknown"?
6. Test plan → STEP 0 present, no assumed-fresh step without proof?
7. Any evidence collected before the last build, restart or edit → re-run or
   retag UNVERIFIED?
8. Anything still untagged → tag it UNVERIFIED, or delete the sentence.

Deleting is usually the better fix. An artifact that says less and is entirely
true beats one that reads fluently and sends someone to the wrong machine.

Assume any rule relying on memory alone will be forgotten mid-task, and any rule
phrased as an aspiration will be rationalised past — a mandatory format has
decayed twice inside one session here, once immediately after being acknowledged.
The tags are the only part that leaves a trace, so they are the part that is not
optional.
