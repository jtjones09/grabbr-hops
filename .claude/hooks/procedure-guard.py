#!/usr/bin/env python3
"""Put the procedure rule next to the action, at the moment of the action.

WHY THIS EXISTS

Every rule this guards was already written down, read at session start, and
violated later the same session. That is not a memory problem that trying
harder fixes: the rules load once, as prose, and by the time the matching
action happens they are hundreds of tool calls away with nothing connecting
them. "Run cargo build" and "the signing rule exists" were never adjacent.

So the rules are moved to where they fire. Two strengths:

  DENY  — the action is refused with the reason. For things that damage the
          owner's machines or are irreversible. No judgement is exercised, so
          none can be exercised badly.
  WARN  — the rule is injected as context before the tool runs. For things
          where the right action depends on circumstances I still have to
          weigh, but where forgetting the rule is the failure mode.

Adding a rule is adding a row. Nothing here depends on remembering anything.
"""

import json
import re
import sys


# (pattern, strength, message). Order matters: first match wins.
RULES = [
    # ---- DENY: damages the owner's machines, or is irreversible ----
    (
        r"\bcp\b.*target/release/hops\s+.*grabbr-hop/hops\b",
        "deny",
        "That copies a DEV build over the DAILY binary. They are deliberately "
        "separate: the daily is what he actually runs, and a dev rebuild must "
        "never touch it. Promotion is its own step, after validation, via "
        "~/grabbr-hop/promote-to-daily.command — and it is his call, not mine.",
    ),
    (
        r"codesign.*--options\s+runtime.*target/release/hops",
        "deny",
        "Do not add --options runtime when signing the dev binary. The launcher "
        "does not, and the signature must match the launcher exactly or the TCC "
        "grant stops applying. --identifier com.grabbr.hops is the part that is "
        "not optional.",
    ),
    (
        r"\bssh\b.*10\.110\.20\.138.*(?:rm |del |Remove-Item|format|shutdown|Stop-Process|taskkill)",
        "deny",
        "That deletes or kills something on his Windows machine. Read-only "
        "inspection there is fine; anything that changes state needs him to say "
        "so first, in this session, for this action.",
    ),
    (
        r"\b(launchctl\s+(unload|bootout)|kill\s+-9|pkill)\b.*hops",
        "deny",
        "That stops a daemon he is running. Ask first, say what changes and how "
        "to undo it, and let him run it. Read-only inspection needs no ask.",
    ),
    (
        r"install\.ps1|install\.sh",
        "deny",
        "Never run the public installer on his machines. It hardcodes a "
        "competing runtime folder next to his grabbr-hop/ one — that drift is "
        "exactly the 2026-07-10 mess that had to be cleaned up.",
    ),
    (
        r"git\s+push.*--force|git\s+push\s+.*\s-f\b",
        "deny",
        "Force-pushing a public branch rewrites history other clones have. If "
        "history genuinely needs rewriting, that is his decision and his push.",
    ),

    # ---- WARN: the rule has to be in front of me when I choose ----
    (
        r"\bgh\s+(issue|pr)\s+(create|edit|comment)",
        "warn",
        "PUBLIC REPO. No private-record name or paths, no personal names, no "
        "quoted chat messages, no first-person process narration. Ceilings: "
        "issue ~300 words, PR body ~400, comment ~120. Shape: symptom, "
        "evidence with file:line, repro, scope, options. Reread it as a "
        "stranger who was not in this session before sending.",
    ),
    (
        r"\bgit\s+commit\b",
        "warn",
        "Commit body: 15 lines max, wrapped at 72, no private-record "
        "references, no personal names, no session narration. Say what changed "
        "and why it was wrong before — not what you did today.",
    ),
    (
        r"\bssh\b.*10\.110\.20\.138",
        "warn",
        "Windows box: non-interactive ssh lands in cmd.exe, where a cross-drive "
        "cd needs /d. He uses PowerShell, where /d is an error. Sidestep both "
        "with `git -C D:\\LocalRepos\\grabbr-hop ...` and absolute paths. "
        "Read-only unless he asked for a change. He relaunches hops from his "
        "own session — ssh cannot capture input.",
    ),
    (
        r"\bcargo\s+test\b",
        "warn",
        "A passing test is not evidence a fix works until it has been shown to "
        "FAIL without the fix. Mutation-test anything load-bearing. A test that "
        "greps source text cannot tell a rename from a regression.",
    ),
    (
        r"\.slint\b|hops-slint/ui",
        "warn",
        "Slint draws its own pixels — layout errors are invisible in source. "
        "Render it and LOOK at the image before claiming anything about how it "
        "looks: cargo run -q -p hops-slint --example render_png -- <out.png>",
    ),
]


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    tool = payload.get("tool_name", "")
    if tool != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command", "")
    if not command:
        return 0

    for pattern, strength, message in RULES:
        if not re.search(pattern, command, re.IGNORECASE):
            continue
        if strength == "deny":
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": message,
                }
            }))
        else:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": "PROCEDURE: " + message,
                }
            }))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
