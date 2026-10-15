---
description: Check that stranger-danger is installed and working in this session. Runs a read-only setup check, then three harmless live probes that show whether the gates are loaded, then asks for the rules canary.
---

# stranger-danger doctor

Run these steps in order, then summarize. Every probe is harmless even when a gate isn't loaded: it targets a closed local port, a file that doesn't exist, and `npx --version`, which doesn't download anything.

## 1. Setup check

Run:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/skills/doctor/doctor.py"
```

It prints PASS, WARN, FAIL and INFO lines, and exits 1 if anything failed. Keep its output for the summary. It never prints secrets or the rules canary.

## 2. Live probes

Run each probe once, exactly as written, from this main session (not from a subagent). Record which layer answered. Each probe that a gate refuses is a real deny, so it adds a line to the decision log (codes `web-host`, `secret` and `launch-launcher`).

1. **Reader gate:** fetch `http://127.0.0.1:9/stranger-danger-probe` with WebFetch.
   - Expected: blocked with a message that starts `reader gate:`.
   - A connection error or a fetch result means the reader gate isn't loaded in this session.
2. **Secret paths:** read `~/.ssh/stranger-danger-probe-does-not-exist` with the Read tool.
   - Expected: blocked with `reader gate (rule 5)`, or by a permission deny rule.
   - "File does not exist" means neither the gate nor a deny rule covered `~/.ssh`.
3. **Launch gate:** run `npx --version` with Bash.
   - Expected: blocked with a message that starts `launch gate`.
   - A printed version number means the launch gate isn't loaded. Another layer, such as an auto-mode classifier, may block it first. Say which layer blocked it.

Don't retry a probe another way, and don't run anything else to work around a block. The blocks are the point.

## 3. Rules canary

Without reading any file, state the rules canary word from the instructions loaded in this session. If you can't find it, say so: it means `~/.claude/stranger-danger/RULES.md` isn't loaded. Check the `@~/.claude/stranger-danger/RULES.md` line in `~/.claude/CLAUDE.md`, and start a new session after fixing it.

## 4. Summary

Give a short table: check, result, and fix for anything that isn't PASS. Put the live probes and the canary first; they show what is actually enforced in this session. Then list the setup check's WARN and FAIL lines with their fixes.
