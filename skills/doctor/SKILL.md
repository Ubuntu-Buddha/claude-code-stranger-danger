---
description: Check that stranger-danger is installed and working in this session. Runs a read-only setup check, then four harmless live probes that show whether the gates and the settings guard are loaded, then asks for the rules canary.
---

# stranger-danger doctor

Run these steps in order, then summarize. Every probe is harmless even when a gate isn't loaded: it targets a closed local port, a file that doesn't exist, `npx --version`, which doesn't download anything, and a write to a file the settings template denies, which you decline if asked.

## 1. Setup check

Run:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/skills/doctor/doctor.py"
```

It prints PASS, WARN, FAIL and INFO lines, and exits 1 if anything failed. Keep its output for the summary. It never prints secrets or the rules canary.

## 2. Live probes

Run each probe once, exactly as written, from this main session (not from a subagent). Record which layer answered. Each probe that a gate refuses is a real deny, so it adds a line to the decision log (codes `web-host`, `secret`, `launch-launcher` and `settings-guard`).

1. **Reader gate:** fetch `http://127.0.0.1:9/stranger-danger-probe` with WebFetch.
   - Expected: blocked with a message that starts `reader gate:`.
   - A connection error or a fetch result means the reader gate isn't loaded in this session.
2. **Secret paths:** read `~/.ssh/stranger-danger-probe-does-not-exist` with the Read tool.
   - Expected: blocked with `reader gate (rule 5)`, or by a permission deny rule.
   - "File does not exist" means neither the gate nor a deny rule covered `~/.ssh`.
3. **Launch gate:** run `npx --version` with Bash.
   - Expected: blocked with a message that starts `launch gate`.
   - A printed version number means the launch gate isn't loaded. Another layer, such as an auto-mode classifier, may block it first. Say which layer blocked it.

4. **Settings guard:** only if step 1's `settings deny rules` line is PASS; if it isn't, skip this probe and say why, since a Write that nothing stops would create the folder. Write the one line `probe` to `.config/stranger-danger/doctor-probe` in the user's home folder with the Write tool, giving its full absolute path.
   - Expected: blocked with a message that starts `settings guard:`.
   - A block by a permission deny rule instead means either the settings guard isn't loaded in this session, or this Claude Code version checks deny rules before hooks (not yet tested: VERIFY.md row S1). Say it's one of the two. While the guard isn't loaded, your settings file, the `CLAUDE.md` that loads the rules and the rules folder are only asked about, not checked. If you're asked to approve the write, decline it, and say the guard isn't loaded.

Don't retry a probe another way, and don't run anything else to work around a block. The blocks are the point.

## 3. Rules canary

Without reading any file, find the rules canary word in the instructions loaded in this session (the `Rules canary:` line). Don't look for it any other way.

- If you can't find it, or it's still `<your-canary-word>`, say so: either `~/.claude/stranger-danger/RULES.md` isn't loaded, or its word isn't filled in yet. Check the `@~/.claude/stranger-danger/RULES.md` line in `~/.claude/CLAUDE.md`, and start a new session after fixing it. The plugin fills in a placeholder line at the next session start.
- If you found it and it holds only letters, digits, `-` and `_`, run this once, with the word in single quotes in place of `WORD`:

  ```bash
  python3 "${CLAUDE_PLUGIN_ROOT}/skills/doctor/doctor.py" --canary 'WORD'
  ```

  It compares the word with the rules file and prints one line: matches, doesn't match, or not set. Report that line. It never prints the file's word.
- If the word holds any other character, don't run it: tell the user to compare it with their rules file in their own editor.

## 4. Summary

Give a short table: check, result, and fix for anything that isn't PASS. Put the live probes and the canary first; they show what is actually enforced in this session. Then list the setup check's WARN and FAIL lines with their fixes.
