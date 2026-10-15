---
description: Print a summary of this install to paste into a GitHub issue — versions, the plugin's own doctor checks, a count of the setup checks and a week of rough decision-log counts — with no paths, hosts or file contents. The user reads it and pastes it; nothing is sent.
---

# stranger-danger report

Run:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/skills/doctor/doctor.py" --report
```

Show the output to the user exactly as printed, in one code block, and nothing else from it.

Then tell the user three things:

1. Read it before pasting it anywhere. It leaves out paths, hosts, the log's agent names and the doctor's details on purpose, and names only the plugin's own checks. A FAIL there shows a gate isn't working, so they may want to fix it before posting. Add only what they're comfortable sharing, and never a secret.
2. Bugs go in a GitHub issue on the plugin's repo, using the bug report template.
3. A way past the reader gate or the reader-tools hook is a security problem: report it privately, as SECURITY.md says, not in a public issue. A command the launch gate misses can go in an ordinary issue.

Don't open an issue, post the report or send it anywhere yourself. The user does that.
