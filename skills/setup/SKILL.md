---
description: Print the stranger-danger install commands with this install's real file paths filled in, ready for the user to copy into a terminal. Read-only; it writes nothing.
---

# stranger-danger setup

After `/plugin install`, the templates live in the installed plugin's folder, not in the user's project. This skill prints the commands that copy and merge them, with that folder filled in.

1. Run:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/skills/setup/setup.py"
   ```

   It only prints. It writes nothing and runs nothing.
2. Show the user its output exactly as printed, every command in full. Don't shorten, reformat or reorder the commands.
3. Don't run the printed commands yourself, and don't make the same changes another way. They change the user's permission rules, sandbox, rules file and gate config, which are the user's to change. Tell the user to run them in a terminal, then restart Claude Code and run `/stranger-danger:doctor`.

If the script fails, show its error and point the user to the install steps in the plugin's README.
