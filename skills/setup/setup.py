#!/usr/bin/env python3
"""stranger-danger setup: print the install commands with this install's paths.

Read-only: it writes nothing and runs nothing. After ``/plugin install`` the
templates live in the installed plugin's folder, not in your project, so this
prints the commands that copy and merge them with that folder filled in. You
run them yourself, in a terminal: they change your guardrails.

Every command is safe to run twice. The merge adds only rules that are
missing, keeps a ``.bak`` copy of your settings, and stops without writing if
your file has a different shape than it expects. A copy never overwrites a
file that's already there.

Standard library only.
"""
from __future__ import annotations

import os
import shlex
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(os.path.dirname(HERE))
RULES_IMPORT = "@~/.claude/stranger-danger/RULES.md"
FILES = ("templates/settings.json", "templates/sandbox.json", "templates/automode.json",
         "templates/config.json", "rules/RULES.md", "skills/setup/apply.py",
         "skills/coordinator/install.py",
         "templates/coordinator/open-items.md", "templates/coordinator/pending-decisions.md",
         "templates/coordinator/decisions-made.md")

# Merges JSON templates into ~/.claude/settings.json: objects merge key by key,
# lists gain the entries they lack, other values take the template's value.
MERGE = r"""python3 - TEMPLATES <<'MERGE'
import json, os, shutil, sys
base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
if not os.path.isabs(base) or any(c in form for form in (base, os.path.realpath(base))
                                  for c in "()*?[]{}\\"):
    sys.exit("CLAUDE_CONFIG_DIR must be an absolute path with no ( ) * ? [ ] { } or \\")
path = os.path.join(base, "settings.json")
settings = {}
if os.path.exists(path):
    with open(path) as fh:
        settings = json.load(fh)
if not isinstance(settings, dict):
    sys.exit(path + " isn't a JSON object; merge by hand")
yours = json.loads(json.dumps(settings))

def merge(into, new, where):
    for key, value in new.items():
        old = into.get(key)
        if isinstance(value, dict) and isinstance(old, dict):
            merge(old, value, where + key + ".")
        elif isinstance(value, list) and isinstance(old, list):
            old.extend([v for v in value if v not in old])
        elif key in into and type(old) is not type(value):
            sys.exit(where + key + " in " + path + " has another type; merge by hand")
        else:
            into[key] = value

for template in sys.argv[1:]:
    with open(template) as fh:
        data = json.load(fh)
    # Another profile folder: its CLAUDE.md, settings, hooks and agents need
    # the same deny rules the template gives ~/.claude.
    if os.path.realpath(base) != os.path.realpath(os.path.expanduser("~/.claude")):
        forms = list(dict.fromkeys([base.rstrip("/"), os.path.realpath(base)]))
        for kind in ("deny", "ask"):
            rules = data.get("permissions", {}).get(kind, [])
            rules += [r.replace("(~/.claude/", "(/" + form + "/", 1)
                      .replace("(~/.claude.json)", "(/" + form + "/.claude.json)", 1)
                      for form in forms for r in rules
                      if "(~/.claude/" in r or "(~/.claude.json)" in r]
    merge(settings, data, "")
# A sandbox.allowUnsandboxedCommands you've set yourself keeps your value.
mine = yours.get("sandbox")
if isinstance(mine, dict) and "allowUnsandboxedCommands" in mine \
        and isinstance(settings.get("sandbox"), dict):
    settings["sandbox"]["allowUnsandboxedCommands"] = mine["allowUnsandboxedCommands"]
# Sandboxed commands mustn't write the files setup changes (their Edit rules
# are ask, not deny). Only paths that exist, or this settings file: Claude
# Code holds a missing denied path with an empty placeholder file. A path
# your allowWrite names, or one inside or above an entry of it, is left
# alone: a deny would override your allow.
home_real = os.path.realpath(os.path.expanduser("~"))
sandbox = settings.setdefault("sandbox", {})
fs = sandbox.setdefault("filesystem", {}) if isinstance(sandbox, dict) else None
deny_write = fs.get("denyWrite", []) if isinstance(fs, dict) else None
allow_write = fs.get("allowWrite", []) if isinstance(fs, dict) else None
if not isinstance(deny_write, list) or not isinstance(allow_write, list):
    sys.exit("sandbox.filesystem in " + path + " has another shape; merge by hand")
allowed = [os.path.realpath(os.path.expanduser(a)).rstrip(os.sep) for a in allow_write
           if isinstance(a, str) and a.startswith(("/", "~/"))]
for folder in dict.fromkeys([base, os.path.expanduser("~/.claude")]):
    for name in ("settings.json", "CLAUDE.md", "stranger-danger"):
        p = os.path.join(folder, name)
        if os.path.islink(p) or not (os.path.lexists(p) or p == path):
            continue
        real = os.path.realpath(p)
        if any(a == real or a.startswith(real + os.sep) or real.startswith(a + os.sep)
               for a in allowed):
            continue
        entry = "~" + real[len(home_real):] if real.startswith(home_real + os.sep) else real
        if entry not in deny_write:
            deny_write.append(entry)
if deny_write:
    fs["denyWrite"] = deny_write
os.makedirs(os.path.dirname(path), exist_ok=True)
if os.path.exists(path):
    shutil.copy2(path, path + ".bak")
with open(path + ".tmp", "w") as fh:
    json.dump(settings, fh, indent=2)
    fh.write("\n")
if os.path.exists(path):
    shutil.copymode(path, path + ".tmp")
os.replace(path + ".tmp", path)
print("merged into " + path)
MERGE"""


def _plain(path: str) -> bool:
    return not any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") for ch in path)


def merge_command(root: str, *templates: str) -> str:
    paths = " ".join(shlex.quote(os.path.join(root, t)) for t in templates)
    return MERGE.replace("TEMPLATES", paths, 1)


def render(root: str) -> str:
    q = lambda rel: shlex.quote(os.path.join(root, rel))  # noqa: E731
    config_dir = "~/.config/stranger-danger"
    return "\n".join([
        "# stranger-danger setup",
        "",
        f"Plugin files: {root}",
        "",
        "Run these yourself, in a terminal. They change your guardrails, so an agent "
        "shouldn't run them. Each one is safe to run twice.",
        "",
        "## In one command",
        "",
        "Steps 1 to 3 at once. It shows every change as a diff and asks before it writes. "
        "Add --automode for step 4 as well. Steps 5 and 6 stay separate.",
        "",
        "```bash",
        f"python3 -I {q('skills/setup/apply.py')}",
        "```",
        "",
        "Or step by step:",
        "",
        "## 1. Settings: permission deny rules and the Bash sandbox",
        "",
        "Merges templates/settings.json and templates/sandbox.json into your "
        "settings.json (CLAUDE_CONFIG_DIR when you've set it, else ~/.claude) and "
        "keeps the old file as settings.json.bak.",
        "",
        "```bash",
        merge_command(root, "templates/settings.json", "templates/sandbox.json"),
        "```",
        "",
        "With the sandbox on, Read deny rules for exact paths (such as ~/.ssh) also hide "
        "those files from sandboxed commands. Glob rules (such as **/.env) don't: on Claude "
        "Code 2.1.280 a sandboxed command can still read a file they cover. Add an exact "
        "Read deny rule for each secret file you keep, such as Read(~/work/app/.env); the "
        "doctor lists the ones in your project that lack one. The settings template's env "
        "entries set npm's min-release-age=7 (said to need npm 11.10.0 or later) and "
        "ignore-scripts=true for the commands Claude Code runs; for your own terminal, put "
        "the same two settings in your project's .npmrc. The README says what they break. The sandbox template also sets "
        "allowUnsandboxedCommands to false, unless you've set it yourself, so a command the "
        "sandbox stops can't be run again outside it.",
        "",
        "The one-command install also adds your start-up paths to "
        "sandbox.filesystem.denyWrite: the folders in your home folder that claude, your "
        "PATH tools and your shell start from, such as ~/.local and ~/.bashrc, each one "
        "only if it exists. This merge doesn't, because they differ per machine: the "
        "doctor's \"start paths\" check lists the ones to add. The one-command install "
        "also adds to sandbox.filesystem.denyRead the untrusted, quarantine and plain secret folders "
        "your gate config names that exist; the doctor's \"sandbox read denies\" check "
        "lists the missing ones.",
        "",
        "## 2. Rules",
        "",
        "Copies the rules file and adds its import line to your CLAUDE.md. The `cdir` "
        "variable follows CLAUDE_CONFIG_DIR when you've set it, else ~/.claude, and the "
        "import line points at the copy in that same folder.",
        "",
        "```bash",
        'cdir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"',
        'imp="@$cdir/stranger-danger/RULES.md"',
        f'if [ "$cdir" = "$HOME/.claude" ]; then imp={shlex.quote(RULES_IMPORT)}; fi',
        'mkdir -p "$cdir/stranger-danger"',
        f'[ -e "$cdir/stranger-danger/RULES.md" ] || cp {q("rules/RULES.md")} '
        '"$cdir/stranger-danger/RULES.md"',
        'grep -qxF "$imp" "$cdir/CLAUDE.md" 2>/dev/null || '
        "printf '\\n%s\\n' \"$imp\" >> \"$cdir/CLAUDE.md\"",
        "```",
        "",
        'Then edit the RULES.md in your stranger-danger folder (`"$cdir/stranger-danger/'
        'RULES.md"`) and list your repos. Leave the <your-canary-word> line as it is: at '
        "your next session start the plugin fills in a random word that no session sees, "
        "and the doctor checks that a session knows it only from the rules. (If you put in "
        "a word of your own instead, don't type it into a Claude Code session.)",
        "",
        "## 3. Gate config (optional: needed for untrusted and quarantine folders)",
        "",
        "```bash",
        f"mkdir -p {config_dir}",
        f"chmod 700 {config_dir}",
        f"[ -e {config_dir}/config.json ] || cp {q('templates/config.json')} "
        f"{config_dir}/config.json",
        f"chmod 600 {config_dir}/config.json",
        "```",
        "",
        f"Then edit the folder lists in {config_dir}/config.json.",
        "",
        "## 4. Auto-mode rules (optional: only if you use auto mode)",
        "",
        "```bash",
        merge_command(root, "templates/automode.json"),
        "```",
        "",
        "## 5. Coordinator (optional: recommended if you run Claude Code in several projects)",
        "",
        "Names one session as the coordinator: it keeps track across your projects and "
        "brings you decisions, and it never approves anything. Run this in the folder whose "
        "session will coordinate, or put that folder's path in folder=. It writes the folder "
        "and name to your gate config and a recognition paragraph to your CLAUDE.md, and "
        "makes a notes folder, .stranger-danger, in that folder. To rename or move it, change "
        "name= or folder= and run it again. To take it out, run install.py with --remove in "
        "place of the folder and name.",
        "",
        "```bash",
        'folder="$PWD"',
        "name='the StrangerDanger coordinator'",
        f'python3 -I {q("skills/coordinator/install.py")} "$folder" "$name"',
        "```",
        "",
        "## 6. Check",
        "",
        "Restart Claude Code, then run /stranger-danger:doctor.",
    ])


def main() -> int:
    root = PLUGIN_ROOT
    if not _plain(root):
        print("stranger-danger setup: the plugin folder's path has control characters; "
              "copy the templates by hand.", file=sys.stderr)
        return 1
    missing = [f for f in FILES if not os.path.isfile(os.path.join(root, f))]
    if missing:
        print(f"stranger-danger setup: missing from {root}: {', '.join(missing)}. "
              "Reinstall the plugin.", file=sys.stderr)
        return 1
    print(render(root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
