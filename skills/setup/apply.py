#!/usr/bin/env python3
"""stranger-danger apply: the whole baseline install in one command.

You run this yourself, in a terminal. It works out every change first, shows
each one as a diff, and writes nothing until you type "y". An agent shouldn't
run it: it changes your guardrails. It refuses to run without a terminal, and
the settings template and the sandbox keep agents out of these files anyway.

    python3 -I apply.py              settings, sandbox, rules and gate config
    python3 -I apply.py --automode   the same, plus the auto-mode rules

What it changes (``$CLAUDE_CONFIG_DIR`` when set, else ``~/.claude``):

- ``settings.json``: merges templates/settings.json and templates/sandbox.json
  (and templates/automode.json with --automode). Objects merge key by key and
  lists gain only the entries they lack; nothing you have is removed. A value
  of another type stops it, with nothing written. The old file is kept as
  ``settings.json.bak``.
- ``stranger-danger/RULES.md``: copied from rules/RULES.md if it isn't there.
- ``CLAUDE.md``: gains the rules import line if it lacks it (old file kept as
  ``CLAUDE.md.bak``).
- ``~/.config/stranger-danger/config.json``: copied from templates/config.json
  if it isn't there, at mode 600 in a folder at mode 700.

Safe to run twice: the second run finds nothing to change. The coordinator is
a separate, optional step (setup step 5).

Standard library only.
"""
from __future__ import annotations

import difflib
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_IMPORT = "@~/.claude/stranger-danger/RULES.md"


class Stop(Exception):
    """A change that can't be made safely; nothing is written."""


def merge(into: dict, new: dict, where: str = "") -> None:
    """Objects merge key by key, lists gain the entries they lack, and other
    values take the template's value. The same rules as setup's step 1."""
    for key, value in new.items():
        old = into.get(key)
        if isinstance(value, dict) and isinstance(old, dict):
            merge(old, value, where + key + ".")
        elif isinstance(value, list) and isinstance(old, list):
            old.extend(v for v in value if v not in old)
        elif key in into and type(old) is not type(value):
            raise Stop(f"{where}{key} in your settings has another type than the template's; "
                       "merge that key by hand")
        else:
            into[key] = value


def profile_rules(template: dict, cdir: str, home: str) -> dict:
    """`template`, plus a copy of each rule that names ~/.claude/ for another
    profile folder (CLAUDE_CONFIG_DIR): its CLAUDE.md, settings, hooks and
    agents need the same protection."""
    if os.path.realpath(cdir) == os.path.realpath(os.path.join(home, ".claude")):
        return template
    perms = template.get("permissions")
    if not isinstance(perms, dict):
        return template
    # Both the path as given and its real path: a rule naming a symlink may
    # not match an edit made through the real path.
    forms = list(dict.fromkeys([cdir.rstrip("/"), os.path.realpath(cdir)]))
    for kind in ("deny", "ask"):
        rules = perms.get(kind)
        if isinstance(rules, list):
            # The profile's own .claude.json (MCP servers, account state) moves
            # into it too under CLAUDE_CONFIG_DIR.
            rules += [r.replace("(~/.claude/", "(/" + form + "/", 1)
                      .replace("(~/.claude.json)", "(/" + form + "/.claude.json)", 1)
                      for form in forms for r in rules
                      if isinstance(r, str) and ("(~/.claude/" in r or "(~/.claude.json)" in r)]
    return template


def _read(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _json_text(data) -> str:
    return json.dumps(data, indent=2) + "\n"


def plan(root: str, home: str, cdir: str, config_path: str, automode: bool) -> list:
    """[(path, old text or None, new text, mode for a new file)] for each file
    that changes. Raises Stop when a change can't be made safely."""
    changes = []
    templates = ["templates/settings.json", "templates/sandbox.json"]
    if automode:
        templates.append("templates/automode.json")
    path = os.path.join(cdir, "settings.json")
    old = _read(path)
    try:
        settings = json.loads(old) if old is not None else {}
    except ValueError:
        raise Stop(f"{path} isn't valid JSON; fix it first") from None
    if not isinstance(settings, dict):
        raise Stop(f"{path} isn't a JSON object; merge by hand")
    merged = json.loads(json.dumps(settings))
    for rel in templates:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            merge(merged, profile_rules(json.load(fh), cdir, home))
    if merged != settings:
        changes.append((path, old, _json_text(merged), 0o600))

    rules = os.path.join(cdir, "stranger-danger", "RULES.md")
    if not os.path.lexists(rules):
        changes.append((rules, None, _read(os.path.join(root, "rules", "RULES.md")), 0o644))

    claude_md = os.path.join(cdir, "CLAUDE.md")
    line = DEFAULT_IMPORT if os.path.normpath(cdir) == os.path.join(home, ".claude") \
        else "@" + rules
    old = _read(claude_md)
    if line not in (old or "").splitlines():
        base = (old or "").rstrip("\n")
        changes.append((claude_md, old, (base + "\n\n" if base else "") + line + "\n", 0o644))

    if not os.path.lexists(config_path):
        changes.append((config_path, None,
                        _read(os.path.join(root, "templates", "config.json")), 0o600))
    return changes


def show(changes: list) -> str:
    out = []
    for path, old, new, _mode in changes:
        if old is None:
            out.append(f"--- new file: {path} ({len(new.splitlines())} lines)")
            if not path.endswith("RULES.md"):
                out.append(new.rstrip("\n"))
        else:
            if path.endswith(".json"):
                # Compare like with like, so the diff shows what's added, not
                # the reformatting (the file is written back with indent 2).
                old = _json_text(json.loads(old))
            out.extend(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                            fromfile=path, tofile=path + " (new)", lineterm=""))
        out.append("")
    return "\n".join(out)


def _write(path: str, text: str, mode: int) -> None:
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    real = os.path.realpath(path)  # a symlinked file is written through
    if os.path.exists(real):
        shutil.copy2(real, real + ".bak")
        mode = os.stat(real).st_mode & 0o777
    fd, tmp = tempfile.mkstemp(prefix=".sd-", dir=os.path.dirname(real))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, real)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def apply(changes: list, config_path: str) -> None:
    for path, _old, new, mode in changes:
        if path == config_path:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            os.chmod(os.path.dirname(path), 0o700)
        _write(path, new, mode)


def main(argv=None, *, ask=input, isatty=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ["--automode"]):
        print("usage: apply.py [--automode]", file=sys.stderr)
        return 2
    if os.environ.get("CLAUDECODE") or not (isatty or sys.stdin.isatty)():
        print("stranger-danger apply: run this yourself, in a terminal. It changes your "
              "guardrails and asks before it writes.", file=sys.stderr)
        return 2
    home = os.path.expanduser("~")
    cdir = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")
    # Both forms become rule text, so neither may hold a pattern character.
    if not os.path.isabs(cdir) or any(c in form for form in (cdir, os.path.realpath(cdir))
                                      for c in "()*?[]{}\\"):
        print("stranger-danger apply: CLAUDE_CONFIG_DIR must be an absolute path with no "
              "( ) * ? [ ] { } or \\. Nothing was changed.", file=sys.stderr)
        return 2
    sys.path.insert(0, os.path.join(PLUGIN_ROOT, "hooks"))
    import _config
    if os.environ.get(_config.ENV_OVERRIDE):
        print(f"stranger-danger apply: {_config.ENV_OVERRIDE} is set; only the plugin's tests "
              "use it. Unset it. Nothing was changed.", file=sys.stderr)
        return 2
    config_path = os.path.join(home, ".config", "stranger-danger", "config.json")
    try:
        changes = plan(PLUGIN_ROOT, home, cdir, config_path, args == ["--automode"])
    except (Stop, OSError) as exc:
        print(f"stranger-danger apply: {exc}. Nothing was changed.", file=sys.stderr)
        return 1
    if not changes:
        print("Nothing to change: the baseline is already in place.")
        return 0
    print(show(changes))
    print("These files change; each one that exists is kept as .bak first:")
    for path, *_ in changes:
        print(f"  {path}")
    try:
        answer = ask("Apply these changes? [y/N] ")
    except EOFError:
        answer = ""
    if answer.strip().lower() not in ("y", "yes"):
        print("Nothing was changed.")
        return 1
    try:
        apply(changes, config_path)
    except OSError as exc:
        print(f"stranger-danger apply: {exc}", file=sys.stderr)
        return 1
    print("Done. Next:")
    print(f"  1. Edit {os.path.join(cdir, 'stranger-danger', 'RULES.md')}: list your repos and "
          "replace <your-canary-word> with an unusual word.")
    print(f"  2. Edit the folder lists in {config_path} if you use untrusted or quarantine folders.")
    print("  3. Restart Claude Code and run /stranger-danger:doctor.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
