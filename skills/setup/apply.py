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
  ``settings.json.bak``. It also adds to ``sandbox.filesystem.denyWrite`` the
  start-up paths in your home folder that exist (see start_paths): the folders
  ``claude``, your PATH tools and your shell start from. It leaves out any your
  ``sandbox.filesystem.allowWrite`` names; that's how you keep one writable, since
  a deny you only delete comes back the next time you run it.
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


# Direct children of your home folder that hold what a later shell or `claude`
# runs: Claude Code's native launcher and versions (~/.local), the Node version
# managers an npm-installed claude lives under, other tool folders that go on
# PATH, and shell start files. In a session whose writable folders include your
# home (started in ~, or with --add-dir ~), sandboxed Bash could plant code
# there that later runs outside the sandbox. Each is denied whole: a deeper
# entry can be got round by renaming its parent folder.
START_CANDIDATES = (
    ".local", ".nvm", ".volta", ".fnm", ".npm-global", ".bun", ".deno", ".cargo", ".rustup",
    ".pyenv", ".rbenv", ".asdf", "bin", ".gitconfig", ".bashrc", ".bash_profile", ".bash_login",
    ".bash_aliases", ".profile", ".zshrc", ".zshenv", ".zprofile", ".zlogin",
)
# Never denied whole: Claude Code's own folder and the shared config folder hold
# far more than start-up code (the defaults and your deny rules cover parts),
# and a cache, venv or data folder that a PATH entry sits in is where sandboxed
# pip, npm, uv and poetry write.
START_NEVER = frozenset({".claude", ".config", ".ssh", ".gnupg", ".cache", ".npm", ".venv",
                         ".virtualenvs", ".pnpm-store", ".yarn", ".docker", ".git"})
# Shell start files that bash or zsh reads if they exist. One that doesn't
# exist can't be denied (an empty placeholder would change which file bash
# reads), so an agent could still create it; the doctor lists them.
START_FILES = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv",
               ".zprofile", ".zlogin")


def _home_child(path: str, home: str):
    """The first part of `path` below `home`, or None if it isn't below it."""
    rel = os.path.relpath(os.path.abspath(os.path.expanduser(path)), home)
    if rel == "." or rel.startswith(".." + os.sep) or rel == ".." or os.path.isabs(rel):
        return None
    return rel.split(os.sep, 1)[0]


def start_paths(home: str, path_env: str) -> list:
    """The start-up paths to deny writes to, as absolute paths: the candidates,
    plus the hidden folders (and ~/bin) that a PATH entry or `claude` itself
    sits in. Only ones that exist and aren't symlinks: on Linux, Claude Code
    holds a denied path that doesn't exist with an empty placeholder file, and an empty
    ~/.bash_profile would stop bash reading ~/.profile."""
    home = os.path.realpath(home)
    names = set(START_CANDIDATES)
    # A relative entry (`.`, node_modules/.bin) depends on the folder apply.py
    # runs in, so it says nothing about your start-up paths.
    found = [e for e in path_env.split(os.pathsep) if os.path.isabs(e)]
    claude = shutil.which("claude", path=path_env) if path_env else None
    if claude:
        found += [claude, os.path.realpath(claude)]
    for entry in found:
        for form in (entry, os.path.realpath(entry)):
            child = _home_child(form, home)
            if child and (child.startswith(".") or child == "bin"):
                names.add(child)
    out = []
    for name in sorted(names - START_NEVER):
        path = os.path.join(home, name)
        if os.path.lexists(path) and not os.path.islink(path):
            out.append(path)
    return out


def _deny_write_entries(settings) -> list:
    sandbox = settings.get("sandbox") if isinstance(settings, dict) else None
    fs = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
    entries = fs.get("denyWrite") if isinstance(fs, dict) else None
    return [e for e in entries if isinstance(e, str)] if isinstance(entries, list) else []


def write_denied(path: str, entries: list, home: str) -> bool:
    """Whether a denyWrite entry covers `path`: the path itself, or a folder
    above it, written as an absolute or ~/ path."""
    target = os.path.realpath(path)
    for entry in entries:
        e = _entry_path(entry, home)
        if e and (target == e or target.startswith(e.rstrip(os.sep) + os.sep)):
            return True
    return False


def _entry_path(entry: str, home: str):
    """A sandbox path entry as a real absolute path (~/ is your home), or None."""
    e = os.path.expanduser(entry.replace("~", home, 1) if entry.startswith("~/") else entry)
    return os.path.realpath(e) if os.path.isabs(e) else None


def _allow_write_entries(settings) -> list:
    sandbox = settings.get("sandbox") if isinstance(settings, dict) else None
    fs = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
    entries = fs.get("allowWrite") if isinstance(fs, dict) else None
    return [e for e in entries if isinstance(e, str)] if isinstance(entries, list) else []


def allow_write_relation(path: str, settings, home: str):
    """How your sandbox.filesystem.allowWrite names this path: "same", "inside"
    (an entry in a folder below it) or "above" (an entry for a folder above
    it), or None. A deny would override any of them, so apply.py leaves the path
    alone; the doctor warns for "inside" and "above", which keep the whole path
    writable."""
    target = os.path.realpath(path)
    found = None
    for entry in _allow_write_entries(settings):
        e = _entry_path(entry, home)
        if not e:
            continue
        if e == target:
            return "same"
        if e.startswith(target + os.sep):
            found = found or "inside"
        elif target.startswith(e.rstrip(os.sep) + os.sep):
            found = "above"
    return found


def kept_writable(path: str, settings, home: str) -> bool:
    """Whether your allowWrite keeps this path writable (allow_write_relation)."""
    return allow_write_relation(path, settings, home) is not None


def add_start_paths(settings: dict, home: str, path_env: str) -> list:
    """Add the missing start paths to sandbox.filesystem.denyWrite. Returns the
    ones skipped because your allowWrite keeps them writable."""
    missing, kept = [], []
    for p in start_paths(home, path_env):
        if write_denied(p, _deny_write_entries(settings), home):
            continue
        (kept if kept_writable(p, settings, home) else missing).append(p)
    if not missing:
        return kept
    sandbox = settings.setdefault("sandbox", {})
    fs = sandbox.setdefault("filesystem", {}) if isinstance(sandbox, dict) else None
    deny = fs.setdefault("denyWrite", []) if isinstance(fs, dict) else None
    if not isinstance(deny, list):
        raise Stop("sandbox.filesystem.denyWrite in your settings isn't a list; merge by hand")
    deny.extend(missing)
    return kept


def _read(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _json_text(data) -> str:
    return json.dumps(data, indent=2) + "\n"


def plan(root: str, home: str, cdir: str, config_path: str, automode: bool,
         path_env: str = "", notes=None) -> list:
    """[(path, old text or None, new text, mode for a new file)] for each file
    that changes. Raises Stop when a change can't be made safely. Lines for
    you to read go to `notes` when it's a list."""
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
    kept = add_start_paths(merged, home, path_env)
    if kept and isinstance(notes, list):
        notes.append("Left writable, because your sandbox.filesystem.allowWrite names them: "
                     + ", ".join(kept) + ". Sandboxed commands could plant start-up code "
                     "there in a session whose writable folders include your home folder.")
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
        notes: list = []
        changes = plan(PLUGIN_ROOT, home, cdir, config_path, args == ["--automode"],
                       os.environ.get("PATH", ""), notes)
    except (Stop, OSError) as exc:
        print(f"stranger-danger apply: {exc}. Nothing was changed.", file=sys.stderr)
        return 1
    for note in notes:
        print(f"Note: {note}")
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
