#!/usr/bin/env python3
"""stranger-danger setup in chat: what the setup skill runs, step by step.

The skill (SKILL.md) runs these commands, then writes each file with the
Write tool, so you approve one prompt per file and see its diff. Nothing
here writes your files. The settings guard hook (hooks/settings_guard.py)
works out the same plan and refuses any edit to these files that isn't it.

    chat.py check                     is your settings file safe to read?
    chat.py plan [--automode] [--osv]       which files change
    chat.py show NAME [--automode] [--osv]  stage one file's new text for the Write
    chat.py next                      the steps only you can do, with real paths

NAME is rules, claude-md or settings, the order the skill writes them in, so
the settings file is planned last, once the files it denies sandboxed writes
to exist.

``check`` comes first because Claude has to read your settings file to
change it, and whatever it reads lands in the session. It prints only the
names of values that look like secrets, never a value. ``plan`` and
``show`` refuse while ``check`` doesn't pass. That's this script's own
order; nothing stops a session reading the file some other way.

It plans what apply.py plans, with these differences: the rules file keeps
its canary placeholder (the canary_fill hook fills it in at a later start,
so no session sees the word except by loading the rules); your PATH isn't
used for the sandbox's start-up paths (the hook couldn't know the shell's
PATH), so only the fixed list is added; the folder Claude Code works in
counts as the work folder; a file not yet written gets no sandbox write deny
until a later run; and the gate config isn't written (see chat_plan), so
``next`` gives the one command that creates it.

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import apply  # noqa: E402

# Shapes of keys and tokens: GitHub, Anthropic and OpenAI-style, AWS, Slack,
# Google, GitLab, npm, PyPI, PEM blocks, Stripe-style and JWTs; a key handed
# over in a header or an assignment; and a URL with a password in it.
SECRET_VALUE = re.compile(
    r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gh[ousr]_[A-Za-z0-9]{20,}"
    r"|sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{32,}|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20}"
    r"|npm_[A-Za-z0-9]{36}|pypi-AgE[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z0-9 ]+-----"
    r"|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
    r"|(?i:bearer)\s+[^\s\"']{8,}"
    r"|(?i:token|api[-_]?key|password|passwd|secret)[\"']?\s*[:=]\s*[\"']?[^\s\"'&]{8,}"
    r"|[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")
# An env entry whose name says it holds one, or whose value is a long run of
# key characters with no spaces.
SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASS|CREDENTIAL|AUTH|COOKIE|SESSION|PRIVATE|BEARER",
                         re.IGNORECASE)
LONG_RUN = re.compile(r"[A-Za-z0-9+/=_.-]{32,}")
MAX_SHOWN = 10
STAGE_PREFIX = "stranger-danger-setup-"
# The names `show` takes, and the order the skill writes the files in.
NAMES = ("rules", "claude-md", "settings")


class Duplicate(ValueError):
    pass


def _printable(text: str, limit: int = 60) -> str:
    return "".join(c if c.isprintable() and c.isascii() else "?" for c in text)[:limit]


def _pairs(items):
    keys = [k for k, _ in items]
    if len(keys) != len(set(keys)):
        raise Duplicate("duplicate key")
    return dict(items)


def _long_run(value: str) -> bool:
    """A long run of key characters. In a path (/... or ~/...), each folder name
    is judged on its own, so a long path such as a CA bundle's isn't a hit."""
    if value.startswith(("/", "~/")):
        return any(LONG_RUN.search(part) for part in value.split("/"))
    return bool(LONG_RUN.search(value))


def secret_paths(data, where: str = "") -> list:
    """Dotted paths of the values in `data` that look like secrets."""
    found = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{where}.{key}" if where else str(key)
            if where == "env" and isinstance(value, str) and value and (
                    SECRET_NAME.search(str(key)) or _long_run(value)):
                found.append(path)
            else:
                found += secret_paths(value, path)
    elif isinstance(data, list):
        for i, value in enumerate(data):
            found += secret_paths(value, f"{where}[{i}]")
    elif isinstance(data, str) and SECRET_VALUE.search(data):
        found.append(where)
    return found


class Paths:
    def __init__(self, home: str, cdir: str):
        self.home, self.cdir = home, cdir
        self.settings = os.path.join(cdir, "settings.json")
        self.rules = os.path.join(cdir, "stranger-danger", "RULES.md")
        self.claude_md = os.path.join(cdir, "CLAUDE.md")
        self.config = os.path.join(home, ".config", "stranger-danger", "config.json")

    def name_of(self, path: str) -> str:
        return {self.rules: "rules", self.claude_md: "claude-md",
                self.settings: "settings"}.get(path, "")


def _how_to_fix(paths: Paths, step: str) -> list:
    return ["What to do, in your own editor (not in Claude Code):",
            f"  1. Open {paths.settings}.",
            f"  2. {step}",
            "  3. Save the file, start a new Claude Code session and run "
            "/stranger-danger:setup again."]


def check(paths: Paths) -> tuple:
    """(lines to print, exit code). 0 means setup in chat may read the file."""
    text = apply._read(paths.settings) if os.path.lexists(paths.settings) else None
    if text is None:
        return ([f"settings check: {paths.settings} doesn't exist yet, so there's nothing "
                 "to read."], 0)
    try:
        data = json.loads(text, object_pairs_hook=_pairs)
    except Duplicate:
        return ([f"settings check: {paths.settings} names the same key twice in one place. "
                 "Only the last one counts, and the others weren't checked, so setup in "
                 "chat stops here."]
                + _how_to_fix(paths, "Keep one of each repeated key and delete the others."),
                1)
    except (ValueError, RecursionError):
        return ([f"settings check: {paths.settings} isn't valid JSON, so setup in chat "
                 "stops here.",
                 "Fix it in your own editor (not in Claude Code), then run "
                 "/stranger-danger:setup again."], 1)
    hits = secret_paths(data)
    if hits:
        shown = ", ".join(_printable(h) for h in hits[:MAX_SHOWN])
        more = f" and {len(hits) - MAX_SHOWN} more" if len(hits) > MAX_SHOWN else ""
        return ([f"settings check: {paths.settings} holds {len(hits)} value(s) that look "
                 f"like secrets, at: {shown}{more}.",
                 "Setup in chat has to read this file to change it, and whatever it reads "
                 "lands in the session, so it stops here. Its values weren't shown."]
                + _how_to_fix(paths, "Move each value named above out of it: for example "
                              "into your shell's start file (such as ~/.bashrc) as export "
                              "NAME=value, or into your system's key store.")
                + ["If none of them is a secret (a name can match by chance), you can set up "
                   "in a terminal of your own instead, which never shows the file to a "
                   "session: python3 -I "
                   + shlex.quote(os.path.join(PLUGIN_ROOT, "skills", "setup", "apply.py"))],
                1)
    perms = data.get("permissions") if isinstance(data, dict) else None
    deny = perms.get("deny") if isinstance(perms, dict) else None
    stuck = [r for r in apply.moved_rules(paths.cdir, paths.home)
             if isinstance(deny, list) and r in deny]
    if stuck:
        return ([f"settings check: {paths.settings} denies edits to the files setup "
                 "changes (the v0.1 template did, or you kept the deny), and a deny wins over "
                 "the prompt, so setup in chat stops here."]
                + _how_to_fix(paths, "In permissions.deny, delete these lines: "
                              + ", ".join(stuck) + ". Setup puts them in permissions.ask, and "
                              "the settings guard hook refuses any edit to these files but "
                              "setup's own.")
                + ["If you keep that deny on purpose, set up from a terminal instead: ask "
                   "for the terminal install."], 1)
    return ([f"settings check: found nothing in {paths.settings} that looks like a secret."],
            0)


def chat_plan(paths: Paths, automode: bool, workdir: str, notes=None, osv: bool = False) -> list:
    """apply.plan as setup in chat makes it (see the module docstring), less
    the gate config: the Write tool creates files with your default mode,
    which can let your group write them (a umask of 002, which pam_umask's
    usergroups setting gives on systems with a group per user, such as
    Ubuntu), and the gates refuse a config like that. next_steps gives the
    command."""
    return [c for c in apply.plan(PLUGIN_ROOT, paths.home, paths.cdir, paths.config, automode,
                                  "", notes, fill=False, workdir=workdir, deny_new=False, osv=osv)
            if c[0] != paths.config]


def config_command(paths: Paths) -> str:
    """One command that creates the gate config from the template, private."""
    template = os.path.join(PLUGIN_ROOT, "templates", "config.json")
    folder = shlex.quote(os.path.dirname(paths.config))
    return (f"mkdir -p {folder} && chmod 700 {folder} && install -m 600 "
            f"{shlex.quote(template)} {shlex.quote(paths.config)}")


def stage(text: str, name: str, base: str) -> str:
    """Write one file's new text into a new private folder under `base`, for
    the skill to read and copy into the Write. Returns its path."""
    folder = tempfile.mkdtemp(prefix=STAGE_PREFIX, dir=base)
    path = os.path.join(folder, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return path


def clear_staged(base: str) -> int:
    """Remove the folders `stage` made under `base` (yours, real folders, not
    links), since each holds a full copy of a file's new text. Returns how many."""
    removed = 0
    try:
        names = os.listdir(base)
    except OSError:
        return 0
    for name in names:
        if not name.startswith(STAGE_PREFIX):
            continue
        folder = os.path.join(base, name)
        try:
            info = os.lstat(folder)
            if not stat.S_ISDIR(info.st_mode) or (
                    hasattr(os, "getuid") and info.st_uid != os.getuid()):
                continue
            shutil.rmtree(folder)
            removed += 1
        except OSError:
            continue
    return removed


def _loose(path: str) -> bool:
    """Whether others than you can write it (group or world write bits). A
    link is left out: chmod would change what it points to, not setup's file."""
    try:
        info = os.lstat(path)
        return not stat.S_ISLNK(info.st_mode) and bool(
            info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    except OSError:
        return False


def next_steps(paths: Paths) -> list:
    has_config = os.path.lexists(paths.config)
    loose = [p for p in (paths.settings, paths.claude_md, os.path.dirname(paths.rules),
                         paths.rules) if _loose(p)]
    steps = [
        "What's left is yours to do. Claude can't do these for you, by design:",
        f"  1. List your repos in {paths.rules}, in your own editor: under the line about "
        "your own repos, one per line, as owner/name. Leave its canary line as it is.",
    ]
    if loose:
        steps.append(
            "  2. Files Claude writes get your default permissions, and these let your group "
            "write them too. Make them yours only, in a terminal of your own (not in Claude "
            "Code): chmod go-w " + " ".join(shlex.quote(p) for p in loose))
    n = 3 if loose else 2
    steps += [
        f"  {n}. Restart Claude Code: in a terminal, type /exit and run claude again; in the "
        "desktop app, start a new session. That loads the new settings and rules, and the "
        "plugin fills in your rules canary at a session start, without showing it.",
        f"  {n + 1}. In that new session, run /stranger-danger:doctor and follow what it "
        "flags. If it says the canary isn't filled in yet, start one more session.",
        f"  {n + 2}. Run /stranger-danger:setup once more, in a new session: it adds the "
        "sandbox write denies for files that didn't exist yet, and says when there's "
        "nothing left to change.",
        f"  {n + 3}. Only if you keep documents from others or strangers' code on this "
        "machine: the gate config lists their folders.",
    ]
    sub = iter("abc")
    if not has_config:
        steps.append(f"     {next(sub)}. Create it, in a terminal of your own (not in Claude "
                     "Code), with this one command, which makes it readable only by you: "
                     + config_command(paths))
    steps.append(f"     {next(sub)}. In your own editor, open {paths.config} and list those "
                 "folders under untrusted_paths (documents) and quarantine_paths (strangers' "
                 "code).")
    steps.append(f"     {next(sub)}. Run /stranger-danger:setup again, so sandboxed commands "
                 "can't read those folders either.")
    return steps


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    automode = "--automode" in args
    osv = "--osv" in args
    args = [a for a in args if a not in ("--automode", "--osv")]
    if not args or args[0] not in ("check", "plan", "show", "next") or (
            args[0] == "show" and (len(args) != 2 or args[1] not in NAMES)) or (
            args[0] != "show" and len(args) != 1):
        print("usage: chat.py check | plan [--automode] [--osv] | show rules|claude-md|settings "
              "[--automode] [--osv] | next", file=sys.stderr)
        return 2
    home = os.path.expanduser("~")
    cdir = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")
    if not os.path.isabs(cdir) or any(c in form for form in (cdir, os.path.realpath(cdir))
                                      for c in "()*?[]{}\\"):
        print("stranger-danger setup: CLAUDE_CONFIG_DIR must be an absolute path with no "
              "( ) * ? [ ] { } or \\.", file=sys.stderr)
        return 2
    paths = Paths(home, cdir)
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()
    if args[0] == "next":
        removed = clear_staged(base)
        if removed:
            print(f"Removed setup's {removed} staged cop{'y' if removed == 1 else 'ies'} "
                  "from your temp folder.")
        print("\n".join(next_steps(paths)))
        return 0
    lines, code = check(paths)
    if args[0] == "check" or code:
        print("\n".join(lines))
        return code
    notes: list = []
    try:
        changes = chat_plan(paths, automode, os.getcwd(), notes, osv)
    except UnicodeDecodeError as exc:
        print(f"stranger-danger setup: a file isn't UTF-8 text ({exc.reason}).", file=sys.stderr)
        return 1
    except (apply.Stop, OSError) as exc:
        print(f"stranger-danger setup: {exc}.", file=sys.stderr)
        return 1
    by_name = {paths.name_of(c[0]): c for c in changes}
    if args[0] == "plan":
        for note in notes:
            print(f"Note: {note}")
        if not changes:
            print("Nothing to change: the baseline is already in place.")
            return 0
        print("Setup in chat changes these files, one prompt each, in this order:")
        for name in NAMES:
            if name in by_name:
                path, old, new, _mode = by_name[name]
                kind = "new file" if old is None else "changes"
                print(f"  {name}: {path} ({kind}, {len(new.splitlines())} lines)")
        return 0
    change = by_name.get(args[1])
    if change is None:
        print(f"stranger-danger setup: {args[1]} has nothing to change now.")
        return 0
    staged = stage(change[2], os.path.basename(change[0]), base)
    print(f"Staged: {staged} ({len(change[2].splitlines())} lines). Read it and Write its "
          f"text, exactly, to {change[0]}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
