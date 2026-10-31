#!/usr/bin/env python3
"""Settings guard: an agent may change setup's own files only as setup would.

The settings template asks, rather than denies, before the file tools change
three things: your settings file, the CLAUDE.md that loads the rules and the
rules folder (both forms when CLAUDE_CONFIG_DIR names another profile). That
lets /stranger-danger:setup make them in chat, one prompt each. This hook
refuses every Edit, Write, MultiEdit and NotebookEdit call to those, and to
the gate config folder, except a Write whose text is exactly what setup in
chat works out from your files as they are now (skills/setup/chat.py, which
uses apply.py's plan). A Write it lets through then gets the normal prompt,
with its diff, so you still approve or decline it. A changed rule, a dropped
deny, a different canary line or a new file in those folders is refused
before you're asked. Edits are refused there too: the guard can't be sure it
would apply one exactly as the tool does.

Which paths count: a path as written or as its real path (a leading ~/ is
your home), compared ignoring case, since a disk that ignores case (macOS by
default) treats Settings.json as settings.json; the file it names, by device
and inode, so a hard link elsewhere counts; and any folder above it, by
device and inode, so a guarded folder reached by another name counts. A
link, a ~user path that could name a guarded file (read either way: as that
user's home, or as a name in the working folder), or, with a relative
CLAUDE_CONFIG_DIR, any settings.json, CLAUDE.md or stranger-danger folder
is refused.

How it compares: with each planned change for that path, with and without
the auto-mode rules, and with and without the OSV check's part
(templates/osv.json). So an agent can stage either option unasked; it still
reaches you as a Write prompt with its diff. JSON files compare as JSON values of the same types
(Python's == says true equals 1), refusing duplicate keys, NaN and Infinity;
other files compare as text with trailing newlines ignored. The plan uses the
folder Claude Code reports as the session's working folder.

It reads the hook event on stdin. Exit 2 refuses; exit 0 passes. Any error,
input it can't read, or a timeout refuses a call to these files; calls to
any other file pass at once. Each refusal it decides is logged with a code,
the tool and the agent_type (see _log.py). It runs as you, so anything that
can write these files outside Claude Code's tools (your own editor, or a
command outside the sandbox) isn't stopped by it. Standard library only.
"""
from __future__ import annotations

import json
import os
import signal
import sys
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(HERE)
for _p in (HERE, os.path.join(PLUGIN_ROOT, "skills", "setup")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _log import log_deny  # noqa: E402

GUARD_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
MAX_INPUT_BYTES = 64 << 20
TIMEOUT_SECONDS = 5


def _printable(text: str, limit: int = 160) -> str:
    return "".join(c if c.isprintable() and c.isascii() else "?" for c in text)[:limit]


def config_dir(home: str, env_value: Optional[str]) -> Optional[str]:
    """The profile folder in use, or None for a relative CLAUDE_CONFIG_DIR."""
    if env_value:
        return env_value if os.path.isabs(env_value) else None
    return os.path.join(home, ".claude")


ZONE_FILES = ("settings.json", "CLAUDE.md")
ZONE_FOLDER = "stranger-danger"


def zone(home: str, cdir: str) -> tuple:
    """(files, folders) the guard covers, as absolute paths."""
    files, folders = set(), set()
    for base in {cdir, os.path.join(home, ".claude")}:
        files.update(os.path.join(base, name) for name in ZONE_FILES)
        folders.add(os.path.join(base, ZONE_FOLDER))
    folders.add(os.path.join(home, ".config", ZONE_FOLDER))
    return files, folders


def _forms(path: str) -> set:
    """The path as written and as its real path, case-folded: on a disk that
    ignores case (macOS by default) Settings.json is settings.json."""
    return {os.path.normpath(path).casefold(), os.path.realpath(path).casefold()}


def _ids(paths) -> set:
    """(device, inode) of each path that exists, following links."""
    out = set()
    for p in paths:
        try:
            info = os.stat(p)
        except OSError:
            continue
        out.add((info.st_dev, info.st_ino))
    return out


def in_zone(path: str, home: str, cdir: str) -> bool:
    """Whether `path` is, or is inside, one of the guarded files or folders:
    by its text (as written or real, ignoring case), by the file it names (a
    hard link elsewhere to a guarded file), or by any folder above it (a
    guarded folder reached by another name)."""
    files, folders = zone(home, cdir)
    file_forms = set().union(*(_forms(f) for f in files))
    folder_forms = set().union(*(_forms(d) for d in folders))
    for form in _forms(path):
        if form in file_forms or any(form == d or form.startswith(d.rstrip(os.sep) + os.sep)
                                     for d in folder_forms):
            return True
    file_ids, folder_ids = _ids(files), _ids(folders)
    try:
        info = os.stat(path)
        if (info.st_dev, info.st_ino) in file_ids | folder_ids:
            return True
    except OSError:
        pass
    parent = os.path.dirname(os.path.abspath(path))
    while True:
        if _ids([parent]) & folder_ids:
            return True
        up = os.path.dirname(parent)
        if up == parent:
            return False
        parent = up


def _no_constants(name: str):
    raise ValueError(f"{name} isn't JSON")


def _strict_json(text: str):
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=_no_constants)


def _typed_equal(a, b) -> bool:
    """Equal values of the same JSON types: Python's == says True == 1 and
    1 == 1.0, which mean different things in a settings file."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_typed_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_typed_equal(x, y) for x, y in zip(a, b))
    return a == b


def same_text(path: str, got: str, planned: str) -> bool:
    """JSON files compare as JSON values of the same types, refusing duplicate
    keys and NaN or Infinity; other files compare as text, with trailing
    newlines ignored."""
    if path.endswith(".json"):
        try:
            return _typed_equal(_strict_json(got), _strict_json(planned))
        except (ValueError, RecursionError):
            return False
    return got.rstrip("\r\n") == planned.rstrip("\r\n")


def allowed(path: str, got: str, home: str, cdir: str, workdir: str) -> bool:
    """Whether `got` is setup in chat's planned text for `path`."""
    import chat
    target = _forms(path)
    paths = chat.Paths(home, cdir)
    for automode, osv in ((False, False), (True, False), (False, True), (True, True)):
        try:
            changes = chat.chat_plan(paths, automode, workdir, osv=osv)
        except chat.apply.Stop:
            return False
        for planned_path, _old, planned, _mode in changes:
            if _forms(planned_path) & target and same_text(planned_path, got, planned):
                return True
    return False


def _looks_guarded(path: str) -> bool:
    """With no fixed profile folder, any settings.json, CLAUDE.md or
    stranger-danger folder could be the active one."""
    parts = [p.casefold() for p in os.path.normpath(path).split(os.sep)]
    return bool(parts) and (parts[-1] in {n.casefold() for n in ZONE_FILES}
                            or ZONE_FOLDER in parts)


def check(event: dict, home: str, env_cdir: Optional[str]) -> Optional[str]:
    """The refusal reason, or None."""
    tool = event.get("tool_name")
    if tool not in GUARD_TOOLS:
        return None
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return "settings guard: the call has no tool input; blocked to be safe."
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if path is None:
        return None  # no file to place; the tool itself refuses such a call
    workdir = event.get("cwd")
    if not isinstance(path, str) or not path or "\0" in path:
        return "settings guard: the call's path can't be read; blocked to be safe."
    if path == "~" or path.startswith("~/"):
        path = home + path[1:]
    elif path.startswith("~"):
        # ~user/... or a file named ~notes.md: refused only if either reading
        # lands on a guarded file, since which one the tool uses isn't known.
        expanded = os.path.expanduser(path)  # unchanged when there's no such user
        readings = [expanded] if expanded != path else []
        if isinstance(workdir, str) and os.path.isabs(workdir):
            readings.append(os.path.join(workdir, path))
        cdir = config_dir(home, env_cdir)
        if not readings:
            return "settings guard: a ~user path can't be placed; blocked to be safe."
        for reading in readings:
            if not os.path.isabs(reading) or (
                    in_zone(reading, home, cdir) if cdir is not None
                    else in_zone(reading, home, os.path.join(home, ".claude"))
                    or _looks_guarded(reading)):
                return "settings guard: a ~user path can't be placed; blocked to be safe."
        return None
    if not os.path.isabs(path):
        if not (isinstance(workdir, str) and os.path.isabs(workdir)):
            return "settings guard: a relative path with no working folder; blocked to be safe."
        path = os.path.join(workdir, path)
    cdir = config_dir(home, env_cdir)
    if cdir is None:
        if in_zone(path, home, os.path.join(home, ".claude")) or _looks_guarded(path):
            return ("settings guard: CLAUDE_CONFIG_DIR is a relative path, so the guarded "
                    "files can't be placed; blocked to be safe.")
        return None
    if not in_zone(path, home, cdir):
        return None
    shown = _printable(path)
    if os.path.islink(path):
        return (f"settings guard: {shown} is a link, so it's refused: the change could land "
                "somewhere else. Change it yourself, in your own editor.")
    refusal = (f"settings guard: {tool} to {shown} isn't the change /stranger-danger:setup "
               "works out, so it's refused before you're asked. Agents change this file only "
               "through setup in chat, which stages each file's exact new text for the Write "
               "tool. If you meant to change it yourself, do it in your own editor. If setup "
               "itself was refused, run its plan again: a file may have changed.")
    content = tool_input.get("content")
    # Only Write: the guard can't be sure it applies an Edit exactly as the tool does.
    if tool != "Write" or not isinstance(content, str):
        return refusal
    if not isinstance(workdir, str) or not os.path.isabs(workdir):
        return refusal
    if not allowed(path, content, home, cdir, workdir):
        return refusal
    return None


def _deny(reason: str, *, code: str, event=None) -> int:
    log_deny(code, event, _printable)
    print(reason, file=sys.stderr)
    return 2


def _on_alarm(_signum, _frame):  # pragma: no cover - exercised in a subprocess
    os.write(2, b"settings guard: timed out while checking; blocked to be safe.\n")
    os._exit(2)


def main() -> int:
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(TIMEOUT_SECONDS)
    event = None
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            return _deny("settings guard: hook input too large; blocked to be safe.",
                         code="settings-guard-bad-input")
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return _deny("settings guard: hook input isn't valid JSON; blocked to be safe.",
                         code="settings-guard-bad-input")
        if not isinstance(event, dict):
            return _deny("settings guard: hook input isn't a JSON object; blocked to be safe.",
                         code="settings-guard-bad-input")
        reason = check(event, os.path.expanduser("~"), os.environ.get("CLAUDE_CONFIG_DIR") or None)
        return _deny(reason, code="settings-guard", event=event) if reason else 0
    except Exception as exc:  # a timeout or anything unexpected blocks
        return _deny(f"settings guard: internal error ({type(exc).__name__}); blocked to be safe.",
                     code="settings-guard-internal", event=event)
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
