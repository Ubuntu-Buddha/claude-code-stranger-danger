#!/usr/bin/env python3
"""SessionStart hook: after Claude Code or this plugin changes, suggest the doctor.

The gates rely on how Claude Code runs hooks, sandboxes commands and reads
settings, and an update can change any of that. So at the first session after
one, this shows you a fixed line asking you to run /stranger-danger:doctor.
hooks.json runs it only when a session starts or resumes (not on /clear or
compaction, which keep the process that was already running).

How it notices an update: no hook input or environment variable gives the
Claude Code version, and running ``claude --version`` at every session start
would be slow. Instead it notes the ``claude`` that's first on PATH (absolute
PATH entries only; its real path, size, inode and change times) and this
plugin's version, and keeps a hash of them in
``~/.local/state/stranger-danger/last-seen.json``, with the last few it saw,
so switching between a terminal and the desktop app doesn't remind you each
time. A ``claude`` that isn't on PATH, such as the desktop app's own copy,
isn't seen, so its updates aren't noticed (only plugin updates are). A
headless run (``claude -p``, the Agent SDK) that starts first sees the change
first, and nobody reads its reminder.

It shows only its own fixed text, never anything it read (it uses nothing from
the event), and only to you
(``systemMessage``), not as an instruction to Claude. It makes no network call
and runs nothing. It never blocks a session: Claude Code's docs say no exit
code from a SessionStart hook does, an error before it prints means no
reminder, and it stops itself after a few seconds. It prints before it saves,
so a state folder it can't write means a reminder at every start, not none. It runs as you, so anything that can write
that folder can silence it; it's a reminder, not a guard.

Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(HERE)
MAX_STATE_BYTES = 4096
MAX_INPUT_BYTES = 1_000_000
KEEP_SEEN = 8  # hashes remembered, newest first
TIME_LIMIT = 3  # seconds, well inside hooks.json's 10

USER_TEXT = ("StrangerDanger: Claude Code or the plugin is new or has changed since your "
             "last session. Run /stranger-danger:doctor to check the gates still work.")


def state_path(home: str) -> str:
    return os.path.join(home, ".local", "state", "stranger-danger", "last-seen.json")


def plugin_version(root: str) -> str:
    try:
        with open(os.path.join(root, ".claude-plugin", "plugin.json"), encoding="utf-8") as fh:
            version = json.load(fh).get("version")
    except (OSError, ValueError, AttributeError):
        return "unknown"
    return version if isinstance(version, str) else "unknown"


def fingerprint(path_env: str, root: str) -> str:
    """A hash of the claude on PATH and the plugin's version. npm sets every
    file's time in a package to a fixed date, so the inode and change time
    (which a reinstall renews and nobody can set) count as well as the size."""
    parts: list = ["v2", plugin_version(root)]
    # A relative entry (`.`, node_modules/.bin) finds a different claude in each folder.
    absolute = os.pathsep.join(e for e in path_env.split(os.pathsep) if os.path.isabs(e))
    claude = shutil.which("claude", path=absolute) if absolute else None
    if claude:
        real = os.path.realpath(claude)
        try:
            info = os.stat(real)
            parts += [real, info.st_size, info.st_ino, info.st_dev, info.st_mtime_ns,
                      info.st_ctime_ns]
        except OSError:
            parts.append("unreadable")
    else:
        parts.append("no-claude")
    return hashlib.sha256(json.dumps(parts).encode("utf-8", "surrogateescape")).hexdigest()


def last_seen(path: str) -> list:
    """The hashes saved before, newest first; [] when there are none."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return []
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return []
        data = json.loads(os.read(fd, MAX_STATE_BYTES).decode("ascii"))
    except (OSError, ValueError, RecursionError):
        return []
    finally:
        os.close(fd)
    seen = data.get("seen") if isinstance(data, dict) else None
    if not isinstance(seen, list):
        return []
    return [s for s in seen if isinstance(s, str) and len(s) == 64][:KEEP_SEEN]


def save(path: str, seen: list) -> None:
    """Replace the state file, through a new file in the same folder."""
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".last-seen-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(json.dumps({"seen": seen[:KEEP_SEEN]}) + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def nudge(home: str, path_env: str, root: str = PLUGIN_ROOT, emit=None):
    """The hook's output as a dict, or None when this setup was seen recently.
    Records what it saw, after handing the output to `emit` when given, so a
    hook stopped in between reminds you again rather than not at all."""
    path = state_path(home)
    now = fingerprint(path_env, root)
    seen = last_seen(path)
    if now in seen:
        return None
    out = {"systemMessage": USER_TEXT}
    if emit is not None:
        emit(out)
    save(path, [now] + seen)
    return out


def _stop(_signum, _frame) -> None:
    os._exit(0)  # a stalled check means no reminder, never a slow start


def _print(out: dict) -> None:
    print(json.dumps(out), flush=True)


def main() -> int:
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _stop)
        signal.alarm(TIME_LIMIT)
    try:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        from _config import home_dir
        nudge(home_dir(), os.environ.get("PATH", ""), emit=_print)
    except Exception:
        return 0
    # The event isn't used. It's read after the work, so a stdin left open
    # costs only the alarm's wait, never the reminder.
    try:
        sys.stdin.buffer.read(MAX_INPUT_BYTES)
    except (OSError, ValueError):
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
