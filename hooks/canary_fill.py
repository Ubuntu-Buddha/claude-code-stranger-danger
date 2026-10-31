#!/usr/bin/env python3
"""SessionStart hook: give a rules file that still has the canary placeholder
a random word, without any session seeing the word.

Setup in chat copies the rules file with its ``Rules canary:
<your-canary-word>`` line as it is, so the Edit's diff holds no word. If an
agent wrote the word itself, that session would know it without loading the
rules, and the doctor's canary check would prove nothing. So this hook fills
it in at the next session start instead, and says only fixed text. The word
then reaches a session only by loading the rules, which is what the check
tests. The doctor compares the word a session states with the file and prints
only whether it matches.

It changes only a line that is exactly the placeholder line, once stripped,
and never a word you chose. The file is ``$CLAUDE_CONFIG_DIR`` (when it's an
absolute path) or ``~/.claude``, then ``stranger-danger/RULES.md``. It leaves
the file alone unless it's a regular file you own, not a link and with no
second name (a hard link), in a folder that isn't a link, at most 1 MB of
UTF-8 text. It writes a new file in the
same folder and renames it over the old one, keeping its permissions, and
only if the file hasn't changed since it was read. A file it leaves alone
gets the refusal line only while it still has the placeholder, so a linked
rules file with a word in it says nothing.

What it shows you (``systemMessage``, not an instruction to Claude) is one of
two fixed lines, never the word or anything it read; most starts it shows
nothing. It uses nothing from the event, makes no network call and runs
nothing. It never blocks a session: no exit code from a SessionStart hook
does, and it stops itself after a few seconds. It runs as you, so anything
that can write the rules file can change the word; the canary shows that
the rules loaded, it isn't a guard.

Standard library only.
"""
from __future__ import annotations

import json
import os
import signal
import stat
import sys
import tempfile
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import _canary  # noqa: E402
from _config import home_dir  # noqa: E402

MAX_RULES_BYTES = 1_000_000
MAX_INPUT_BYTES = 1_000_000
TIME_LIMIT = 3  # seconds, well inside hooks.json's 10

FILLED_TEXT = ("StrangerDanger: your rules file got a random canary word. It isn't shown "
               "anywhere. Start a new session, then run /stranger-danger:doctor to check "
               "that your rules load.")
REFUSED_TEXT = ("StrangerDanger: your rules file still has the canary placeholder, and the "
                "plugin left it alone: it isn't a plain UTF-8 file you own with one name, "
                "its folder can't be written, or it changed while being read. Put an unusual "
                "word in its place in your own editor.")


def rules_path(home: str, config_dir: Optional[str]) -> Optional[str]:
    """Where this profile's rules file is; None for a relative CLAUDE_CONFIG_DIR,
    which names no fixed folder."""
    if config_dir:
        if not os.path.isabs(config_dir):
            return None
        base = config_dir
    else:
        base = os.path.join(home, ".claude")
    return os.path.join(base, "stranger-danger", "RULES.md")


def _owned_regular(info) -> bool:
    return (stat.S_ISREG(info.st_mode)
            and (not hasattr(os, "getuid") or info.st_uid == os.getuid()))


_PENDING: list = []  # a temporary file to remove if the alarm stops the hook


def _has_placeholder(path: str) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False
    try:
        data = os.read(fd, MAX_RULES_BYTES + 1)
    except OSError:
        return False
    finally:
        os.close(fd)
    return _canary.fill(data.decode("utf-8", "replace"), "x") is not None


def _refused(path: str) -> str:
    """For a file the hook won't write: "refused" while it still has the
    placeholder, so you're told, else "set". It only reads, following a link
    (a dotfiles manager's link is fine to read); a file it can't read counts
    as still having the placeholder."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return "refused"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RULES_BYTES:
            return "refused"
        data = os.read(fd, MAX_RULES_BYTES + 1)
    except OSError:
        return "refused"
    finally:
        os.close(fd)
    return "refused" if _canary.fill(data.decode("utf-8", "replace"), "x") is not None \
        else "set"


def fill_file(path: str, make=_canary.make) -> str:
    """Fill the placeholder in. Returns "filled", "set" (nothing to fill,
    including a missing file) or "refused"."""
    folder = os.path.dirname(path)
    try:
        if stat.S_ISLNK(os.lstat(folder).st_mode):
            return _refused(path)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return "set"
    except OSError:
        # A link opened with O_NOFOLLOW lands here too.
        return _refused(path) if os.path.lexists(path) else "set"
    try:
        before = os.fstat(fd)
        # A second name (a hard link) would keep the old text after the rename.
        if not _owned_regular(before) or before.st_size > MAX_RULES_BYTES \
                or before.st_nlink > 1:
            return _refused(path)
        data = os.read(fd, MAX_RULES_BYTES + 1)
    except OSError:
        return "refused"
    finally:
        os.close(fd)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "refused" if _canary.LINE.encode() in data else "set"
    new = _canary.fill(text, make())
    if new is None:
        return "set"
    # The alarm waits while the copy is made and noted, so it can't leave one.
    masked = hasattr(signal, "pthread_sigmask") and hasattr(signal, "SIGALRM")
    if masked:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    try:
        fd, tmp = tempfile.mkstemp(prefix=".RULES-", dir=folder)
        _PENDING.append(tmp)
    except OSError:
        return "refused"  # a folder it can't write
    finally:
        if masked:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), stat.S_IMODE(before.st_mode))
            fh.write(new.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        now = os.lstat(path)
        if (now.st_ino, now.st_dev, now.st_size, now.st_mtime_ns) != (
                before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns):
            os.unlink(tmp)
            # Another session starting at the same moment may have filled it.
            return "refused" if _has_placeholder(path) else "set"
        os.replace(tmp, path)
    except BaseException as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if isinstance(exc, OSError):
            return "refused"  # a full disk, say: the placeholder stays, and you're told
        raise
    finally:
        _PENDING.remove(tmp)
    return "filled"


def run(home: str, config_dir, emit=None):
    """The hook's output as a dict, or None when there's nothing to say."""
    path = rules_path(home, config_dir)
    if path is None:
        return None
    result = fill_file(path)
    out = {"filled": {"systemMessage": FILLED_TEXT},
           "refused": {"systemMessage": REFUSED_TEXT}}.get(result)
    if out is not None and emit is not None:
        emit(out)
    return out


def _stop(_signum, _frame) -> None:
    # A stalled fill means no word yet, never a slow start, and no stray copy.
    for tmp in _PENDING:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    os._exit(0)


def _print(out: dict) -> None:
    print(json.dumps(out), flush=True)


def main() -> int:
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _stop)
        signal.alarm(TIME_LIMIT)
    try:
        run(home_dir(), os.environ.get("CLAUDE_CONFIG_DIR") or None, emit=_print)
    except Exception:
        return 0
    # The event isn't used; read it after the work, as doctor_nudge does.
    try:
        sys.stdin.buffer.read(MAX_INPUT_BYTES)
    except (OSError, ValueError):
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
