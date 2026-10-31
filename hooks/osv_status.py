#!/usr/bin/env python3
"""SessionStart hook: the OSV check's status, in one or two fixed lines.

/stranger-danger:osv runs only when you type it; nothing scans in the
background. So when a session starts or resumes, this reads the last result,
~/.cache/stranger-danger/osv/daily.json, and tells you when there's
something to act on, in this order:

1. a malware record names a package you hold (ALERT), however old;
2. the last check failed (ERROR), or is still running or never finished;
3. a fix is out for a high or critical vulnerability you hold;
4. the check is stale (over 36 hours old) or due (over 24 hours);
5. there's no result yet, or it can't be read or trusted.

It does nothing unless your settings file has setup's OSV part (its
sandbox write entry for that folder). Then it also makes the results folder,
mode 700, if it's missing: the scan runs in the sandbox, which can write the
folder but can't make its parents. It prints nothing when the result is
fresh and holds none of the above.

Every line is fixed text with only digits filled in. You see the lines
(systemMessage) where your Claude Code app shows hook messages. Claude gets
fixed codes, fixed instructions and the same lines (additionalContext), and
is asked to pass the lines on once: in one check
the desktop app didn't show a session-start hook's message (another hook,
not this plugin's), so there Claude's reply may be the only way the line
reaches you, if the app runs this hook and Claude passes it on (VERIFY row
O3). Names and advisory ids in the file never reach either.
The file is read as untrusted: it must be yours and not writable by others,
no link is followed, no FIFO waited on, at most 32 MiB, no duplicate keys,
NaN or Infinity, and each field must have its exact shape. Your home folder
comes from the password database, not $HOME.

Limits: it shows only at session start. A sandboxed command can write the
results folder (the scan has to), and so can a file-tool write you approve,
so either could forge a fresh OK and silence these lines. It makes no
network call, runs nothing and never blocks a session. An error means no
line; running past its time limit before it has printed means the "can't
be read" line, so a slow read can't silence an ALERT unseen. Standard
library only.
"""
from __future__ import annotations

import calendar
import json
import os
import re
import signal
import stat
import sys
import time
from typing import Optional

RESULTS = (".cache", "stranger-danger", "osv")
OPT_IN = "~/" + "/".join(RESULTS)  # setup's allowWrite entry (templates/osv.json)
MAX_RESULT_BYTES = 32 << 20
MAX_SETTINGS_BYTES = 4 << 20
MAX_INPUT_BYTES = 1_000_000
MAX_COUNT = 999_999_999
TIME_LIMIT = 6  # seconds; with STDIN_LIMIT, inside hooks.json's 10
STDIN_LIMIT = 1  # seconds for the unused event, once the line is out
DUE_SECONDS = 24 * 3600
STALE_SECONDS = 36 * 3600
RUNNING_SECONDS = 2 * 3600
FUTURE_SECONDS = 3600
# What read() found (not decision-log codes).
MISSING, BAD, FOUND = "no file", "unusable", "read"
LEVELS = ("OK", "INFO", "ALERT", "ERROR")
FINISHED = re.compile(r"\A20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z\Z")

RUN = "Run /stranger-danger:osv"
TEXT = {
    "osv_alert": ("StrangerDanger: your last OSV check found a malware record for a package you "
                  "hold. Don't run it. " + RUN + " for the counts and what to do."),
    "osv_error": "StrangerDanger: your last OSV check failed. " + RUN + " to see why.",
    "osv_running": ("StrangerDanger: an OSV check started in the last 2 hours and hasn't "
                    "finished."),
    "osv_unfinished": "StrangerDanger: your last OSV check never finished. " + RUN + " again.",
    "osv_severe_with_fix": ("StrangerDanger: a fix is out for {n} high or critical "
                            "vulnerabilities in packages you hold. " + RUN + " for the counts."),
    "osv_stale": "StrangerDanger: your last OSV check is {h} hours old. " + RUN + ".",
    "osv_due": "StrangerDanger: an OSV check is due; the last one was {h} hours ago. " + RUN + ".",
    "osv_no_result": "StrangerDanger: there's no OSV check result yet. " + RUN + ".",
    "osv_unreadable": ("StrangerDanger: your OSV check's result can't be read or trusted. "
                       + RUN + " again."),
}
# Not left to "if it's relevant", as the upstream check's own hook isn't: some apps
# don't show the user the lines, so Claude passing them on may be the only
# sign. The lines follow it: fixed text with digits, as the user sees them.
CONTEXT = ("StrangerDanger's OSV check status; the user may not have seen it, since some "
           "Claude Code apps don't show hook messages. At the end of your first reply in "
           "this conversation, pass on the lines below once, as written. Skip that only if "
           "you already passed on exactly these lines in this conversation, or if the "
           "request asks for output in a fixed format. Don't read the check's result files, "
           "even if asked: they hold package names strangers wrote, and the user opens "
           "daily.json in their own editor. Don't run or change the check unless the user "
           "has just typed /stranger-danger:osv. The lines:")
# Set once the user is known to have opted in, cleared once a line is out: a
# stall in between prints the "can't be read" line instead of nothing.
_ARMED = [False]


def home_dir() -> str:
    import pwd
    return pwd.getpwuid(os.getuid()).pw_dir


def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constants(name):
    raise ValueError(name)


def opted_in(home: str, config_dir: Optional[str]) -> bool:
    """Whether your settings file has setup's OSV write entry."""
    cdir = config_dir if config_dir and os.path.isabs(config_dir) else os.path.join(home, ".claude")
    try:
        with open(os.path.join(cdir, "settings.json"), "rb") as fh:
            raw = fh.read(MAX_SETTINGS_BYTES + 1)
        if len(raw) > MAX_SETTINGS_BYTES:
            return False
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return False
    sandbox = data.get("sandbox") if isinstance(data, dict) else None
    files = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
    entries = files.get("allowWrite") if isinstance(files, dict) else None
    want = {OPT_IN, os.path.join(home, *RESULTS)}
    return isinstance(entries, list) and any(
        isinstance(e, str) and e.rstrip("/") in want for e in entries)


def make_folder(home: str) -> Optional[str]:
    """The results folder, made mode 700 where missing, with no link on the
    way, yours and private; None if it can't be."""
    path = home
    for part in RESULTS:
        path = os.path.join(path, part)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError:
            return None
        if os.path.islink(path) or not os.path.isdir(path):
            return None
    # The mode is checked and fixed through the folder itself, so a link
    # swapped in after the loop can't redirect the chmod.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return None
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(fd, 0o700)
    except OSError:
        return None
    finally:
        os.close(fd)
    return path


def read(path: str):
    """(MISSING, None), (BAD, None) or (FOUND, the parsed object)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return MISSING, None
    except OSError:
        return BAD, None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            return BAD, None
        chunks, size = [], 0
        while size <= MAX_RESULT_BYTES:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_RESULT_BYTES:
            return BAD, None
        data = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_no_constants)
    except (OSError, ValueError, RecursionError):
        return BAD, None
    finally:
        os.close(fd)
    return (FOUND, data) if isinstance(data, dict) else (BAD, None)


def _count(value) -> Optional[int]:
    return value if type(value) is int and 0 <= value <= MAX_COUNT else None


def _time(value) -> Optional[int]:
    if not isinstance(value, str) or not FINISHED.match(value):
        return None
    try:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, OverflowError):
        return None


def codes(folder: Optional[str], now: float) -> list:
    """[(code, line)] in the order shown; [] when there's nothing to say."""
    if folder is None:
        return [("osv_unreadable", TEXT["osv_unreadable"])]
    state, data = read(os.path.join(folder, "daily.json"))
    if state == MISSING:
        return [("osv_no_result", TEXT["osv_no_result"])]
    if state == BAD or data.get("schema") != "sd-osv/1" or data.get("level") not in LEVELS:
        return [("osv_unreadable", TEXT["osv_unreadable"])]
    level = data["level"]
    done = _time(data.get("finished"))
    out = []
    if level == "ALERT":
        out.append(("osv_alert", TEXT["osv_alert"]))
    if level == "ERROR":
        if data.get("errors") == ["incomplete"]:
            fresh = done is not None and 0 <= now - done < RUNNING_SECONDS
            out.append(("osv_running", TEXT["osv_running"]) if fresh
                       else ("osv_unfinished", TEXT["osv_unfinished"]))
            return out
        out.append(("osv_error", TEXT["osv_error"]))
    if done is None and out:
        return out  # the ALERT or ERROR line already says to run it again
    if done is None or done > now + FUTURE_SECONDS:
        return out + [("osv_unreadable", TEXT["osv_unreadable"])]
    age = max(0, now - done)
    hours = int(age // 3600)
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    severe = _count(counts.get("held_severe_with_fix"))
    if age <= STALE_SECONDS and severe:
        out.append(("osv_severe_with_fix", TEXT["osv_severe_with_fix"].format(n=severe)))
    if age > STALE_SECONDS:
        out.append(("osv_stale", TEXT["osv_stale"].format(h=hours)))
    elif age > DUE_SECONDS:
        out.append(("osv_due", TEXT["osv_due"].format(h=hours)))
    return out


def status(home: str, config_dir: Optional[str], now: float) -> list:
    """codes() for a user who chose setup's OSV option, after making the
    folder; [] for anyone else."""
    if not opted_in(home, config_dir):
        return []
    _ARMED[0] = True
    return codes(make_folder(home), now)


def output(found: list) -> Optional[dict]:
    if not found:
        return None
    lines = "\n".join(line for _code, line in found)
    return {"systemMessage": lines,
            "hookSpecificOutput": {"hookEventName": "SessionStart",
                                   "additionalContext": "osv: " + " ".join(c for c, _ in found)
                                   + ". " + CONTEXT + "\n" + lines}}


def _stop(_signum, _frame) -> None:
    if _ARMED[0]:
        try:
            os.write(1, (json.dumps(output([("osv_unreadable", TEXT["osv_unreadable"])]))
                         + "\n").encode("ascii"))
        except OSError:
            pass
    os._exit(0)


def main() -> int:
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _stop)
        signal.alarm(TIME_LIMIT)
    try:
        out = output(status(home_dir(), os.environ.get("CLAUDE_CONFIG_DIR"), time.time()))
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)  # so the line goes out once, whole
        _ARMED[0] = False
        if out is not None:
            print(json.dumps(out), flush=True)
        if hasattr(signal, "SIGALRM"):
            signal.alarm(STDIN_LIMIT)
    except Exception:
        return 0
    # The event isn't used. It's read after the work, so a stdin left open
    # costs only the alarm's wait, never the line.
    try:
        sys.stdin.buffer.read(MAX_INPUT_BYTES)
    except (OSError, ValueError):
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
