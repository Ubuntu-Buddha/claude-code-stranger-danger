"""The gates' decision log, shared by the three hooks.

One JSON line per decision, appended to
~/.local/state/stranger-danger/decisions.jsonl (mode 0600, links not
followed). A record holds a reason code and names only: the tool, the
claimed agent_type, and for the reader gate a path or a host. Never file
contents, command text, queries or search terms. Writing never raises, so
logging can't change a decision. It stops growing at MAX_LOG_BYTES.
Standard library only.
"""
from __future__ import annotations

import json
import os
import stat
import time
from typing import Callable

# Past this size nothing more is appended, so a hijacked agent that triggers
# refusals in a loop can't fill the disk. The write that would cross it adds
# a "log-full" line instead, padded with spaces to reach the cap, so only one
# is written (two hooks writing at the same moment can each add one).
MAX_LOG_BYTES = 20 << 20

# Every decision and code the hooks write. The writer turns anything else into
# "invalid" or "invalid-code", so a hook's tests fail if a new code isn't
# listed, and the bug report shows a word put in the log by something else
# only as "other".
KNOWN_DECISIONS = frozenset({"deny", "ask", "note", "pass-unresolved", "invalid"})
KNOWN_CODES = frozenset({
    # reader gate
    "bad-input", "config", "dns-failed", "glob-reach", "grep-ancestor", "grep-root",
    "internal", "path-chars", "proc", "quarantine", "reader-confined", "secret",
    "transcripts", "untrusted", "web-host", "web-identity", "web-scheme", "web-url",
    # launch gate
    "launch-bad-input", "launch-config", "launch-decode-run", "launch-download-pipe",
    "launch-download-run", "launch-download-subst", "launch-guardrails-off",
    "launch-hidden-command", "launch-internal", "launch-launcher", "launch-marker",
    "launch-domains", "launch-domains-host", "launch-monitor-feed", "launch-monitor-field", "launch-monitor-ws",
    "launch-other", "launch-privilege", "launch-reader-shell", "launch-session-forge",
    "launch-sftp", "launch-ssh-alone", "launch-ssh-expand", "launch-ssh-host", "launch-ssh-option",
    "launch-ssh-tricky",
    "launch-too-deep", "launch-too-long", "launch-unparseable",
    # reader-tools hook
    "reader-tools", "reader-tools-bad-input", "reader-tools-internal",
    # the writer itself
    "invalid-code", "log-full",
})


def log_path(home: str) -> str:
    return os.path.join(home, ".local", "state", "stranger-danger", "decisions.jsonl")


def file_logger(home: str, clock: Callable[[], float] = time.time) -> Callable[[dict], None]:
    path = log_path(home)

    def write(record: dict) -> None:
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock()))}
            entry.update(record)
            # Only a known code and decision are written, so a mistake can't
            # put an event's input in those fields.
            if not (isinstance(entry.get("code"), str) and entry["code"] in KNOWN_CODES):
                entry["code"] = "invalid-code"
            if not (isinstance(entry.get("decision"), str)
                    and entry["decision"] in KNOWN_DECISIONS):
                entry["decision"] = "invalid"
            line = (json.dumps(entry, ensure_ascii=True) + "\n").encode("ascii")
            # O_NONBLOCK: a FIFO put in the log's place can't stall the hook.
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                info = os.fstat(fd)
                # Not a hard link either: its other name could be any file.
                if stat.S_ISREG(info.st_mode) and info.st_nlink < 2 \
                        and info.st_size < MAX_LOG_BYTES:
                    if info.st_size + len(line) >= MAX_LOG_BYTES:
                        full = json.dumps({"time": entry["time"], "decision": "note",
                                           "code": "log-full"}).encode("ascii")
                        room = MAX_LOG_BYTES - info.st_size - len(full) - 1
                        line = full + b" " * max(0, room) + b"\n"
                    os.write(fd, line)
            finally:
                os.close(fd)
        except (OSError, ValueError):
            pass  # logging never changes the decision

    return write


def log_deny(code: str, event, show: Callable[[str], str], decision: str = "deny") -> None:
    """Log a deny (or an ask): the code, the tool and the claimed agent_type,
    shown through `show`. Never raises."""
    try:
        event = event if isinstance(event, dict) else {}
        tool, agent = event.get("tool_name"), event.get("agent_type")
        file_logger(os.path.expanduser("~"))({
            "decision": decision, "code": code,
            "tool": show(tool) if isinstance(tool, str) else None,
            "agent_type": show(agent) if isinstance(agent, str) else None})
    except Exception:
        pass
