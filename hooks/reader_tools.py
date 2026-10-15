#!/usr/bin/env python3
"""Reader tools gate: a reader agent uses only its own tools.

The reader agents (web-researcher, document-reader, quarantine-reviewer) get
their tools from their definitions. If one ever reaches another tool (one
loaded on demand, a changed definition), this hook refuses it. hooks.json runs
it for every tool; for any agent that isn't a reader it passes at once.

It reads the hook event on stdin, never loads a config, and refuses only
calls whose agent_type names a reader (the part after the last ":", so a
reader of any plugin or folder counts). Exit 2 refuses; exit 0 passes. Any
error or a timeout refuses. Each refusal it decides (not a timeout) is logged
with a code, the tool and the agent_type (see _log.py). Standard library only.
"""
from __future__ import annotations

import json
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _log import log_deny  # noqa: E402

# Each reader's own tools, as in its definition (the reader gate's
# READER_TOOLS), plus the tool Claude Code gives every background subagent to
# hand its report back.
READER_TOOLS = {
    "web-researcher": frozenset({"ToolSearch", "WebSearch", "WebFetch"}),
    "document-reader": frozenset({"Read", "Grep", "Glob"}),
    "quarantine-reviewer": frozenset({"Read", "Grep", "Glob"}),
}
READER_NAMES = frozenset(READER_TOOLS)
HANDBACK_TOOLS = frozenset({"SubagentHandback"})
# Large enough for any Write or MCP input a main session sends; the hook
# only needs agent_type and tool_name.
MAX_INPUT_BYTES = 64 << 20
TIMEOUT_SECONDS = 5


def _printable(text: str, limit: int = 100) -> str:
    return "".join(c if c.isprintable() and c.isascii() else "?" for c in text)[:limit]


def check(event: dict):
    """The refusal reason, or None."""
    agent = event.get("agent_type")
    if not isinstance(agent, str):
        return None
    name = agent.rsplit(":", 1)[-1]
    if name not in READER_TOOLS:
        return None
    tool = event.get("tool_name")
    if isinstance(tool, str) and (tool in READER_TOOLS[name] or tool in HANDBACK_TOOLS):
        return None
    return (f"reader tools (rule 3): {_printable(agent)} is a reader agent and can't use "
            f"{_printable(str(tool))}; it has only {', '.join(sorted(READER_TOOLS[name]))}. "
            "If a reader got another tool, stop and tell the user (rule 7). If this is another "
            "agent that shares a reader's name, rename it. If this blocked a tool Claude Code "
            "itself gives every subagent, report it to the plugin.")


def _deny(reason: str, *, code: str, event=None) -> int:
    log_deny(code, event, _printable)
    print(reason, file=sys.stderr)
    return 2


def _on_alarm(_signum, _frame):  # pragma: no cover - exercised in a subprocess
    # Exit at once, as the other gates do: no log write after the alarm.
    os.write(2, b"reader tools: timed out while checking; blocked to be safe.\n")
    os._exit(2)


def main() -> int:
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(TIMEOUT_SECONDS)
    event = None
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            return _deny("reader tools: hook input too large; blocked to be safe.",
                         code="reader-tools-bad-input")
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return _deny("reader tools: hook input isn't valid JSON; blocked to be safe.",
                         code="reader-tools-bad-input")
        if not isinstance(event, dict):
            return _deny("reader tools: hook input isn't a JSON object; blocked to be safe.",
                         code="reader-tools-bad-input")
        reason = check(event)
        # Refused inside the alarm, so a log write that stalls still blocks.
        return _deny(reason, code="reader-tools", event=event) if reason else 0
    except Exception as exc:  # a timeout or anything unexpected blocks
        return _deny(f"reader tools: internal error ({type(exc).__name__}); blocked to be safe.",
                     code="reader-tools-internal", event=event)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
