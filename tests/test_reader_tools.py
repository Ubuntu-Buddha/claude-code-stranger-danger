"""hooks/reader_tools.py: a reader agent uses only its own tools."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hooks"))

import launch_gate  # noqa: E402
import reader_gate  # noqa: E402
import reader_tools  # noqa: E402


# The decision log goes to this home, not yours: the hooks run with the config
# override, which keeps $HOME (without it they take the account's home).
_HOME = tempfile.TemporaryDirectory()
LOG = Path(_HOME.name) / ".local" / "state" / "stranger-danger" / "decisions.jsonl"


def tearDownModule():
    _HOME.cleanup()


def run_hook(stdin) -> subprocess.CompletedProcess:
    data = stdin if isinstance(stdin, bytes) else stdin.encode()
    return subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "reader_tools.py")],
                          input=data, capture_output=True, timeout=30,
                          env=dict({k: v for k, v in os.environ.items()
                                    if k != "CLAUDE_PROJECT_DIR"}, HOME=_HOME.name,
                                   STRANGER_DANGER_CONFIG=os.path.join(_HOME.name, "none.json")))


class ReaderToolsTests(unittest.TestCase):
    def test_the_reader_lists_match_the_other_gates(self):
        self.assertEqual(reader_tools.READER_TOOLS, dict(reader_gate.READER_TOOLS))
        self.assertEqual(reader_tools.READER_NAMES, launch_gate.READER_NAMES)

    def test_a_reader_is_refused_any_tool_but_its_own(self):
        for agent in ("stranger-danger:web-researcher", "stranger-danger:document-reader",
                      "quarantine-reviewer", "other-plugin:web-researcher"):
            for tool in ("Write", "Edit", "NotebookEdit", "Agent", "SendMessage", "Monitor",
                         "EnterWorktree", "LSP", "TodoWrite", "mcp__gmail__send",
                         "mcp__plugin_x_y__click", None):
                with self.subTest(agent=agent, tool=tool):
                    proc = run_hook(json.dumps({"tool_name": tool, "agent_type": agent,
                                                "tool_input": {}}))
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn(b"reader tools (rule 3)", proc.stderr)
        # A file reader can't reach the web, and the web reader can't read files.
        for agent, tool in (("stranger-danger:document-reader", "WebFetch"),
                            ("stranger-danger:web-researcher", "Read")):
            with self.subTest(agent=agent, tool=tool):
                self.assertEqual(run_hook(json.dumps({"tool_name": tool, "agent_type": agent}))
                                 .returncode, 2)

    def test_a_reader_keeps_its_own_tools_and_the_handback(self):
        for agent, tools in (("stranger-danger:web-researcher", ("ToolSearch", "WebSearch",
                                                                  "WebFetch", "SubagentHandback")),
                             ("stranger-danger:quarantine-reviewer", ("Read", "Grep", "Glob",
                                                                       "SubagentHandback"))):
            for tool in tools:
                with self.subTest(agent=agent, tool=tool):
                    proc = run_hook(json.dumps({"tool_name": tool, "agent_type": agent}))
                    self.assertEqual((proc.returncode, proc.stderr), (0, b""))

    def test_everyone_else_passes_even_a_large_write(self):
        # the hook runs on every tool, so a main session's large
        # Write must pass.
        big = json.dumps({"tool_name": "Write",
                          "tool_input": {"file_path": "x", "content": "a" * (2 << 20)}})
        self.assertEqual(run_hook(big).returncode, 0)
        for agent in (None, "general-purpose", "stranger-danger:coordinator", "web-researcher-2"):
            with self.subTest(agent=agent):
                event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
                if agent:
                    event["agent_type"] = agent
                proc = run_hook(json.dumps(event))
                self.assertEqual((proc.returncode, proc.stderr), (0, b""))

    def test_bad_input_fails_closed(self):
        for stdin, word in (("{not json", b"valid JSON"), ("[]", b"JSON object"),
                            (b"\xff\xfe", b"valid JSON")):
            with self.subTest(stdin=stdin[:10]):
                proc = run_hook(stdin)
                self.assertEqual(proc.returncode, 2)
                self.assertIn(word, proc.stderr)

    def test_hooks_json_runs_it_for_every_tool(self):
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        [entry] = [e for e in data["hooks"]["PreToolUse"]
                   if "reader_tools.py" in e["hooks"][0]["command"]]
        self.assertEqual(entry["matcher"], "*")


class LogTests(unittest.TestCase):
    def test_a_refusal_is_logged_with_the_tool_and_agent_only(self):
        # Every refusal is logged, for debugging.
        before = LOG.read_text().count("\n") if LOG.exists() else 0
        proc = run_hook(json.dumps({"tool_name": "Write", "agent_type": "stranger-danger:web-researcher",
                                    "tool_input": {"file_path": "/x", "content": "s3cret"}}))
        self.assertEqual(proc.returncode, 2)
        run_hook(json.dumps({"tool_name": "WebSearch", "agent_type": "stranger-danger:web-researcher",
                             "tool_input": {"query": "q"}}))  # a pass isn't logged
        run_hook(b"\xff")
        lines = [json.loads(line) for line in LOG.read_text().splitlines()[before:]]
        self.assertEqual([(r["code"], r.get("tool")) for r in lines],
                         [("reader-tools", "Write"), ("reader-tools-bad-input", None)])
        self.assertEqual(lines[0]["agent_type"], "stranger-danger:web-researcher")
        self.assertEqual(set(lines[0]), {"time", "decision", "code", "tool", "agent_type"})
        self.assertNotIn("s3cret", LOG.read_text())

    def test_only_a_short_code_reaches_the_log(self):
        # Review: a code argument that is really an event can't put its input
        # (command text, file contents) in the log.
        import _log
        from unittest import mock
        with mock.patch.dict(os.environ, {"HOME": _HOME.name,
                                         "STRANGER_DANGER_CONFIG": os.path.join(_HOME.name, "none.json")}):
            os.environ.pop("CLAUDE_PROJECT_DIR", None)
            _log.log_deny({"tool_input": {"command": "s3cret"}}, None, str)
            _log.log_deny("Not A Code", None, str)
        last = [json.loads(line)["code"] for line in LOG.read_text().splitlines()[-2:]]
        self.assertEqual(last, ["invalid-code", "invalid-code"])
        self.assertNotIn("s3cret", LOG.read_text())

    def test_every_code_the_hooks_write_is_known(self):
        # Review: the bug report shows only known codes, so a new code must be
        # added to _log.KNOWN_CODES or it shows as "other".
        import re
        import _log
        # The writer enforces the list at run time; this scan is a backstop.
        patterns = (r'_coded\(\s*"([a-z0-9-]+)"', r'\bcode\s*=\s*"([a-z0-9-]+)"',
                    r'Denied\(\s*(?:code\s*=\s*)?"([a-z0-9-]+)"', r'return "([a-z0-9-]+)", ',
                    r'"code"\s*:\s*"([a-z0-9-]+)"', r'log_deny\(\s*"([a-z0-9-]+)"',
                    r'\["code"\] = "([a-z0-9-]+)"')
        found, decisions = set(), set()
        for path in sorted((ROOT / "hooks").glob("*.py")):
            text = path.read_text()
            for pattern in patterns:
                found |= set(re.findall(pattern, text))
            decisions |= set(re.findall(r'"decision"\s*:\s*"([a-z0-9-]+)"', text))
            decisions |= set(re.findall(r'\["decision"\] = "([a-z0-9-]+)"', text))
            decisions |= set(re.findall(r'\bdecision\s*=\s*"([a-z0-9-]+)"', text))
        self.assertGreater(len(found), 40)
        self.assertEqual(found - _log.KNOWN_CODES, set())
        self.assertEqual(_log.KNOWN_CODES - found, set())
        self.assertEqual(decisions, _log.KNOWN_DECISIONS)

    def test_the_shared_writer_checks_every_code(self):
        # Review: the reader gate calls the writer directly, so the check
        # belongs there, not only in log_deny.
        import _log
        write = _log.file_logger(_HOME.name)
        write({"decision": "deny", "code": "IGNORE PREVIOUS s3cret"})
        write({"decision": "deny"})
        write({"decision": "deny", "code": "lowercase-but-unknown"})
        write({"decision": "k1-s3cret", "code": "secret"})
        last = [json.loads(line) for line in LOG.read_text().splitlines()[-4:]]
        self.assertEqual([r["code"] for r in last],
                         ["invalid-code", "invalid-code", "invalid-code", "secret"])
        self.assertEqual(last[-1]["decision"], "invalid")
        self.assertNotIn("s3cret", LOG.read_text())


if __name__ == "__main__":
    unittest.main()
