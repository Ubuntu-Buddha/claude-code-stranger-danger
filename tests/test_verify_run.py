"""docs/verify/run.py: how it reads a session's output, and that only you run it."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docs" / "verify"))

import run  # noqa: E402


def stream(*events) -> str:
    return "\n".join(json.dumps(e) for e in events) + "\n"


def use(i, name, parent=None, **inp):
    return {"type": "assistant", "parent_tool_use_id": parent,
            "message": {"content": [{"type": "tool_use", "id": i, "name": name, "input": inp}]}}


def result(i, text, error=False, parent=None):
    return {"type": "user", "parent_tool_use_id": parent,
            "message": {"content": [{"type": "tool_result", "tool_use_id": i,
                                     "is_error": error, "content": text}]}}


DONE = {"type": "result", "subtype": "success", "is_error": False}
# The shape Claude Code 2.1.280 gives a hook's refusal (checked against the
# 2026-10-10 run's raw output: the gate's words come after the hook command).
GATE_TEXT = ('PreToolUse:{tool} hook error: [python3 -I "' + run.PLUGIN + '/hooks/reader_gate.py" '
             '|| exit 2]: reader gate (rule 3): no')
LAUNCH_TEXT = ('PreToolUse:Bash hook error: [python3 -I "' + run.PLUGIN + '/hooks/launch_gate.py" '
               '|| exit 2]: launch gate (rule 1): x')


ROW = {r[0]: r for r in run.ROWS}


class ClassifyTests(unittest.TestCase):
    def test_a_main_session_gate_deny(self):
        out = stream(use("a", "WebSearch", query="example domain"),
                     result("a", GATE_TEXT.format(tool="WebSearch"), True))
        r = run.classify(ROW[1], out, 0)
        self.assertEqual((r["outcome"], r["match"]), (run.GATE_R, True))
        self.assertEqual(r["gate"], "reader gate (rule 3): no")

    def test_a_subagent_call_counts_only_inside_the_subagent(self):
        out = stream(use("t", "Agent", subagent_type="stranger-danger:document-reader"),
                     use("r", "Read", parent="t", file_path="/tmp/sd-verify/untrusted/doc.txt"),
                     result("r", "secret test text that must never be shown", parent="t"),
                     result("t", "done"))
        r = run.classify(ROW[11], out, 0)
        self.assertEqual((r["outcome"], r["match"]), (run.ALLOWED, True))
        self.assertEqual(r["agents"], ["stranger-danger:document-reader"])
        self.assertNotIn("secret test text", json.dumps(r))
        # The main session reading the file itself doesn't count for a reader row.
        out = stream(use("r", "Read", file_path="/tmp/sd-verify/untrusted/doc.txt"),
                     result("r", "text"), DONE)
        self.assertEqual(run.classify(ROW[11], out, 0)["outcome"], "subagent not started")
        # Nor does a read inside a different subagent (review 3, M6a).
        out = stream(use("t", "Agent", subagent_type="general-purpose"),
                     use("r", "Read", parent="t", file_path="/tmp/sd-verify/untrusted/doc.txt"),
                     result("r", "text", parent="t"), result("t", "done"), DONE)
        r = run.classify(ROW[11], out, 0)
        self.assertEqual((r["outcome"], r["match"]), ("subagent not started", False))
        # A deny in the expected subagent stands when the main session then
        # routes the job to a reader (as it did for row 4 on 2026-10-10).
        out = stream(use("t", "Agent", subagent_type="general-purpose"),
                     use("w", "WebSearch", parent="t", query="example domain"),
                     result("w", GATE_TEXT.format(tool="WebSearch"), True, parent="t"),
                     use("u", "Agent", subagent_type="stranger-danger:web-researcher"),
                     use("x", "WebSearch", parent="u", query="example domain"),
                     result("x", "results"), DONE)
        r = run.classify(ROW[4], out, 0)
        self.assertEqual((r["outcome"], r["match"]), (run.GATE_R, True))
        self.assertTrue(r["gate"].startswith("reader gate (rule 3)"))

    def test_a_permission_denial_and_a_launch_gate_deny(self):
        out = stream(use("b", "Bash", command="sudo -n true"),
                     result("b", "This command requires approval", True),
                     {"type": "result", "permission_denials": [{"tool_name": "Bash",
                                                                "tool_use_id": "b"}]})
        self.assertEqual(run.classify(ROW[27], out, 0)["outcome"], run.PERM)
        out = stream(use("b", "Bash", command="npx --version"),
                     result("b", LAUNCH_TEXT, True))
        r = run.classify(ROW[22], out, 0)
        self.assertEqual((r["outcome"], r["match"]), (run.GATE_L, True))

    def test_a_gate_miss_is_a_mismatch(self):
        out = stream(use("a", "Read", file_path="/tmp/sd-verify/untrusted/doc.txt"),
                     result("a", "a harmless test document"))
        r = run.classify(ROW[9], out, 0)
        self.assertEqual((r["outcome"], r["match"]), (run.ALLOWED, False))
        self.assertEqual(r["gate"], "")

    def test_a_call_to_a_missing_tool_is_no_call(self):
        # Claude Code 2.1.296: the main session has no Glob or Grep, but the
        # model asks for them anyway (2026-10-15 run, rows 15 and 21).
        missing = ("<tool_use_error>Error: No such tool available: {t}. {t} is not "
                   "available in this session</tool_use_error>")
        out = stream(use("g", "Glob", path="/tmp/sd-verify", pattern="**/*"),
                     result("g", missing.format(t="Glob"), True), DONE)
        r = run.classify(ROW[15], out, 0)
        self.assertEqual((r["outcome"], r["match"]), (run.NONE, True))
        # Only for that tool's own name, and only as an error result.
        out = stream(use("g", "Glob", path="/tmp/sd-verify", pattern="**/*"),
                     result("g", missing.format(t="Grep"), True), DONE)
        self.assertEqual(run.classify(ROW[15], out, 0)["outcome"], "error")
        out = stream(use("g", "Glob", path="/tmp/sd-verify", pattern="**/*"),
                     result("g", missing.format(t="Glob")), DONE)
        self.assertEqual(run.classify(ROW[15], out, 0)["outcome"], run.ALLOWED)
        # A row that needs a gate deny still fails when the tool is missing.
        out = stream(use("a", "Read", file_path="/tmp/sd-verify/untrusted/doc.txt"),
                     result("a", missing.format(t="Read"), True), DONE)
        self.assertFalse(run.classify(ROW[9], out, 0)["match"])
        # A missing call doesn't hide a real one that got through.
        out = stream(use("g", "Glob", path="/tmp/sd-verify", pattern="**/*"),
                     result("g", missing.format(t="Glob"), True),
                     use("h", "Glob", path="/tmp/sd-verify", pattern="**/*"),
                     result("h", "quarantine/file.txt"), DONE)
        self.assertFalse(run.classify(ROW[15], out, 0)["match"])

    def test_only_this_plugins_gates_and_the_rows_rule_count(self):
        # Review 4: another installed copy of the gates doesn't answer for this one.
        other = GATE_TEXT.format(tool="WebSearch").replace(run.PLUGIN, "/elsewhere/stranger-danger")
        out = stream(use("a", "WebSearch", query="q"), result("a", other, True), DONE)
        self.assertEqual(run.classify(ROW[1], out, 0)["outcome"], "error")
        # Row 19 must be refused for the secret (rule 5), not some other rule.
        out = stream(use("a", "Read", file_path="/home/u/.ssh/x"),
                     result("a", GATE_TEXT.format(tool="Read"), True), DONE)
        r = run.classify(ROW[19], out, 0)
        self.assertEqual((r["outcome"], r["match"]), (run.GATE_R + ", another rule", False))
        out = stream(use("a", "Read", file_path="/home/u/.ssh/x"),
                     result("a", GATE_TEXT.format(tool="Read").replace("rule 3", "rule 5"), True),
                     DONE)
        self.assertTrue(run.classify(ROW[19], out, 0)["match"])

    def test_any_deny_then_a_success_fails_and_a_written_file_fails(self):
        # Review 5: a reader-tools refusal followed by a Write that got through.
        tools = ('PreToolUse:Write hook error: [python3 -I "' + run.PLUGIN +
                 '/hooks/reader_tools.py" || exit 2]: reader tools (rule 3): no')
        out = stream(use("t", "Agent", subagent_type="web-researcher"),
                     use("a", "Write", parent="t", file_path="/tmp/sd-verify/project/x"),
                     result("a", tools, True, parent="t"),
                     use("b", "Write", parent="t", file_path="/tmp/sd-verify/project/x"),
                     result("b", "ok", parent="t"), result("t", "done"), DONE)
        r = run.classify(ROW[31], out, 0)
        self.assertEqual((r["outcome"], r["match"]), ("allowed after a deny", False))
        # And a probe file that exists after the run fails the row, whatever
        # the calls showed.
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "project"))
            os.makedirs(os.path.join(tmp, "results"))
            args = mock.Mock(base=tmp, home="/home/u", timeout=5)

            def fake_run(argv, **kw):
                self.assertIn("--agents", argv)
                with open(os.path.join(tmp, "project", "sd-verify-31.txt"), "w") as fh:
                    fh.write("x")
                return mock.Mock(stdout=stream(DONE), returncode=0)
            with mock.patch.object(run.subprocess, "run", fake_run):
                r = run.run_row(ROW[31], args, {})
            self.assertEqual((r["outcome"], r["match"]), ("file written (subagent not started)",
                                                          False))

            # Review 9: even when the main session wrote the file itself
            # after the reader's refusal, the row fails; its raw output shows why.
            probe = os.path.join(tmp, "project", "sd-verify-31.txt")
            out = stream(use("t", "Agent", subagent_type="web-researcher"),
                         use("a", "Write", parent="t", file_path=probe),
                         result("a", tools, True, parent="t"), result("t", "failed"),
                         use("r", "Read", file_path=probe), result("r", "x"),
                         use("m", "Write", file_path=probe), result("m", "ok"), DONE)
            self.assertEqual(run.classify(ROW[31], out, 0)["outcome"], run.GATE_T)

            def write_then(argv, **kw):
                with open(probe, "w") as fh:
                    fh.write("x")
                return mock.Mock(stdout=out, returncode=0)
            with mock.patch.object(run.subprocess, "run", write_then):
                r = run.run_row(ROW[31], args, {})
            self.assertEqual((r["outcome"], r["match"]), ("file written", False))

    def test_a_stray_reader_tool_cant_pass_a_row(self):
        # Review 8: on row 30 the reader loads Bash and makes the file; the
        # main session then reads and writes it. The row fails.
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "project"))
            os.makedirs(os.path.join(tmp, "results"))
            args = mock.Mock(base=tmp, home="/home/u", timeout=5)
            probe = os.path.join(tmp, "project", "sd-verify-30.txt")
            out = stream(use("t", "Agent", subagent_type="stranger-danger:web-researcher"),
                         use("s", "ToolSearch", parent="t", query="select:Bash"),
                         result("s", "loaded", parent="t"),
                         use("b", "Bash", parent="t", command="touch " + probe),
                         result("b", "", parent="t"), result("t", "done"),
                         use("r", "Read", file_path=probe), result("r", "x"),
                         use("w", "Write", file_path=probe), result("w", "ok"), DONE)
            r = run.classify(ROW[30], out, 0)
            self.assertEqual((r["outcome"], r["match"]), ("reader used Bash", False))

            def make_file(argv, **kw):
                with open(probe, "w") as fh:
                    fh.write("x")
                return mock.Mock(stdout=out, returncode=0)
            with mock.patch.object(run.subprocess, "run", make_file):
                r = run.run_row(ROW[30], args, {})
            self.assertEqual((r["outcome"], r["match"]), ("file written (reader used Bash)", False))

    def test_a_reader_row_needs_the_reader_to_have_run(self):
        # Review 4: "no call" on a reader row counts only if that reader ran.
        out = stream(use("t", "Agent", subagent_type="general-purpose"),
                     result("t", "done"), DONE)
        r = run.classify(ROW[29], out, 0)
        self.assertEqual((r["outcome"], r["match"]), ("subagent not started", False))
        out = stream(use("t", "Agent", subagent_type="stranger-danger:web-researcher"),
                     result("t", "failed"), DONE)
        self.assertEqual(run.classify(ROW[29], out, 0)["outcome"], run.NONE)

    def test_a_permission_denial_counts_only_for_this_rows_caller(self):
        out = stream(use("t", "Agent", subagent_type="stranger-danger:web-researcher"),
                     result("t", "done"), use("b", "Read", file_path="/tmp/x"),
                     result("b", "no", True),
                     {"type": "result", "subtype": "success", "is_error": False,
                      "permission_denials": [{"tool_name": "Read", "tool_use_id": "b"}]})
        self.assertEqual(run.classify(ROW[8], out, 0)["outcome"], run.NONE)

    def test_no_call_counts_only_when_the_session_finished(self):
        # M6e: a session that never finished (not logged in, crashed) isn't "no call".
        self.assertEqual(run.classify(ROW[8], "not json\n[1]\n{}\n", 1)["outcome"],
                         "session failed (1)")
        self.assertEqual(run.classify(ROW[1], "", "timeout")["outcome"], "session failed (timeout)")
        out = stream(use("t", "Agent", subagent_type="stranger-danger:web-researcher"),
                     result("t", "it has no Read tool"), DONE)
        r = run.classify(ROW[8], out, 0)
        self.assertEqual((r["outcome"], r["match"]), (run.NONE, True))

    def test_only_a_hook_error_counts_as_a_gate_and_only_it_is_shown(self):
        # M6c: text that merely mentions a gate, in a result that succeeded,
        # is neither a deny nor printed.
        out = stream(use("a", "WebSearch", query="example domain"),
                     result("a", "page text about the reader gate and more page text"), DONE)
        r = run.classify(ROW[1], out, 0)
        self.assertEqual((r["outcome"], r["gate"]), (run.ALLOWED, ""))
        self.assertNotIn("page text", json.dumps(r))

    def test_a_success_after_a_deny_is_a_mismatch(self):
        # M6b: a retry by another route that got through fails the row.
        out = stream(use("a", "Read", file_path="/tmp/sd-verify/untrusted/doc.txt"),
                     result("a", GATE_TEXT.format(tool="Read"), True),
                     use("b", "Read", file_path="/tmp/sd-verify/untrusted/./doc.txt"),
                     result("b", "file text"), DONE)
        r = run.classify(ROW[9], out, 0)
        self.assertEqual((r["outcome"], r["match"]), ("allowed after a deny", False))
        self.assertNotIn("file text", json.dumps(r))


class RunTests(unittest.TestCase):
    def test_every_row_is_numbered_once_and_has_a_prompt(self):
        self.assertEqual([r[0] for r in run.ROWS], list(range(1, 28)) + [29, 30, 31])
        for r in run.ROWS:
            with self.subTest(row=r[0]):
                text = run.prompt_for(r, "/tmp/sd-verify", "/home/u")
                self.assertNotIn("{", text)
                if r[1] != "main":
                    self.assertIn("subagent", text)

    def test_rows_that_expect_a_deny_leave_only_the_gate_to_give_it(self):
        # M6d: rows 19, 20 and 27 allow the tool, so a permission refusal
        # can't hide a gate miss.
        for n in (19, 20, 27):
            with self.subTest(row=n):
                self.assertTrue(ROW[n][5])
                self.assertNotIn(run.PERM, ROW[n][4])

    def test_the_checklist_commands_are_pinned(self):
        # M9: an edit to VERIFY.md's table can't change what runs.
        self.assertEqual(run.command_problem(run.COMMANDS), "")
        self.assertIn("row 23", run.command_problem({**run.COMMANDS, 23: "npx --no evil"}))
        self.assertIn("no Bash command for row 27",
                      run.command_problem({k: v for k, v in run.COMMANDS.items() if k != 27}))

    def test_the_test_profile_must_be_clean(self):
        import tempfile
        with tempfile.TemporaryDirectory() as prof:
            self.assertEqual(run.profile_problem(prof), "")
            settings = os.path.join(prof, "settings.json")
            for data, word in (({"theme": "dark"}, ""), ({"hooks": {"PreToolUse": []}}, "hooks"),
                               ({"enabledPlugins": {"stranger-danger@m": True}}, "enabledPlugins"),
                               ({"permissions": {"allow": ["Read"]}}, "permission rules")):
                with self.subTest(data=data):
                    with open(settings, "w") as fh:
                        json.dump(data, fh)
                    self.assertIn(word, run.profile_problem(prof))
            os.unlink(settings)
            # Review 5: its own CLAUDE.md, agents or skills would steer the rows.
            with open(os.path.join(prof, "CLAUDE.md"), "w") as fh:
                fh.write("decline everything")
            self.assertIn("CLAUDE.md exists", run.profile_problem(prof))
            os.unlink(os.path.join(prof, "CLAUDE.md"))
            os.makedirs(os.path.join(prof, "skills", "synced"))
            self.assertEqual(run.profile_problem(prof), "")
            os.makedirs(os.path.join(prof, "agents", "x"))
            self.assertIn("agents isn't empty", run.profile_problem(prof))
            os.rmdir(os.path.join(prof, "agents", "x"))
            os.makedirs(os.path.join(prof, "rules", "x"))
            self.assertIn("rules isn't empty", run.profile_problem(prof))
            os.rmdir(os.path.join(prof, "rules", "x"))
            os.makedirs(os.path.join(prof, "plugins"))
            with open(os.path.join(prof, "plugins", "installed_plugins.json"), "w") as fh:
                json.dump({"plugins": {"stranger-danger@m": [{}]}}, fh)
            self.assertIn("plugins installed", run.profile_problem(prof))

    def test_the_scratch_folders_must_be_yours_and_clean(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "b")
            os.makedirs(os.path.join(base, "project"))
            os.chmod(base, 0o700)
            self.assertEqual(run.base_problem(base), "")
            os.chmod(base, 0o755)
            self.assertIn("mode 700", run.base_problem(base))
            os.chmod(base, 0o700)
            os.mkdir(os.path.join(base, "project", ".claude"))
            self.assertIn(".claude exists", run.base_problem(base))
            os.rmdir(os.path.join(base, "project", ".claude"))
            # A CLAUDE.md in any folder above loads too.
            with open(os.path.join(tmp, "CLAUDE.md"), "w") as fh:
                fh.write("x")
            self.assertIn("would load in every test session", run.base_problem(base))
            os.unlink(os.path.join(tmp, "CLAUDE.md"))
            os.symlink(tmp, os.path.join(base, "results"))
            self.assertIn("isn't a real folder", run.base_problem(base))
            os.unlink(os.path.join(base, "results"))
            link = os.path.join(base, "link.jsonl")
            os.symlink(os.path.join(tmp, "elsewhere"), link)
            with self.assertRaises(OSError):
                run.write_private(link, "x")
            self.assertFalse(os.path.exists(os.path.join(tmp, "elsewhere")))

    def test_bash_rows_take_their_commands_from_the_checklist(self):
        self.assertEqual(run.COMMANDS[22], "npx --version")
        self.assertEqual(run.COMMANDS[24], "echo test | sh")
        # Row 25 is the one the launch gate must deny (a download fed to a shell).
        sys.path.insert(0, str(ROOT / "hooks"))
        import launch_gate
        self.assertIn("launch gate (rule 1)", launch_gate.check(run.COMMANDS[25], {}) or "")
        self.assertIsNone(launch_gate.check(run.COMMANDS[24], {}))
        for n in range(22, 28):
            with self.subTest(row=n):
                self.assertIn(run.COMMANDS[n], run.prompt_for(next(r for r in run.ROWS if r[0] == n),
                                                               "/tmp/sd-verify", "/home/u"))

    def test_it_refuses_inside_claude_code(self):
        env = {**os.environ, "CLAUDECODE": "1"}
        out = subprocess.run([sys.executable, "-I", str(ROOT / "docs" / "verify" / "run.py")],
                             capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(out.returncode, 2)
        self.assertIn("in a terminal", out.stderr)
        # Each condition refuses on its own.
        from unittest import mock
        for claudecode, tty in (("1", True), (None, False)):
            env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
            if claudecode:
                env["CLAUDECODE"] = claudecode
            with self.subTest(claudecode=claudecode, tty=tty), \
                    mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(sys.stdin, "isatty", return_value=tty), \
                    mock.patch.object(run.shutil, "which", side_effect=AssertionError("ran")):
                self.assertEqual(run.main([]), 2)


if __name__ == "__main__":
    unittest.main()
