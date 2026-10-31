"""Tests for hooks/canary_fill.py, the SessionStart hook that fills in the
rules canary, and hooks/_canary.py, which it shares with setup and the doctor.

Everything runs against a fake home under a temporary folder; nothing touches
the real home.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hooks"))

import _canary  # noqa: E402
import canary_fill  # noqa: E402

TEMPLATE = (ROOT / "rules" / "RULES.md").read_text(encoding="utf-8")


class CanaryFillTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.rules = self.home / ".claude" / "stranger-danger" / "RULES.md"
        self.rules.parent.mkdir(parents=True)

    def write(self, text: str, mode: int = 0o644) -> None:
        self.rules.write_bytes(text.encode("utf-8"))
        self.rules.chmod(mode)

    def run_hook(self, stdin: str = '{"hook_event_name": "SessionStart"}', env=None):
        env = {"HOME": str(self.home), "PATH": os.environ.get("PATH", ""),
               "STRANGER_DANGER_CONFIG": str(self.home / "none.json"), **(env or {})}
        return subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "canary_fill.py")],
                              input=stdin, capture_output=True, text=True, env=env, timeout=30)

    def word(self) -> str:
        return _canary.word_in(self.rules.read_text(encoding="utf-8"))

    def test_the_template_has_the_placeholder_line(self):
        self.assertIn(_canary.LINE, TEMPLATE.splitlines())

    def test_fills_the_placeholder_once_and_says_only_fixed_text(self):
        self.write(TEMPLATE, 0o640)
        proc = self.run_hook()
        self.assertEqual((proc.returncode, proc.stderr), (0, ""))
        self.assertEqual(json.loads(proc.stdout), {"systemMessage": canary_fill.FILLED_TEXT})
        word = self.word()
        self.assertRegex(word, r"^[a-z]+-[0-9][a-z]$")
        self.assertNotIn(word, proc.stdout)
        # Only the one line changed, and the file keeps its permissions.
        self.assertEqual(self.rules.read_text(encoding="utf-8"),
                         TEMPLATE.replace(_canary.LINE, f"Rules canary: {word}", 1))
        self.assertEqual(stat.S_IMODE(self.rules.stat().st_mode), 0o640)
        self.assertEqual([p.name for p in self.rules.parent.iterdir()], ["RULES.md"])
        # The next start has nothing to do and says nothing.
        proc = self.run_hook()
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
        self.assertEqual(self.word(), word)

    def test_never_replaces_a_word_you_chose(self):
        text = TEMPLATE.replace(_canary.PLACEHOLDER, "larkspur", 1)
        self.write(text)
        self.assertIsNone(canary_fill.run(str(self.home), None))
        self.assertEqual(self.rules.read_text(encoding="utf-8"), text)

    def test_a_quoted_example_of_the_line_isnt_filled(self):
        text = "# rules\n> Rules canary: <your-canary-word>\n`Rules canary: <your-canary-word>`\n"
        self.write(text)
        self.assertIsNone(canary_fill.run(str(self.home), None))
        self.assertEqual(self.rules.read_text(encoding="utf-8"), text)

    def test_keeps_crlf_line_endings(self):
        self.write("# rules\r\nRules canary: <your-canary-word>\r\nend\r\n")
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "filled")
        self.assertRegex(self.rules.read_bytes().decode(),
                         r"^# rules\r\nRules canary: [a-z]+-[0-9][a-z]\r\nend\r\n$")

    def test_no_rules_file_and_no_folder_say_nothing(self):
        self.assertIsNone(canary_fill.run(str(self.home), None))
        self.assertIsNone(canary_fill.run(str(Path(self.tmp.name) / "nobody"), None))

    def test_uses_an_absolute_claude_config_dir_and_ignores_a_relative_one(self):
        profile = Path(self.tmp.name) / "profile"
        (profile / "stranger-danger").mkdir(parents=True)
        (profile / "stranger-danger" / "RULES.md").write_text(TEMPLATE, encoding="utf-8")
        self.write(TEMPLATE)
        proc = self.run_hook(env={"CLAUDE_CONFIG_DIR": str(profile)})
        self.assertEqual(json.loads(proc.stdout), {"systemMessage": canary_fill.FILLED_TEXT})
        self.assertIsNotNone(_canary.word_in(
            (profile / "stranger-danger" / "RULES.md").read_text(encoding="utf-8")))
        self.assertIsNone(self.word())  # the default profile's copy is left alone
        self.assertIsNone(canary_fill.rules_path(str(self.home), "relative/profile"))
        proc = self.run_hook(env={"CLAUDE_CONFIG_DIR": "relative/profile"})
        self.assertEqual((proc.returncode, proc.stdout), (0, ""))
        self.assertIsNone(self.word())

    def test_refuses_a_link(self):
        real = Path(self.tmp.name) / "elsewhere.md"
        real.write_text(TEMPLATE, encoding="utf-8")
        self.rules.symlink_to(real)
        self.assertEqual(canary_fill.run(str(self.home), None),
                         {"systemMessage": canary_fill.REFUSED_TEXT})
        self.assertEqual(real.read_text(encoding="utf-8"), TEMPLATE)
        self.assertTrue(self.rules.is_symlink())

    def test_a_linked_file_or_folder_with_a_word_set_says_nothing(self):
        real = Path(self.tmp.name) / "dotfiles"
        real.mkdir()
        text = TEMPLATE.replace(_canary.PLACEHOLDER, "rue-1a", 1)
        (real / "RULES.md").write_text(text, encoding="utf-8")
        self.rules.symlink_to(real / "RULES.md")
        self.assertIsNone(canary_fill.run(str(self.home), None))
        self.rules.unlink()
        self.rules.parent.rmdir()
        self.rules.parent.symlink_to(real)
        self.assertIsNone(canary_fill.run(str(self.home), None))
        self.assertEqual((real / "RULES.md").read_text(encoding="utf-8"), text)

    def test_a_second_name_with_a_word_set_says_nothing(self):
        self.write(TEMPLATE.replace(_canary.PLACEHOLDER, "rue-1a", 1))
        os.link(self.rules, Path(self.tmp.name) / "other.md")
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "set")

    def test_a_folder_it_cant_write_is_a_refusal_with_no_stray_copy(self):
        self.write(TEMPLATE)
        self.rules.parent.chmod(0o500)
        self.addCleanup(self.rules.parent.chmod, 0o700)
        if os.access(self.rules.parent, os.W_OK):
            self.skipTest("running as a user who can write anywhere")
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "refused")
        self.assertEqual(self.rules.read_text(encoding="utf-8"), TEMPLATE)
        self.assertEqual(canary_fill._PENDING, [])

    def test_refuses_a_linked_folder(self):
        real = Path(self.tmp.name) / "elsewhere"
        real.mkdir()
        (real / "RULES.md").write_text(TEMPLATE, encoding="utf-8")
        self.rules.parent.rmdir()
        self.rules.parent.symlink_to(real)
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "refused")
        self.assertEqual((real / "RULES.md").read_text(encoding="utf-8"), TEMPLATE)

    def test_refuses_a_folder_or_fifo_in_its_place(self):
        self.rules.mkdir()
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "refused")
        self.rules.rmdir()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.rules)
            self.assertEqual(canary_fill.fill_file(str(self.rules)), "refused")

    def test_refuses_text_that_isnt_utf8_or_is_too_big(self):
        self.rules.write_bytes(b"\xff\xfe" + _canary.LINE.encode() + b"\n")
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "refused")
        self.rules.write_bytes(b"\xff\xfe no canary line\n")
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "set")
        big = _canary.LINE + "\n" + "x" * canary_fill.MAX_RULES_BYTES
        self.write(big)
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "refused")
        self.assertEqual(self.rules.read_text(encoding="utf-8"), big)

    def test_refuses_a_file_that_changed_while_it_was_read(self):
        self.write(TEMPLATE)
        edited = TEMPLATE + "\nmy own line\n"

        def make():
            # The user saves the file between the hook's read and its write.
            self.rules.write_text(edited, encoding="utf-8")
            return "rue-1a"

        self.assertEqual(canary_fill.fill_file(str(self.rules), make=make), "refused")
        self.assertEqual(self.rules.read_text(encoding="utf-8"), edited)
        self.assertEqual([p.name for p in self.rules.parent.iterdir()], ["RULES.md"])

    def test_refuses_a_file_with_a_second_name(self):
        self.write(TEMPLATE)
        other = Path(self.tmp.name) / "dotfiles-RULES.md"
        os.link(self.rules, other)
        self.assertEqual(canary_fill.fill_file(str(self.rules)), "refused")
        self.assertEqual(other.read_text(encoding="utf-8"), TEMPLATE)

    def test_a_fill_by_another_session_at_the_same_moment_isnt_a_refusal(self):
        self.write(TEMPLATE)

        def make():
            # Another session's hook fills it between this one's read and write.
            self.rules.write_text(TEMPLATE.replace(_canary.LINE, "Rules canary: rue-1a"),
                                  encoding="utf-8")
            return "rue-2b"

        self.assertEqual(canary_fill.fill_file(str(self.rules), make=make), "set")
        self.assertEqual(self.word(), "rue-1a")
        self.assertEqual([p.name for p in self.rules.parent.iterdir()], ["RULES.md"])

    def test_a_home_that_isnt_the_accounts_is_left_alone(self):
        self.write(TEMPLATE, 0o640)
        env = {"HOME": str(self.home), "PATH": os.environ.get("PATH", "")}
        proc = subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "canary_fill.py")],
                              input='{"hook_event_name": "SessionStart"}', capture_output=True,
                              text=True, env=env, timeout=30)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
        self.assertEqual(self.rules.read_text(encoding="utf-8"), TEMPLATE)

    def test_it_never_blocks_a_session(self):
        # Input that isn't JSON, and a folder it can't write: exit 0, the
        # fixed refusal line, and the file stays as it was.
        self.write(TEMPLATE)
        self.rules.parent.chmod(0o500)
        self.addCleanup(self.rules.parent.chmod, 0o700)
        if os.access(self.rules.parent, os.W_OK):
            self.skipTest("running as a user who can write anywhere")
        proc = self.run_hook(stdin="not json")
        self.assertEqual((proc.returncode, proc.stderr), (0, ""))
        self.assertEqual(json.loads(proc.stdout), {"systemMessage": canary_fill.REFUSED_TEXT})
        self.assertEqual(self.rules.read_text(encoding="utf-8"), TEMPLATE)

    def test_its_texts_are_fixed_and_it_reaches_nothing_outside(self):
        for text in (canary_fill.FILLED_TEXT, canary_fill.REFUSED_TEXT):
            self.assertTrue(text.isascii())
            self.assertNotIn("<", text)
        self.assertIn("/stranger-danger:doctor", canary_fill.FILLED_TEXT)
        source = (ROOT / "hooks" / "canary_fill.py").read_text()
        for word in ("urllib", "socket", "subprocess", "http", "additionalContext"):
            self.assertNotIn(word, source)


class CanaryTests(unittest.TestCase):
    def test_words_are_a_word_a_digit_and_a_letter(self):
        words = {_canary.make() for _ in range(200)}
        for word in words:
            self.assertRegex(word, r"^[a-z]+-[0-9][a-z]$")
            self.assertTrue(_canary.CHECKABLE.fullmatch(word))
        self.assertGreater(len(words), 100)
        self.assertEqual(len(set(_canary.WORDS)), 64)

    def test_word_in_reads_the_line_as_the_doctor_does(self):
        self.assertIsNone(_canary.word_in(_canary.LINE))
        self.assertIsNone(_canary.word_in("no line here"))
        self.assertIsNone(_canary.word_in("Rules canary: <something else>"))
        self.assertEqual(_canary.word_in("Rules canary: rue-1a."), "rue-1a")
        # The line of its own wins over a quoted example above it.
        quoted = "> `Rules canary: <your-canary-word>`\nRules canary: rue-1a\n"
        self.assertEqual(_canary.word_in(quoted), "rue-1a")
        # A word mentioned mid-sentence still counts when there's no such line.
        self.assertEqual(_canary.word_in("the end. Rules canary: rue-1a."), "rue-1a")

    def test_matches_compares_without_showing_either_word(self):
        text = "x\nRules canary: rue-1a\n"
        self.assertTrue(_canary.matches("rue-1a", text))
        self.assertFalse(_canary.matches("rue-1b", text))
        self.assertFalse(_canary.matches("", text))
        self.assertIsNone(_canary.matches("rue-1a", _canary.LINE))

    def test_apply_and_the_doctor_share_it(self):
        for rel in ("skills/setup/apply.py", "skills/doctor/doctor.py"):
            source = (ROOT / rel).read_text()
            self.assertIn("import _canary", source)
            self.assertIsNone(re.search(r'"alder", "amaranth"', source), rel)


if __name__ == "__main__":
    unittest.main()
