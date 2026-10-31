"""Tests for hooks/doctor_nudge.py, the SessionStart reminder to run the doctor.

Everything runs against a fake home and a fake `claude` under a temporary
folder; nothing touches the real home or runs a real claude.
"""
from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hooks"))

import doctor_nudge  # noqa: E402


class NudgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.bin = base / "bin"
        self.bin.mkdir()
        self.claude = self.bin / "claude"
        self.claude.write_text("#!/bin/sh\nexit 0\n")
        self.claude.chmod(0o755)
        self.plugin = base / "plugin"
        (self.plugin / ".claude-plugin").mkdir(parents=True)
        self.set_version("0.2.0")
        self.state = Path(doctor_nudge.state_path(str(self.home)))

    def set_version(self, version: str) -> None:
        (self.plugin / ".claude-plugin" / "plugin.json").write_text(json.dumps({"version": version}))

    def nudge(self, path_env=None):
        return doctor_nudge.nudge(str(self.home), str(self.bin) if path_env is None else path_env,
                                  str(self.plugin))

    def test_first_session_nudges_then_stays_quiet(self):
        out = self.nudge()
        # Shown to you only: nothing is added to the session as text for Claude.
        self.assertEqual(out, {"systemMessage": doctor_nudge.USER_TEXT})
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.state.parent.stat().st_mode), 0o700)
        self.assertIsNone(self.nudge())
        self.assertIsNone(self.nudge())

    def test_a_claude_update_or_a_plugin_update_nudges_once(self):
        self.nudge()
        self.claude.write_text("#!/bin/sh\necho newer\nexit 0\n")
        self.assertIsNotNone(self.nudge())
        self.assertIsNone(self.nudge())
        self.set_version("0.2.1")
        self.assertIsNotNone(self.nudge())
        self.assertIsNone(self.nudge())

    def test_a_native_style_symlink_to_a_new_version_nudges(self):
        versions = self.home / "versions"
        versions.mkdir()
        for v in ("1", "2"):
            (versions / v).write_text("#!/bin/sh\n")
            (versions / v).chmod(0o755)
        self.claude.unlink()
        self.claude.symlink_to(versions / "1")
        self.nudge()
        self.claude.unlink()
        self.claude.symlink_to(versions / "2")
        self.assertIsNotNone(self.nudge())

    def test_a_reinstall_with_the_same_size_and_time_nudges(self):
        # npm gives every file in a package the same fixed time.
        self.nudge()
        info = self.claude.stat()
        replacement = self.bin / "claude.new"
        replacement.write_text(self.claude.read_text())
        os.utime(replacement, ns=(info.st_atime_ns, info.st_mtime_ns))
        os.replace(replacement, self.claude)
        self.assertIsNotNone(self.nudge())

    def test_switching_between_two_setups_nudges_once_for_each(self):
        other = Path(self.tmp.name) / "otherbin"
        other.mkdir()
        (other / "claude").write_text("#!/bin/sh\necho other build\n")
        (other / "claude").chmod(0o755)
        self.assertIsNotNone(self.nudge())
        self.assertIsNotNone(self.nudge(path_env=str(other)))
        for _ in range(3):
            self.assertIsNone(self.nudge())
            self.assertIsNone(self.nudge(path_env=str(other)))

    def test_it_remembers_only_the_last_few(self):
        for i in range(doctor_nudge.KEEP_SEEN + 2):
            self.set_version(f"0.0.{i}")
            self.assertIsNotNone(self.nudge())
        seen = json.loads(self.state.read_text())["seen"]
        self.assertEqual(len(seen), doctor_nudge.KEEP_SEEN)
        self.set_version("0.0.0")  # forgotten by now
        self.assertIsNotNone(self.nudge())

    def test_relative_path_entries_are_ignored(self):
        (self.home / "claude").write_text("#!/bin/sh\n")
        (self.home / "claude").chmod(0o755)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.home)
        self.assertEqual(doctor_nudge.fingerprint(".", str(self.plugin)),
                         doctor_nudge.fingerprint("", str(self.plugin)))

    def test_no_claude_on_path_still_tracks_the_plugin(self):
        self.assertIsNotNone(self.nudge(path_env=""))
        self.assertIsNone(self.nudge(path_env=""))
        self.set_version("0.3.0")
        self.assertIsNotNone(self.nudge(path_env=""))

    def test_a_bad_or_odd_state_file_means_a_nudge_not_a_crash(self):
        self.state.parent.mkdir(parents=True)
        for content in (b"{nope", b"[]", b'{"seen": 5}', b"\xff\xfe", b"x" * 10000):
            with self.subTest(content=content[:10]):
                self.state.write_bytes(content)
                self.assertIsNotNone(self.nudge())
                self.assertIsNone(self.nudge())

    def test_a_symlinked_state_file_is_replaced_not_followed(self):
        self.state.parent.mkdir(parents=True)
        target = self.home / "elsewhere"
        target.write_text("keep me")
        self.state.symlink_to(target)
        self.assertIsNotNone(self.nudge())
        self.assertEqual(target.read_text(), "keep me")
        self.assertFalse(self.state.is_symlink())
        self.assertIsNone(self.nudge())

    def test_a_fifo_state_file_doesnt_hang(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFOs here")
        self.state.parent.mkdir(parents=True)
        os.mkfifo(self.state)
        self.assertIsNotNone(self.nudge())

    def run_hook(self, home: Path, stdin: str = '{"hook_event_name": "SessionStart"}'):
        env = {"HOME": str(home), "PATH": str(self.bin),
               "STRANGER_DANGER_CONFIG": str(home / "none.json")}
        return subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "doctor_nudge.py")],
                              input=stdin, capture_output=True, text=True, env=env, timeout=30)

    def test_as_claude_code_runs_it_prints_fixed_json_once_and_exits_0(self):
        proc = self.run_hook(self.home)
        self.assertEqual((proc.returncode, proc.stderr), (0, ""))
        out = json.loads(proc.stdout)
        self.assertEqual(out, {"systemMessage": doctor_nudge.USER_TEXT})
        proc = self.run_hook(self.home)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))

    def test_a_home_that_isnt_the_accounts_prints_nothing(self):
        env = {"HOME": str(self.home), "PATH": str(self.bin)}
        proc = subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "doctor_nudge.py")],
                              input='{"hook_event_name": "SessionStart"}', capture_output=True,
                              text=True, env=env, timeout=30)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))

    def test_it_never_blocks_a_session(self):
        # A home it can't write to, and input that isn't JSON: exit 0. It can't
        # save what it saw, so it reminds you (each time, until it can).
        locked = Path(self.tmp.name) / "locked"
        locked.mkdir()
        locked.chmod(0o500)
        self.addCleanup(locked.chmod, 0o700)
        if os.access(locked, os.W_OK):
            self.skipTest("running as a user who can write anywhere")
        proc = self.run_hook(locked, stdin="not json")
        self.assertEqual((proc.returncode, json.loads(proc.stdout), proc.stderr),
                         (0, {"systemMessage": doctor_nudge.USER_TEXT}, ""))

    def test_a_stdin_left_open_doesnt_stall_the_session(self):
        if not hasattr(signal, "SIGALRM"):
            self.skipTest("no alarm signal here")
        env = {"HOME": str(self.home), "PATH": str(self.bin),
               "STRANGER_DANGER_CONFIG": str(self.home / "none.json")}
        proc = subprocess.Popen([sys.executable, "-I", str(ROOT / "hooks" / "doctor_nudge.py")],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env)
        self.addCleanup(proc.stdin.close)
        start = time.monotonic()
        # stdin stays open, so only the hook's own alarm can end it; these
        # reads return when it exits.
        out, err = proc.stdout.read(), proc.stderr.read()
        proc.wait(timeout=10)
        proc.stdout.close()
        proc.stderr.close()
        self.assertLess(time.monotonic() - start, doctor_nudge.TIME_LIMIT + 5)
        # The reminder still got out: it's printed before stdin is read.
        self.assertEqual((proc.returncode, json.loads(out), err),
                         (0, {"systemMessage": doctor_nudge.USER_TEXT}, b""))

    def test_the_text_is_fixed_and_names_only_the_doctor(self):
        text = doctor_nudge.USER_TEXT
        self.assertIn("/stranger-danger:doctor", text)
        self.assertTrue(text.isascii())
        self.assertFalse(hasattr(doctor_nudge, "MODEL_TEXT"))
        source = (ROOT / "hooks" / "doctor_nudge.py").read_text()
        for word in ("urllib", "socket", "subprocess", "http"):
            self.assertNotIn(word, source)


if __name__ == "__main__":
    unittest.main()
