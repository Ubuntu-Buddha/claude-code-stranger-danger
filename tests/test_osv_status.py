"""The OSV session line (hooks/osv_status.py): when it speaks, in what order,
and that it says only its own fixed text. Runs use a fake home."""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

if os.name != "posix":
    raise unittest.SkipTest("the OSV check is POSIX only")

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "osv_status.py"
sys.path.insert(0, str(ROOT / "hooks"))

import osv_status  # noqa: E402

MARKER = "zqxmarker"
NOW = 1_800_000_000.0


def stamp(hours_ago: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - hours_ago * 3600))


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)
        self.cdir = os.path.join(self.home, ".claude")
        self.folder = os.path.join(self.home, ".cache", "stranger-danger", "osv")
        self.opt_in()

    def opt_in(self, entries=("~/.cache/stranger-danger/osv",)):
        os.makedirs(self.cdir, exist_ok=True)
        with open(os.path.join(self.cdir, "settings.json"), "w") as fh:
            json.dump({"sandbox": {"filesystem": {"allowWrite": list(entries)}}}, fh)

    def write(self, data=None, text=None, **over):
        os.makedirs(self.folder, mode=0o700, exist_ok=True)
        if text is None:
            base = {"schema": "sd-osv/1", "level": "OK", "finished": stamp(1), "errors": [],
                    "counts": {"held_severe_with_fix": 0},
                    "info": {"severe_with_fix": [{"package": MARKER}]}}
            base.update(data or {})
            base.update(over)
            text = json.dumps(base)
        path = os.path.join(self.folder, "daily.json")
        with open(path, "w") as fh:
            fh.write(text)
        os.chmod(path, 0o600)

    def found(self) -> list:
        return osv_status.status(self.home, self.cdir, NOW)

    def codes(self) -> list:
        return [c for c, _ in self.found()]

    def test_silent_unless_opted_in(self):
        for settings in (None, "{", "[]", {"sandbox": {"filesystem": {"allowWrite": ["~/.cache"]}}},
                         {"sandbox": {"filesystem": {"allowWrite": "~/.cache/stranger-danger/osv"}}}):
            if settings is None:
                os.unlink(os.path.join(self.cdir, "settings.json"))
            else:
                with open(os.path.join(self.cdir, "settings.json"), "w") as fh:
                    fh.write(settings if isinstance(settings, str) else json.dumps(settings))
            with self.subTest(settings=str(settings)[:40]):
                self.assertEqual(self.codes(), [])
                self.assertFalse(os.path.lexists(os.path.join(self.home, ".cache")))

    def test_the_absolute_form_and_config_dir_count(self):
        other = os.path.join(self.home, "conf")
        os.makedirs(other)
        with open(os.path.join(other, "settings.json"), "w") as fh:
            json.dump({"sandbox": {"filesystem": {"allowWrite": [self.folder + "/"]}}}, fh)
        self.assertEqual([c for c, _ in osv_status.status(self.home, other, NOW)],
                         ["osv_no_result"])

    def test_it_makes_the_folder_private(self):
        self.assertEqual(self.codes(), ["osv_no_result"])
        self.assertEqual(os.stat(self.folder).st_mode & 0o777, 0o700)
        os.chmod(self.folder, 0o755)
        self.assertEqual(self.codes(), ["osv_no_result"])
        self.assertEqual(os.stat(self.folder).st_mode & 0o777, 0o700)

    def test_the_core_writes_the_schema_this_hook_trusts(self):
        out = os.path.join(self.home, "placeholder")
        os.makedirs(out, mode=0o700)
        core = ROOT / "skills" / "osv" / "core" / "osvd.py"
        subprocess.run([sys.executable, "-I", "-B", str(core), "placeholder", out], check=True,
                       capture_output=True)
        os.makedirs(self.folder, mode=0o700, exist_ok=True)
        path = os.path.join(self.folder, "daily.json")
        shutil.copy(os.path.join(out, "daily.json"), path)
        os.chmod(path, 0o600)
        self.assertIn("osv_error", self.codes())
        self.assertNotIn("osv_unreadable", self.codes())
        with open(path) as fh:
            data = json.load(fh)
        data["schema"] = "other/1"
        with open(path, "w") as fh:
            json.dump(data, fh)
        self.assertEqual(self.codes(), ["osv_unreadable"])

    def test_a_folder_it_cant_trust_is_unreadable(self):
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, True)
        os.makedirs(os.path.dirname(self.folder))
        os.symlink(other, self.folder)
        self.assertEqual(self.codes(), ["osv_unreadable"])
        shutil.rmtree(os.path.join(self.home, ".cache"))
        os.symlink(other, os.path.join(self.home, ".cache"))
        self.assertEqual(self.codes(), ["osv_unreadable"])
        os.unlink(os.path.join(self.home, ".cache"))
        os.makedirs(self.folder)
        with mock.patch("os.getuid", return_value=os.getuid() + 1):
            self.assertEqual(osv_status.codes(osv_status.make_folder(self.home), NOW),
                             [("osv_unreadable", osv_status.TEXT["osv_unreadable"])])

    def test_silent_when_fresh_and_clean(self):
        for level in ("OK", "INFO"):
            self.write(level=level)
            self.assertEqual(self.codes(), [], level)

    def test_due_and_stale(self):
        for hours, want in ((23.9, []), (24.1, ["osv_due"]), (35.9, ["osv_due"]),
                            (36.1, ["osv_stale"]), (500, ["osv_stale"])):
            self.write(finished=stamp(hours))
            with self.subTest(hours=hours):
                self.assertEqual(self.codes(), want)

    def test_severe_with_a_fix(self):
        self.write(counts={"held_severe_with_fix": 3})
        found = self.found()
        self.assertEqual([c for c, _ in found], ["osv_severe_with_fix"])
        self.assertIn("a fix is out for 3 high", found[0][1])

    def test_severe_shows_at_every_level(self):
        for level, errors, first in (("INFO", [], []), ("ALERT", [], ["osv_alert"]),
                                     ("ERROR", ["osv_ver"], ["osv_error"])):
            self.write(level=level, errors=errors, counts={"held_severe_with_fix": 2})
            with self.subTest(level=level):
                self.assertEqual(self.codes(), first + ["osv_severe_with_fix"])

    def test_an_rt_node_error_is_a_failure(self):
        # v3.2: rt_node is Node's release list alone, so its error is a real
        # loss of the security-release check (V32-2), whatever its word.
        for word in ("unreachable", "malformed"):
            self.write(level="ERROR", errors=["rt_node"], sources={"rt_node": word,
                                                                    "rt_node_eol": "skipped"})
            with self.subTest(word=word):
                self.assertEqual(self.codes(), ["osv_error"])
        self.write(level="OK", sources={"rt_node": "ok", "rt_node_eol": "skipped"})
        self.assertEqual(self.codes(), [])

    def test_a_stale_severe_count_gives_way_to_stale(self):
        self.write(counts={"held_severe_with_fix": 3}, finished=stamp(40))
        self.assertEqual(self.codes(), ["osv_stale"])

    def test_order_alert_error_then_age(self):
        self.write(level="ALERT", finished=stamp(30))
        self.assertEqual(self.codes(), ["osv_alert", "osv_due"])
        self.write(level="ERROR", errors=["osv_ver"], finished=stamp(40))
        self.assertEqual(self.codes(), ["osv_error", "osv_stale"])

    def test_an_alert_shows_however_old(self):
        self.write(level="ALERT", finished=stamp(1000))
        self.assertEqual(self.codes(), ["osv_alert", "osv_stale"])

    def test_a_run_in_progress_and_one_that_never_finished(self):
        self.write(level="ERROR", errors=["incomplete"], finished=stamp(1))
        self.assertEqual(self.codes(), ["osv_running"])
        self.write(level="ERROR", errors=["incomplete"], finished=stamp(3))
        self.assertEqual(self.codes(), ["osv_unfinished"])

    def test_an_error_with_no_time_says_failed_once(self):
        self.write(text='{"schema":"sd-osv/1","level":"ERROR","errors":["run"]}')
        self.assertEqual(self.codes(), ["osv_error"])

    def test_unreadable_or_untrusted(self):
        for kwargs in ({"text": "{"}, {"text": "[]"}, {"text": '{"a":1,"a":2}'},
                       {"text": '{"level": NaN}'}, {"schema": "sd-osv/2"}, {"level": MARKER},
                       {"finished": "yesterday"}, {"finished": stamp(-2)},
                       {"finished": "2026-13-45T99:99:99Z"}):
            self.write(**kwargs)
            with self.subTest(kwargs=str(kwargs)[:40]):
                self.assertEqual(self.codes(), ["osv_unreadable"])

    def test_a_file_others_can_write_is_unreadable(self):
        self.write()
        os.chmod(os.path.join(self.folder, "daily.json"), 0o622)
        self.assertEqual(self.codes(), ["osv_unreadable"])

    def test_bad_counts_are_ignored(self):
        for value in (-1, True, "3", 10 ** 10, 2.0, [3]):
            self.write(counts={"held_severe_with_fix": value})
            with self.subTest(value=value):
                self.assertEqual(self.codes(), [])

    def test_links_and_fifos_are_refused(self):
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, True)
        with open(os.path.join(other, "daily.json"), "w") as fh:
            json.dump({"schema": "sd-osv/1", "level": "OK", "finished": stamp(1)}, fh)
        os.makedirs(self.folder)
        os.symlink(os.path.join(other, "daily.json"), os.path.join(self.folder, "daily.json"))
        self.assertEqual(self.codes(), ["osv_unreadable"])
        os.unlink(os.path.join(self.folder, "daily.json"))
        os.mkfifo(os.path.join(self.folder, "daily.json"))
        self.assertEqual(self.codes(), ["osv_unreadable"])

    def test_texts_are_fixed_ascii_and_never_echo(self):
        self.write(level="ALERT", counts={"held_severe_with_fix": 1})
        out = osv_status.output(self.found())
        text = json.dumps(out)
        self.assertNotIn(MARKER, text)
        self.assertTrue(text.isascii())
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertTrue(ctx.startswith("osv: osv_alert osv_severe_with_fix. "
                                       + osv_status.CONTEXT + "\n"))
        self.assertTrue(ctx.endswith(out["systemMessage"]))
        for line in osv_status.TEXT.values():
            self.assertTrue(line.isascii())
            self.assertTrue(line.startswith("StrangerDanger: "))

    def test_claude_is_told_to_say_it_once_whatever_the_app_shows(self):
        """The desktop app didn't show the lines when checked, so Claude gets
        the same fixed lines and is asked to pass them on once, not "if it's
        relevant"; the lines still go to systemMessage."""
        self.write(level="ERROR", errors=["osv_ver"])
        out = osv_status.output(self.found())
        self.assertEqual(out["systemMessage"], osv_status.TEXT["osv_error"])
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertTrue(ctx.endswith("\n" + osv_status.TEXT["osv_error"]))
        for words in ("may not have seen", "pass on the lines below once, as written",
                      "only if you already passed on exactly these lines", "fixed format",
                      "Don't read the check's result files, even if asked", "daily.json",
                      "Don't run or change the check unless the user has just typed"):
            self.assertIn(words, osv_status.CONTEXT)
        for words in ("relevant", "unless the user asks", "shows the counts", "already did"):
            self.assertNotIn(words, osv_status.CONTEXT)
        self.assertTrue(osv_status.CONTEXT.isascii())

    def test_a_running_check_isnt_pointed_at_a_second_run(self):
        """osv_running's line has no "Run /stranger-danger:osv"; Claude's text
        mustn't add one."""
        self.write(level="ERROR", errors=["incomplete"], finished=stamp(1))
        out = osv_status.output(self.found())
        self.assertEqual(out["systemMessage"], osv_status.TEXT["osv_running"])
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(ctx, "osv: osv_running. " + osv_status.CONTEXT + "\n"
                         + osv_status.TEXT["osv_running"])
        self.assertNotIn("/stranger-danger:osv", osv_status.TEXT["osv_running"])


class HookProcessTests(unittest.TestCase):
    def setUp(self):
        # A config folder with no OSV part, so the run never reads or makes
        # anything in the real home.
        self.cdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.cdir, True)
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CLAUDE_CONFIG_DIR": self.cdir}

    def test_it_runs_quietly_and_exits_0(self):
        proc = subprocess.run([sys.executable, "-I", str(HOOK)], input=b'{"hook_event_name":"x"}',
                              capture_output=True, timeout=30, env=self.env)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, b"")
        self.assertEqual(proc.stdout, b"")

    def test_a_stdin_left_open_never_blocks(self):
        start = time.monotonic()
        proc = subprocess.Popen([sys.executable, "-I", str(HOOK)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        self.addCleanup(proc.stdin.close)
        try:
            self.assertEqual(proc.wait(timeout=osv_status.TIME_LIMIT + 5), 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            proc.stdout.close()
            proc.stderr.close()
        self.assertLess(time.monotonic() - start, osv_status.TIME_LIMIT + 5)

    def test_an_error_means_no_line(self):
        with mock.patch.object(osv_status, "home_dir", side_effect=KeyError("x")), \
                mock.patch("sys.stdin") as stdin, mock.patch("builtins.print") as printed, \
                mock.patch("signal.alarm"):
            stdin.buffer.read.return_value = b""
            self.assertEqual(osv_status.main(), 0)
            printed.assert_not_called()

    def test_the_real_alarm_after_opting_in_prints_the_unreadable_line(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        cdir = os.path.join(home, ".claude")
        os.makedirs(cdir)
        with open(os.path.join(cdir, "settings.json"), "w") as fh:
            json.dump({"sandbox": {"filesystem": {"allowWrite": [osv_status.OPT_IN]}}}, fh)
        written = []
        old = signal.getsignal(signal.SIGALRM)
        self.addCleanup(signal.signal, signal.SIGALRM, old)
        self.addCleanup(signal.alarm, 0)
        with mock.patch.object(osv_status, "home_dir", return_value=home), \
                mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": cdir}), \
                mock.patch.object(osv_status, "TIME_LIMIT", 1), \
                mock.patch.object(osv_status, "codes", side_effect=lambda *a: time.sleep(5)), \
                mock.patch.object(osv_status, "_ARMED", [False]), \
                mock.patch("os.write", side_effect=lambda fd, b: written.append(b)), \
                mock.patch("os._exit", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                osv_status.main()
        self.assertEqual(len(written), 1)
        self.assertTrue(json.loads(written[0])["hookSpecificOutput"]["additionalContext"]
                        .startswith("osv: osv_unreadable."))

    def test_the_line_goes_out_before_a_stdin_left_open(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        cdir = os.path.join(home, ".claude")
        os.makedirs(cdir)
        with open(os.path.join(cdir, "settings.json"), "w") as fh:
            json.dump({"sandbox": {"filesystem": {"allowWrite": [osv_status.OPT_IN]}}}, fh)
        printed = []
        old = signal.getsignal(signal.SIGALRM)
        self.addCleanup(signal.signal, signal.SIGALRM, old)
        self.addCleanup(signal.alarm, 0)

        def stuck(_n):
            self.assertEqual(len(printed), 1)  # the line is already out
            time.sleep(5)
        with mock.patch.object(osv_status, "home_dir", return_value=home), \
                mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": cdir}), \
                mock.patch("sys.stdin") as stdin, \
                mock.patch("builtins.print", lambda *a, **k: printed.append(a)), \
                mock.patch("os._exit", side_effect=SystemExit):
            stdin.buffer.read.side_effect = stuck
            start = time.monotonic()
            with self.assertRaises(SystemExit):
                osv_status.main()
        self.assertLess(time.monotonic() - start, 4)
        self.assertIn("osv_no_result", printed[0][0])

    def test_a_stall_after_opting_in_prints_the_unreadable_line(self):
        written = []
        with mock.patch.object(osv_status, "_ARMED", [True]), \
                mock.patch("os.write", side_effect=lambda fd, b: written.append(b)), \
                mock.patch("os._exit", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                osv_status._stop(14, None)
        self.assertEqual(json.loads(written[0])["hookSpecificOutput"]["additionalContext"][:20],
                         "osv: osv_unreadable.")
        with mock.patch.object(osv_status, "_ARMED", [False]), \
                mock.patch("os.write") as write, mock.patch("os._exit", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                osv_status._stop(14, None)
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
