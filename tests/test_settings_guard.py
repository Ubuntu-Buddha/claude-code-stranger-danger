"""Tests for setup in chat: skills/setup/chat.py (the secret check, the plan and
the staged files) and hooks/settings_guard.py (the hook that lets through only
the edits setup works out).

Everything runs against a fake home under a temporary folder; nothing touches
the real home.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hooks"))
sys.path.insert(0, str(ROOT / "skills" / "setup"))

import _canary  # noqa: E402
import chat  # noqa: E402
import settings_guard  # noqa: E402

TEMPLATE_RULES = (ROOT / "rules" / "RULES.md").read_text(encoding="utf-8")
# Built at run time, so this file holds no key-shaped string.
FAKE_TOKEN = "gh" + "p_" + "a1B2" * 9


class ChatSetupBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.home = base / "home"
        self.cdir = self.home / ".claude"
        self.cdir.mkdir(parents=True)
        self.work = self.home / "proj"
        self.work.mkdir()
        self.paths = chat.Paths(str(self.home), str(self.cdir))
        self.settings = self.cdir / "settings.json"

    def plan(self, automode=False, osv=False):
        return chat.chat_plan(self.paths, automode, str(self.work), osv=osv)

    def planned(self, name: str, automode=False, osv=False) -> str:
        [new] = [new for path, _old, new, _mode in self.plan(automode, osv)
                 if os.path.basename(path) == name]
        return new

    def event(self, tool: str, path, **tool_input) -> dict:
        tool_input = {"file_path": str(path), **tool_input}
        return {"tool_name": tool, "tool_input": tool_input, "cwd": str(self.work)}

    def guard(self, event, env_cdir=None):
        return settings_guard.check(event, str(self.home), env_cdir)


class ChatTests(ChatSetupBase):
    def test_check_passes_a_missing_or_plain_settings_file(self):
        self.assertEqual(chat.check(self.paths)[1], 0)
        self.settings.write_text(json.dumps({"env": {"DEBUG": "1"}, "model": "opus"}))
        self.assertEqual(chat.check(self.paths)[1], 0)

    def test_check_names_secret_looking_values_and_never_shows_them(self):
        self.settings.write_text(json.dumps({
            "env": {"GITHUB_TOKEN": "x", "DEBUG": "1", "LONG": "Q" * 40},
            "apiKeyHelper": f"echo {FAKE_TOKEN}"}))
        lines, code = chat.check(self.paths)
        text = "\n".join(lines)
        self.assertEqual(code, 1)
        self.assertIn("3 value(s)", text)
        for name in ("env.GITHUB_TOKEN", "env.LONG", "apiKeyHelper"):
            self.assertIn(name, text)
        self.assertNotIn("env.DEBUG", text)
        self.assertNotIn(FAKE_TOKEN, text)
        self.assertNotIn("Q" * 40, text)
        self.assertIn("your own editor", text)

    def test_plan_and_show_refuse_while_check_fails(self):
        self.settings.write_text(json.dumps({"env": {"API_KEY": "x"}}))
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            self.assertEqual(chat.main(["plan"]), 1)
            self.assertEqual(chat.main(["show", "settings"]), 1)
        self.assertNotIn("Staged", out.getvalue())

    def test_check_catches_keys_in_commands_urls_and_repeated_keys(self):
        cases = {
            "a bearer header": {"hooks": {"Stop": [{"hooks": [{
                "command": "curl -H 'Authorization: Bearer "
                           "abcdefgh12345' x"}]}]}},
            "a URL with a password": {"statusLine": {"command": "psql postgres://me:"
                                                                "pw@db/x"}},
            "an assignment": {"apiKeyHelper": "echo api_key="
                                              "abcdefgh123"},
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.settings.write_text(json.dumps(data))
                self.assertEqual(chat.check(self.paths)[1], 1)
        self.settings.write_text('{"env": {"X": "secret-in-the-first"}, "env": {}}')
        lines, code = chat.check(self.paths)
        self.assertEqual(code, 1)
        self.assertIn("same key twice", lines[0])
        self.assertNotIn("secret-in-the-first", "\n".join(lines))

    def test_the_shipped_templates_hold_nothing_that_looks_secret(self):
        merged: dict = {}
        for name in ("settings.json", "sandbox.json", "automode.json", "osv.json"):
            chat.apply.merge(merged, json.loads((ROOT / "templates" / name).read_text()))
        self.assertEqual(chat.secret_paths(merged), [])

    def test_the_osv_part_comes_only_when_asked(self):
        self.settings.write_text(json.dumps({"sandbox": {"network": {"allowedDomains": ["example.org"]}}}))
        without = json.loads(self.planned("settings.json"))
        self.assertEqual(without["sandbox"]["network"]["allowedDomains"], ["example.org"])
        self.assertNotIn("allowWrite", json.dumps(without))
        got = json.loads(self.planned("settings.json", osv=True))
        self.assertEqual(got["sandbox"]["network"]["allowedDomains"],
                         ["example.org", "api.osv.dev", "api.github.com", "nodejs.org",
                          "peps.python.org", "www.python.org"])
        self.assertEqual(got["sandbox"]["filesystem"]["allowWrite"],
                         ["~/.cache/stranger-danger/osv"])
        self.assertNotIn("stranger-danger/osv", json.dumps(got.get("permissions")))
        self.assertNotIn("raw.githubusercontent.com", json.dumps(got))

    def test_the_osv_hosts_match_the_runner(self):
        sys.path.insert(0, str(ROOT / "skills" / "osv"))
        import osv
        template = json.loads((ROOT / "templates" / "osv.json").read_text())
        self.assertEqual(tuple(template["sandbox"]["network"]["allowedDomains"]), osv.HOSTS)
        self.assertEqual(template["sandbox"]["filesystem"]["allowWrite"],
                         ["~/" + "/".join(osv.RESULTS)])

    def test_plan_takes_the_osv_flag(self):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            self.assertEqual(chat.main(["plan", "--osv"]), 0)
            self.assertEqual(chat.main(["plan", "--osv", "--automode"]), 0)

    def test_check_finds_the_v01_denies_that_would_block_setup(self):
        self.settings.write_text(json.dumps(
            {"permissions": {"deny": ["Edit(~/.claude/settings.json)", "Read(~/.ssh/**)"]}}))
        lines, code = chat.check(self.paths)
        self.assertEqual(code, 1)
        self.assertIn("Edit(~/.claude/settings.json)", "\n".join(lines))
        self.assertNotIn("Read(~/.ssh/**)", "\n".join(lines))
        self.assertIn("terminal", "\n".join(lines))

    def test_a_deny_kept_beside_its_ask_stays(self):
        self.settings.write_text(json.dumps({"permissions": {
            "deny": ["Edit(~/.claude/settings.json)"], "ask": ["Edit(~/.claude/settings.json)"]}}))
        merged = json.loads(self.planned("settings.json"))["permissions"]
        self.assertIn("Edit(~/.claude/settings.json)", merged["deny"])

    def test_the_plan_keeps_the_canary_placeholder(self):
        rules = self.planned("RULES.md")
        self.assertEqual(rules, TEMPLATE_RULES)
        self.assertIsNone(_canary.word_in(rules))
        # A copy that's already there, placeholder and all, isn't touched.
        (self.cdir / "stranger-danger").mkdir()
        (self.cdir / "stranger-danger" / "RULES.md").write_text(TEMPLATE_RULES)
        self.assertNotIn("RULES.md", [os.path.basename(c[0]) for c in self.plan()])

    def test_the_plan_moves_the_v01_denies_to_ask(self):
        self.settings.write_text(json.dumps({"permissions": {"deny": [
            "Edit(~/.claude/settings.json)", "Edit(~/.claude/hooks/**)"]}}))
        merged = json.loads(self.planned("settings.json"))["permissions"]
        self.assertNotIn("Edit(~/.claude/settings.json)", merged["deny"])
        self.assertIn("Edit(~/.claude/hooks/**)", merged["deny"])
        self.assertIn("Edit(~/.claude/settings.json)", merged["ask"])

    def test_show_stages_the_exact_text_privately(self):
        stage = Path(self.tmp.name) / "stage"
        out = io.StringIO()
        env = {"HOME": str(self.home), "TMPDIR": str(stage)}
        with redirect_stdout(out), mock.patch.dict(os.environ, env), \
                mock.patch("os.getcwd", return_value=str(self.work)), \
                mock.patch("sys.stderr", io.StringIO()):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            stage.mkdir()
            self.assertEqual(chat.main(["plan"]), 0)
            self.assertEqual(chat.main(["show", "settings"]), 0)
            self.assertEqual(chat.main(["show", "9"]), 2)
        [folder] = stage.iterdir()
        self.assertTrue(folder.name.startswith(chat.STAGE_PREFIX))
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        staged = folder / "settings.json"
        self.assertEqual(staged.read_text(), self.planned("settings.json"))
        self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
        self.assertIn(f"Staged: {staged}", out.getvalue())

    def test_writing_each_staged_file_in_turn_finishes_the_plan(self):
        """The skill's own loop: show each name in order, write it, and the
        guard lets each through. A file written early doesn't shift the
        others (P7-4), and a second run has only the write denies left."""
        stage = Path(self.tmp.name) / "stage"
        stage.mkdir()
        env = {"HOME": str(self.home), "TMPDIR": str(stage)}
        with mock.patch.dict(os.environ, env), mock.patch("os.getcwd", return_value=str(self.work)):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            for name in chat.NAMES:
                with self.subTest(name=name):
                    out = io.StringIO()
                    with redirect_stdout(out):
                        self.assertEqual(chat.main(["show", name]), 0)
                    staged = Path(out.getvalue().split("Staged: ", 1)[1].split(" (", 1)[0])
                    target = out.getvalue().rstrip().rsplit(" to ", 1)[1].rstrip(".")
                    text = staged.read_text()
                    self.assertIsNone(self.guard(self.event("Write", target, content=text)))
                    Path(target).parent.mkdir(parents=True, exist_ok=True)
                    Path(target).write_text(text)
        names = [os.path.basename(c[0]) for c in self.plan()]
        self.assertEqual(names, [])
        self.assertEqual(json.loads(self.settings.read_text())["sandbox"]["filesystem"]["denyWrite"],
                         ["~/.claude/settings.json", "~/.claude/CLAUDE.md",
                          "~/.claude/stranger-danger"])

    def test_next_asks_you_to_tighten_files_your_group_can_write(self):
        self.settings.write_text("{}")
        self.settings.chmod(0o664)
        text = "\n".join(chat.next_steps(self.paths))
        self.assertIn("chmod go-w", text)
        self.assertIn(str(self.settings), text)
        self.settings.chmod(0o600)
        self.assertNotIn("chmod go-w", "\n".join(chat.next_steps(self.paths)))

    def test_next_leaves_a_linked_file_out_of_the_chmod(self):
        real = Path(self.tmp.name) / "dotfiles-settings.json"
        real.write_text("{}")
        real.chmod(0o664)
        self.settings.symlink_to(real)
        self.assertNotIn("chmod go-w", "\n".join(chat.next_steps(self.paths)))

    def test_long_paths_in_env_arent_hits_and_a_hit_names_the_terminal_way(self):
        self.settings.write_text(json.dumps({"env": {
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates-bundle.crt",
            "TOOLS": "~/some/fairly/long/folder/of/tools/for-this-machine"}}))
        self.assertEqual(chat.check(self.paths)[1], 0)
        self.settings.write_text(json.dumps({"env": {"BLOB": "/" + "Q" * 40}}))
        lines, code = chat.check(self.paths)
        self.assertEqual(code, 1)
        self.assertIn("apply.py", "\n".join(lines))
        self.assertNotIn("Q" * 40, "\n".join(lines))

    def test_next_removes_only_setups_own_staged_copies(self):
        stage = Path(self.tmp.name) / "stage"
        stage.mkdir()
        mine = Path(chat.stage("{}", "settings.json", str(stage))).parent
        other = stage / "something-else"
        other.mkdir()
        linked = stage / (chat.STAGE_PREFIX + "link")
        linked.symlink_to(other)
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict(os.environ, {"HOME": str(self.home),
                                                                "TMPDIR": str(stage)}):
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
            self.assertEqual(chat.main(["next"]), 0)
        self.assertFalse(mine.exists())
        self.assertTrue(other.is_dir())
        self.assertTrue(linked.is_symlink())
        self.assertIn("Removed setup's 1 staged copy", out.getvalue())

    def test_next_names_the_real_files_and_the_users_own_steps(self):
        text = "\n".join(chat.next_steps(self.paths))
        self.assertIn(str(self.cdir / "stranger-danger" / "RULES.md"), text)
        self.assertIn("/stranger-danger:doctor", text)
        self.assertIn("your own editor", text)

    def test_the_gate_config_comes_from_one_private_command_not_a_write(self):
        self.assertNotIn(self.paths.config, [c[0] for c in self.plan()])
        command = chat.config_command(self.paths)
        self.assertIn(command, "\n".join(chat.next_steps(self.paths)))
        proc = subprocess.run(["bash", "-c", command], capture_output=True, text=True,
                              timeout=30, env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        config = Path(self.paths.config)
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(config.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(config.read_text(), (ROOT / "templates" / "config.json").read_text())
        # Once it's there, the step to create it goes.
        self.assertNotIn(command, "\n".join(chat.next_steps(self.paths)))

    def test_usage(self):
        with mock.patch("sys.stderr", io.StringIO()):
            for args in ([], ["show"], ["show", "x"], ["plan", "extra"], ["write"]):
                with self.subTest(args=args):
                    self.assertEqual(chat.main(args), 2)


class GuardTests(ChatSetupBase):
    def test_setups_own_writes_pass_for_every_planned_file(self):
        for path, _old, new, _mode in self.plan():
            with self.subTest(path=path):
                self.assertIsNone(self.guard(self.event("Write", path, content=new)))
        # With the auto-mode rules, the OSV part, or both.
        for automode, osv in ((True, False), (False, True), (True, True)):
            with self.subTest(automode=automode, osv=osv):
                self.assertIsNone(self.guard(self.event(
                    "Write", self.settings,
                    content=self.planned("settings.json", automode=automode, osv=osv))))

    def test_an_osv_part_with_more_hosts_is_refused(self):
        merged = json.loads(self.planned("settings.json", osv=True))
        for change in (lambda m: m["sandbox"]["network"]["allowedDomains"].append(
                           "raw.githubusercontent.com"),
                       lambda m: m["sandbox"]["filesystem"]["allowWrite"].append("~"),
                       lambda m: m["sandbox"]["filesystem"]["allowWrite"].__setitem__(
                           0, "~/.cache")):
            text = json.loads(json.dumps(merged))
            change(text)
            with self.subTest(change=change):
                self.assertIsNotNone(self.guard(self.event(
                    "Write", self.settings, content=json.dumps(text))))

    def test_json_compares_as_json_and_text_ignores_the_last_newline(self):
        compact = json.dumps(json.loads(self.planned("settings.json")))
        self.assertIsNone(self.guard(self.event("Write", self.settings, content=compact)))
        rules = self.cdir / "stranger-danger" / "RULES.md"
        self.assertIsNone(self.guard(self.event(
            "Write", rules, content=self.planned("RULES.md").rstrip("\n"))))

    def test_json_types_must_match(self):
        """Python's == says True == 1 and 1 == 1.0 (P7-3)."""
        planned = self.planned("settings.json")
        merged = json.loads(planned)
        for name, change in {
                "1 for true": ('"enabled": true', '"enabled": 1'),
                "0 for false": ('"allowUnsandboxedCommands": false',
                                '"allowUnsandboxedCommands": 0'),
                "1.0 for 1": ('"npm_config_min_release_age": "7"', '"npm_config_min_release_age": 7'),
                "NaN": ('"enabled": true', '"enabled": NaN')}.items():
            with self.subTest(name):
                self.assertIn(change[0], planned)
                text = planned.replace(change[0], change[1], 1)
                self.assertIsNotNone(self.guard(self.event("Write", self.settings, content=text)))
        self.assertTrue(merged)

    def test_home_paths_hard_links_and_case_count(self):
        planned = self.planned("settings.json")
        tilde = self.event("Write", "~/.claude/settings.json", content="{}")
        self.assertIsNotNone(self.guard(tilde))
        self.assertIsNone(self.guard(self.event("Write", "~/.claude/settings.json",
                                                content=planned)))
        # ~name: refused only when a reading of it lands on a guarded file.
        self.assertIsNone(self.guard(self.event("Write", "~notes.md", content="x")))
        self.assertIsNone(self.guard(self.event("Write", "~nosuchuser/x", content="x")))
        me = lambda p: str(self.home) + p[3:] if p.startswith("~me/") else p  # noqa: E731
        with mock.patch("os.path.expanduser", me):
            self.assertIsNotNone(self.guard(self.event("Write", "~me/.claude/settings.json",
                                                       content="{}")))
            self.assertIsNone(self.guard(self.event("Write", "~me/notes.md", content="x")))
        no_cwd = {"tool_name": "Write", "tool_input": {"file_path": "~nosuchuser/x",
                                                       "content": "x"}}
        self.assertIsNotNone(self.guard(no_cwd))
        self.assertIsNotNone(self.guard(self.event("Write", "~/.claude/../.claude/settings.json",
                                                   content="{}")))
        self.assertIsNotNone(self.guard(self.event(
            "Write", "~/.config/stranger-danger/config.json", content="{}")))
        # Another spelling of the same folder or file.
        upper = self.cdir / "Settings.json"
        self.assertIsNotNone(self.guard(self.event("Write", upper, content="{}")))
        (self.cdir / "stranger-danger").mkdir()
        self.assertIsNotNone(self.guard(self.event(
            "Write", self.cdir / "Stranger-Danger" / "x.md", content="x")))
        # A hard link in the project to the settings file.
        self.settings.write_text("{}")
        alias = self.work / "s.json"
        os.link(self.settings, alias)
        self.assertIsNotNone(self.guard(self.event("Write", alias, content="{}")))
        # A folder above the target that is a guarded folder by another name.
        other = self.work / "elsewhere"
        other.symlink_to(self.cdir / "stranger-danger")
        self.assertIsNotNone(self.guard(self.event("Write", other / "RULES.md", content="x")))

    def test_any_other_change_to_the_guarded_files_is_refused(self):
        merged = json.loads(self.planned("settings.json"))
        merged["permissions"]["deny"].remove("Bash(sudo *)")
        rules = self.cdir / "stranger-danger" / "RULES.md"
        cases = {
            "a dropped deny": (self.settings, json.dumps(merged)),
            "a new allow": (self.settings, json.dumps(
                {**merged, "permissions": {**merged["permissions"], "allow": ["Bash(*)"]}})),
            "a filled canary": (rules, self.planned("RULES.md").replace(
                _canary.LINE, "Rules canary: rue-1a")),
            "another file in the rules folder": (rules.with_name("notes.md"), "hi\n"),
            "the gate config, changed": (Path(self.paths.config), "{}\n"),
            "a duplicate key": (self.settings, self.planned("settings.json").replace(
                "{", '{"permissions": {}, ', 1)),
        }
        for name, (path, content) in cases.items():
            with self.subTest(name):
                reason = self.guard(self.event("Write", path, content=content))
                self.assertIsNotNone(reason)
                self.assertTrue(reason.startswith("settings guard:"))

    def test_only_a_write_passes_in_the_zone(self):
        """The guard can't be sure it applies an Edit as the tool does, so
        even an Edit whose result would match is refused (P7-9)."""
        claude_md = self.cdir / "CLAUDE.md"
        claude_md.write_text("# mine\n")
        planned = self.planned("CLAUDE.md")
        self.assertIsNone(self.guard(self.event("Write", claude_md, content=planned)))
        edit = self.event("Edit", claude_md, old_string="# mine\n", new_string=planned)
        self.assertIsNotNone(self.guard(edit))
        multi = {"tool_name": "MultiEdit", "cwd": str(self.work), "tool_input": {
            "file_path": str(claude_md),
            "edits": [{"old_string": "# mine\n", "new_string": planned}]}}
        self.assertIsNotNone(self.guard(multi))
        notebook = {"tool_name": "NotebookEdit", "cwd": str(self.work),
                    "tool_input": {"notebook_path": str(claude_md), "new_source": "x"}}
        self.assertIsNotNone(self.guard(notebook))
        # Outside the zone, edits pass at once.
        self.assertIsNone(self.guard(self.event("Edit", self.work / "a.py",
                                                old_string="a", new_string="b")))

    def test_once_written_nothing_more_passes(self):
        rules = self.cdir / "stranger-danger" / "RULES.md"
        rules.parent.mkdir()
        rules.write_text(TEMPLATE_RULES)
        self.assertIsNotNone(self.guard(self.event("Write", rules, content=TEMPLATE_RULES)))

    def test_other_files_pass_at_once(self):
        for path in (self.work / "app.py", self.home / ".claude" / "agents" / "x.md",
                     self.home / ".config" / "other" / "config.json"):
            with self.subTest(path=path):
                self.assertIsNone(self.guard(self.event("Write", path, content="x")))
        self.assertIsNone(self.guard({"tool_name": "Read", "tool_input": {
            "file_path": str(self.settings)}}))

    def test_links_and_odd_paths_are_refused(self):
        real = Path(self.tmp.name) / "real.json"
        real.write_text("{}")
        self.settings.symlink_to(real)
        self.assertIsNotNone(self.guard(self.event("Write", self.settings, content="{}")))
        # A link elsewhere that points into the guarded folder.
        (self.cdir / "stranger-danger").mkdir()
        sneaky = self.work / "sneaky.md"
        sneaky.symlink_to(self.cdir / "stranger-danger" / "RULES.md")
        self.assertIsNotNone(self.guard(self.event("Write", sneaky, content="x")))
        relative = self.event("Write", "../.claude/CLAUDE.md", content="x")
        self.assertIsNotNone(self.guard(relative))
        self.assertIsNotNone(self.guard({"tool_name": "Write", "tool_input": "x"}))

    def test_another_profile_is_guarded_too(self):
        alt = Path(self.tmp.name) / "alt"
        alt.mkdir()
        for path in (alt / "settings.json", self.settings):
            with self.subTest(path=path):
                self.assertIsNotNone(self.guard(self.event("Write", path, content="{}"),
                                                env_cdir=str(alt)))
        self.assertIsNotNone(self.guard(self.event("Write", self.settings, content="{}"),
                                        env_cdir="relative"))
        # With no fixed profile folder, any settings file could be the live one.
        elsewhere = self.work / "relative" / "settings.json"
        self.assertIsNotNone(self.guard(self.event("Write", elsewhere, content="{}"),
                                        env_cdir="relative"))
        self.assertIsNone(self.guard(self.event("Write", self.work / "app.py", content="x"),
                                     env_cdir="relative"))

    def test_as_claude_code_runs_it(self):
        # The override keeps the decision log in the fake home (the hooks log to
        # the account's home otherwise).
        env = {"HOME": str(self.home), "PATH": os.environ.get("PATH", ""),
               "STRANGER_DANGER_CONFIG": str(self.home / "none.json")}

        def run(event):
            return subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "settings_guard.py")],
                                  input=json.dumps(event), capture_output=True, text=True,
                                  env=env, timeout=60)

        good = run(self.event("Write", self.settings, content=self.planned("settings.json")))
        self.assertEqual((good.returncode, good.stdout, good.stderr), (0, "", ""))
        bad = run(self.event("Write", self.settings, content="{}"))
        self.assertEqual(bad.returncode, 2)
        self.assertTrue(bad.stderr.startswith("settings guard:"))
        broken = subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "settings_guard.py")],
                                input="not json", capture_output=True, text=True, env=env,
                                timeout=60)
        self.assertEqual(broken.returncode, 2)


if __name__ == "__main__":
    unittest.main()
