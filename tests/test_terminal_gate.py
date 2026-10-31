"""hooks/terminal_gate.py: approve-to-run, check lines only."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hooks"))

import terminal_gate as tg  # noqa: E402

SHA = "/usr/bin/sha256sum "
STAT = "/usr/bin/stat -c '%F %U %G %a %s %n' "


class GateCase(unittest.TestCase):
    """A fake home and a fake lane folder; the real ones are never touched."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(os.path.realpath(self._tmp.name)) / "home"
        self.lane = Path(os.path.realpath(self._tmp.name)) / "lane"
        self.project = Path(os.path.realpath(self._tmp.name)) / "project"
        for p in (self.home / ".claude", self.lane, self.project):
            p.mkdir(parents=True)
        (self.home / ".claude/settings.json").write_text(
            json.dumps({"permissions": {"ask": [tg.ASK_ENTRY]}}))
        (self.lane / "tool.sh").write_text("x")
        env = mock.patch.dict(os.environ, {
            "HOME": str(self.home), "STRANGER_DANGER_CONFIG": str(self.home / "none.json"),
            "CLAUDE_CODE_ENTRYPOINT": "claude-desktop"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLAUDE_PROJECT_DIR", None)
        for name, value in (("ALLOWED_DIRS", (str(self.lane),)),
                            ("MANAGED_FILE", self.home / "managed.json"),
                            ("MANAGED_DIR", self.home / "managed.d")):
            patch = mock.patch.object(tg, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def settings(self, **extra):
        data = {"permissions": {"ask": [tg.ASK_ENTRY]}}
        data.update(extra)
        (self.home / ".claude/settings.json").write_text(json.dumps(data))

    def event(self, command, tool="run_in_terminal", session="s1", **over):
        ev = {"hook_event_name": "PreToolUse", "tool_name": tg.PREFIX + tool, "session_id": session,
              "cwd": str(self.project), "permission_mode": "default",
              "tool_input": {"command": command} if command is not None else {}, "tool_use_id": "u1"}
        ev.update(over)
        return ev

    def decide(self, command, **over):
        return tg.decide(self.event(command, **over))


class LineTests(GateCase):
    def test_the_check_lines_are_asked(self):
        path = str(self.lane / "tool.sh")
        for line in (SHA + path, STAT + path, "/usr/bin/sudo -k " + SHA + path,
                     "/usr/bin/systemctl --user --no-pager is-active foo.service",
                     "/usr/bin/systemctl --no-pager is-enabled foo.timer", tg.PASSWORD_LINE):
            with self.subTest(line=line):
                decision, reason = self.decide(line)
                self.assertEqual(decision, tg.ASK, reason)

    def test_everything_else_is_denied(self):
        path = str(self.lane / "tool.sh")
        for line in ("ls /", "npm install foo", "/usr/bin/sudo -k /usr/bin/apt install x",
                     "/usr/bin/systemctl --user --no-pager start other.service",
                     "/usr/bin/systemctl --user --no-pager daemon-reload",
                     "/usr/bin/systemctl --no-pager is-active foo.service; id",
                     "/usr/bin/tailscale status --peers=false", "/usr/bin/sudo -k /usr/sbin/ufw status",
                     "/usr/local/sbin/helper-tool envcheck",
                     SHA + path + " /etc/passwd", SHA + path + "; id", SHA + path + "\nid",
                     SHA + "$(id)", "sha256sum " + path, " " + SHA + path,
                     "/usr/bin/systemctl --user --no-pager is-active ../x.service",
                     "/usr/bin/systemctl --user --no-pager is-active x", "", None, 5,
                     SHA + path + " " * 5 + "a" * 200):
            with self.subTest(line=line):
                self.assertEqual(self.decide(line)[0], tg.DENY)

    def test_paths(self):
        outside = Path(self._tmp.name) / "outside.txt"
        outside.write_text("x")
        (self.lane / "link").symlink_to(outside)
        (self.lane / "dir").mkdir()
        (self.lane / "dir/.env").write_text("x")
        (self.lane / "id_rsa").write_text("x")
        (self.lane / "token.txt").write_text("x")
        os.link(self.lane / "tool.sh", self.lane / "twin.sh")
        (self.lane / "solo.sh").write_text("x")
        cases = {
            str(self.lane / "solo.sh"): tg.ASK,
            str(self.lane / "missing"): tg.DENY,      # sha256sum needs a regular file now (stat just errors)
            str(self.lane / "link"): tg.DENY,         # link out of the lane
            str(self.lane / "dir"): tg.DENY,          # a folder is not a regular file
            str(self.lane / "dir/.env"): tg.DENY,
            str(self.lane / "id_rsa"): tg.DENY,
            str(self.lane / "token.txt"): tg.DENY,
            str(self.lane / "twin.sh"): tg.DENY,      # two hard links
            str(self.lane / "tool.sh"): tg.DENY,      # same
            str(self.lane) + "/../outside.txt": tg.DENY,
            str(self.lane) + "/./solo.sh": tg.DENY,
            str(self.lane) + "//solo.sh": tg.DENY,
            "/etc/passwd": tg.DENY,
            str(outside): tg.DENY,
            "relative.sh": tg.DENY,
            str(self.lane) + "/sp ace": tg.DENY,
        }
        for path, want in cases.items():
            for tool in (SHA, STAT):
                if tool == STAT and path.endswith(("/dir", "/missing")):
                    continue   # stat of a folder or a missing file only prints; it is not the point here
                with self.subTest(path=path, tool=tool):
                    self.assertEqual(self.decide(tool + path)[0], want)

    def test_deny_read_rules_apply(self):
        self.settings(permissions={"ask": [tg.ASK_ENTRY], "deny": [f"Read({self.lane}/solo.sh)"]})
        (self.lane / "solo.sh").write_text("x")
        self.assertEqual(self.decide(SHA + str(self.lane / "solo.sh"))[0], tg.DENY)
        self.settings(sandbox={"filesystem": {"denyRead": [str(self.lane)]}})
        (self.lane / "solo.sh").write_text("x")
        self.assertEqual(self.decide(SHA + str(self.lane / "solo.sh"))[0], tg.DENY)

    def test_the_home_lane_is_the_account_home_not_a_fixed_name(self):
        hook = self.home / ".claude/hooks"
        hook.mkdir()
        (hook / "h.py").write_text("x")
        with mock.patch.object(tg, "ALLOWED_DIRS", ()):
            self.assertEqual(self.decide(SHA + str(hook / "h.py"))[0], tg.ASK)
            self.assertEqual(self.decide(SHA + str(self.home / ".claude/settings.json"))[0], tg.ASK)
            self.assertEqual(self.decide(SHA + str(self.home / ".claude/.credentials.json"))[0], tg.DENY)

    def test_the_line_length_limit(self):
        long = "/usr/bin/systemctl --user --no-pager is-active " + "a" * 190 + ".service"
        self.assertEqual(self.decide(long)[0], tg.DENY)


class SettingsTests(GateCase):
    def off(self, **extra):
        (self.home / ".claude/settings.json").write_text(json.dumps(dict(
            {"permissions": {"ask": [tg.ASK_ENTRY]}}, **extra)))
        decision, reason = self.decide(tg.PASSWORD_LINE)
        self.assertEqual(decision, tg.DENY, reason)
        return reason

    def test_it_is_on_with_the_ask_entry(self):
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.ASK)

    def test_off_without_the_ask_entry(self):
        (self.home / ".claude/settings.json").write_text("{}")
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.DENY)
        (self.home / ".claude/settings.json").unlink()
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.DENY)

    def test_off_when_an_allow_rule_could_cover_a_terminal_tool(self):
        for entry in ("mcp__terminal__run_in_terminal", "mcp__other__Terminal_x", "mcp__*", "mcp__terminal__(x)"):
            with self.subTest(entry=entry):
                self.off(permissions={"ask": [tg.ASK_ENTRY], "allow": [entry]})

    def test_other_plugins_turn_it_off_but_this_one_does_not(self):
        self.settings(enabledPlugins={"stranger-danger@market": True})
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.ASK)
        self.settings(enabledPlugins={"stranger-danger@market": True, "other@market": False})
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.ASK)
        self.off(enabledPlugins={"stranger-danger@market": True, "other@market": True})
        self.off(enabledPlugins={"stranger-dangerous@market": True})
        self.off(enabledPlugins=["x"])

    def test_off_for_hooks_that_could_answer_or_change_a_line(self):
        hook = [{"type": "command", "command": "true"}]
        self.off(hooks={"PermissionRequest": [{"hooks": hook}]})
        self.off(hooks={"PreToolUse": [{"matcher": "mcp__terminal__.*", "hooks": hook}]})
        self.off(hooks={"PreToolUse": [{"hooks": hook}]})
        self.off(hooks={"PreToolUse": ["x"]})
        self.off(hooks=[])
        # A hook on other tools does not matter.
        self.settings(hooks={"PreToolUse": [{"matcher": "Bash", "hooks": hook}]})
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.ASK)

    def test_off_when_rules_are_limited_to_managed_ones(self):
        self.off(allowManagedPermissionRulesOnly=True)

    def test_off_with_a_server_managed_cache_or_unreadable_settings(self):
        (self.home / ".claude/remote-settings.json").write_text("{}")
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.DENY)
        (self.home / ".claude/remote-settings.json").unlink()
        (self.home / ".claude/settings.json").write_text("{not json")
        with self.assertRaises(tg.GateError):
            self.decide(tg.PASSWORD_LINE)
        (self.home / ".claude/settings.json").write_text("[]")
        with self.assertRaises(tg.GateError):
            self.decide(tg.PASSWORD_LINE)

    def test_a_project_settings_file_is_read(self):
        (self.project / ".claude").mkdir()
        (self.project / ".claude/settings.local.json").write_text(
            json.dumps({"permissions": {"allow": ["mcp__terminal__run_in_terminal"]}}))
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.DENY)

    def test_no_absolute_cwd_means_off(self):
        self.assertEqual(self.decide(tg.PASSWORD_LINE, cwd=None)[0], tg.DENY)
        self.assertEqual(self.decide(tg.PASSWORD_LINE, cwd="relative")[0], tg.DENY)
        # (CLAUDE_PROJECT_DIR marks a Claude Code session, so the fake home is set on the gate.)
        with mock.patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(self.project)}), \
                mock.patch.object(tg, "_home", lambda: self.home):
            self.assertEqual(self.decide(tg.PASSWORD_LINE, cwd=None)[0], tg.ASK)


class ContextTests(GateCase):
    def test_context_is_checked(self):
        cases = [
            self.event(tg.PASSWORD_LINE, agent_id="a1"),
            self.event(tg.PASSWORD_LINE, permission_mode="plan"),
            self.event(tg.PASSWORD_LINE, permission_mode="bypassPermissions"),
            self.event(tg.PASSWORD_LINE, permission_mode="dontAsk"),
            self.event(tg.PASSWORD_LINE, session_id=""),
            self.event(tg.PASSWORD_LINE, tool_input=[]),
            self.event(tg.PASSWORD_LINE, tool_input={"command": tg.PASSWORD_LINE, "tab_id": "t"}),
            self.event(tg.PASSWORD_LINE, tool_input={"command": tg.PASSWORD_LINE, "cwd": "/"}),
            self.event(tg.PASSWORD_LINE, tool_input={"command": tg.PASSWORD_LINE, "title": "a;b"}),
            self.event(tg.PASSWORD_LINE, tool="open_terminal_tab"),
            self.event(tg.PASSWORD_LINE, tool="list_terminal_tabs"),
            self.event(tg.PASSWORD_LINE, tool_name="mcp__other__terminal_run"),
            self.event(tg.PASSWORD_LINE, tool_name=None),
        ]
        for ev in cases:
            with self.subTest(ev=ev):
                self.assertEqual(tg.decide(ev)[0], tg.DENY)

    def test_the_entrypoint(self):
        for value in (None, "cli", "sdk-py", "claude-vscode"):
            with self.subTest(value=value), mock.patch.dict(os.environ, {}):
                if value is None:
                    os.environ.pop("CLAUDE_CODE_ENTRYPOINT")
                else:
                    os.environ["CLAUDE_CODE_ENTRYPOINT"] = value
                self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.DENY)

    def test_modes_that_prompt_pass(self):
        for mode in ("default", "acceptEdits", "auto"):
            with self.subTest(mode=mode):
                self.assertEqual(self.decide(tg.PASSWORD_LINE, permission_mode=mode)[0], tg.ASK)

    def test_a_title_may_be_set(self):
        ev = self.event(tg.PASSWORD_LINE, tool_input={"command": tg.PASSWORD_LINE, "title": "Check 1"})
        self.assertEqual(tg.decide(ev)[0], tg.ASK)


class TabTests(GateCase):
    def run_line(self, command, session="s1", tab="tab1"):
        self.assertEqual(self.decide(command, session=session)[0], tg.ASK)
        post = self.event(command, session=session, hook_event_name="PostToolUse",
                          tool_response={"content": [{"type": "text", "text": json.dumps({"tab_id": tab})}]})
        self.assertEqual(tg.record_tab(post), "tab owned")

    def read(self, tab="tab1", session="s1", **inp):
        return tg.decide(self.event(None, tool="read_terminal", session=session,
                                    tool_input=dict({"tab_id": tab}, **inp)))

    def stop(self, tab="tab1", session="s1", **inp):
        return tg.decide(self.event(None, tool="stop_terminal_tab", session=session,
                                    tool_input=dict({"tab_id": tab, "close": True}, **inp)))

    def test_one_read_then_close(self):
        self.run_line("/usr/bin/systemctl --user --no-pager is-active foo.service")
        self.assertEqual(self.read()[0], tg.ALLOW)
        self.assertEqual(self.read()[0], tg.DENY)     # once
        self.assertEqual(self.stop()[0], tg.ALLOW)
        self.assertEqual(self.stop()[0], tg.DENY)     # gone
        self.assertEqual(self.read()[0], tg.DENY)

    def test_another_tab_or_session_is_never_read_or_closed(self):
        self.run_line("/usr/bin/systemctl --user --no-pager is-active foo.service")
        self.assertEqual(self.read(tab="other")[0], tg.DENY)
        self.assertEqual(self.read(session="s2")[0], tg.DENY)
        self.assertEqual(self.stop(tab="other")[0], tg.DENY)
        self.assertEqual(self.stop(session="s2")[0], tg.DENY)
        self.assertEqual(self.read(tab="../x")[0], tg.DENY)

    def test_a_sudo_tab_is_never_read_but_can_be_closed(self):
        self.run_line(tg.PASSWORD_LINE)
        self.assertEqual(self.read()[0], tg.DENY)
        self.assertEqual(self.stop()[0], tg.ALLOW)

    def test_read_and_stop_parameters(self):
        self.run_line("/usr/bin/systemctl --user --no-pager is-active foo.service")
        for inp in ({"lines": 0}, {"lines": 101}, {"lines": True}, {"wait_for_output_ms": -1},
                    {"wait_for_output_ms": 120001}, {"extra": 1}):
            with self.subTest(inp=inp):
                self.assertEqual(self.read(**inp)[0], tg.DENY)
        self.assertEqual(self.stop(close=False)[0], tg.DENY)
        self.assertEqual(self.stop(extra=1)[0], tg.DENY)
        self.assertEqual(tg.decide(self.event(None, tool="stop_terminal_tab",
                                              tool_input={"tab_id": "tab1"}))[0], tg.DENY)

    def test_a_late_read_is_denied(self):
        self.run_line("/usr/bin/systemctl --user --no-pager is-active foo.service")
        with mock.patch.object(tg.time, "time", return_value=tg.time.time() + tg.READ_WINDOW + 1):
            self.assertEqual(self.read()[0], tg.DENY)

    def test_a_result_without_one_tab_owns_none(self):
        line = "/usr/bin/systemctl --user --no-pager is-active foo.service"
        for resp in ("no json", {"content": []}, [{"text": json.dumps({"tab_id": "a"})},
                                                  {"text": json.dumps({"tab_id": "b"})}]):
            with self.subTest(resp=resp):
                self.assertEqual(self.decide(line)[0], tg.ASK)
                post = self.event(line, hook_event_name="PostToolUse", tool_response=resp)
                self.assertNotEqual(tg.record_tab(post), "tab owned")
                self.assertEqual(self.read(tab="a")[0], tg.DENY)

    def test_a_post_event_without_an_approved_line_owns_nothing(self):
        post = self.event(tg.PASSWORD_LINE, hook_event_name="PostToolUse",
                          tool_response={"text": json.dumps({"tab_id": "tab1"})})
        self.assertEqual(tg.record_tab(post), "no pending approved line for this call")
        self.assertEqual(self.read()[0], tg.DENY)

    def test_a_denied_line_is_not_pending(self):
        self.assertEqual(self.decide("ls")[0], tg.DENY)
        post = self.event("ls", hook_event_name="PostToolUse", tool_response={"text": json.dumps({"tab_id": "tab1"})})
        self.assertNotEqual(tg.record_tab(post), "tab owned")

    def test_the_state_folder_must_be_private(self):
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.ASK)
        os.chmod(tg.state_dir(), 0o777)
        with self.assertRaises(tg.GateError):
            self.decide(tg.PASSWORD_LINE)


class ReviewFixTests(GateCase):
    """Cases from an independent review."""
    run_line, read, stop = TabTests.run_line, TabTests.read, TabTests.stop

    def test_one_own_key_across_all_the_settings_files(self):
        self.settings(enabledPlugins={"stranger-danger@real": True})
        (self.project / ".claude").mkdir()
        (self.project / ".claude/settings.json").write_text(
            json.dumps({"enabledPlugins": {"stranger-danger@evil": True}}))
        decision, reason = self.decide(tg.PASSWORD_LINE)
        self.assertEqual(decision, tg.DENY, reason)

    def test_a_tab_id_reused_by_another_session_is_owned_by_neither(self):
        self.run_line("/usr/bin/systemctl --user --no-pager is-active foo.service", session="s1")
        post = self.event(tg.PASSWORD_LINE, session="s2", hook_event_name="PostToolUse",
                          tool_response={"content": [{"type": "text", "text": json.dumps({"tab_id": "tab1"})}]})
        self.assertEqual(self.decide(tg.PASSWORD_LINE, session="s2")[0], tg.ASK)
        self.assertEqual(tg.record_tab(post), "tab id reused; no tab owned")
        self.assertEqual(self.read(session="s1")[0], tg.DENY)
        self.assertEqual(self.read(session="s2")[0], tg.DENY)

    def off(self, **extra):
        self.settings(**extra)
        decision, reason = self.decide(tg.PASSWORD_LINE)
        self.assertEqual(decision, tg.DENY, reason)

    def test_a_profile_folder_is_where_the_user_settings_are(self):
        profile = self.home.parent / "profile"
        profile.mkdir()
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(profile)}):
            self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.DENY)   # no ask entry there
            (profile / "settings.json").write_text(json.dumps({"permissions": {"ask": [tg.ASK_ENTRY]}}))
            self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.ASK)
            (profile / "settings.json").write_text(json.dumps(
                {"permissions": {"ask": [tg.ASK_ENTRY], "allow": [tg.ASK_ENTRY]}}))
            self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.DENY)
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "relative/dir"}):
            with self.assertRaises(tg.GateError):
                tg.decide(self.event(tg.PASSWORD_LINE))

    def test_exactly_one_enabled_key_of_this_plugin(self):
        self.off(enabledPlugins={"stranger-danger@a": True, "stranger-danger@b": True})
        self.off(enabledPlugins={"stranger-danger": True})
        self.settings(enabledPlugins={"stranger-danger@a": True, "stranger-danger@b": False})
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.ASK)

    def test_sudo_is_not_for_files_in_the_home_folder(self):
        path = str(self.home / ".claude/settings.json")
        self.assertEqual(self.decide(SHA + path)[0], tg.ASK)
        decision, reason = self.decide("/usr/bin/sudo -k " + SHA + path)
        self.assertEqual(decision, tg.DENY)
        self.assertIn("outside your home", reason)
        self.assertEqual(self.decide("/usr/bin/sudo -k " + SHA + str(self.lane / "tool.sh"))[0], tg.ASK)

    def test_a_one_slash_read_rule_under_the_profile_folder_applies(self):
        path = str(self.home / ".claude/settings.json")
        self.settings(permissions={"ask": [tg.ASK_ENTRY], "deny": ["Read(/settings.json)"]})
        self.assertEqual(self.decide(SHA + path)[0], tg.DENY)

    def test_a_reused_tab_id_owns_nothing(self):
        self.run_line("/usr/bin/systemctl --user --no-pager is-active foo.service")
        post = self.event(tg.PASSWORD_LINE, hook_event_name="PostToolUse",
                          tool_response={"content": [{"type": "text", "text": json.dumps({"tab_id": "tab1"})}]})
        self.assertEqual(self.decide(tg.PASSWORD_LINE)[0], tg.ASK)
        self.assertEqual(tg.record_tab(post), "tab id reused; no tab owned")
        self.assertEqual(self.read()[0], tg.DENY)

    def test_an_unknown_tool_name_is_logged_as_other(self):
        self.assertEqual(tg._loggable({"tool_name": "mcp__x__Terminal_" + "a" * 50}), {"tool_name": "other"})
        self.assertEqual(tg._loggable({"tool_name": tg.TERMINAL_TOOLS[0]}), {"tool_name": tg.TERMINAL_TOOLS[0]})

    def test_the_sudo_reason_says_when_to_type_the_password(self):
        decision, reason = self.decide(tg.PASSWORD_LINE)
        self.assertEqual(decision, tg.ASK)
        self.assertIn("only at a visible", reason)


class RunTests(GateCase):
    def run_hook(self, stdin, env=None):
        base = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
        base.update(env or {})
        # The wrapper points the managed-settings paths at the fake home (the machine's own
        # are not the test's), then runs the hook's main().
        wrapper = Path(self._tmp.name) / "wrap.py"
        wrapper.write_text(
            "import sys\n"
            f"sys.path.insert(0, {str(ROOT / 'hooks')!r})\n"
            "import terminal_gate as tg\n"
            "from pathlib import Path\n"
            f"tg.MANAGED_FILE = Path({str(self.home / 'managed.json')!r})\n"
            f"tg.MANAGED_DIR = Path({str(self.home / 'managed.d')!r})\n"
            f"tg.ALLOWED_DIRS = ({str(self.lane)!r},)\n"
            "sys.exit(tg.main())\n")
        return subprocess.run([sys.executable, "-I", str(wrapper)],
                              input=stdin if isinstance(stdin, bytes) else stdin.encode(),
                              capture_output=True, timeout=30, env=base)

    def test_bad_input_blocks(self):
        for stdin in (b"", b"{", b"[]", b"\xff"):
            with self.subTest(stdin=stdin):
                proc = self.run_hook(stdin)
                self.assertEqual(proc.returncode, 2)

    def test_a_settings_error_blocks(self):
        (self.home / ".claude/settings.json").write_text("{bad")
        proc = self.run_hook(json.dumps(self.event(tg.PASSWORD_LINE)))
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"terminal-gate: blocked", proc.stderr)

    def test_an_allowed_line_prints_ask(self):
        proc = self.run_hook(json.dumps(self.event(tg.PASSWORD_LINE)))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "ask")
        self.assertIn("Root:", out["permissionDecisionReason"])
        self.assertIn(tg.PASSWORD_LINE, out["permissionDecisionReason"])

    def test_a_refusal_prints_deny_and_is_logged_without_the_line(self):
        proc = self.run_hook(json.dumps(self.event("npm install secret-pkg-name")))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        log = (self.home / ".local/state/stranger-danger/decisions.jsonl").read_text()
        self.assertIn('"terminal-gate"', log)
        self.assertNotIn("secret-pkg-name", log)

    def test_the_post_event_exits_0_and_never_prints(self):
        post = self.event(tg.PASSWORD_LINE, hook_event_name="PostToolUse", tool_response={})
        proc = self.run_hook(json.dumps(post))
        self.assertEqual((proc.returncode, proc.stdout), (0, b""))

    def test_the_real_file_runs_as_the_hook_and_blocks_bad_input(self):
        proc = subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "terminal_gate.py")],
                              input=b"{", capture_output=True, timeout=30,
                              env=dict(os.environ, HOME=str(self.home)))
        self.assertEqual(proc.returncode, 2)

    def test_the_timers_are_armed_when_run_as_the_hook(self):
        src = (ROOT / "hooks" / "terminal_gate.py").read_text()
        self.assertLess(src.index("arm_timers()\n    except"), src.index("import fcntl"))
        self.assertLess(tg.ALARM_SECONDS, tg.WATCHDOG_SECONDS)
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]
        [entry] = [e for e in hooks["PreToolUse"] if "terminal_gate.py" in json.dumps(e)]
        timeout = entry["hooks"][0]["timeout"]
        self.assertLess(tg.WATCHDOG_SECONDS, timeout)

    def test_hooks_json_wires_it(self):
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]
        pre = [e for e in hooks["PreToolUse"] if "terminal_gate.py" in json.dumps(e)]
        self.assertEqual(len(pre), 1)
        self.assertEqual(pre[0]["hooks"][0]["onFailure"], "block")
        self.assertTrue(pre[0]["hooks"][0]["command"].endswith("|| exit 2"))
        import re
        for tool in tg.TERMINAL_TOOLS + ("mcp__terminal__open_terminal_tab", "mcp__terminal__list_terminal_tabs"):
            self.assertTrue(re.search(pre[0]["matcher"], tool), tool)
        # Another server's tool with "terminal" in its name is not the desktop app's.
        for tool in ("Bash", "mcp__other__Terminal_x", "mcp__x__open_terminal_tab"):
            self.assertFalse(re.search(pre[0]["matcher"], tool), tool)

    def test_no_personal_name_or_path_is_in_the_hook(self):
        text = (ROOT / "hooks" / "terminal_gate.py").read_text()
        self.assertNotIn("/ho" + "me/", text)


if __name__ == "__main__":
    unittest.main()
