"""Tests for skills/setup/apply.py, the one-command install.

Everything runs against a fake home under a temporary folder. The terminal
check and the y/N answer are injected; nothing touches the real home.
"""
from __future__ import annotations

import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "setup"))
sys.path.insert(0, str(ROOT / "skills" / "doctor"))
sys.path.insert(0, str(ROOT / "hooks"))

import apply  # noqa: E402
import doctor  # noqa: E402

TEMPLATE_DENY = json.loads((ROOT / "templates" / "settings.json").read_text())["permissions"]["deny"]
# The sandbox write denies for the files setup changes, once they all exist.
SETUP_WRITE_DENIES = ["~/.claude/settings.json", "~/.claude/CLAUDE.md", "~/.claude/stranger-danger"]
TEMPLATE_ENV = json.loads((ROOT / "templates" / "settings.json").read_text())["env"]


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.cdir = self.home / ".claude"
        self.config = self.home / ".config" / "stranger-danger" / "config.json"
        patcher = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("CLAUDE_CONFIG_DIR", "STRANGER_DANGER_CONFIG", "CLAUDECODE"):
            os.environ.pop(name, None)  # restored by the patcher

    def run_apply(self, *args, answer="y", tty=True) -> tuple:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = apply.main(list(args), ask=lambda prompt: answer, isatty=lambda: tty)
        return code, out.getvalue(), err.getvalue()

    def snapshot(self) -> dict:
        return {str(p): p.read_bytes() for p in self.home.rglob("*") if p.is_file()}

    def test_fresh_install_in_one_step_then_nothing_to_do(self):
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        settings = json.loads((self.cdir / "settings.json").read_text())
        self.assertEqual(settings["permissions"]["deny"], TEMPLATE_DENY)
        self.assertIs(settings["sandbox"]["enabled"], True)
        self.assertNotIn("autoMode", settings)
        self.assertEqual(settings["env"], TEMPLATE_ENV)
        self.assertIs(settings["sandbox"]["allowUnsandboxedCommands"], False)
        [canary] = re.findall(r"Its rules canary is now (\S+)\. ", out)
        self.assertRegex(canary, r"^[a-z]+-[0-9][a-z]$")
        template = (ROOT / "rules" / "RULES.md").read_text()
        self.assertEqual((self.cdir / "stranger-danger" / "RULES.md").read_text(),
                         template.replace("Rules canary: <your-canary-word>",
                                          f"Rules canary: {canary}", 1))
        self.assertNotIn(canary, out.replace(f"Its rules canary is now {canary}.", ""))
        self.assertIn(apply.DEFAULT_IMPORT, (self.cdir / "CLAUDE.md").read_text().splitlines())
        self.assertEqual(self.config.read_bytes(), (ROOT / "templates" / "config.json").read_bytes())
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.config.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.cdir / "settings.json").stat().st_mode), 0o600)
        self.assertIn("--- new file:", out)
        before = self.snapshot()
        code, out, _ = self.run_apply()
        self.assertEqual(code, 0)
        self.assertIn("Nothing to change", out)
        self.assertEqual(self.snapshot(), before)
        # The doctor agrees.
        ctx = doctor.Context(home=str(self.home), cwd=str(self.home), managed_settings=str(self.home / "managed-settings.json"), run=lambda argv, cwd=None: "3.12.3\n" if argv[:1] == ["python3"] else None)
        checks = doctor.run_all(ctx)
        self.assertEqual([(c.name, c.detail) for c in checks if c.status == "FAIL"], [])
        for name in ("settings deny rules", "sandbox", "sandbox retries", "config",
                     "rules import", "rules canary", "package lane env"):
            with self.subTest(check=name):
                self.assertIn("PASS", [c.status for c in checks if c.name == name])

    def test_the_settings_file_is_written_last(self):
        # Its write denies name the files the other changes make, so a write
        # that fails before it leaves no deny on a path that isn't there.
        order = []
        real = apply._write
        with mock.patch.object(apply, "_write",
                               lambda path, text, mode: (order.append(os.path.basename(path)),
                                                         real(path, text, mode))):
            code, _out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        self.assertEqual(order[-1], "settings.json")
        self.assertEqual(sorted(order), ["CLAUDE.md", "RULES.md", "config.json", "settings.json"])

    def test_it_writes_nothing_without_a_terminal_or_a_yes(self):
        for kwargs in ({"tty": False}, {"answer": "n"}, {"answer": ""}, {"answer": "yes please"}):
            with self.subTest(**kwargs):
                code, _, _ = self.run_apply(**kwargs)
                self.assertNotEqual(code, 0)
                self.assertEqual(self.snapshot(), {})

    def test_refuses_without_a_terminal_when_run_as_a_script(self):
        proc = subprocess.run([sys.executable, "-I", str(ROOT / "skills" / "setup" / "apply.py")],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
                              env={"HOME": str(self.home), "PATH": os.environ.get("PATH", "")})
        self.assertEqual(proc.returncode, 2)
        self.assertIn("in a terminal", proc.stderr)
        self.assertEqual(self.snapshot(), {})

    def test_merge_keeps_yours_shows_a_diff_and_keeps_a_backup(self):
        self.cdir.mkdir()
        mine = {"model": "x", "permissions": {"allow": ["Bash(ls)"], "deny": ["Read(~/mine)"]},
                "sandbox": {"enabled": False, "excludedCommands": ["docker"]}}
        (self.cdir / "settings.json").write_text(json.dumps(mine))
        (self.cdir / "CLAUDE.md").write_text("# mine\n")
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        settings = json.loads((self.cdir / "settings.json").read_text())
        self.assertEqual(settings["model"], "x")
        self.assertEqual(settings["permissions"]["allow"], ["Bash(ls)"])
        self.assertEqual(settings["permissions"]["deny"], ["Read(~/mine)"] + TEMPLATE_DENY)
        self.assertEqual(settings["sandbox"], {
            "enabled": True, "excludedCommands": ["docker"], "allowUnsandboxedCommands": False,
            "filesystem": {"denyWrite": SETUP_WRITE_DENIES}})
        self.assertEqual(json.loads((self.cdir / "settings.json.bak").read_text()), mine)
        self.assertEqual((self.cdir / "CLAUDE.md.bak").read_text(), "# mine\n")
        self.assertEqual((self.cdir / "CLAUDE.md").read_text(), "# mine\n\n" + apply.DEFAULT_IMPORT + "\n")
        self.assertIn('-    "enabled": false', out)
        self.assertIn('+    "enabled": true', out)

    def test_a_type_clash_stops_before_writing(self):
        self.cdir.mkdir()
        for text in ('{"permissions": []}', '{"permissions": {"deny": "Read(x)"}}', "[]", "{bad"):
            with self.subTest(text=text):
                (self.cdir / "settings.json").write_text(text)
                before = self.snapshot()
                code, _, err = self.run_apply()
                self.assertEqual(code, 1)
                self.assertIn("Nothing was changed", err)
                self.assertEqual(self.snapshot(), before)

    def test_existing_rules_and_config_are_never_overwritten(self):
        rules = self.cdir / "stranger-danger" / "RULES.md"
        rules.parent.mkdir(parents=True)
        rules.write_text("edited\n")
        self.config.parent.mkdir(parents=True, mode=0o700)
        self.config.write_text("{}\n")
        os.chmod(self.config, 0o600)
        self.assertEqual(self.run_apply()[0], 0)
        self.assertEqual(rules.read_text(), "edited\n")
        self.assertEqual(self.config.read_text(), "{}\n")

    def test_a_symlinked_profile_gets_rules_for_both_paths(self):
        # the real-path form, exercised through a real link.
        real = self.home / "real-profile"
        real.mkdir()
        link = self.home / "linked-profile"
        link.symlink_to(real)
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(link)}):
            code, _, err = self.run_apply()
        self.assertEqual(code, 0, err)
        perms = json.loads((real / "settings.json").read_text())["permissions"]
        for form in (link, real):
            with self.subTest(form=form):
                self.assertIn(f"Edit(/{form}/settings.local.json)", perms["deny"])
                self.assertIn(f"Edit(/{form}/settings.json)", perms["ask"])
        # A link whose target holds a pattern character is refused.
        odd = self.home / "odd[profile]"
        odd.mkdir()
        link2 = self.home / "plain-link"
        link2.symlink_to(odd)
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(link2)}):
            code, _, err = self.run_apply()
        self.assertEqual(code, 2)
        self.assertIn("Nothing was changed", err)

    def test_automode_and_claude_config_dir(self):
        alt = self.home / "alt-profile"
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(alt)}):
            code, _, err = self.run_apply("--automode")
        self.assertEqual(code, 0, err)
        settings = json.loads((alt / "settings.json").read_text())
        self.assertIn("$defaults", settings["autoMode"]["hard_deny"])
        self.assertFalse((self.cdir / "settings.json").exists())
        lines = (alt / "CLAUDE.md").read_text().splitlines()
        self.assertEqual(lines, [f"@{alt}/stranger-danger/RULES.md"])
        ctx = doctor.Context(home=str(self.home), cwd=str(self.home), managed_settings=str(self.home / "managed-settings.json"), run=lambda argv, cwd=None: "3.12.3\n" if argv[:1] == ["python3"] else None,
                             config_dir=str(alt))
        self.assertEqual([c.status for c in doctor.check_rules(ctx) if c.name == "rules import"],
                         ["PASS"])
        # The other profile's own files get the deny rules ~/.claude gets.
        deny = settings["permissions"]["deny"]
        for rule in ("Edit(~/.claude/hooks/**)", "Edit(~/.claude/agents/**)",
                     "Edit(~/.claude.json)", "Read(~/.claude.json)"):
            rule = rule.replace("(~/.claude.json)", "(~/.claude/.claude.json)")
            with self.subTest(rule=rule):
                self.assertIn(rule.replace("(~/.claude/", f"(/{alt}/"), deny)
                # And through its real path, when the profile folder is a link.
                self.assertIn(rule.replace("(~/.claude/", f"(/{os.path.realpath(alt)}/"), deny)
        # And the asked rules for the files setup in chat writes (D4).
        ask = settings["permissions"]["ask"]
        for rule in ("Edit(~/.claude/CLAUDE.md)", "Edit(~/.claude/settings.json)",
                     "Edit(~/.claude/stranger-danger/**)"):
            with self.subTest(rule=rule):
                for form in (str(alt), os.path.realpath(alt)):
                    self.assertIn(rule.replace("(~/.claude/", f"(/{form}/"), ask)
                    self.assertNotIn(rule.replace("(~/.claude/", f"(/{form}/"), deny)
        # The step-by-step merge agrees.
        sys.path.insert(0, str(ROOT / "skills" / "setup"))
        import setup
        block = setup.merge_command(str(ROOT), "templates/settings.json", "templates/sandbox.json")
        (alt / "settings.json").unlink()
        proc = subprocess.run(["bash", "-c", block], capture_output=True, text=True, timeout=30,
                              env={"HOME": str(self.home), "PATH": os.environ.get("PATH", ""),
                                   "CLAUDE_CONFIG_DIR": str(alt)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads((alt / "settings.json").read_text())["permissions"]["deny"],
                         [r for r in deny])

    def test_refuses_a_redirected_or_unclear_setup(self):
        for env in ({"STRANGER_DANGER_CONFIG": str(self.config)}, {"CLAUDE_CONFIG_DIR": "rel"},
                    {"CLAUDECODE": "1"},
                    {"CLAUDE_CONFIG_DIR": str(self.home / "a*b")}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env):
                self.assertEqual(self.run_apply()[0], 2)
        self.assertEqual(self.snapshot(), {})

    def test_writes_through_a_symlinked_settings_file(self):
        dotfiles = Path(self.tmp.name) / "dotfiles"
        dotfiles.mkdir()
        (dotfiles / "settings.json").write_text("{}")
        self.cdir.mkdir()
        (self.cdir / "settings.json").symlink_to(dotfiles / "settings.json")
        self.assertEqual(self.run_apply()[0], 0)
        self.assertTrue((self.cdir / "settings.json").is_symlink())
        self.assertIn("sandbox", json.loads((dotfiles / "settings.json").read_text()))

    def test_same_result_as_the_step_by_step_merge(self):
        # setup.py's printed merge and apply.py must agree on the settings file.
        sys.path.insert(0, str(ROOT / "skills" / "setup"))
        import setup
        self.assertEqual(self.run_apply()[0], 0)
        by_apply = (self.cdir / "settings.json").read_text()
        (self.cdir / "settings.json").unlink()
        block = setup.merge_command(str(ROOT), "templates/settings.json", "templates/sandbox.json")
        proc = subprocess.run(["bash", "-c", block], capture_output=True, text=True, timeout=30,
                              env={"HOME": str(self.home), "PATH": os.environ.get("PATH", "")})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads((self.cdir / "settings.json").read_text()), json.loads(by_apply))

    def test_start_paths_that_exist_are_write_denied(self):
        (self.home / ".bashrc").write_text("# mine\n")
        (self.home / ".local" / "bin").mkdir(parents=True)
        (self.home / "elsewhere").mkdir()
        (self.home / ".cargo").symlink_to(self.home / "elsewhere")
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        settings = json.loads((self.cdir / "settings.json").read_text())
        home = os.path.realpath(self.home)
        self.assertEqual(settings["sandbox"]["filesystem"]["denyWrite"], SETUP_WRITE_DENIES
                         + [os.path.join(home, ".bashrc"), os.path.join(home, ".local")])
        self.assertIn(".bashrc", out)
        # No placeholder-prone entry for a file that isn't there.
        self.assertFalse((self.home / ".bash_profile").exists())
        code, out, _ = self.run_apply()
        self.assertIn("Nothing to change", out)

    def test_start_paths_keep_your_entries_and_never_duplicate(self):
        (self.home / ".profile").write_text("")
        (self.home / ".nvm").mkdir()
        self.cdir.mkdir()
        (self.cdir / "settings.json").write_text(json.dumps(
            {"sandbox": {"filesystem": {"denyWrite": ["~/.profile", "/srv/mine"]}}}))
        self.assertEqual(self.run_apply()[0], 0)
        deny = json.loads((self.cdir / "settings.json").read_text())["sandbox"]["filesystem"]["denyWrite"]
        self.assertEqual(deny, ["~/.profile", "/srv/mine"] + SETUP_WRITE_DENIES
                         + [os.path.join(os.path.realpath(self.home), ".nvm")])

    def test_start_paths_never_include_whole_config_folders(self):
        for name in (".claude", ".config", ".ssh"):
            (self.home / name).mkdir(exist_ok=True)
        path_env = os.pathsep.join([str(self.home / ".config" / "x" / "bin"), "/usr/bin"])
        self.assertEqual(apply.start_paths(str(self.home), path_env), [])

    def test_start_paths_skip_caches_venvs_and_relative_path_entries(self):
        for sub in (".venv/bin", ".cache/pypoetry/v/bin", ".npm/_npx/a/node_modules/.bin",
                    ".docker/bin", ".hidden-project/node_modules/.bin", ".opencode/bin"):
            (self.home / sub).mkdir(parents=True)
        path_env = os.pathsep.join(
            [str(self.home / s) for s in (".venv/bin", ".cache/pypoetry/v/bin",
                                          ".npm/_npx/a/node_modules/.bin", ".docker/bin",
                                          ".opencode/bin")] + ["node_modules/.bin", "."])
        cwd = os.getcwd()
        os.chdir(self.home / ".hidden-project")
        self.addCleanup(os.chdir, cwd)
        self.assertEqual(apply.start_paths(str(self.home), path_env),
                         [os.path.join(os.path.realpath(self.home), ".opencode")])

    def test_allow_write_keeps_a_start_path_writable_and_says_so(self):
        (self.home / ".cargo").mkdir()
        (self.home / ".local" / "share" / "pnpm").mkdir(parents=True)
        (self.home / ".profile").write_text("")
        self.cdir.mkdir()
        (self.cdir / "settings.json").write_text(json.dumps(
            {"sandbox": {"filesystem": {"allowWrite": ["~/.cargo", "~/.local/share/pnpm"]}}}))
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        fs = json.loads((self.cdir / "settings.json").read_text())["sandbox"]["filesystem"]
        self.assertEqual(fs["denyWrite"], SETUP_WRITE_DENIES
                         + [os.path.join(os.path.realpath(self.home), ".profile")])
        self.assertIn("Left writable", out)
        self.assertIn(".cargo", out)

    def test_the_osv_part_leaves_start_paths_write_denied(self):
        (self.home / ".local" / "bin").mkdir(parents=True)
        (self.home / ".cache").mkdir()
        code, out, err = self.run_apply("--osv")
        self.assertEqual(code, 0, err)
        fs = json.loads((self.cdir / "settings.json").read_text())["sandbox"]["filesystem"]
        self.assertEqual(fs["allowWrite"], ["~/.cache/stranger-danger/osv"])
        self.assertIn(os.path.join(os.path.realpath(self.home), ".local"), fs["denyWrite"])
        self.assertNotIn("Left writable", out)

    def test_the_osv_part_is_refused_inside_a_setup_folder(self):
        cdir = self.home / ".cache"
        cdir.mkdir()
        with self.assertRaises(apply.Stop):
            apply.plan(str(ROOT), str(self.home), str(cdir), "", False, osv=True)
        apply.plan(str(ROOT), str(self.home), str(cdir), "", False)

    def test_a_symlinked_start_file_is_not_denied(self):
        (self.home / "dotfiles").mkdir()
        (self.home / "dotfiles" / "bashrc").write_text("")
        (self.home / ".bashrc").symlink_to(self.home / "dotfiles" / "bashrc")
        self.assertEqual(apply.start_paths(str(self.home), ""), [])

    def test_a_denywrite_of_another_type_stops(self):
        (self.home / ".profile").write_text("")
        self.cdir.mkdir()
        (self.cdir / "settings.json").write_text(json.dumps(
            {"sandbox": {"filesystem": {"denyWrite": "~/.profile"}}}))
        before = self.snapshot()
        code, _out, err = self.run_apply()
        self.assertEqual(code, 1)
        self.assertIn("denyWrite", err)
        self.assertEqual(self.snapshot(), before)

    def test_canary_words_are_a_word_a_digit_and_a_letter(self):
        words = {apply.make_canary() for _ in range(200)}
        self.assertGreater(len(words), 150)
        for word in words:
            self.assertRegex(word, r"^[a-z]+-[0-9][a-z]$")
        self.assertEqual(len(set(apply.CANARY_WORDS)), len(apply.CANARY_WORDS))

    def test_a_rules_copy_with_the_placeholder_gets_a_canary_and_others_stay(self):
        rules = self.cdir / "stranger-danger" / "RULES.md"
        rules.parent.mkdir(parents=True)
        template = (ROOT / "rules" / "RULES.md").read_text()
        rules.write_text("my edits\n" + template)
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        [canary] = re.findall(r"Its rules canary is now (\S+)\. ", out)
        self.assertEqual(rules.read_text(), "my edits\n" + template.replace(
            "<your-canary-word>", canary, 1))
        self.assertIn(f"+Rules canary: {canary}", out)
        # A word of your own is never replaced.
        rules.write_text(template.replace("<your-canary-word>", "larkspur", 1))
        before = self.snapshot()
        code, out, _ = self.run_apply()
        self.assertEqual(code, 0)
        self.assertNotIn("Its rules canary", out)
        self.assertEqual(self.snapshot(), before)

    def test_the_placeholder_only_counts_on_its_own_line(self):
        text = "Rules canary: <your-canary-word> and more\nsee <your-canary-word>\n"
        self.assertIsNone(apply.fill_canary(text, "rue-1a"))
        self.assertEqual(apply.fill_canary("x\n  Rules canary: <your-canary-word>\n", "rue-1a"),
                         "x\n  Rules canary: rue-1a\n")

    def test_your_own_allow_unsandboxed_setting_is_kept_and_said(self):
        self.cdir.mkdir()
        (self.cdir / "settings.json").write_text(json.dumps(
            {"sandbox": {"enabled": True, "allowUnsandboxedCommands": True}}))
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        settings = json.loads((self.cdir / "settings.json").read_text())
        self.assertIs(settings["sandbox"]["allowUnsandboxedCommands"], True)
        self.assertIn("Kept your own sandbox.allowUnsandboxedCommands", out)
        # The same value as the template's needs no note.
        settings["sandbox"]["allowUnsandboxedCommands"] = False
        (self.cdir / "settings.json").write_text(json.dumps(settings))
        code, out, _ = self.run_apply()
        self.assertNotIn("Kept your own", out)

    def write_gate_config(self, section: dict) -> None:
        self.config.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.config.write_text(json.dumps({"reader_gate": section}))
        os.chmod(self.config, 0o600)

    def test_gate_config_folders_that_exist_are_read_denied(self):
        for name in ("docs", "quar", "vault", "real"):
            (self.home / name).mkdir()
        (self.home / "linked").symlink_to(self.home / "real")
        self.write_gate_config({
            "untrusted_paths": ["~/docs", "~/missing", "~/linked/"],
            "quarantine_paths": [str(self.home / "quar")],
            "secret_paths": ["~/vault/**", "**/*.secret", "~/docs"]})
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        fs = json.loads((self.cdir / "settings.json").read_text())["sandbox"]["filesystem"]
        # In your home folder, the ~/ form; a symlink, at its real path.
        self.assertEqual(fs["denyRead"], ["~/docs", "~/real", "~/quar", "~/vault"])
        self.assertIn("No sandbox read deny for **/*.secret:", out)
        before = self.snapshot()
        code, out, _ = self.run_apply()
        self.assertIn("Nothing to change", out)
        self.assertEqual(self.snapshot(), before)

    def test_home_root_and_covered_folders_get_no_read_deny(self):
        (self.home / "work" / "docs").mkdir(parents=True)
        self.cdir.mkdir()
        (self.cdir / "settings.json").write_text(json.dumps(
            {"sandbox": {"filesystem": {"denyRead": ["~/work"]}}}))
        self.write_gate_config({"untrusted_paths": ["~/", "~", "/", str(self.home.parent),
                                                    "~/work/docs"]})
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        fs = json.loads((self.cdir / "settings.json").read_text())["sandbox"]["filesystem"]
        self.assertEqual(fs["denyRead"], ["~/work"])
        self.assertIn("No sandbox read deny for ~/, ~, /, ", out)

    def test_folders_sandboxed_work_needs_get_no_read_deny(self):
        plugin = Path(apply.PLUGIN_ROOT)
        (self.cdir / "plugins").mkdir(parents=True)
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        keep = apply.guarded(str(self.home), str(self.cdir), str(plugin))
        cases = [self.cdir, self.cdir / "plugins", "/tmp", "/usr", "/usr/share", "/etc", "/var",
                 tempfile.gettempdir(), plugin, plugin / "hooks", sys.prefix,
                 Path(self.tmp.name).parent, self.home, self.home.parent, "/"]
        for entry in cases:
            with self.subTest(entry=str(entry)):
                self.assertTrue(apply.off_limits(os.path.realpath(entry), str(self.home), keep))
        # A folder inside a temporary folder is fine: it hides only itself.
        self.assertFalse(apply.off_limits(os.path.realpath(outside), str(self.home), keep))
        self.assertFalse(apply.off_limits(os.path.realpath(self.home / "docs"), str(self.home),
                                          keep))
        self.write_gate_config({"untrusted_paths": ["~/.claude/plugins", str(outside)]})
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        fs = json.loads((self.cdir / "settings.json").read_text())["sandbox"]["filesystem"]
        self.assertEqual(fs["denyRead"], [os.path.realpath(outside)])
        self.assertIn("No sandbox read deny for ~/.claude/plugins:", out)

    def test_a_gate_config_the_gates_refuse_adds_no_read_denies_and_says_so(self):
        (self.home / "docs").mkdir()
        self.config.parent.mkdir(parents=True, mode=0o700)
        for text, mode in (("{nope", 0o600),
                           (json.dumps({"reader_gate": {"untrusted_paths": ["~/docs"]}}), 0o620),
                           (json.dumps({"reader_gate": {"untrusted_paths": ["~/docs"],
                                                        "typo": 1}}), 0o600)):
            with self.subTest(text=text, mode=oct(mode)):
                self.config.write_text(text)
                os.chmod(self.config, mode)
                code, out, err = self.run_apply()
                self.assertEqual(code, 0, err)
                self.assertIn("The gates refuse", out)
                settings = json.loads((self.cdir / "settings.json").read_text())
                self.assertNotIn("denyRead", settings["sandbox"].get("filesystem", {}))
                self.assertEqual(self.config.read_text(), text)

    def test_a_crlf_rules_file_keeps_its_line_endings(self):
        rules = self.cdir / "stranger-danger" / "RULES.md"
        rules.parent.mkdir(parents=True)
        template = (ROOT / "rules" / "RULES.md").read_text()
        rules.write_bytes(template.replace("\n", "\r\n").encode())
        code, out, err = self.run_apply()
        self.assertEqual(code, 0, err)
        [canary] = re.findall(r"Its rules canary is now (\S+)\. ", out)
        self.assertEqual(rules.read_bytes(), template.replace(
            "<your-canary-word>", canary, 1).replace("\n", "\r\n").encode())

    def test_a_rules_file_that_isnt_utf8_stops_cleanly(self):
        rules = self.cdir / "stranger-danger" / "RULES.md"
        rules.parent.mkdir(parents=True)
        rules.write_bytes(b"Rules canary: \xff\n")
        before = self.snapshot()
        code, _out, err = self.run_apply()
        self.assertEqual(code, 1)
        self.assertIn("isn't UTF-8", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(self.snapshot(), before)

    def test_a_denyread_of_another_type_stops(self):
        (self.home / "docs").mkdir()
        self.write_gate_config({"untrusted_paths": ["~/docs"]})
        self.cdir.mkdir()
        (self.cdir / "settings.json").write_text(json.dumps(
            {"sandbox": {"filesystem": {"denyRead": "~/docs"}}}))
        before = self.snapshot()
        code, _out, err = self.run_apply()
        self.assertEqual(code, 1)
        self.assertIn("denyRead", err)
        self.assertEqual(self.snapshot(), before)

    def test_rejects_unknown_arguments(self):
        self.assertEqual(self.run_apply("--yes")[0], 2)
        self.assertEqual(self.snapshot(), {})


if __name__ == "__main__":
    unittest.main()
