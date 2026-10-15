"""Tests for skills/setup/setup.py.

The printed commands are run for real, with bash, against a fake home under a
temporary folder and a copy of the plugin whose path has a space and a quote
in it. Then the doctor checks the result. Nothing touches the real home.
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "setup"))
sys.path.insert(0, str(ROOT / "skills" / "doctor"))
sys.path.insert(0, str(ROOT / "hooks"))
sys.path.insert(0, str(ROOT / "skills" / "coordinator"))

import doctor  # noqa: E402
import setup  # noqa: E402

TEMPLATE_DENY = json.loads((ROOT / "templates" / "settings.json").read_text())["permissions"]["deny"]
IMPORT_LINE = "@~/.claude/stranger-danger/RULES.md"


def snapshot(folder: Path) -> dict:
    return {str(p.relative_to(folder)): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in folder.rglob("*")}


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.plugin = base / "plug in's cache" / "stranger-danger"
        for part in (".claude-plugin", "agents", "hooks", "templates", "rules", "skills"):
            shutil.copytree(ROOT / part, self.plugin / part)
        # The coordinator step runs in "$PWD": every block runs here, never in the repo.
        self.project = base / "coord project's folder"
        self.project.mkdir()
        bin_dir = base / "bin"
        bin_dir.mkdir()
        os.symlink(sys.executable, bin_dir / "python3")
        self.env = {"HOME": str(self.home), "PATH": f"{bin_dir}:/usr/bin:/bin", "LC_ALL": "C"}
        patcher = mock.patch.dict(os.environ, {
            "HOME": str(self.home),
            "STRANGER_DANGER_CONFIG": str(self.home / ".config" / "stranger-danger" / "config.json")})
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR"):
            os.environ.pop(name, None)  # restored by the patcher

    def run_setup(self) -> str:
        proc = subprocess.run([sys.executable, "-I", str(self.plugin / "skills" / "setup" / "setup.py")],
                              capture_output=True, text=True, env=self.env, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def all_blocks(self, output: str) -> list:
        return re.findall(r"^```bash\n(.*?)^```$", output, re.S | re.M)

    def blocks(self, output: str) -> list:
        """The step-by-step blocks; the one-command form comes first."""
        return self.all_blocks(output)[1:]

    def run_block(self, block: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", "-c", block], capture_output=True, text=True,
                              env=self.env, timeout=30, cwd=self.project)

    def settings(self) -> dict:
        return json.loads((self.home / ".claude" / "settings.json").read_text())

    def test_prints_real_paths_and_writes_nothing(self):
        before_home, before_plugin = snapshot(self.home), snapshot(self.plugin)
        output = self.run_setup()
        self.assertIn(f"Plugin files: {self.plugin}", output)
        for rel in ("templates/settings.json", "templates/sandbox.json", "templates/config.json",
                    "templates/automode.json", "rules/RULES.md"):
            self.assertIn(str(self.plugin / rel).replace("'", "'\"'\"'"), output)
        self.assertNotIn("${CLAUDE_PLUGIN_ROOT}", output)
        self.assertEqual(len(self.blocks(output)), 5)
        [one] = [b for b in self.all_blocks(output) if "setup/apply.py" in b]
        self.assertEqual(one, self.all_blocks(output)[0])
        # It needs a terminal, because it asks before writing; apply's own
        # tests cover the rest.
        proc = self.run_block(one)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("terminal", proc.stderr)
        self.assertEqual(snapshot(self.home), before_home)
        self.assertEqual(snapshot(self.plugin), before_plugin)

    def test_commands_work_on_a_fresh_home_and_twice(self):
        blocks = self.blocks(self.run_setup())
        for attempt in (1, 2):
            for block in blocks:
                with self.subTest(attempt=attempt, block=block[:40]):
                    proc = self.run_block(block)
                    if "coordinator/install.py" not in block:
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        continue
                    # The install wants a terminal and the account's own home
                    # folder, which this test has neither of, so it runs
                    # in-process here.
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertIn("terminal", proc.stderr)
                    self.assertIn('install.py\' "$folder" "$name"', block)
                    import install
                    self.assertEqual(install.install(str(self.project), "the StrangerDanger "
                                                     "coordinator", home=str(self.home),
                                                     out=lambda line: None), 0)
        settings = self.settings()
        self.assertEqual(settings["permissions"]["deny"], TEMPLATE_DENY)
        self.assertIs(settings["sandbox"]["enabled"], True)
        self.assertIn("$defaults", settings["autoMode"]["hard_deny"])
        self.assertEqual(len(settings["autoMode"]["hard_deny"]),
                         len(set(settings["autoMode"]["hard_deny"])))
        self.assertTrue((self.home / ".claude" / "settings.json.bak").is_file())
        rules = self.home / ".claude" / "stranger-danger" / "RULES.md"
        self.assertEqual(rules.read_bytes(), (ROOT / "rules" / "RULES.md").read_bytes())
        claude_md = (self.home / ".claude" / "CLAUDE.md").read_text().splitlines()
        self.assertEqual(claude_md.count(IMPORT_LINE), 1)
        config = self.home / ".config" / "stranger-danger" / "config.json"
        # The template, plus the coordinator the last step named: this folder.
        expected = json.loads((ROOT / "templates" / "config.json").read_text())
        expected["coordinator"] = {"project": os.path.realpath(self.project),
                                   "name": "the StrangerDanger coordinator"}
        self.assertEqual(json.loads(config.read_text()), expected)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(config.parent.stat().st_mode), 0o700)
        self.assertEqual(claude_md.count("<!-- stranger-danger:coordinator begin -->"), 1)
        # The doctor agrees: nothing fails, and the settings, sandbox, config,
        # import and coordinator checks pass. (The canary is still the
        # placeholder, a WARN.)
        ctx = doctor.Context(home=str(self.home), plugin_root=str(self.plugin),
                             cwd=str(self.project), run=lambda argv, cwd=None: "3.12.3\n" if argv[:1] == ["python3"] else None)
        checks = doctor.run_all(ctx)
        self.assertEqual([(c.name, c.detail) for c in checks if c.status == "FAIL"], [])
        for name in ("settings deny rules", "sandbox", "config", "rules import", "coordinator",
                     "ssh allow rules"):
            with self.subTest(check=name):
                self.assertIn("PASS", [c.status for c in checks if c.name == name])

    def test_merge_keeps_what_is_there(self):
        (self.home / ".claude").mkdir()
        mine = {"model": "x", "permissions": {"allow": ["Bash(ls)"], "deny": ["Read(~/mine)",
                                                                             TEMPLATE_DENY[0]]},
                "sandbox": {"enabled": False, "excludedCommands": ["docker"]}}
        (self.home / ".claude" / "settings.json").write_text(json.dumps(mine))
        os.chmod(self.home / ".claude" / "settings.json", 0o600)
        (self.home / ".claude" / "CLAUDE.md").write_text("# mine\n" + IMPORT_LINE + "\n")
        for block in self.blocks(self.run_setup())[:2]:
            self.assertEqual(self.run_block(block).returncode, 0)
        settings = self.settings()
        self.assertEqual(settings["model"], "x")
        self.assertEqual(settings["permissions"]["allow"], ["Bash(ls)"])
        self.assertEqual(settings["permissions"]["deny"], ["Read(~/mine)"] + TEMPLATE_DENY)
        self.assertEqual(settings["sandbox"], {"enabled": True, "excludedCommands": ["docker"]})
        self.assertEqual(json.loads((self.home / ".claude" / "settings.json.bak").read_text()), mine)
        self.assertEqual(stat.S_IMODE((self.home / ".claude" / "settings.json").stat().st_mode),
                         0o600)
        self.assertEqual((self.home / ".claude" / "CLAUDE.md").read_text(),
                         "# mine\n" + IMPORT_LINE + "\n")

    def test_the_merge_refuses_a_profile_whose_real_path_holds_a_pattern_character(self):
        # Review 4: the rules name the real path too, so it's checked too.
        odd = self.home / "odd[profile]"
        odd.mkdir()
        link = self.home / "plain-link"
        link.symlink_to(odd)
        block = self.blocks(self.run_setup())[0]
        proc = subprocess.run(["bash", "-c", block], capture_output=True, text=True,
                              env=dict(self.env, CLAUDE_CONFIG_DIR=str(link)), timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("must be an absolute path", proc.stderr)
        self.assertFalse((odd / "settings.json").exists())

    def test_commands_follow_claude_config_dir(self):
        # The printed commands honor CLAUDE_CONFIG_DIR at run time (F6): the merge
        # and the rules copy land in that profile, not ~/.claude.
        alt = self.home / "alt-claude"
        env = dict(self.env, CLAUDE_CONFIG_DIR=str(alt))
        for block in self.blocks(self.run_setup())[:2]:  # settings merge, then rules
            proc = subprocess.run(["bash", "-c", block], capture_output=True, text=True,
                                  env=env, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((alt / "settings.json").is_file())
        self.assertFalse((self.home / ".claude" / "settings.json").exists())
        settings = json.loads((alt / "settings.json").read_text())
        # The template's rules, then each ~/.claude/ rule again for this profile.
        profile = [r.replace("(~/.claude/", f"(/{alt}/", 1)
                   .replace("(~/.claude.json)", f"(/{alt}/.claude.json)", 1) for r in TEMPLATE_DENY
                   if "(~/.claude/" in r or "(~/.claude.json)" in r]
        self.assertTrue(profile)
        self.assertEqual(settings["permissions"]["deny"], TEMPLATE_DENY + profile)
        self.assertEqual((alt / "stranger-danger" / "RULES.md").read_bytes(),
                         (ROOT / "rules" / "RULES.md").read_bytes())
        # The import points at this profile's copy, not ~/.claude's, and the
        # doctor run against this profile agrees.
        lines = (alt / "CLAUDE.md").read_text().splitlines()
        self.assertEqual(lines.count(f"@{alt}/stranger-danger/RULES.md"), 1)
        self.assertNotIn(IMPORT_LINE, lines)
        ctx = doctor.Context(home=str(self.home), plugin_root=str(self.plugin),
                             cwd=str(self.home), run=lambda argv, cwd=None: "3.12.3\n" if argv[:1] == ["python3"] else None, config_dir=str(alt))
        self.assertEqual([c.status for c in doctor.check_rules(ctx) if c.name == "rules import"],
                         ["PASS"])

    def test_merge_stops_on_an_unexpected_shape(self):
        (self.home / ".claude").mkdir()
        path = self.home / ".claude" / "settings.json"
        for text in ('{"permissions": []}', '{"permissions": {"deny": "Read(x)"}}', "[]"):
            with self.subTest(text=text):
                path.write_text(text)
                proc = self.run_block(self.blocks(self.run_setup())[0])
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(path.read_text(), text)

    def test_copies_never_overwrite(self):
        rules = self.home / ".claude" / "stranger-danger" / "RULES.md"
        config = self.home / ".config" / "stranger-danger" / "config.json"
        for path in (rules, config):
            path.parent.mkdir(parents=True)
            path.write_text("edited\n")
        for block in self.blocks(self.run_setup())[1:3]:
            self.assertEqual(self.run_block(block).returncode, 0)
        self.assertEqual(rules.read_text(), "edited\n")
        self.assertEqual(config.read_text(), "edited\n")

    def test_refuses_a_path_with_control_characters(self):
        with mock.patch.object(setup, "PLUGIN_ROOT", "/tmp/x\n; rm -rf ~"), \
                mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(setup.main(), 1)

    def test_reports_missing_templates(self):
        (self.plugin / "templates" / "sandbox.json").unlink()
        with mock.patch.object(setup, "PLUGIN_ROOT", str(self.plugin)), \
                mock.patch("sys.stderr", io.StringIO()) as err, redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(), 1)
        self.assertIn("templates/sandbox.json", err.getvalue())


if __name__ == "__main__":
    unittest.main()
