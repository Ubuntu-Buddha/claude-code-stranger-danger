"""Repository checks that CI also runs: JSON validity, hook commands, templates
and the reader agents' tool lists."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hooks"))

import _config  # noqa: E402
import launch_gate  # noqa: E402
import reader_gate  # noqa: E402


def tracked_files() -> list:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,
                             check=True).stdout.decode()
        return [ROOT / p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        return [p for p in ROOT.rglob("*") if ".git" not in p.parts and p.is_file()]


class RepoTests(unittest.TestCase):
    def test_every_json_file_parses(self):
        files = [p for p in tracked_files() if p.suffix == ".json"]
        self.assertTrue(files)
        for path in files:
            with self.subTest(path=str(path.relative_to(ROOT))):
                json.loads(path.read_text(encoding="utf-8"))

    def test_every_hook_command_points_at_a_file(self):
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        commands = [h["command"] for entries in data["hooks"].values()
                    for entry in entries for h in entry["hooks"]]
        gates = [h["command"] for entry in data["hooks"]["PreToolUse"] for h in entry["hooks"]]
        self.assertTrue(commands)
        for command in commands:
            with self.subTest(command=command):
                scripts = re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\"' ]+)", command)
                self.assertTrue(scripts, "a hook command must run a file from the plugin")
                for script in scripts:
                    self.assertTrue((ROOT / script).is_file(), script)
                if command in gates:
                    self.assertTrue(command.rstrip().endswith("|| exit 2"),
                                    "a gate that crashes must block, not pass")
                self.assertIn("python3 -I", command)

    def test_every_hook_blocks_on_failure(self):
        """A hook that times out lets the call through unless it sets
        onFailure: "block" (Claude Code 2.1.295 and later). The value must be
        exactly "block": 2.1.296 refuses to load a hook with any other value
        than "continue" or "block", which would leave the gate off."""
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        hooks = [h for entry in data["hooks"]["PreToolUse"] for h in entry["hooks"]]
        self.assertTrue(hooks)
        for hook in hooks:
            with self.subTest(command=hook["command"]):
                self.assertEqual(hook.get("onFailure"), "block")

    def test_only_the_gates_the_update_reminder_the_canary_fill_and_the_scan_are_hooked(self):
        """The gates are the only PreToolUse hooks. The others are the
        SessionStart reminder, canary fill and OSV status line, which must
        never block a session, and the scan skill's UserPromptSubmit hook,
        which must never block a prompt: no onFailure and no exit 2 on any of
        them."""
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        self.assertEqual(sorted(data["hooks"]), ["PostToolUse", "PreToolUse", "SessionStart", "UserPromptSubmit"])
        template = json.loads((ROOT / "templates" / "settings.json").read_text())["permissions"]
        for entry in ("mcp__terminal__run_in_terminal", "mcp__terminal__read_terminal",
                      "mcp__terminal__stop_terminal_tab"):
            self.assertIn(entry, template["ask"])
        for entry in ("mcp__terminal__open_terminal_tab", "mcp__terminal__list_terminal_tabs",
                      "Edit(~/.claude/skills/**)", "Edit(//**/.claude/skills/**)"):
            self.assertIn(entry, template["deny"])
        [post] = data["hooks"]["PostToolUse"]
        self.assertEqual(post["matcher"], "mcp__terminal__run_in_terminal")
        for hook in post["hooks"]:
            self.assertNotIn("onFailure", hook)
            self.assertTrue(hook["command"].rstrip().endswith("|| exit 0"))
        [scan_entry] = data["hooks"]["UserPromptSubmit"]
        self.assertNotIn("matcher", scan_entry)
        self.assertEqual([hook["command"] for hook in scan_entry["hooks"]],
                         ['python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/scan_prompt.py" || exit 0'])
        for hook in scan_entry["hooks"]:
            self.assertNotIn("onFailure", hook)
        entry, instr_entry = data["hooks"]["SessionStart"]
        # Not on /clear or compaction: those keep a process that may predate an update.
        self.assertEqual(entry["matcher"], "startup|resume")
        self.assertEqual([hook["command"] for hook in entry["hooks"]],
                         ['python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/doctor_nudge.py"',
                          'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/canary_fill.py"',
                          'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/osv_status.py"'])
        for hook in entry["hooks"]:
            self.assertNotIn("onFailure", hook)
        # instr-check also runs on /clear, compaction and fork (the docs list both; neither is tested
        # against a live Claude Code here): a planted instruction file is loaded again then.
        self.assertEqual(instr_entry["matcher"], "startup|resume|clear|compact|fork")
        [instr] = instr_entry["hooks"]
        self.assertNotIn("onFailure", instr)
        self.assertTrue(instr["command"].startswith('python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/instr_check.py" || echo '))

    def test_instr_check_says_so_when_the_interpreter_is_missing(self):
        """A hook that cannot start must not read as a clean check: the fallback
        prints one JSON object for the user and the model."""
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        command = data["hooks"]["SessionStart"][1]["hooks"][0]["command"]
        done = subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True, timeout=30,
                              env={"PATH": "/nonexistent", "CLAUDE_PLUGIN_ROOT": str(ROOT)})
        self.assertEqual(done.returncode, 0)
        out = json.loads(done.stdout)
        self.assertIn("did not run", out["systemMessage"])
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "SessionStart")
        self.assertIn("did not run", out["hookSpecificOutput"]["additionalContext"])

    def test_instr_check_says_so_when_the_script_crashes_at_import(self):
        """A script that fails before it prints anything exits nonzero, and the
        fallback then prints the one fixed line, so a crash is not read as clean."""
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        command = data["hooks"]["SessionStart"][1]["hooks"][0]["command"]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "hooks").mkdir()
            (Path(tmp) / "hooks" / "instr_check.py").write_text("import no_such_module_for_this_test\n")
            (Path(tmp) / "bin").mkdir()
            os.symlink(sys.executable, Path(tmp) / "bin" / "python3")
            done = subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True, timeout=30,
                                  env={"PATH": str(Path(tmp) / "bin"), "CLAUDE_PLUGIN_ROOT": tmp})
        self.assertEqual(done.returncode, 0)
        # the script ran and failed at import, not an interpreter that never started
        self.assertIn("no_such_module_for_this_test", done.stderr)
        out = json.loads(done.stdout)
        self.assertIn("did not run", out["systemMessage"])

    def test_gate_sources_are_printable_ascii(self):
        """Hook and skill source must be printable ASCII, with any other
        character written as a \\u or \\N{} escape. A literal combining mark,
        zero-width space, bidi control or byte-order mark hidden in a pattern
        reads as safe but changes what the gate matches. (Both a U+20E3
        keycap in a regex source and a stray BOM have happened.)"""
        allowed = {0x09, 0x0A, 0x0D}  # tab, newline, carriage return
        sources = sorted((ROOT / "hooks").glob("*.py")) + sorted((ROOT / "skills").rglob("*.py"))
        self.assertTrue(sources)
        for path in sources:
            with self.subTest(path=str(path.relative_to(ROOT))):
                raw = path.read_bytes()
                for i, b in enumerate(raw):
                    if not (0x20 <= b <= 0x7E or b in allowed):
                        line = raw[:i].count(b"\n") + 1
                        self.fail(f"byte 0x{b:02x} at line {line} is not printable ASCII; "
                                  f"write non-ASCII as a \\u or \\N{{}} escape")

    def test_config_template_loads_and_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o700)
            path = Path(tmp) / "config.json"
            path.write_bytes((ROOT / "templates" / "config.json").read_bytes())
            os.chmod(path, 0o600)
            config = _config.load_config(path)
        reader_gate.Policy.from_config(config, reader_gate.Env(home="/fake/home"))
        launch_gate._allow_prefixes(config)
        self.assertEqual(set(config), {"reader_gate", "launch_gate"})

    def test_settings_template_shape(self):
        data = json.loads((ROOT / "templates" / "settings.json").read_text())
        deny = data["permissions"]["deny"]
        self.assertEqual(len(deny), len(set(deny)), "duplicate rules")
        self.assertNotIn("Read(~/.npmrc)", deny,
                         "denying ~/.npmrc hides npm's own safety settings from sandboxed npm")

    def test_settings_template_reads_are_also_closed_by_the_gate(self):
        """Every Read deny in the template names a path the reader gate refuses too."""
        deny = json.loads((ROOT / "templates" / "settings.json").read_text())["permissions"]["deny"]
        reads = [r[len("Read("):-1] for r in deny if r.startswith("Read(")]
        self.assertGreater(len(reads), 40)
        with tempfile.TemporaryDirectory() as tmp:
            env = reader_gate.Env(home=tmp, plugin_root=str(ROOT))
            for rule in reads:
                sample = rule.replace("//", "/", 1) if rule.startswith("//") else rule
                sample = sample.replace("**", "some/dir").replace("*", "x")
                sample = sample.replace("/some/dir", tmp + "/proj", 1) \
                    if sample.startswith("/some/dir") else sample
                event = {"tool_name": "Read", "tool_input": {"file_path": sample}, "cwd": tmp}
                with self.subTest(rule=rule, sample=sample):
                    reason = reader_gate.decide(event, {}, env) or ""
                    # Claude Code's records (history.jsonl, file-history, ...) are
                    # refused under rule 3; everything else as a secret.
                    if any(f"/.claude/{name}" in rule for name in reader_gate.CLAUDE_STATE):
                        self.assertIn("own records", reason)
                    else:
                        self.assertIn("rule 5", reason)

    def test_new_secret_paths_are_in_both_lists(self):
        # Literal lists (2026-10-09 review): the gate's built-ins and the template agree.
        both = ["~/snap/firefox/**", "~/snap/chromium/**", "~/.config/solana/**",
                "~/.ethereum/keystore/**", "**/keystore/UTC--*", "~/.local/share/fish/fish_history",
                "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.kdbx", "~/.password-store/**",
                "~/.var/app/org.mozilla.firefox/**", "~/.var/app/com.google.Chrome/**",
                "~/.var/app/org.chromium.Chromium/**", "~/.var/app/com.brave.Browser/**",
                # Podman's Linux login file and Poetry's on macOS.
                "**/containers/auth.json", "~/Library/Application Support/pypoetry/auth.toml"]
        gate_only = ["**/id_ecdsa*", "**/id_dsa*", "~/.npmrc"]
        deny = json.loads((ROOT / "templates" / "settings.json").read_text())["permissions"]["deny"]
        for pattern in both + gate_only:
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, reader_gate.BUILTIN_SECRETS)
        for pattern in both:
            rule = "Read(" + ("//" + pattern if pattern.startswith("**") else pattern) + ")"
            with self.subTest(rule=rule):
                self.assertIn(rule, deny)

    def test_gap_fix_secret_paths_are_in_both_lists(self):
        # 2026-10-15 gap fix A and H: a sample of each kind, in the gate and the template.
        both = ["~/.config/microsoft-edge/**", "~/Library/Application Support/Firefox/**",
                "~/Library/Safari/**", "~/.foundry/keystores/**", "~/.bitcoin/**", "~/.sui/**",
                "~/.oci/**", "~/.config/doctl/**", "~/.fly/**", "~/.claude/backups/**",
                "~/.claude.json.*", "**/.git-credentials", "**/*.tfstate", "**/*.env",
                "**/client_secret*.json", "**/.aws/credentials"]
        gate_only = ["~/.kube/**"]
        deny = json.loads((ROOT / "templates" / "settings.json").read_text())["permissions"]["deny"]
        self.assertEqual(len(deny), len(set(deny)), "duplicate rules")
        self.assertEqual(len(reader_gate.BUILTIN_SECRETS), len(set(reader_gate.BUILTIN_SECRETS)))
        for pattern in both + gate_only:
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, reader_gate.BUILTIN_SECRETS)
        for pattern in both:
            rule = "Read(" + ("//" + pattern if pattern.startswith("**") else pattern) + ")"
            with self.subTest(rule=rule):
                self.assertIn(rule, deny)
        # Registry logins that turn up in projects.
        for pattern in ("**/.npmrc", "**/.yarnrc.yml"):
            self.assertIn(pattern, reader_gate.BUILTIN_SECRETS)
        # Claude Code state, more profiles, Electron stores.
        for pattern in ("~/.claude/ide/**", "~/.thunderbird/**", "~/.local/share/kwalletd/**",
                        "~/Library/Application Support/Google/**", "**/.ssh/**",
                        "~/.config/Claude/claude_desktop_config.json/**",
                        "~/.config/Slack/Cookies/**", "~/.config/discord/Local Storage/**"):
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, reader_gate.BUILTIN_SECRETS)
        self.assertNotIn("~/.config/Claude/**", reader_gate.BUILTIN_SECRETS)
        for rule in ("Read(~/.claude/history.jsonl)", "Read(~/.claude/file-history/**)",
                     "Read(~/.claude/debug/**)", "Read(~/.claude/paste-cache/**)",
                     "Read(~/.claude/uploads/**)", "Read(~/.claude/todos/**)",
                     "Read(~/.claude/ide/**)", "Read(~/.config/Claude/claude_desktop_config.json)",
                     "Read(~/.config/Claude/Local Storage/**)", "Read(//**/.ssh/**)"):
            with self.subTest(rule=rule):
                self.assertIn(rule, deny)
        # Sandboxed Bash reads these to set up each command (a user report,
        # anthropics/claude-code issue 28308: every Bash command fails when the
        # sandbox can't read the shell snapshot), so the template leaves them
        # to the gate (the Read tool) alone.
        for rule in ("Read(~/.claude/shell-snapshots/**)", "Read(~/.claude/session-env/**)"):
            with self.subTest(rule=rule):
                self.assertNotIn(rule, deny)

    def test_settings_template_asks_before_going_public_or_driving_a_browser(self):
        perms = json.loads((ROOT / "templates" / "settings.json").read_text())["permissions"]
        ask = perms["ask"]
        self.assertEqual(len(ask), len(set(ask)), "duplicate rules")
        self.assertFalse(set(ask) & set(perms["deny"]))
        for rule in ("Edit(//**/.stranger-danger/**)", "Bash(gh repo create *)",
                     "Bash(gh repo edit *)", "Bash(gh release *)", "Bash(gh gist *)",
                     "Bash(gh pr create *)", "Bash(gh pr merge *)", "Bash(gh issue comment *)",
                     "Bash(gh api *)", "Bash(npm publish)", "Bash(npm publish *)",
                     "Bash(cargo publish)", "Bash(twine upload *)", "Bash(docker push *)",
                     "mcp__claude-in-chrome", "mcp__playwright",
                     # more subcommands, image pushes, publishers.
                     "Bash(gh pr edit *)", "Bash(gh workflow run *)", "Bash(gh secret set *)",
                     "Bash(docker image push *)", "Bash(skopeo copy *)",
                     "Bash(python3 -m twine upload *)", "Bash(hatch publish *)", "mcp__github"):
            with self.subTest(rule=rule):
                self.assertIn(rule, ask)
        # Branch pushes to your private repos need no OK, and a rule can't tell
        # a public push apart, so pushes stay with the auto-mode rules.
        self.assertFalse([r for r in ask if r.startswith("Bash(git push")])

    def test_settings_template_protects_the_guardrails(self):
        """Agents can't edit what keeps them in check: settings, hooks, agent
        definitions, MCP config, the rules, the gate config, the gates' log and the
        installed plugin."""
        perms = json.loads((ROOT / "templates" / "settings.json").read_text())["permissions"]
        deny = perms["deny"]
        for rule in ("Edit(//**/.claude/settings.json)",
                     "Edit(//**/.claude/settings.local.json)", "Edit(~/.claude/settings.local.json)",
                     "Edit(~/.claude/hooks/**)", "Edit(//**/.claude/hooks/**)",
                     "Edit(~/.claude/agents/**)", "Edit(//**/.claude/agents/**)",
                     "Edit(//**/.mcp.json)", "Edit(~/.claude.json)",
                     "Edit(~/.config/stranger-danger/**)",
                     "Edit(~/.local/state/stranger-danger/**)", "Edit(~/.claude/plugins/**)"):
            with self.subTest(rule=rule):
                self.assertIn(rule, deny)
        # The files setup in chat writes are asked instead (D4), and the
        # settings guard refuses every edit to them but the one setup works out.
        for rule in ("Edit(~/.claude/settings.json)", "Edit(~/.claude/CLAUDE.md)",
                     "Edit(~/.claude/stranger-danger/**)"):
            with self.subTest(rule=rule):
                self.assertIn(rule, perms["ask"])
                self.assertNotIn(rule, deny)

    def test_rules_and_automode_match_the_protocol(self):
        """The shipped rules and auto-mode rules carry the protocol's points
        (B7: they had drifted from the canonical rules)."""
        rules = (ROOT / "rules" / "RULES.md").read_text()
        for phrase in ("covers the action it names, once", "a standing instruction",
                       "can't get an OK", "reports BLOCKED", "never cloned onto this machine",
                       "`cargo add` or `cargo update`", "pinned by digest", "--only-binary :all:",
                       "Never weaken the package managers' safety settings",
                       "MCP and connector tools", "only public identifiers", "**Browsers:**",
                       "never run `sudo`", "messages to people", "tools given to readers",
                       "tell it to follow this file", "another read-only route", "`gh api`",
                       "`~/.claude/CLAUDE.md`", "no values", "`git push origin <branch>`",
                       "your repos' container images", "own signed archive", "a brief or a memory",
                       "captured test fixtures", "is the enforcement", "page text"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, rules)
        auto = json.loads((ROOT / "templates" / "automode.json").read_text())["autoMode"]
        text = json.dumps(auto)
        for phrase in ("messages to people", "a standing instruction", "Rust crates",
                       "pinned by digest", "Browser Control:", "STRANGER_DANGER_CONFIG", "sudo",
                       "Stranger Container Images:", "by any route", "Dependabot"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        self.assertNotIn("dependency docs", text)
        # Every entry the user can clear says what doesn't clear it (all of
        # them: a narrower check missed the dependency entry).
        clearable = [e for e in auto["soft_deny"]
                     if any(w in e for w in ("Cleared", "unless the user", "the user's OK"))]
        self.assertGreaterEqual(len(clearable), 7)
        for entry in clearable:
            with self.subTest(entry=entry[:30]):
                self.assertIn("doesn't clear it", entry)
        self.assertIn("by any route", rules)
        self.assertIn("rule 7 report", rules)

    def test_every_claim_names_a_test_that_exists(self):
        """docs/CLAIMS.md maps the README's claims to tests; each must exist."""
        import ast
        claims = (ROOT / "docs" / "CLAIMS.md").read_text()
        refs = set(re.findall(r"`(tests/[\w]+\.py)::(\w+)::(\w+)`", claims))
        self.assertGreater(len(refs), 40)
        defined = {}
        for rel in {r[0] for r in refs}:
            tree = ast.parse((ROOT / rel).read_text())
            defined[rel] = {(c.name, f.name) for c in tree.body if isinstance(c, ast.ClassDef)
                            for f in c.body if isinstance(f, ast.FunctionDef)}
        missing = sorted(f"{rel}::{cls}::{fn}" for rel, cls, fn in refs
                         if (cls, fn) not in defined[rel])
        self.assertEqual(missing, [])

    def test_every_readme_piece_has_its_claims(self):
        readme = (ROOT / "README.md").read_text()
        claims = (ROOT / "docs" / "CLAIMS.md").read_text()
        table = readme.split("## What you get", 1)[1].split("\n## ", 1)[0]
        pieces = re.findall(r"^\| \*\*([^*]+)\*\*", table, re.M)
        self.assertGreater(len(pieces), 8)
        sections = set(re.findall(r"^## (.+)$", claims, re.M))
        self.assertEqual([p for p in pieces if p not in sections], [])

    def test_documented_config_keys_match_the_loader(self):
        doc = (ROOT / "docs" / "HOW-IT-WORKS.md").read_text()
        documented = set(re.findall(r"^\| `([a-z_]+)\.([a-z_]+)` \|", doc, re.M))
        self.assertEqual(documented, {("reader_gate", "untrusted_paths"),
                                      ("reader_gate", "quarantine_paths"),
                                      ("reader_gate", "secret_paths"),
                                      ("reader_gate", "private_hosts"),
                                      ("launch_gate", "allow"),
                                      ("launch_gate", "ssh_hosts"),
                                      ("launch_gate", "ask_for_domains"),
                                      ("coordinator", "project"),
                                      ("coordinator", "name")})
        loader = {(section, key) for section, keys in _config.KNOWN_KEYS.items() for key in keys}
        self.assertEqual(documented, loader)

    def test_reader_agents_keep_narrow_tools(self):
        env = reader_gate.Env(home="/fake/home", plugin_root=str(ROOT))
        for reader in reader_gate.READER_TOOLS:
            with self.subTest(reader=reader):
                self.assertIsNone(reader_gate._definition_problem(reader, env))

    def test_plugin_and_marketplace_agree(self):
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        [entry] = market["plugins"]
        self.assertEqual(entry["name"], plugin["name"])
        self.assertEqual(entry["source"], ".")
        changelog = (ROOT / "CHANGELOG.md").read_text()
        self.assertIn(f"## [{plugin['version']}]", changelog)


if __name__ == "__main__":
    unittest.main()
