"""Tests for hooks/reader_gate.py.

Run from the repo root:  python3 -m unittest -v
Everything happens under temporary folders with a fake home, a copy of the
plugin's own agent files and a fake DNS resolver. No real secret file is ever
read and nothing touches the network.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hooks"))

import _config  # noqa: E402
import reader_gate as rg  # noqa: E402

WEB = ("stranger-danger:web-researcher", "agent-web-1")
DOC = ("stranger-danger:document-reader", "agent-doc-1")
QUAR = ("stranger-danger:quarantine-reviewer", "agent-quar-1")
OTHER = ("general-purpose", "agent-gp-1")
CALLERS = {"main": None, "other": OTHER, "web": WEB, "doc": DOC, "quar": QUAR}

DNS = {
    "example.com": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
    "docs.example.org": ["203.0.113.10"],   # TEST-NET-3: not global, so refused
    "public.example.net": ["8.8.8.8"],
    "private.example.net": ["10.0.0.5"],
    "loop.example.net": ["127.0.0.1"],
    "meta.example.net": ["169.254.169.254"],
    "cgnat.example.net": ["100.64.1.2"],
    "v6loop.example.net": ["::1"],
    "mapped.example.net": ["::ffff:10.1.2.3"],
    "multicast.example.net": ["224.0.0.1"],
    "zero.example.net": ["0.0.0.0"],
    "mixed.example.net": ["8.8.8.8", "192.168.1.1"],
}


def resolver(host):
    if host in DNS:
        return DNS[host]
    raise OSError("no such host")


@contextlib.contextmanager
def realpath_refuses_proc():
    """realpath as before Python 3.13 on a machine where /proc links can't be
    read: it raises, naming the link, on any path that is or goes through a
    link into /proc or /dev."""
    real = os.path.realpath

    def refuse(path, *args, **kwargs):
        text = str(path)
        if text.startswith(("/proc/", "/dev/")):
            raise PermissionError(13, "Permission denied", text)
        parts = text.split("/")
        for i in range(2, len(parts) + 1):
            prefix = "/".join(parts[:i])
            if os.path.islink(prefix) and os.readlink(prefix).startswith(("/proc/", "/dev/")):
                raise PermissionError(13, "Permission denied", os.readlink(prefix))
        return real(path, *args, **kwargs)

    os.path.realpath = refuse
    try:
        yield
    finally:
        os.path.realpath = real


class GateCase(unittest.TestCase):
    """A fake home with a project, an untrusted folder and a quarantine folder."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.home = base / "home"
        self.plugin = base / "plugin"
        shutil.copytree(ROOT / "agents", self.plugin / "agents")
        shutil.copytree(ROOT / ".claude-plugin", self.plugin / ".claude-plugin")
        for sub in ("proj/src", "inbox", "q/repo", ".ssh", ".config/nvim", ".cargo/registry",
                    "data/nested"):
            (self.home / sub).mkdir(parents=True, exist_ok=True)
        (self.home / "proj" / "src" / "main.py").write_text("print('hi')\n")
        (self.home / "inbox" / "mail.eml").write_text("Subject: hello\n")
        (self.home / "q" / "repo" / "index.js").write_text("// stranger\n")
        self.config = {"reader_gate": {"untrusted_paths": ["~/inbox", "~/data/nested"],
                                       "quarantine_paths": ["~/q"],
                                       "secret_paths": ["~/vault/**"],
                                       "private_hosts": ["corp.example"]}}
        self.logged = []
        self.env = rg.Env(home=str(self.home), plugin_root=str(self.plugin),
                          resolver=resolver, log=self.logged.append, casefold=False)

    def tearDown(self):
        self.tmp.cleanup()

    def p(self, *parts) -> str:
        return str(self.home.joinpath(*parts))

    def event(self, tool, tool_input, who="main", cwd=None):
        event = {"tool_name": tool, "tool_input": tool_input,
                 "cwd": cwd if cwd is not None else self.p("proj"),
                 "session_id": "s1", "hook_event_name": "PreToolUse"}
        ident = CALLERS[who] if isinstance(who, str) else who
        if ident:
            event["agent_type"], event["agent_id"] = ident
        return event

    def decide(self, tool, tool_input, who="main", cwd=None, config=None):
        return rg.decide(self.event(tool, tool_input, who, cwd),
                         self.config if config is None else config, self.env)

    def assertDenied(self, reason, *needles):
        self.assertIsNotNone(reason, "expected a deny")
        for needle in needles:
            self.assertIn(needle, reason)

    def assertPass(self, reason):
        self.assertIsNone(reason, f"expected no decision, got: {reason}")


class WebTests(GateCase):
    def test_websearch_only_for_the_web_reader(self):
        for who in ("main", "other", "doc", "quar"):
            with self.subTest(who=who):
                self.assertDenied(self.decide("WebSearch", {"query": "x"}, who),
                                  "stranger-danger:web-researcher")
        self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))

    def test_webfetch_only_for_the_web_reader(self):
        for who in ("main", "other", "doc", "quar"):
            with self.subTest(who=who):
                self.assertDenied(self.decide("WebFetch", {"url": "https://example.com/"}, who),
                                  "only the")
        self.assertPass(self.decide("WebFetch", {"url": "https://example.com/a?q=1"}, "web"))

    def test_private_resolutions_are_refused(self):
        for host in ("private.example.net", "loop.example.net", "meta.example.net",
                     "cgnat.example.net", "v6loop.example.net", "mapped.example.net",
                     "multicast.example.net", "zero.example.net", "mixed.example.net",
                     "docs.example.org"):
            with self.subTest(host=host):
                self.assertDenied(self.decide("WebFetch", {"url": f"https://{host}/x"}, "web"),
                                  "local or private address")

    def test_public_resolution_passes(self):
        self.assertPass(self.decide("WebFetch", {"url": "https://public.example.net/"}, "web"))

    def test_host_tricks_are_refused_for_everyone(self):
        tricks = ["http://0x7f.1/", "http://2130706433/", "http://127.1/",
                  "http://[::ffff:127.0.0.1]/", "http://foo.local/", "http://LOCALHOST./",
                  "http://localhost:8080/", "http://api.localhost/", "http://intranet/",
                  "http://db.internal/", "http://router.home.arpa/", "http://corp.example/",
                  "http://wiki.corp.example/", "http://017700000001/", "http://0177.0.0.1/",
                  "http://8.8.8.8/", "http://user@169.254.169.254/latest/",
                  "http://[fd00:ec2::254]/", "http://nas.lan/"]
        for url in tricks:
            for who in ("web", "main"):
                with self.subTest(url=url, who=who):
                    reason = self.decide("WebFetch", {"url": url}, who)
                    self.assertDenied(reason, "WebFetch refused")

    def test_bad_schemes_and_urls(self):
        for url in ("file:///etc/passwd", "ftp://example.com/x", "javascript:alert(1)",
                    "https://exa\u200bmple.com/", "https://example.com/\nx", "https:///nohost",
                    "https://example.com:99999/", "https://" + "a" * 9000 + ".com/"):
            with self.subTest(url=url[:40]):
                self.assertIsNotNone(self.decide("WebFetch", {"url": url}, "web"))

    def test_missing_or_wrong_url(self):
        for tool_input in ({}, {"url": 5}, {"url": ""}):
            with self.subTest(tool_input=tool_input):
                self.assertDenied(self.decide("WebFetch", tool_input, "web"), "no URL")

    def test_unresolvable_host_passes_and_is_logged(self):
        self.assertPass(self.decide("WebFetch", {"url": "https://nx.example.com/?token=abc"},
                                    "web"))
        self.assertEqual(self.logged[-1]["code"], "dns-failed")
        self.assertEqual(self.logged[-1]["host"], "nx.example.com")
        self.assertNotIn("token", json.dumps(self.logged))

    def test_log_holds_host_only(self):
        self.decide("WebFetch", {"url": "https://example.com/path?secret=1"}, "main")
        record = self.logged[-1]
        self.assertEqual(record["host"], "example.com")
        self.assertNotIn("secret", json.dumps(record))
        self.assertNotIn("path", record)

    def test_search_query_never_logged(self):
        self.decide("WebSearch", {"query": "my private question"}, "main")
        self.assertNotIn("private question", json.dumps(self.logged))


class IdentityTests(GateCase):
    def test_bare_name_is_not_a_reader(self):
        reason = self.decide("WebSearch", {"query": "x"}, ("web-researcher", "a1"))
        self.assertDenied(reason, "only the stranger-danger:web-researcher")

    def test_missing_or_bad_agent_id(self):
        for agent_id in (None, "", "a b", "x" * 129, 7, "../../x"):
            with self.subTest(agent_id=agent_id):
                event = self.event("WebSearch", {"query": "x"}, "main")
                event["agent_type"] = WEB[0]
                if agent_id is not None:
                    event["agent_id"] = agent_id
                reason = rg.decide(event, self.config, self.env)
                self.assertDenied(reason, "claims to be the web-researcher")

    def write_agent(self, folder: Path, name: str, filename="evil.md", tools="Bash"):
        folder.mkdir(parents=True, exist_ok=True)
        (folder / filename).write_text(f"---\nname: {name}\ndescription: x\ntools: {tools}\n---\nbody\n")

    def test_project_agent_claiming_the_reserved_name(self):
        self.write_agent(self.home / "proj" / ".claude" / "agents",
                         "stranger-danger:web-researcher")
        reason = self.decide("WebSearch", {"query": "x"}, "web")
        self.assertDenied(reason, "reserved prefix")

    def test_project_agent_in_a_parent_of_cwd(self):
        self.write_agent(self.home / "proj" / ".claude" / "agents", '"stranger-danger:other"')
        reason = self.decide("WebSearch", {"query": "x"}, "web", cwd=self.p("proj", "src"))
        self.assertDenied(reason, "reserved prefix")

    def test_user_agent_claiming_the_reserved_name(self):
        self.write_agent(self.home / ".claude" / "agents" / "nested",
                         "stranger-danger:document-reader")
        reason = self.decide("Read", {"file_path": self.p("inbox", "mail.eml")}, "doc")
        self.assertDenied(reason, "reserved prefix")

    def test_claude_project_dir_agents_are_checked(self):
        project = Path(self.tmp.name) / "elsewhere"
        self.write_agent(project / ".claude" / "agents", "stranger-danger:web-researcher")
        self.env.project_dir = str(project)
        self.assertDenied(self.decide("WebSearch", {"query": "x"}, "web"), "reserved prefix")

    def write_raw(self, folder: Path, filename: str, data) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / filename
        if isinstance(data, str):
            data = data.encode("utf-8")
        path.write_bytes(data)
        return path

    def assertShadowed(self, cwd=None):
        reason = self.decide("WebSearch", {"query": "x"}, "web", cwd=cwd)
        self.assertDenied(reason, "reserved prefix", "stranger-danger:")
        return reason

    def test_shadow_forms_the_old_check_missed(self):
        agents = self.home / "proj" / ".claude" / "agents"
        name = "stranger-danger:web-researcher"
        forms = {
            "trailing YAML comment": f"---\nname: {name} # mine\ntools: Bash\n---\n",
            "UTF-8 BOM": "\ufeff" + f"---\nname: {name}\ntools: Bash\n---\n",
            "folded scalar": f"---\nname: >-\n  {name}\ntools: Bash\n---\n",
            "quoted key": f'---\n"name": {name}\ntools: Bash\n---\n',
            "CRLF": f"---\r\nname: {name}\r\ntools: Bash\r\n---\r\n",
            "hex escape": '---\nname: "stranger-danger\\x3aweb-researcher"\ntools: Bash\n---\n',
            "unicode escape": '---\nname: "stranger\\u002Ddanger\\u003Aweb-researcher"\n---\n',
            "escaped line break": '---\nname: "stranger-dan\\\n    ger:web-researcher"\n---\n',
            "upper case": f"---\nname: {name.upper()}\n---\n",
            "hidden character": "---\nname: stranger-danger\u200b:web-researcher\n---\n",
            "fullwidth colon": "---\nname: stranger-danger\uff1aweb-researcher\n---\n",
            "after 64 KB": "---\n" + "# pad\n" * 12000 + f"name: {name}\n---\n",
            "body only": "---\nname: helper\n---\nBrief stranger-danger:web-researcher.\n",
            # base64 of the name, which a YAML parser turns back into its bytes
            "binary tag": "---\nname: !!binary c3RyYW5nZXItZGFuZ2VyOndlYi1yZXNlYXJjaGVy\n"
                          "tools: Bash\n---\n",
        }
        for label, text in forms.items():
            with self.subTest(label):
                path = self.write_raw(agents, "x.md", text)
                self.assertShadowed()
                path.unlink()
        for label, data in {"UTF-16 with BOM": f"---\nname: {name}\n---\n".encode("utf-16"),
                            "UTF-16 without BOM": f"name: {name}\n".encode("utf-16-le"),
                            "UTF-32 with BOM": f"name: {name}\n".encode("utf-32")}.items():
            with self.subTest(label):
                path = self.write_raw(agents, "x.md", data)
                self.assertShadowed()
                path.unlink()

    def test_shadow_file_names_and_places_the_old_check_missed(self):
        text = "---\nname: stranger-danger:web-researcher\ntools: Bash\n---\n"
        agents = self.home / "proj" / ".claude" / "agents"
        for filename in ("x.MD", "x.Md", "x.markdown", "x.yaml", "x", "x.txt", ".x.md"):
            with self.subTest(filename=filename):
                path = self.write_raw(agents, filename, text)
                self.assertShadowed()
                path.unlink()
        deep = agents / "a" / "b" / "c"
        self.write_raw(deep, "x.md", text)
        self.assertShadowed()
        shutil.rmtree(agents)

    def test_shadow_through_a_symlinked_folder(self):
        elsewhere = Path(self.tmp.name) / "elsewhere" / "kit"
        self.write_raw(elsewhere, "x.md", "---\nname: stranger-danger:web-researcher\n---\n")
        agents = self.home / "proj" / ".claude" / "agents"
        agents.mkdir(parents=True)
        os.symlink(elsewhere, agents / "kit")
        self.assertShadowed()
        os.unlink(agents / "kit")
        self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))
        # The agents folder itself as a link, and a linked file.
        agents.rmdir()
        os.symlink(elsewhere, agents)
        self.assertShadowed()
        os.unlink(agents)
        agents.mkdir()
        os.symlink(elsewhere / "x.md", agents / "y.md")
        self.assertShadowed()

    def test_shadow_folder_named_after_the_plugin(self):
        agents = self.home / ".claude" / "agents"
        self.write_raw(agents / "stranger-danger", "web-researcher.md",
                       "---\nname: web-researcher\ntools: Bash\n---\n")
        self.assertShadowed()
        shutil.rmtree(agents)
        self.write_raw(agents, "stranger-danger:web-researcher.md", "---\ntools: Bash\n---\n")
        self.assertShadowed()

    def test_shadow_under_claude_config_dir(self):
        config_dir = Path(self.tmp.name) / "alt-claude"
        self.write_raw(config_dir / "agents", "x.md", "name: stranger-danger:web-researcher\n")
        self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))
        self.env.config_dir = str(config_dir)
        self.assertShadowed()

    def test_shadow_check_fails_closed_when_it_cant_finish(self):
        agents = self.home / "proj" / ".claude" / "agents"
        deep = agents.joinpath(*["d"] * (rg.MAX_AGENT_DEPTH + 1))
        deep.mkdir(parents=True)
        self.assertDenied(self.decide("WebSearch", {"query": "x"}, "web"), "too deep")
        shutil.rmtree(agents)
        self.write_raw(agents, "big.md", b"x" * (rg.AGENT_SCAN_BYTES + 1))
        self.assertDenied(self.decide("WebSearch", {"query": "x"}, "web"), "too large")
        shutil.rmtree(agents)
        agents.mkdir(parents=True)
        for i in range(rg.MAX_AGENT_FILES + 1):
            (agents / f"a{i}.md").write_bytes(b"")
        self.assertDenied(self.decide("WebSearch", {"query": "x"}, "web"), "too many")

    def test_shadow_check_survives_loops_and_odd_files(self):
        agents = self.home / "proj" / ".claude" / "agents"
        self.write_raw(agents / "sub", "ok.md", "---\nname: helper\n---\n")
        os.symlink(agents, agents / "sub" / "loop")
        os.symlink(agents / "missing", agents / "dangling.md")
        os.mkfifo(agents / "pipe.yaml")
        os.symlink(agents / "pipe.yaml", agents / "pipe-link.md")
        self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))

    def test_shadow_controls_stay_clean(self):
        agents = self.home / "proj" / ".claude" / "agents"
        for text in ("---\nname: stranger-danger-fan\ntools: Bash\n---\n",
                     "---\nname: web-researcher\ntools: Bash, Read\n---\n",
                     "Use the stranger-danger plugin's readers.\n",
                     "stranger danger: be careful\n", "name: stranger_danger:web\n",
                     "name: strangerdanger:web\n", "name: stranger-dangerous:web\n",
                     "name: \"stranger-danger\\x2eweb\"\n"):
            with self.subTest(text=text):
                path = self.write_raw(agents, "x.md", text)
                self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))
                path.unlink()
        # A .claude/agents folder that isn't on the path to the working directory.
        self.write_raw(self.home / "other" / ".claude" / "agents", "x.md",
                       "name: stranger-danger:web-researcher\n")
        self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))

    def test_unrelated_agents_with_bare_names_are_fine(self):
        self.write_agent(self.home / ".claude" / "agents", "web-researcher", tools="Bash, Read")
        self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))

    def test_fifo_in_agents_folder_does_not_hang(self):
        folder = self.home / "proj" / ".claude" / "agents"
        folder.mkdir(parents=True)
        os.mkfifo(folder / "pipe.md")
        self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))

    def edit_plugin_agent(self, reader, frontmatter):
        (self.plugin / "agents" / f"{reader}.md").write_text(f"---\n{frontmatter}\n---\nbody\n")

    def test_plugin_agent_with_bash_added(self):
        self.edit_plugin_agent("web-researcher",
                               "name: web-researcher\ntools: WebSearch, WebFetch, Bash")
        self.assertDenied(self.decide("WebSearch", {"query": "x"}, "web"), "grants Bash")

    def test_plugin_agent_block_list_with_write(self):
        self.edit_plugin_agent("document-reader",
                               "name: document-reader\ntools:\n  - Read\n  - Write")
        reason = self.decide("Read", {"file_path": self.p("inbox", "mail.eml")}, "doc")
        self.assertDenied(reason, "grants Write")

    def test_plugin_agent_without_tools_inherits_everything(self):
        self.edit_plugin_agent("quarantine-reviewer", "name: quarantine-reviewer")
        reason = self.decide("Read", {"file_path": self.p("q", "repo", "index.js")}, "quar")
        self.assertDenied(reason, "no tools list")

    def test_plugin_agent_with_mcp_servers(self):
        self.edit_plugin_agent("web-researcher",
                               "name: web-researcher\ntools: WebFetch\nmcpServers: [x]")
        self.assertDenied(self.decide("WebSearch", {"query": "x"}, "web"), "MCP servers")

    def test_plugin_agent_missing(self):
        (self.plugin / "agents" / "web-researcher.md").unlink()
        self.assertDenied(self.decide("WebSearch", {"query": "x"}, "web"), "missing")

    def test_plugin_root_unknown(self):
        self.env.plugin_root = None
        self.assertDenied(self.decide("WebSearch", {"query": "x"}, "web"), "plugin root")

    def test_flow_list_tools_pass(self):
        self.edit_plugin_agent("web-researcher",
                               'name: web-researcher\ntools: ["WebSearch", "WebFetch"]')
        self.assertPass(self.decide("WebSearch", {"query": "x"}, "web"))

    def test_plugin_name_comes_from_the_manifest(self):
        manifest = self.plugin / ".claude-plugin" / "plugin.json"
        data = json.loads(manifest.read_text())
        data["name"] = "sd"
        manifest.write_text(json.dumps(data))
        self.assertPass(self.decide("WebSearch", {"query": "x"}, ("sd:web-researcher", "a1")))
        self.assertIsNotNone(self.decide("WebSearch", {"query": "x"}, "web"))


class ReadTests(GateCase):
    SECRETS = ["~/.ssh/id_ed25519", "~/.ssh", "~/.aws/credentials", "~/.gnupg/pubring.kbx",
               "~/.kube/config", "~/.docker/config.json", "~/.git-credentials", "~/.netrc",
               "~/.npmrc", "~/.pypirc", "~/.cargo/credentials.toml", "~/.config/gh/hosts.yml",
               "~/.claude.json", "~/.claude/.credentials.json",
               "~/.config/google-chrome/Default/Cookies", "~/.mozilla/firefox/x/logins.json",
               "~/.local/share/keyrings/login.keyring", "~/.bash_history", "~/.zsh_history",
               "~/.config/gcloud/credentials.db", "~/.azure/msal_token_cache.json",
               "~/proj/.env", "~/proj/.env.local", "~/proj/certs/server.pem", "~/proj/tls.key",
               "~/proj/id_rsa.pub", "~/proj/wallet.keystore.json", "~/proj/keypair.json",
               "~/vault/notes.txt", "~/proj/.ENV",
               "~/snap/firefox/common/.mozilla/firefox/x.default/logins.json",
               "~/snap/chromium/common/chromium/Default/Cookies",
               "~/snap/brave/current/.config/BraveSoftware/Brave-Browser/Default/Cookies",
               "~/.var/app/org.mozilla.firefox/.mozilla/firefox/x.default/key4.db",
               "~/.var/app/com.google.Chrome/config/google-chrome/Default/Login Data",
               "~/.var/app/org.chromium.Chromium/config/chromium/Default/Cookies",
               "~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/Default/Cookies",
               "~/.var/app/com.microsoft.Edge/config/microsoft-edge/Default/Cookies",
               "~/.config/solana/id.json", "~/.ethereum/keystore/UTC--2020-01-01T00-00-00Z--ab",
               "~/proj/chain/keystore/UTC--2020-01-01T00-00-00.000Z--0a1b",
               "~/.local/share/fish/fish_history", "~/proj/id_ecdsa", "~/proj/id_ecdsa.pub",
               "~/proj/keys/id_dsa", "~/proj/signing/release.p12", "~/proj/cert.PFX",
               "~/proj/android/release.jks", "~/Documents/passwords.kdbx",
               "~/.password-store/mail/me.gpg"]

    def test_secrets_denied_for_everyone(self):
        for path in self.SECRETS:
            for who in ("main", "other", "doc"):
                with self.subTest(path=path, who=who):
                    self.assertDenied(self.decide("Read", {"file_path": path}, who), "rule 5")

    def test_secret_inside_untrusted_folder_denied_for_the_reader(self):
        self.assertDenied(self.decide("Read", {"file_path": self.p("inbox", ".env")}, "doc"),
                          "secret pattern")

    def test_env_templates_are_not_secrets(self):
        for name in (".env.example", ".env.sample", ".env.template"):
            with self.subTest(name=name):
                self.assertPass(self.decide("Read", {"file_path": self.p("proj", name)}))

    def test_ordinary_project_files_pass(self):
        for path in (self.p("proj", "src", "main.py"), "~/proj/README.md", "src/main.py",
                     self.p(".config", "nvim", "init.lua"), "~/snap/code/common/notes.txt",
                     "~/.var/app/org.gimp.GIMP/config/gimprc", "~/proj/keystore/README.md",
                     "~/.local/share/fish/functions/ll.fish", "~/proj/id_card.png",
                     "~/proj/src/p12.py", "~/proj/jks_notes.txt"):
            with self.subTest(path=path):
                self.assertPass(self.decide("Read", {"file_path": path}))

    def test_untrusted_folder_only_for_the_document_reader(self):
        path = self.p("inbox", "mail.eml")
        for who in ("main", "other", "quar"):
            with self.subTest(who=who):
                self.assertDenied(self.decide("Read", {"file_path": path}, who),
                                  "untrusted folder", "document-reader")
        self.assertPass(self.decide("Read", {"file_path": path}, "doc"))

    def test_quarantine_only_for_the_reviewer(self):
        path = self.p("q", "repo", "index.js")
        for who in ("main", "other", "doc"):
            with self.subTest(who=who):
                self.assertDenied(self.decide("Read", {"file_path": path}, who),
                                  "quarantine folder")
        self.assertPass(self.decide("Read", {"file_path": path}, "quar"))

    def test_readers_are_confined(self):
        project_file = self.p("proj", "src", "main.py")
        self.assertDenied(self.decide("Read", {"file_path": project_file}, "doc"),
                          "only inside the configured untrusted folders")
        self.assertDenied(self.decide("Read", {"file_path": project_file}, "quar"),
                          "only inside the configured quarantine folders")
        self.assertDenied(self.decide("Read", {"file_path": project_file}, "web"),
                          "web researcher reads no local files")
        self.assertDenied(self.decide("Read", {"file_path": self.p("inbox", "mail.eml")},
                                      "quar"), "untrusted folder")

    def test_document_reader_with_no_untrusted_folders_reads_nothing(self):
        config = {"reader_gate": {"quarantine_paths": ["~/q"]}}
        self.assertDenied(self.decide("Read", {"file_path": self.p("inbox", "mail.eml")}, "doc",
                                      config=config), "only inside")

    def test_symlink_into_secret_folder(self):
        os.symlink(self.home / ".ssh", self.home / "proj" / "keys")
        self.assertDenied(self.decide("Read", {"file_path": self.p("proj", "keys", "id_rsa")}),
                          "rule 5")

    def test_symlink_into_untrusted_folder(self):
        os.symlink(self.home / "inbox", self.home / "proj" / "mail")
        self.assertDenied(self.decide("Read", {"file_path": self.p("proj", "mail", "mail.eml")}),
                          "untrusted folder")

    def test_symlink_out_of_untrusted_folder_for_the_reader(self):
        os.symlink(self.home / "proj", self.home / "inbox" / "escape")
        reason = self.decide("Read", {"file_path": self.p("inbox", "escape", "src", "main.py")},
                             "doc")
        self.assertDenied(reason, "only inside")

    def test_tilde_forms(self):
        for path in ("~//.ssh/id_rsa", "~/./.ssh/id_rsa", "~///.config//gh/hosts.yml",
                     "~/proj/../.ssh/id_rsa"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "rule 5")
        for path in ("~root/.ssh/id_rsa", "~other/x", "~x"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "starting with ~/")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": "~//inbox"}),
                          "untrusted folder")

    def test_lexical_then_kernel_resolution(self):
        # A tool that normalizes first opens home/.aws/credentials here, even
        # though the kernel alone would climb out of home after the link.
        os.symlink(self.home, self.home / "proj" / "l_home")
        path = self.p("proj", "l_home", "..", "l_home", ".aws", "credentials")
        self.assertDenied(self.decide("Read", {"file_path": path}), "rule 5")
        path = self.p("proj", "l_home", "..", "l_home", "inbox", "mail.eml")
        self.assertDenied(self.decide("Read", {"file_path": path}), "untrusted folder")

    def test_dotdot_into_secret(self):
        self.assertDenied(self.decide("Read", {"file_path": self.p("proj", "..", ".ssh",
                                                                    "id_rsa")}), "rule 5")

    def test_relative_path_into_untrusted(self):
        self.assertDenied(self.decide("Read", {"file_path": "../inbox/mail.eml"}),
                          "untrusted folder")

    def test_relative_path_without_cwd(self):
        event = self.event("Read", {"file_path": "src/main.py"})
        del event["cwd"]
        self.assertDenied(rg.decide(event, self.config, self.env), "no working directory")

    def test_proc_and_dev_fd_tricks(self):
        for path in ("/proc/self/root" + self.p(".ssh", "id_rsa"), "/proc/self/environ",
                     "/proc/1234/cwd/secret.txt", "/proc/1234/root/etc/hostname",
                     "/proc/1/task/1/fd/3", "/dev/fd/3", "/dev/stdin", "/proc/thread-self/cwd"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "/proc or /dev/fd")

    def test_proc_checked_before_realpath(self):
        with realpath_refuses_proc():
            for path in ("/proc/1/task/1/fd/3", "/proc/./self/environ", "/dev/fd/../fd/3",
                         "/tmp/../proc/self/environ", "/dev/x/../fd/3"):
                with self.subTest(path=path):
                    self.assertDenied(self.decide("Read", {"file_path": path}),
                                      "/proc or /dev/fd")

    def test_proc_ns_links(self):
        for path in ("/proc/1234/ns/net", "/proc/1/task/1/ns/mnt"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "/proc or /dev/fd")

    def test_link_to_proc_when_realpath_refuses(self):
        os.symlink("/proc/1/task/1/fd/3", self.p("proj", "fdlink"))
        os.symlink("/proc/1/root", self.p("proj", "rootlink"))
        with realpath_refuses_proc():
            for path in (self.p("proj", "fdlink"), self.p("proj", "rootlink", "etc", "hostname"),
                         "/proc/1234/ns/net"):
                with self.subTest(path=path):
                    self.assertDenied(self.decide("Read", {"file_path": path}),
                                      "/proc or /dev/fd")

    def test_proc_and_dev_ignore_case_where_paths_do(self):
        env = rg.Env(home=str(self.home), plugin_root=str(self.plugin), resolver=resolver,
                     log=self.logged.append, casefold=True)
        for path in ("/DEV/FD/3", "/Proc/Self/environ", "/proc/1/NS/net"):
            with self.subTest(path=path):
                self.assertDenied(rg.decide(self.event("Read", {"file_path": path}),
                                            self.config, env), "/proc or /dev/fd")
        self.assertDenied(rg.decide(self.event("Glob", {"pattern": "*", "path": "/DEV"}),
                                    self.config, env), "refused")

    def test_devices_and_kernel_memory(self):
        self.assertDenied(self.decide("Read", {"file_path": "/proc/kcore"}), "kernel memory")
        for path in sorted(rg.SAFE_DEVICES):
            if os.path.exists(path):
                with self.subTest(path=path):
                    self.assertPass(self.decide("Read", {"file_path": path}))
        device = next((d for d in ("/dev/tty", "/dev/ptmx", "/dev/console", "/dev/loop0")
                       if os.path.exists(d) and (stat.S_ISCHR(os.stat(d).st_mode)
                                                 or stat.S_ISBLK(os.stat(d).st_mode))), None)
        if device is None:
            self.skipTest("no block or character device to test with")
        os.symlink(device, self.p("proj", "devlink"))
        for path in (device, self.p("proj", "devlink")):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "device")

    def test_link_to_proc_that_realpath_resolves(self):
        # realpath turns a link to /proc/self/root into "/", so the gate walks
        # the link chain itself.
        os.symlink("/proc/self/root", self.p("proj", "selfroot"))
        os.symlink(self.p("proj", "selfroot"), self.p("proj", "hop1"))
        os.symlink("/proc/1/root/..", self.p("proj", "uproot"))
        os.symlink("/proc/1/cmdline", self.p("proj", "cmdlink"))
        for path in (self.p("proj", "selfroot", "etc", "hostname"),
                     self.p("proj", "hop1", "etc", "hostname"),
                     self.p("proj", "uproot", "etc", "hostname"),
                     self.p("proj", "cmdlink")):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "/proc or /dev/fd")
        self.assertDenied(self.decide("Glob", {"pattern": "selfroot/etc/*"}), "refused")
        self.assertDenied(self.decide("Glob", {"pattern": "*", "path": self.p("proj", "hop1")}),
                          "/proc")

    def test_link_loop_is_refused(self):
        os.symlink(self.p("proj", "b"), self.p("proj", "a"))
        os.symlink(self.p("proj", "a"), self.p("proj", "b"))
        self.assertDenied(self.decide("Read", {"file_path": self.p("proj", "a", "x")}),
                          "can't be followed")

    def test_ordinary_links_still_pass(self):
        os.symlink(self.p("proj", "src"), self.p("proj", "srclink"))
        os.symlink("src/main.py", self.p("proj", "mainlink"))
        for path in (self.p("proj", "srclink", "main.py"), self.p("proj", "mainlink")):
            with self.subTest(path=path):
                self.assertPass(self.decide("Read", {"file_path": path}))

    def test_private_proc_files(self):
        for path in ("/proc/1234/cmdline", "/proc/1/task/1/cmdline", "/proc/1234/auxv",
                     "/proc/1234/pagemap", "/proc/1234/stack", "/proc/1234/syscall",
                     "/proc/1234/maps", "/proc/1234/smaps", "/proc/1234/mountinfo",
                     "/proc/1234/attr/current", "/proc/1/task/1/maps", "/proc/1234",
                     "/proc/cmdline", "/proc/keys"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "command line")
        for path in ("/proc/1234/environ", "/proc/1/task/1/mem"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "/proc")
        for path in ("/proc/1234/status", "/proc/1234/stat", "/proc/1234/statm",
                     "/proc/1234/limits", "/proc/1/task/1/stat", "/proc/meminfo"):
            with self.subTest(path=path):
                self.assertPass(self.decide("Read", {"file_path": path}))
        if os.path.islink("/etc/mtab") and "proc" in os.readlink("/etc/mtab"):
            self.assertDenied(self.decide("Read", {"file_path": "/etc/mtab"}), "/proc")

    def test_device_check_by_device_number(self):
        # A character device outside /dev with an unsafe device number
        # (6af98e4 looked only under /dev; 711cba8 refused one anywhere).
        # /dev/shm/x and /dev/null/x are refused by name since 85c4610.
        target = self.p("proj", "src", "main.py")
        real = os.stat

        def fake(path, *args, **kwargs):
            if str(path) == target:
                return types.SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=0xDEAD0001)
            return real(path, *args, **kwargs)
        with mock.patch("os.stat", fake):
            self.assertDenied(self.decide("Read", {"file_path": target}), "a device")
        if os.path.exists("/dev/null"):
            os.symlink("/dev/null", self.p("proj", "nulllink"))
            self.assertPass(self.decide("Read", {"file_path": self.p("proj", "nulllink")}))
        for path in ("/dev/shm/x", "/dev/null/x"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "a device")

    def test_proc_and_dev_casefold(self):
        env = rg.Env(home=str(self.home), plugin_root=str(self.plugin), resolver=resolver,
                     log=self.logged.append, casefold=True)
        for path, needle in (("/DEV/sda", "a device"), ("/PROC/1/MAPS", "command line")):
            with self.subTest(path=path):
                self.assertDenied(rg.decide(self.event("Read", {"file_path": path}),
                                            self.config, env), needle)

    def test_fifo_is_refused(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFOs here")
        os.mkfifo(self.p("proj", "pipe"))
        self.assertDenied(self.decide("Read", {"file_path": self.p("proj", "pipe")}), "FIFO")

    def test_device_stat_errors(self):
        target = self.p("proj", "src", "main.py")
        real = os.stat
        for error, denied in ((PermissionError(13, "Permission denied", target), True),
                              (OSError(5, "I/O error", target), True),
                              (FileNotFoundError(2, "No such file", target), False),
                              (NotADirectoryError(20, "Not a directory", target), False)):
            def fake(path, *args, **kwargs):
                if str(path) == target:
                    raise error
                return real(path, *args, **kwargs)
            with self.subTest(error=type(error).__name__), mock.patch("os.stat", fake):
                self.assertEqual(bool(rg._device(target)), denied)
                reason = self.decide("Read", {"file_path": target})
                if denied:
                    self.assertDenied(reason, "can't be checked")
                else:
                    self.assertPass(reason)

    def test_link_walk_covers_the_normalized_spelling(self):
        # Tools normalize before they open, so "/bin/../x" opens "/x" even where
        # the kernel would go through /usr.
        os.symlink("/proc/self/root", self.p("proj", "selfroot"))
        os.symlink(self.p("proj", "nowhere"), self.p("proj", "dead"))
        paths = [self.p("proj", "dead", "..", "selfroot", "etc", "hostname")]
        if os.path.islink("/bin") and not os.readlink("/bin").startswith("/"):
            paths.append("/bin/.." + self.p("proj", "selfroot", "etc", "hostname"))
        for path in paths:
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "/proc or /dev/fd")
        self.assertPass(self.decide("Read", {"file_path": self.p("proj", "dead", "..", "src",
                                                                "main.py")}))

    def test_more_links_into_proc(self):
        depth = len(Path(self.p("proj")).parts) - 1
        os.symlink("/dev/fd", self.p("proj", "fdl"))
        os.symlink("/proc", self.p("proj", "p"))
        os.symlink("../" * depth + "proc/1/root", self.p("proj", "relroot"))
        os.symlink("/proc/thread-self", self.p("proj", "ts"))
        os.symlink("../" * depth + "proc/self/root", self.p("proj", "relself"))
        for path in (self.p("proj", "fdl", "3"), self.p("proj", "p", "self", "root", "etc"),
                     self.p("proj", "relroot", "etc", "hostname"), self.p("proj", "ts", "environ"),
                     self.p("proj", "relself", "etc", "hostname")):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "/proc or /dev/fd")

    def test_link_hop_limit(self):
        def chain(name, count):
            for i in range(count):
                nxt = (self.p("proj", f"{name}{i + 1}") if i + 1 < count
                       else self.p("proj", "src", "main.py"))
                os.symlink(nxt, self.p("proj", f"{name}{i}"))
            return self.p("proj", f"{name}0")
        self.assertPass(self.decide("Read", {"file_path": chain("ok", rg.MAX_LINK_HOPS)}))
        self.assertDenied(self.decide("Read", {"file_path": chain("long", rg.MAX_LINK_HOPS + 1)}),
                          "can't be followed")

    def test_other_realpath_errors_propagate(self):
        def refuse(path, *args, **kwargs):
            raise PermissionError(13, "Permission denied", "/srv/locked")
        with mock.patch("os.path.realpath", refuse):
            with self.assertRaises(PermissionError):
                rg._resolved_forms(self.p("proj", "src", "main.py"))

    def test_control_and_invisible_characters(self):
        for path in (self.p("proj", "a\u200b.py"), self.p("proj", "a\n.py"),
                     self.p("proj", "a\x1b[8m.py"), self.p("proj", "\u202eyp.a")):
            with self.subTest(path=repr(path)):
                self.assertDenied(self.decide("Read", {"file_path": path}), "invisible")

    def test_blank_edges_in_a_component(self):
        for path in (self.p("proj", "main.py "), self.p("proj", " src", "x"),
                     self.p(".ssh ", "id_rsa")):
            with self.subTest(path=repr(path)):
                self.assertDenied(self.decide("Read", {"file_path": path}), "blank space")

    def test_bad_file_path_input(self):
        for tool_input in ({}, {"file_path": None}, {"file_path": 3}, {"file_path": ""},
                           {"file_path": "/" + "a" * 5000}):
            with self.subTest(tool_input=str(tool_input)[:40]):
                self.assertIsNotNone(self.decide("Read", tool_input))
        self.assertIsNotNone(rg.decide({"tool_name": "Read", "tool_input": "x"},
                                       self.config, self.env))

    def test_messages_escape_hostile_names(self):
        reason = self.decide("Read", {"file_path": self.p("inbox", "a\x1b[8mb")})
        self.assertNotIn("\x1b", reason)


class GrepTests(GateCase):
    def test_grep_in_project_passes(self):
        self.assertPass(self.decide("Grep", {"pattern": "def "}))
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": self.p("proj", "src")}))

    def test_grep_roots_refused(self):
        for path in ("/", "/proc", "/dev", str(self.home), "~"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Grep", {"pattern": "x", "path": path}),
                                  "narrow the path")

    def test_grep_above_untrusted_folder(self):
        data = self.p("data")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": data}), "untrusted")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": data, "glob": "*.txt"}),
                          "untrusted")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": data,
                                               "glob": "nested/**"}), "untrusted")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": data,
                                               "glob": "!nested/**"}), "untrusted")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": data, "glob": "other/**"}))

    def test_grep_above_secret_folders(self):
        config_dir = self.p(".config")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": config_dir}), "secret")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": config_dir,
                                             "glob": "nvim/**"}))
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": config_dir,
                                               "glob": "gcloud/**"}), "secret")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Podman's runtime login is Linux")
    def test_grep_above_podmans_login_file(self):
        # Review 8: $XDG_RUNTIME_DIR/containers/auth.json, from any folder above it.
        run_user = f"/run/user/{os.getuid()}"
        for path in (run_user, "/run/user", "/run"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Grep", {"pattern": "auth", "path": path}), "secret")
        self.assertDenied(self.decide("Read", {"file_path": run_user + "/containers/auth.json"}),
                          "rule 5")

    def test_grep_in_a_folder_holding_secret_files(self):
        cargo = self.p(".cargo")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": cargo}), "secret")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": cargo,
                                             "glob": "registry/**"}))

    def test_grep_globs_aimed_at_secrets(self):
        for glob in (".env*", ".env", "*.pem", "*.key", "id_*", "**/.env.local", "*keypair*",
                     "*.kdbx", "*.p12", "*.pfx", "*.jks", "id_ecdsa*", "id_dsa", "UTC--*",
                     "keystore/UTC--*"):
            with self.subTest(glob=glob):
                self.assertDenied(self.decide("Grep", {"pattern": "KEY", "glob": glob}), "rule 5")
        for glob in ("*", "*.json", "*.py", "*.{ts,tsx}", "src/**", ".env.example"):
            with self.subTest(glob=glob):
                self.assertPass(self.decide("Grep", {"pattern": "KEY", "glob": glob}))

    def test_grep_brace_globs_aimed_at_secrets(self):
        # ripgrep 14.1 matched .env through each of these (checked by hand, 2026-10-09).
        for glob in ("{.env,.env.local}", "{.env}", ".env{,}", "{a.py,.env}", "*.{pem,crt}",
                     "{src/x,.env}", "**/{.env,README.md}", "{*.py,id_rsa}",
                     # nested (newer ripgrep allows it; older refuses, which is also safe)
                     "{.e{nv,nv.local},x}", "{{.env}}", "{x,{y,{.env}}}",
                     # backslash escapes, which ripgrep honors on Unix
                     "\\.env", ".e\\nv", "\\.env\\.local", "*.p\\em", "{\\.env,x}",
                     "[.]env", ".en[v]", ".env/"):
            with self.subTest(glob=glob):
                self.assertDenied(self.decide("Grep", {"pattern": "KEY", "glob": glob}), "rule 5")

    def test_grep_brace_globs_over_ordinary_names_pass(self):
        for glob in ("*.{ts,tsx}", "{src,lib}/**", "{*.py,*.md}", "{a,b{c,d}}.txt", "a}",
                     "\\{a,b\\}", "{,src/}*.py", "*.{p,q}y"):
            with self.subTest(glob=glob):
                self.assertPass(self.decide("Grep", {"pattern": "KEY", "glob": glob}))

    def test_grep_brace_globs_too_big_or_unclosed_are_refused(self):
        for glob, needle in (("{a,b", "never closed"), ("x{{a,b}", "never closed"),
                             ("{" * 9 + "x" + "}" * 9, "too deep"),
                             ("{a,b}" * 9, "too many"),
                             ("{a,b,c,d,e,f,g,h,i,j}" * 2 + "{a,b,c}", "too many")):
            with self.subTest(glob=glob):
                self.assertDenied(self.decide("Grep", {"pattern": "KEY", "glob": glob}), needle)

    def test_brace_expansion_reference(self):
        cases = {
            "a{b,c}d": ["abd", "acd"],
            "a{b,c{d,e}}f": ["abf", "acdf", "acef"],
            "{,x}y": ["y", "xy"],
            "{a,b}{c,d}": ["ac", "ad", "bc", "bd"],
            "a}b,c": ["a}b,c"],
            "\\{a,b\\}": ["\\{a,b\\}"],
            "[{]x{1,2}": ["[{]x1", "[{]x2"],
            "[]{]{1,2}": ["[]{]1", "[]{]2"],
            "plain": ["plain"],
        }
        for glob, expected in cases.items():
            with self.subTest(glob=glob):
                self.assertEqual(rg._expand_braces(glob), expected)

    def test_grep_brace_glob_anchoring(self):
        data = self.p("data")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": data,
                                               "glob": "{other,nested}/**"}), "untrusted")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": data,
                                               "glob": "{other/**,*.txt}"}), "untrusted")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": data,
                                             "glob": "{other,another}/**"}))

    def test_grep_into_untrusted_and_quarantine(self):
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": self.p("inbox")}),
                          "untrusted folder")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": self.p("inbox")}, "doc"))
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": self.p("q")}, "doc"),
                          "quarantine folder")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": self.p("q")}, "quar"))

    def test_readers_grep_only_their_folders(self):
        self.assertDenied(self.decide("Grep", {"pattern": "x"}, "doc"), "only inside")
        self.assertDenied(self.decide("Grep", {"pattern": "x"}, "quar"), "only inside")

    def test_grep_secret_folder_itself(self):
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": "~/.ssh"}), "rule 5")

    def test_grep_bad_glob(self):
        self.assertDenied(self.decide("Grep", {"pattern": "x", "glob": 5}), "isn't text")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "glob": "*.p\u200by"}),
                          "invisible")


class GlobTests(GateCase):
    def test_glob_in_project_passes(self):
        self.assertPass(self.decide("Glob", {"pattern": "**/*.py"}))

    def test_glob_from_home_reaching_quarantine(self):
        home = str(self.home)
        self.assertDenied(self.decide("Glob", {"pattern": "**/*.js", "path": home}),
                          "quarantine folder")
        self.assertDenied(self.decide("Glob", {"pattern": "q/**", "path": home}),
                          "quarantine folder")
        self.assertDenied(self.decide("Glob", {"pattern": "*/repo/*", "path": home}),
                          "quarantine folder")
        # Claude Code's Glob matches a pattern with no "/" at any depth, so
        # these list names inside ~/q too.
        self.assertDenied(self.decide("Glob", {"pattern": "*.md", "path": home}),
                          "quarantine folder")
        self.assertDenied(self.decide("Glob", {"pattern": "*", "path": home}),
                          "quarantine folder")
        self.assertPass(self.decide("Glob", {"pattern": "proj/**/*.py", "path": home}))
        self.assertPass(self.decide("Glob", {"pattern": "proj/*.md", "path": home}))

    def test_absolute_pattern_into_quarantine(self):
        self.assertDenied(self.decide("Glob", {"pattern": self.p("q") + "/**/*"}),
                          "quarantine folder")
        self.assertDenied(self.decide("Glob", {"pattern": "~/q/repo/*.js"}), "quarantine folder")

    def test_glob_through_a_symlinked_folder(self):
        os.symlink(self.home / "q", self.home / "proj" / "qq")
        self.assertDenied(self.decide("Glob", {"pattern": "qq/**"}), "quarantine folder")
        self.assertDenied(self.decide("Glob", {"pattern": "*.js", "path": self.p("proj", "qq",
                                                                                 "repo")}),
                          "quarantine folder")

    def test_glob_dotdot_and_proc(self):
        self.assertDenied(self.decide("Glob", {"pattern": "../q/**"}), "'..'")
        self.assertDenied(self.decide("Glob", {"pattern": "*", "path": "/proc"}), "refused")
        self.assertDenied(self.decide("Glob", {"pattern": "*", "path": "/proc/1"}), "/proc")

    def test_glob_pattern_into_proc(self):
        patterns = ("/proc/1/root/etc/*", "/proc/self/root" + self.p(".ssh") + "/*",
                    "/proc/*/environ", "/dev/fd/*")
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern}), "refused")
        os.symlink("/proc/1/root", self.p("proj", "rootlink"))
        with realpath_refuses_proc():
            for pattern in patterns + ("rootlink/etc/*", self.p("proj", "rootlink", "etc") + "/*"):
                with self.subTest(pattern=pattern, realpath="refuses"):
                    self.assertDenied(self.decide("Glob", {"pattern": pattern}), "refused")

    def test_glob_rest_without_slash_matches_any_depth(self):
        # Claude Code 2.1.296's Glob: a relative pattern with no "/", and what
        # follows an absolute pattern's literal folders when it has no "/",
        # match file names at any depth.
        home = str(self.home)
        for pattern in ("index.js", "*.js", self.p("index.js"), self.p("*.js"),
                        home + "/*", "~/*.js", "s*/*.js"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern, "path": home}),
                                  "quarantine folder")
        for pattern in ("*.py", "**/*.py", "src/*.py", "src/*/test_*.py", "src/**",
                        self.p("proj", "src") + "/*.py", self.p("proj") + "/**/*.py",
                        self.p("proj", "src", "main.py")):
            with self.subTest(pattern=pattern):
                self.assertPass(self.decide("Glob", {"pattern": pattern}))
        self.assertPass(self.decide("Glob", {"pattern": "*.js", "path": self.p("q")}, "quar"))
        self.assertPass(self.decide("Glob", {"pattern": "*.eml", "path": self.p("inbox")},
                                    "doc"))

    def test_glob_wildcard_segments_into_proc(self):
        q = self.p("q")
        for pattern in ("/pr?c/self/root" + q + "/*", "/[p]roc/self/root" + q + "/*",
                        "/{proc,x}/self/root" + q + "/*", "/*/self/root" + q + "/*",
                        "/*.txt", "/*/*", "/**/x"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern}), "/proc")
        self.assertDenied(self.decide("Glob", {"pattern": "*/self/environ", "path": "/"}),
                          "/proc")

    def test_glob_backslash_and_extglob_segments(self):
        home = str(self.home)
        for pattern in ("\\q/*", "+(q)/*", "@(q|x)/*", home + "/\\q/*", "\\q/repo/*.js"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern, "path": home}),
                                  "quarantine folder")
        self.assertDenied(self.decide("Glob", {"pattern": "/\\proc/self/root" + self.p("q")
                                               + "/*"}), "/proc")
        self.assertDenied(self.decide("Glob", {"pattern": "\\../q/*", "path": self.p("proj")}),
                          "climbs")

    def test_glob_brace_alternatives(self):
        home = str(self.home)
        self.assertDenied(self.decide("Glob", {"pattern": "{..,x}/q/*", "path": self.p("proj")}),
                          "climbs")
        for pattern in ("{x,/proc/self/root}/*", "{x,~/.ssh}/*", "{x,/tmp}/*"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern}), "brace alternative")
        self.assertDenied(self.decide("Glob", {"pattern": "src/{a,b/*.py"}), "can't be checked")
        self.assertDenied(self.decide("Glob", {"pattern": "{proj,q}/*", "path": home}),
                          "quarantine folder")
        for pattern in ("{src,lib}/*.py", "*.{py,md}", "src/**/*.{js,ts}", "{src,tests}/**"):
            with self.subTest(pattern=pattern):
                self.assertPass(self.decide("Glob", {"pattern": pattern}))
        self.assertPass(self.decide("Glob", {"pattern": "{proj,.config/nvim}/*.md", "path": home}))
        # Gap E (2026-10-15): "data/*.md" matches at any depth, so it lists
        # names in the untrusted folder ~/data/nested; it passed before.
        self.assertDenied(self.decide("Glob", {"pattern": "{proj,data}/*.md", "path": home}),
                          "untrusted folder")

    def test_glob_negation_and_comment(self):
        # ripgrep reads "!x" as a negation and "#x" as a comment: nothing is
        # filtered, so everything below the base is listed.
        home = str(self.home)
        for pattern in ("!zz/zz", "#zz/zz", home + "/!zz/*", "src/#x", "{a,!b}/*"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern, "path": home}),
                                  "starts with ! or #")
        self.assertPass(self.decide("Glob", {"pattern": "\\#notes.md"}))
        self.assertIsNone(rg._anchored_first("#zz/zz"))
        config = {"reader_gate": dict(self.config["reader_gate"],
                                      quarantine_paths=["~/proj/vendor"])}
        os.makedirs(self.p("proj", "vendor"))
        self.assertDenied(self.decide("Grep", {"pattern": "harmless", "path": self.p("proj"),
                                               "glob": "#zz/zz"}, config=config), "vendor")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": self.p("proj"),
                                             "glob": "src/*.py"}, config=config))

    def test_glob_class_can_span_folders(self):
        # A class like [!x] matches "/", so "qa[!x]quarantine" matches
        # "qa/quarantine".
        home = str(self.home)
        os.makedirs(self.p("qa", "quarantine"))
        config = {"reader_gate": dict(self.config["reader_gate"],
                                      quarantine_paths=["~/qa/quarantine"])}
        for pattern in ("qa[!x]quarantine/*", "qa[^x]quarantine/*", "qa[.-0]quarantine/*"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern, "path": home},
                                              config=config), "quarantine folder")
        self.assertPass(self.decide("Glob", {"pattern": "src/[a-m]*.py"}))

    def test_glob_pattern_too_long(self):
        self.assertDenied(self.decide("Glob", {"pattern": "a" * (rg.MAX_PATH_CHARS + 1)}),
                          "too long")

    def test_deny_reasons_show_only_the_callers_input(self):
        os.symlink("/proc/self/root", self.p("proj", "selfroot"))
        reason = self.decide("Glob", {"pattern": "selfroot/etc/*"})
        self.assertDenied(reason, "selfroot/etc/*")
        self.assertNotIn("/proc/self/root", reason)

    def test_reader_hint_names_the_form_that_works(self):
        self.assertDenied(self.decide("Glob", {"pattern": self.p("q")}, "quar"),
                          "pattern **/*")
        self.assertPass(self.decide("Glob", {"pattern": "**/*", "path": self.p("q")}, "quar"))

    def test_grep_glob_lists_and_spaces(self):
        # Claude Code splits a Grep glob on commas (unless it holds braces) and
        # on spaces, so "project/**,**/*.txt" also searches quarantine.
        config = {"reader_gate": dict(self.config["reader_gate"],
                                      quarantine_paths=["~/proj/vendor"])}
        os.makedirs(self.p("proj", "vendor"))
        grep = lambda glob: self.decide("Grep", {"pattern": "x", "path": self.p("proj"),
                                                 "glob": glob}, config=config)
        for glob in ("src/**,**/*.txt", "src/**,vendor/**", "{a,!b}/x", "{a,#b}/x"):
            with self.subTest(glob=glob):
                self.assertDenied(grep(glob), "vendor")
        for glob in ("src/** **/*.txt", " #zz/zz", "src/** ", "src/**\u00a0**/*.txt"):
            with self.subTest(glob=glob):
                self.assertDenied(grep(glob), "space", "use ? for a space")
        # Braces and a comma outside them could be read whole or split.
        for glob in ("src/{a,b},**/*.txt", "src/{a}/x,**/*.txt", "\\{a\\},**/*.txt"):
            with self.subTest(glob=glob):
                self.assertDenied(grep(glob), "comma outside them")
        self.assertDenied(grep(".en[,v]"), "never closed")
        self.assertDenied(grep(",".join(f"a{i}" for i in range(rg.MAX_GLOB_ALTERNATIVES + 1))),
                          "too many glob pieces")
        self.assertDenied(grep("src/**\t**/*.txt"))  # a tab is a control character
        self.assertDenied(grep("*.py,.env"), "secret")
        # A glob with braces is kept whole by Claude Code (2.1.296), but its
        # comma-split reading is judged too when every piece is a glob.
        for glob in ("\\{a,.env,b\\}", "{a}[,.env,]"):
            with self.subTest(glob=glob):
                self.assertDenied(grep(glob), "secret")
        for glob in ("\\\\,{a}", "[]],{a}", "[!]],{a}"):
            with self.subTest(glob=glob):
                self.assertDenied(grep(glob), "comma outside them")
        self.assertDenied(grep("[!]"), "never closed")
        # A glob starting with "#" or "!" isn't refused on its own: it only
        # stops counting as narrowing the search (VERIFY row 45). Over a
        # folder with nothing protected below it, it's allowed. Each comma
        # piece is judged on its own, so a negation piece counts as
        # unanchored and the call is refused, even though ripgrep would
        # narrow it to src/ (a deliberate over-refusal).
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": self.p("proj", "src"),
                                             "glob": "#zz/zz"}, config=config))
        self.assertPass(grep("src/**"))
        self.assertDenied(grep("src/**,!src/x"), "vendor")
        self.assertDenied(grep("#zz/zz"), "vendor")  # VERIFY row 33, third call
        self.assertDenied(grep("!zz/zz"), "vendor")
        # Known and accepted: a glob mixing real and escaped braces. Its split
        # reading has a piece that doesn't expand ("{a"), so only the whole
        # glob is judged, and ripgrep reads "\{,.env,\}" as literal text: it
        # matches names like "a{,.env,}", never ".env". Claude Code keeps a
        # glob with braces whole (VERIFY row 43), so the split reading
        # doesn't occur on 2.1.296.
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": self.p("proj"),
                                             "glob": "{a,b}\\{,.env,\\}"}))
        # Without braces Claude Code splits on every comma, even inside [].
        self.assertDenied(grep("src/[a,b]*.py"), "never closed")
        # Escaped braces still count as braces for the split, so this is one
        # glob (it reaches vendor only because it isn't anchored).
        self.assertNotIn("comma outside", grep("\\{a,b\\}"))
        for glob in ("src/**", "src/**,tests/**", "src/*.{js,ts}", "src/{a,b}/*.py",
                     "src/[ab]*.py", "src/{a,b}/[,]x"):
            with self.subTest(glob=glob):
                self.assertPass(grep(glob))

    def test_glob_folder_with_wildcards(self):
        for path in (self.p("q*"), self.p("proj", "s?c"), self.p("{proj,q}"), self.p("\\q")):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Glob", {"pattern": "*", "path": path}), "wildcard")
        os.makedirs(self.p("proj", "app", "[slug]"))
        self.assertPass(self.decide("Glob", {"pattern": "*.tsx",
                                             "path": self.p("proj", "app", "[slug]")}))
        # In case a version joins a bracketed folder and the pattern into one
        # glob, that reading is judged too: "[q]" would then match "q".
        self.assertDenied(self.decide("Glob", {"pattern": "*", "path": self.p("[q]")}),
                          "quarantine folder")
        self.assertDenied(self.decide("Glob", {"pattern": "*", "path": "[q]"},
                                      cwd=str(self.home)), "quarantine folder")
        # The guard reaches what lies beside a bracketed folder, too.
        os.makedirs(self.p("proj", "app", "q2"))
        beside = {"reader_gate": dict(self.config["reader_gate"],
                                      quarantine_paths=["~/proj/app/q2"])}
        self.assertDenied(self.decide("Glob", {"pattern": "*.tsx",
                                               "path": self.p("proj", "app", "[slug]")},
                                      config=beside), "quarantine folder")

    def test_glob_blank_segments_and_double_star_inside(self):
        home = str(self.home)
        for pattern in (" !zz/zz", " #zz/zz", "src /x", "src/x "):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern, "path": home}),
                                  "blank space")
        os.makedirs(self.p("qa", "quarantine"))
        config = {"reader_gate": dict(self.config["reader_gate"],
                                      quarantine_paths=["~/qa/quarantine"])}
        for pattern in ("qa{**}quarantine/*", "qa**quarantine/*"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern, "path": home},
                                              config=config), "quarantine folder")

    def test_glob_literal_name_that_links_into_quarantine(self):
        # Defence in depth: Claude Code 2.1.296 doesn't list a symlinked
        # folder named exactly (live check d), but the gate judges it anyway.
        os.symlink(self.p("q"), self.p("proj", "qlink"))
        for pattern in (self.p("proj", "qlink"), "qlink"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern}), "quarantine folder")
        self.assertPass(self.decide("Glob", {"pattern": self.p("proj", "src", "main.py")}))

    def test_glob_in_untrusted_is_for_the_document_reader(self):
        # Gap E (2026-10-15): listing names in an untrusted folder was open to
        # every agent; now it's the document reader's alone, as for Read.
        for who in ("main", "other", "quar", "web"):
            with self.subTest(who=who):
                self.assertDenied(self.decide("Glob", {"pattern": "*.eml",
                                                       "path": self.p("inbox")}, who))
        self.assertDenied(self.decide("Glob", {"pattern": "*.eml", "path": self.p("inbox")}),
                          "untrusted folder", "document-reader")
        self.assertPass(self.decide("Glob", {"pattern": "*.eml", "path": self.p("inbox")}, "doc"))

    def test_readers_glob_only_their_folders(self):
        self.assertPass(self.decide("Glob", {"pattern": "**/*", "path": self.p("q")}, "quar"))
        self.assertPass(self.decide("Glob", {"pattern": "*.eml", "path": self.p("inbox")}, "doc"))
        self.assertDenied(self.decide("Glob", {"pattern": "**/*"}, "doc"), "only inside")
        self.assertDenied(self.decide("Glob", {"pattern": "**/*"}, "quar"), "only inside")
        self.assertDenied(self.decide("Glob", {"pattern": "*"}, "web"), "lists no local files")
        self.assertDenied(self.decide("Glob", {"pattern": "**/*", "path": self.p("q")}, "doc"),
                          "quarantine folder")

    def test_glob_bad_pattern(self):
        for tool_input in ({}, {"pattern": ""}, {"pattern": 4}, {"pattern": "*\u200b"}):
            with self.subTest(tool_input=tool_input):
                self.assertIsNotNone(self.decide("Glob", tool_input))


class GapFixTests(GateCase):
    """The 2026-10-14 gap check's A, H, B and E, fixed 2026-10-15. Each probe
    here passed before the fix."""

    HOME_SECRETS = [
        # Browser profiles (Linux and macOS).
        "~/.config/microsoft-edge/Default/Cookies", "~/.config/microsoft-edge-beta/Default/Cookies",
        "~/.config/google-chrome-beta/Default/Login Data", "~/.config/vivaldi/Default/Cookies",
        "~/.config/opera/Cookies", "~/.config/mozilla/firefox/x.default/logins.json",
        "~/.librewolf/x.default/key4.db",
        "~/Library/Application Support/Chromium/Default/Cookies",
        "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
        "~/Library/Application Support/Microsoft Edge/Default/Cookies",
        "~/Library/Application Support/Vivaldi/Default/Cookies",
        "~/Library/Application Support/com.operasoftware.Opera/Cookies",
        "~/Library/Application Support/Firefox/Profiles/x.default/logins.json",
        "~/Library/Safari/History.db", "~/Library/Cookies/Cookies.binarycookies",
        "~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
        # Wallets.
        "~/.foundry/keystores/deployer", "~/Library/Ethereum/keystore/UTC--x",
        "~/.config/hardhat-nodejs/vars.json", "~/.bitcoin/wallets/main/wallet.dat",
        "~/.bitcoin/bitcoin.conf", "~/Library/Application Support/Bitcoin/wallets/w/wallet.dat",
        "~/.electrum/wallets/default_wallet", "~/.config/Exodus/exodus.wallet/seed.seco",
        "~/Library/Application Support/Exodus/exodus.wallet/seed.seco",
        "~/.config/atomic/Local Storage/leveldb/000003.log",
        "~/.sui/sui_config/sui.keystore", "~/.aptos/config.yaml",
        "~/.near-credentials/mainnet/me.near.json",
        # Cloud and hosting CLIs.
        "~/.oci/config", "~/.oci/oci_api_key.pem", "~/.config/doctl/config.yaml",
        "~/Library/Application Support/doctl/config.yaml", "~/.config/hcloud/cli.toml",
        "~/.config/linode-cli", "~/.fly/config.yml", "~/.aliyun/config.json",
        "~/.terraform.d/credentials.tfrc.json", "~/.terraformrc", "~/.databrickscfg",
        "~/.wrangler/config/default.toml", "~/.config/.wrangler/config/default.toml",
        "~/.config/rclone/rclone.conf", "~/.s3cfg", "~/.boto", "~/.my.cnf",
        "~/.kube/cache/oidc-login/token", "~/.kube/config",
    ]
    PROJECT_SECRETS = ["prod.env", ".envrc", ".git-credentials", ".netrc", "_netrc", ".pypirc",
                       ".pgpass", ".htpasswd", ".vault-token", ".aws/credentials",
                       ".docker/config.json", ".kube/config", "infra/terraform.tfstate",
                       "infra/terraform.tfstate.backup",
                       "client_secret_123.apps.googleusercontent.com.json", "keys/server.ppk",
                       "ios/AuthKey_ABC123.p8", "old/wallet.dat", ".aptos/config.yaml"]
    STATE = ["~/.claude.json.backup", "~/.claude.json.backup.1760000000000",
             "~/.claude/backups/.claude.json.backup.1760000000000",
             "~/.claude/file-history/0d5e2c1a/3f2a@v2", "~/.claude/file-history",
             "~/.claude/history.jsonl", "~/.claude/debug/0d5e2c1a.txt", "~/.claude/debug"]

    # -- A: missing home paths and project-level credential files -------------

    def test_a_home_paths_are_denied(self):
        for path in self.HOME_SECRETS:
            for who in ("main", "doc"):
                with self.subTest(path=path, who=who):
                    self.assertDenied(self.decide("Read", {"file_path": path}, who), "rule 5")

    def test_a_project_credential_files_are_denied_anywhere(self):
        outside = os.path.join(self.tmp.name, "srv", "app")
        for name in self.PROJECT_SECRETS:
            for path in (self.p("proj", name), self.p("proj", "deploy", "ci", name),
                         os.path.join(outside, name)):
                with self.subTest(path=path):
                    self.assertDenied(self.decide("Read", {"file_path": path}), "rule 5")

    def test_a_grep_globs_aimed_at_the_new_names(self):
        for glob in ("*.env", ".envrc", ".git-credentials", ".netrc", "_netrc", ".pypirc",
                     ".pgpass", ".htpasswd", ".vault-token", "*.tfstate", "*.tfstate.backup",
                     "client_secret*.json", "*.ppk", "AuthKey_*.p8", "wallet.dat",
                     "**/terraform.tfstate"):
            with self.subTest(glob=glob):
                self.assertDenied(self.decide("Grep", {"pattern": "KEY", "glob": glob}), "rule 5")

    def test_a_ordinary_files_still_pass(self):
        for path in ("~/proj/src/env.py", "~/proj/environment.ts", "~/proj/docs/netrc.md",
                     "~/proj/infra/main.tf", "~/proj/infra/variables.tfvars",
                     "~/proj/infra/tfstate.md", "~/proj/src/wallet.py", "~/proj/client_secret.md",
                     "~/proj/.envrc.example", "~/proj/.aws/config", "~/proj/docs/credentials.md",
                     "~/proj/.kube/README.md", "~/proj/keys/README.md", "~/proj/.claude.json.md",
                     "~/proj/history.jsonl", "~/proj/debug/log.txt", "~/proj/backups/db.sql",
                     "~/.config/nvim/init.lua", "~/.claude/settings.json", "~/.claude/CLAUDE.md",
                     "~/.claude/agents/helper.md", "~/.bitcoin-notes.txt", "~/.ocirc.md",
                     "~/proj/game/cart.p8", "~/proj/docker-compose.yml"):
            with self.subTest(path=path):
                self.assertPass(self.decide("Read", {"file_path": path}))
        for glob in ("*.tf", "*.md", "*.cnf", "*.py", "*.json", "src/**", "*.{ts,tsx}"):
            with self.subTest(glob=glob):
                self.assertPass(self.decide("Grep", {"pattern": "KEY", "glob": glob}))

    # -- H: Claude Code state outside ~/.claude/projects ----------------------

    def test_h_claude_code_state_is_closed(self):
        # The reason names the area for every caller, readers included: these
        # checks run before a reader's confinement, so a reader isn't refused
        # only for being outside its folder.
        for path in self.STATE:
            for who in ("main", "other", "doc", "quar"):
                with self.subTest(path=path, who=who):
                    reason = self.decide("Read", {"file_path": path}, who)
                    secret = "backups" in path or ".claude.json" in path
                    self.assertDenied(reason, "rule 5" if secret else "own records")
        for path in ("~/.claude/debug", "~/.claude/file-history", "~/.claude/paste-cache"):
            with self.subTest(grep=path):
                self.assertDenied(self.decide("Grep", {"pattern": "x", "path": path}), "rule 3")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": "~/.claude/backups"}),
                          "rule 5")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": "~/.claude",
                                               "glob": "debug/**"}), "rule 3")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": "~/.claude",
                                             "glob": "agents/**"}))

    def test_h_more_claude_code_state(self):
        # Red-team round, M3: IDE lock files and session environments are
        # secrets; pasted, uploaded and snapshot text and to-dos are records.
        for path in ("~/.claude/ide/41234.lock", "~/.claude/session-env/s1/hook-0.sh"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "rule 5")
        for path in ("~/.claude/paste-cache/abc.txt", "~/.claude/shell-snapshots/snapshot.sh",
                     "~/.claude/uploads/s1/report.pdf", "~/.claude/todos/s1-agent.json"):
            for who in ("main", "doc"):
                with self.subTest(path=path, who=who):
                    self.assertDenied(self.decide("Read", {"file_path": path}, who),
                                      "own records")

    def test_h_claude_config_dir_state_is_closed_too(self):
        alt = self.home / "alt-claude"
        (alt / "debug").mkdir(parents=True)
        secrets = [alt / ".claude.json", alt / ".claude.json.backup", alt / ".credentials.json",
                   alt / "backups" / ".claude.json.backup.1", alt / "ide" / "1.lock",
                   alt / "session-env" / "s" / "env.sh"]
        records = [alt / "file-history" / "s" / "f@v1", alt / "history.jsonl",
                   alt / "debug" / "x.txt", alt / "paste-cache" / "p.txt",
                   alt / "shell-snapshots" / "s.sh", alt / "uploads" / "u.txt",
                   alt / "todos" / "t.json"]
        for path in secrets + records:
            with self.subTest(path=str(path), config_dir=None):
                self.assertPass(self.decide("Read", {"file_path": str(path)}))
        self.env.config_dir = str(alt)
        for path in secrets:
            with self.subTest(path=str(path)):
                self.assertDenied(self.decide("Read", {"file_path": str(path)}), "rule 5")
        for path in records:
            with self.subTest(path=str(path)):
                self.assertDenied(self.decide("Read", {"file_path": str(path)}), "records")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": str(alt / "debug")}),
                          "records")
        self.assertDenied(self.decide("Glob", {"pattern": "*", "path": str(alt / "debug")}),
                          "records")
        self.assertPass(self.decide("Read", {"file_path": str(alt / "agents-notes.md")}))

    def test_h_config_dir_with_wildcard_characters(self):
        alt = self.home / "we[i]rd*claude"
        alt.mkdir()
        self.env.config_dir = str(alt)
        self.assertDenied(self.decide("Read", {"file_path": str(alt / ".claude.json")}), "rule 5")
        self.assertPass(self.decide("Read", {"file_path": self.p("weirdxclaude", ".claude.json")}))

    # -- B: a symlinked secret root -------------------------------------------

    def link_ssh(self) -> Path:
        store = Path(self.tmp.name) / "store"
        real = store / "ssh-keys"
        real.mkdir(parents=True)
        (real / "id_custom").write_text("synthetic\n")
        (store / "notes.txt").write_text("plain\n")
        shutil.rmtree(self.home / ".ssh")
        os.symlink(real, self.home / ".ssh")
        return store

    def test_b_symlinked_secret_root(self):
        store = self.link_ssh()
        real = store / "ssh-keys"
        self.assertDenied(self.decide("Read", {"file_path": self.p(".ssh", "id_custom")}),
                          "rule 5")                                          # through the link
        self.assertDenied(self.decide("Read", {"file_path": str(real / "id_custom")}),
                          "rule 5")                                          # the real target
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": str(store)}),
                          "rule 5")                                          # the real parent
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": str(real)}), "rule 5")
        self.assertDenied(self.decide("Glob", {"pattern": "**/*", "path": str(store)}),
                          "rule 5")
        # Controls: the rest of the real parent.
        self.assertPass(self.decide("Read", {"file_path": str(store / "notes.txt")}))
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": str(store),
                                             "glob": "other/**"}))

    def test_b_symlinked_folder_above_a_secret_root(self):
        xdg = Path(self.tmp.name) / "xdg"
        shutil.move(str(self.home / ".config"), str(xdg))
        os.symlink(xdg, self.home / ".config")
        self.assertDenied(self.decide("Read", {"file_path": str(xdg / "gcloud" / "creds.db")}),
                          "rule 5")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": str(xdg)}), "rule 5")
        self.assertPass(self.decide("Read", {"file_path": str(xdg / "nvim" / "init.lua")}))

    def test_b_grep_at_the_real_parent_of_a_symlinked_quarantine(self):
        strangers = Path(self.tmp.name) / "strangers"
        (strangers / "q2").mkdir(parents=True)
        os.symlink(strangers / "q2", self.home / "q2")
        config = {"reader_gate": dict(self.config["reader_gate"], quarantine_paths=["~/q2"])}
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": str(strangers)},
                                      config=config), "quarantine")

    # -- E: Glob in protected folders -----------------------------------------

    def test_e_glob_in_a_secret_folder(self):
        home = str(self.home)
        for pattern, path in (("*", "~/.ssh"), ("**/*", self.p(".ssh")), (".ssh/*", home),
                              ("~/.ssh/*", None), ("**/*.json", self.p(".config")),
                              ("*", self.p("vault"))):
            tool_input = {"pattern": pattern} if path is None else {"pattern": pattern,
                                                                     "path": path}
            with self.subTest(tool_input=tool_input):
                self.assertDenied(self.decide("Glob", tool_input), "rule 5", "secret folder")
        os.symlink(self.home / ".ssh", self.home / "proj" / "keys")
        self.assertDenied(self.decide("Glob", {"pattern": "keys"}), "rule 5")
        self.assertDenied(self.decide("Glob", {"pattern": "keys/*"}), "rule 5")
        # Controls: a folder beside a secret one, and secret file *names* in
        # an ordinary folder (Read still refuses their contents).
        self.assertPass(self.decide("Glob", {"pattern": "nvim/**", "path": self.p(".config")}))
        self.assertPass(self.decide("Glob", {"pattern": "**/.env"}))
        self.assertPass(self.decide("Glob", {"pattern": "*.pem"}))
        self.assertPass(self.decide("Glob", {"pattern": "registry/*", "path": self.p(".cargo")}))

    def test_e_glob_walking_into_an_untrusted_folder(self):
        data = self.p("data")
        self.assertDenied(self.decide("Glob", {"pattern": "**/*", "path": data}),
                          "untrusted folder")
        self.assertDenied(self.decide("Glob", {"pattern": "*.txt", "path": data}),
                          "untrusted folder")
        self.assertPass(self.decide("Glob", {"pattern": "other/*.txt", "path": data}))
        self.assertPass(self.decide("Glob", {"pattern": "**/*", "path": self.p("data", "nested")},
                                    "doc"))

    def test_e_quarantine_inside_an_untrusted_folder(self):
        # The quarantine rule decides there, as for Read and Grep.
        (self.home / "inbox" / "strange").mkdir()
        config = {"reader_gate": dict(self.config["reader_gate"],
                                      quarantine_paths=["~/inbox/strange"])}
        self.assertPass(self.decide("Glob", {"pattern": "**/*", "path": self.p("inbox", "strange")},
                                    "quar", config=config))
        self.assertDenied(self.decide("Glob", {"pattern": "**/*", "path": self.p("inbox")},
                                      "doc", config=config), "quarantine folder")


    # -- Red-team round (2026-10-15) ------------------------------------------

    def test_m1_grep_globs_aimed_at_folder_and_name_secrets(self):
        for glob in (".aws/credentials", "**/.aws/credentials", "**/.kube/config", ".kube/config",
                     ".docker/config.json", ".aptos/config.yaml", "**/.aptos/config.yaml",
                     ".aws/*", ".aws/**", "containers/auth.json", ".ssh/*", "**/.ssh/**",
                     "{src/**,.aws/credentials}",
                     # Round 3, N1: "**/" standing for no folder at all.
                     ".aws/**/credentials", "**/.aws/**/credentials", "**/.kube/**/config",
                     # Round 3, N2: a glob with no "/" matches names at any depth.
                     "credentials", "cred*", "auth.json", "config", "deploy_key",
                     # Round 4: leading folders above the secret's folder.
                     "deploy/.aws/credentials", "ci/.kube/config", "a/**/.aws/credentials",
                     "infra/containers/auth.json", "a/b/c/.aws/credentials",
                     "a/**/**/.kube/config"):
            with self.subTest(glob=glob):
                self.assertDenied(self.decide("Grep", {"pattern": "KEY", "glob": glob}), "rule 5")
        for glob in ("*/config", "**/config", "**/*", "app/config.yaml", "*/config.yaml",
                     ".aws/config", "src/**", "src/**/config", "config*", "*.json", "config.yaml",
                     "deploy/src/*.py", "deploy/**/*", "deploy/*/*", "src/**/*"):
            with self.subTest(glob=glob):
                self.assertPass(self.decide("Grep", {"pattern": "KEY", "glob": glob}))

    def test_m1_grep_rooted_at_a_named_secret_folder(self):
        for sub in (".aws", ".docker", ".kube", ".aptos", "keystore", "containers"):
            (self.home / "proj" / sub).mkdir()
            folder = self.p("proj", sub)
            with self.subTest(folder=sub):
                self.assertDenied(self.decide("Grep", {"pattern": "x", "path": folder}), "rule 5")
                self.assertDenied(self.decide("Grep", {"pattern": "x", "path": folder,
                                                       "glob": "*"}), "rule 5")
                self.assertPass(self.decide("Grep", {"pattern": "x", "path": folder,
                                                     "glob": "sub/**"}))
        # Through a link named otherwise, the real folder's name counts.
        os.symlink(self.home / "proj" / ".aws", self.home / "proj" / "cloud")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": self.p("proj", "cloud")}),
                          "rule 5")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": self.p("proj", "src")}))

    def test_m2_glob_from_a_repo_with_an_untrusted_folder_inside(self):
        config = {"reader_gate": dict(self.config["reader_gate"],
                                      untrusted_paths=["~/proj/inbox"])}
        (self.home / "proj" / "inbox").mkdir()
        reason = self.decide("Glob", {"pattern": "**/*.py"}, config=config)
        self.assertDenied(reason, "untrusted folder", "src/**/*.py")
        self.assertPass(self.decide("Glob", {"pattern": "src/**/*.py"}, config=config))

    def test_m4_more_profiles_and_stores(self):
        for path in ("~/Library/Application Support/Google/Chrome Beta/Default/Cookies",
                     "~/Library/Application Support/Google/Chrome Canary/Default/Login Data",
                     "~/.thunderbird/x.default/logins.json",
                     "~/Library/Thunderbird/Profiles/x.default/key4.db",
                     "~/.local/share/kwalletd/kdewallet.kwl", "~/proj/deploy/.ssh/deploy_key",
                     "~/proj/.ssh", "/srv/backup/home/.ssh/id_ed25519",
                     "~/.config/Claude/claude_desktop_config.json",
                     "~/.config/Claude/buddy-tokens.json", "~/.config/Claude/Cookies",
                     "~/.config/Claude/Local Storage/leveldb/000003.log",
                     "~/.config/Claude/Partitions/x/Cookies",
                     "~/.config/Claude/Network/Cookies", "~/.config/Claude/Network/Trust Tokens",
                     "~/.config/Slack/Network/Cookies",
                     "~/Library/Application Support/discord/Network/Cookies",
                     "~/Library/Application Support/Claude/claude_desktop_config.json",
                     "~/.config/Slack/Cookies", "~/.config/Slack/IndexedDB/x/1.blob",
                     "~/Library/Application Support/Slack/Local State",
                     "~/.config/discord/Local Storage/leveldb/1.ldb",
                     "~/Library/Application Support/discord/Session Storage/1.log"):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Read", {"file_path": path}), "rule 5")
        notes = self.home / ".config" / "Claude" / "side-session-notes"
        notes.mkdir(parents=True)
        for path in (str(notes / "local_1" / "notes.md"), "~/.config/Claude/logs/main.log",
                     "~/.config/Slack/notes.txt", "~/proj/ssh/README.md"):
            with self.subTest(path=path):
                self.assertPass(self.decide("Read", {"file_path": path}))
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": str(notes)}))
        self.assertPass(self.decide("Glob", {"pattern": "**/*.md", "path": str(notes)}))
        self.assertDenied(self.decide("Glob", {"pattern": "**/*",
                                               "path": self.p(".config", "Claude")}), "rule 5")

    def test_l1_walk_in_for_folders_covered_by_name_patterns(self):
        config = {"reader_gate": dict(self.config["reader_gate"],
                                      secret_paths=["~/vault/*", "~/work/vault/*",
                                                    "**/secrets/*"])}
        (self.home / "work" / "vault").mkdir(parents=True)
        (self.home / "work" / "src").mkdir()
        work = self.p("work")
        self.assertDenied(self.decide("Glob", {"pattern": "**/*", "path": work}, config=config),
                          "rule 5", "vault")
        self.assertDenied(self.decide("Glob", {"pattern": "*", "path": str(self.home)},
                                      config=config))
        self.assertDenied(self.decide("Glob", {"pattern": "vault/*", "path": str(self.home)},
                                      config=config), "rule 5")
        self.assertPass(self.decide("Glob", {"pattern": "src/**", "path": work}, config=config))
        for pattern in ("secrets/*", "**/secrets/*", "src/**/secrets/*", "**/.ssh/*",
                        "deploy/.ssh/**"):
            with self.subTest(pattern=pattern):
                self.assertDenied(self.decide("Glob", {"pattern": pattern}, config=config),
                                  "rule 5")
        for pattern in ("**/*.py", "secrets.md", "**/secretsx/*", "**/secrets"):
            with self.subTest(pattern=pattern):
                self.assertPass(self.decide("Glob", {"pattern": pattern}, config=config))

    def test_n4_globs_like_secret_names_are_refused(self):
        # Round 3, N4 (the owner's safety-first call): these also match
        # ordinary names, but no ordinary sample stands for them, so they stay
        # refused. README, "Grep can still print lines ...", lists them.
        for glob in ("*.dat", "*.backup", ".*rc", "*rc", "*.tf*", "*.p8", ".*", ".e*", ".?*",
                     ".[a-z]*", "wallet.dat", "*.tfstate.backup", ".envrc", "AuthKey_*.p8"):
            with self.subTest(glob=glob):
                self.assertDenied(self.decide("Grep", {"pattern": "KEY", "glob": glob}), "rule 5")
        for glob in ("main.tf", "cart.p8", "*.tf", ".eslintrc"):
            with self.subTest(glob=glob):
                self.assertPass(self.decide("Grep", {"pattern": "KEY", "glob": glob}))

    def test_secret_aim_is_fast_on_hostile_globs(self):
        import time
        for glob in ("*?" * 2048, "*a" * 2047 + "*z", "*/" * 2048, "**/" * 1365 + "x",
                     "[!a]*" * 819, ".a" + "/**" * 1364, "a/" * 2047 + "*",
                     "a/" * 1000 + ".aws/credentials"):
            glob = glob[:rg.MAX_PATH_CHARS]
            with self.subTest(shape=glob[:8]):
                start = time.process_time()
                rg._secret_aim(glob)
                self.decide("Grep", {"pattern": "KEY", "glob": glob})
                self.assertLess(time.process_time() - start, 1.0)

    def test_l7_untrusted_folder_inside_quarantine(self):
        # The quarantine reviewer can't list or search a quarantine folder that
        # has an untrusted folder inside it, and the document reader can't
        # reach that folder either (the quarantine rule comes first): keep the
        # two kinds of folder apart.
        (self.home / "q" / "mail").mkdir()
        config = {"reader_gate": dict(self.config["reader_gate"],
                                      untrusted_paths=["~/q/mail"])}
        q = self.p("q")
        self.assertDenied(self.decide("Glob", {"pattern": "**/*", "path": q}, "quar",
                                      config=config), "untrusted folder")
        self.assertDenied(self.decide("Grep", {"pattern": "x", "path": q}, "quar",
                                      config=config), "untrusted")
        self.assertPass(self.decide("Glob", {"pattern": "repo/**", "path": q}, "quar",
                                    config=config))
        self.assertDenied(self.decide("Glob", {"pattern": "**/*", "path": self.p("q", "mail")},
                                      "doc", config=config), "quarantine folder")

class PolicyTests(GateCase):
    def test_bad_configs_raise(self):
        bad = [{"reader_gate": []}, {"reader_gate": {"untrusted_path": ["~/x"]}},
               {"reader_gate": {"untrusted_paths": "~/x"}},
               {"reader_gate": {"untrusted_paths": [5]}},
               {"reader_gate": {"quarantine_paths": ["relative/q"]}},
               {"reader_gate": {"secret_paths": [""]}},
               {"reader_gate": {"private_hosts": ["x\x00y"]}}]
        for config in bad:
            with self.subTest(config=config):
                with self.assertRaises(_config.ConfigError):
                    rg.decide(self.event("Read", {"file_path": "/x"}), config, self.env)

    def test_empty_config_still_guards_web_and_secrets(self):
        self.assertIsNotNone(self.decide("WebSearch", {"query": "x"}, config={}))
        self.assertIsNotNone(self.decide("Read", {"file_path": "~/.ssh/id_rsa"}, config={}))
        self.assertPass(self.decide("Read", {"file_path": self.p("inbox", "mail.eml")},
                                    config={}))

    def test_other_tools_get_no_decision(self):
        for tool in ("Bash", "Edit", "Write", "mcp__x__y"):
            with self.subTest(tool=tool):
                self.assertIsNone(rg.decide({"tool_name": tool, "tool_input": {}}, {}, self.env))

    def test_non_object_event(self):
        self.assertIsNotNone(rg.decide([], {}, self.env))


# A literal copy of Unicode's Default_Ignorable_Code_Point ranges
# (DerivedCoreProperties.txt). Kept here, apart from the gate's own table, so
# the test doesn't check the gate against itself.
DEFAULT_IGNORABLE = """00AD 034F 061C 115F-1160 17B4-17B5 180B-180F 200B-200F 202A-202E
2060-206F 3164 FE00-FE0F FEFF FFA0 FFF0-FFF8 1BCA0-1BCA3 1D173-1D17A E0000-E0FFF"""


def default_ignorables():
    for token in DEFAULT_IGNORABLE.split():
        lo, _, hi = token.partition("-")
        yield from range(int(lo, 16), int(hi or lo, 16) + 1)


def category_cf():
    import unicodedata
    return [cp for cp in range(0x110000)
            if not 0xD800 <= cp <= 0xDFFF and unicodedata.category(chr(cp)) == "Cf"]


class HiddenOracleTests(GateCase):
    """Every hidden character, from an independent list, is refused in paths and URLs."""

    def hidden(self):
        return sorted(set(default_ignorables()) | set(category_cf()))

    def test_list_is_not_empty_and_includes_unassigned(self):
        self.assertEqual(len(set(default_ignorables())), 4174)
        cps = self.hidden()
        self.assertGreater(len(cps), 4174)  # plus Cf characters outside those ranges
        self.assertIn(0xE0080, cps)  # unassigned, inside the tags block

    def test_every_hidden_character_in_a_path(self):
        for cp in self.hidden():
            reason = self.decide("Read", {"file_path": self.p("proj", f"ma{chr(cp)}in.py")})
            if reason is None:
                self.fail(f"U+{cp:04X} in a path passed")

    def test_every_hidden_character_in_a_url_host(self):
        for cp in self.hidden():
            reason = self.decide("WebFetch", {"url": f"https://exa{chr(cp)}mple.com/"}, "web")
            if reason is None:
                self.fail(f"U+{cp:04X} in a URL passed")

    def test_controls_and_separators(self):
        for cp in list(range(0x00, 0x20)) + list(range(0x7F, 0xA0)) + [0x2028, 0x2029]:
            with self.subTest(cp=hex(cp)):
                self.assertIsNotNone(self.decide("Read",
                                                 {"file_path": self.p("proj", f"a{chr(cp)}b")}))

    def test_ordinary_unicode_names_pass(self):
        for name in ("résumé.txt", "日本語.md", "файл.py", "a b.txt", "naïve.py"):
            with self.subTest(name=name):
                self.assertPass(self.decide("Read", {"file_path": self.p("proj", name)}))


class GenerativePathTests(GateCase):
    """Seeded one-step variants of known-bad paths stay denied; controls stay clean."""

    SEED = 20261009

    def setUp(self):
        super().setUp()
        proj = self.home / "proj"
        os.symlink(self.home, proj / "l_home")
        os.symlink(self.home / ".ssh", proj / "l_ssh")
        os.symlink(self.home / "inbox", proj / "l_inbox")
        os.symlink(self.home / "q", proj / "l_q")
        import random
        self.rng = random.Random(self.SEED)

    def mutate(self, path: str, case_ok: bool) -> tuple:
        """Return (path, cwd) after one to three random one-step changes."""
        rng, home = self.rng, str(self.home)
        cwd = self.p("proj")
        steps = rng.randint(1, 3)
        for _ in range(steps):
            kind = rng.choice(["dot", "double", "updown", "trail", "via_home_link",
                               "via_dir_link", "case", "detour"])
            parts = path.split("/")
            if kind == "dot":
                i = rng.randrange(1, len(parts))
                parts.insert(i, ".")
                path = "/".join(parts)
            elif kind == "double":
                i = rng.randrange(1, len(parts))
                parts[i] = "/" + parts[i]
                path = "/".join(parts)
            elif kind == "updown" and len(parts) > 2:
                i = rng.randrange(1, len(parts) - 1)
                if parts[i] not in ("", ".", ".."):   # "x/../x" only for a real name
                    parts.insert(i + 1, "..")
                    parts.insert(i + 2, parts[i])
                    path = "/".join(parts)
            elif kind == "trail":
                path = path.rstrip("/") + "/"
            elif kind == "via_home_link" and path.startswith(home + "/"):
                path = self.p("proj", "l_home") + path[len(home):]
            elif kind == "via_dir_link":
                for name, target in (("l_ssh", ".ssh"), ("l_inbox", "inbox"), ("l_q", "q")):
                    prefix = self.p(target) + "/"
                    if path.startswith(prefix):
                        path = self.p("proj", name) + "/" + path[len(prefix):]
                        break
            elif kind == "case" and case_ok:
                # Flip letters in the file name only: on a case-sensitive file
                # system a flipped folder is simply another (missing) folder.
                head, _, name = path.rpartition("/")
                chars = list(name)
                for _ in range(2 if chars else 0):
                    j = rng.randrange(len(chars))
                    chars[j] = chars[j].swapcase()
                path = head + "/" + "".join(chars)
            elif kind == "detour":
                path = path.replace(home + "/", home + "/proj/../", 1)
        if case_ok and path.startswith("/") and rng.random() < 0.15:
            return "/proc/self/root" + path, cwd
        style = rng.choice(["abs", "abs", "tilde", "relative"])
        if style == "tilde" and path.startswith(home + "/"):
            path = "~" + path[len(home):]
        elif style == "relative" and path.startswith("/") and not path.startswith("/proc"):
            cwd = rng.choice([self.p("proj"), self.p("proj", "src")])
            # relpath is lexical, so only rewrite paths whose meaning it can't
            # change: no '..' and no symlinked folder (a '..' after a link is
            # resolved by the kernel from the link's target, not lexically).
            if ".." not in path.split("/") and "/l_" not in path:
                path = os.path.relpath(path, cwd)
        return path, cwd

    def test_bad_paths_stay_denied(self):
        bases = [(self.p(".ssh", "id_rsa"), True), (self.p(".aws", "credentials"), True),
                 (self.p("proj", ".env"), True), (self.p(".config", "gh", "hosts.yml"), True),
                 (self.p("inbox", "mail.eml"), False), (self.p("q", "repo", "index.js"), False),
                 (self.p("vault", "notes.txt"), True)]
        count = 0
        for _ in range(60):
            for base, case_ok in bases:
                path, cwd = self.mutate(base, case_ok)
                for tool, key in (("Read", "file_path"), ("Grep", "path")):
                    for who in ("main", "other"):
                        reason = self.decide(tool, {key: path, "pattern": "x"}, who, cwd=cwd)
                        count += 1
                        if reason is None:
                            self.fail(f"{tool} by {who} passed for {path!r} (cwd {cwd}) "
                                      f"from {base}")
        self.assertGreaterEqual(count, 1600)

    def test_controls_stay_clean(self):
        bases = [self.p("proj", "src", "main.py"), self.p("proj", "README.md"),
                 self.p(".config", "nvim", "init.lua"), self.p("data", "other.txt")]
        count = 0
        for _ in range(60):
            for base in bases:
                path, cwd = self.mutate(base, case_ok=False)
                reason = self.decide("Read", {"file_path": path}, "main", cwd=cwd)
                count += 1
                if reason is not None:
                    self.fail(f"control {path!r} (cwd {cwd}) was denied: {reason}")
        self.assertGreaterEqual(count, 240)


class GenerativeHostTests(GateCase):
    """Seeded variants of local and private hosts stay refused; public ones pass."""

    SEED = 77

    def setUp(self):
        super().setUp()
        import random
        self.rng = random.Random(self.SEED)

    IPV4_FORMS = {
        "127.0.0.1": ["127.0.0.1", "2130706433", "0x7f000001", "0177.0.0.01", "127.1",
                      "0x7f.0.0.1", "127.000.000.001", "127.0.1", "[::ffff:127.0.0.1]",
                      "[::ffff:7f00:1]", "[0:0:0:0:0:ffff:7f00:1]", "１２７.０.０.１",
                      "127。0。0。1", "127．0．0．1"],
        "169.254.169.254": ["169.254.169.254", "2852039166", "0xa9fea9fe",
                            "0251.0376.0251.0376", "[::ffff:a9fe:a9fe]"],
        "10.0.0.5": ["10.0.0.5", "167772165", "012.0.0.05", "10.5"],
    }
    NAMES = ["localhost", "foo.local", "db.internal", "wiki.corp.example", "router.home.arpa",
             "loop.example.net", "meta.example.net", "private.example.net", "intranet",
             "api.localhost", "nas.lan"]

    def variant(self, host: str) -> str:
        rng = self.rng
        if rng.random() < 0.5 and not host.startswith("["):
            host = "".join(c.upper() if rng.random() < 0.4 else c for c in host)
        if rng.random() < 0.3 and not host.startswith("[") and not host[0].isdigit():
            host += "."
        scheme = rng.choice(["http", "https", "HTTP", "Https"])
        port = rng.choice(["", ":80", ":443", ":8080"])
        tail = rng.choice(["/", "/a/b?x=1", "#frag", "", "/?q=%2F"])
        userinfo = rng.choice(["", "", "", "user@", "u:p@"])
        return f"{scheme}://{userinfo}{host}{port}{tail}"

    def test_bad_hosts_stay_refused(self):
        hosts = [form for forms in self.IPV4_FORMS.values() for form in forms] + self.NAMES
        count = 0
        for _ in range(16):
            for host in hosts:
                url = self.variant(host)
                count += 1
                if self.decide("WebFetch", {"url": url}, "web") is None:
                    self.fail(f"{url!r} passed")
        self.assertGreaterEqual(count, 500)

    def test_public_hosts_pass(self):
        count = 0
        for _ in range(60):
            for host in ("example.com", "public.example.net"):
                url = self.variant(host).replace("user@", "").replace("u:p@", "")
                count += 1
                reason = self.decide("WebFetch", {"url": url}, "web")
                if reason is not None:
                    self.fail(f"{url!r} was refused: {reason}")
        self.assertGreaterEqual(count, 120)

    def test_parser_differential_backslash(self):
        for url in ("http://127.0.0.1\\@example.com/", "http://example.com\\@127.0.0.1/",
                    "https://example.com\\.evil/"):
            with self.subTest(url=url):
                self.assertDenied(self.decide("WebFetch", {"url": url}, "web"), "backslash")

    def test_percent_encoded_host(self):
        self.assertDenied(self.decide("WebFetch", {"url": "http://%6cocalhost/"}, "web"),
                          "percent-encoded")


class GenerativeIdentityTests(GateCase):
    """Near-miss agent_type values are never a reader."""

    def test_mutated_reader_names(self):
        import random
        rng = random.Random(5)
        name = WEB[0]
        mutations = [lambda s: s.upper(), lambda s: s.title(), lambda s: " " + s,
                     lambda s: s + " ", lambda s: s + "\u200b", lambda s: s.replace(":", "\uff1a"),
                     lambda s: "stranger-danger:" + s, lambda s: s + ".md",
                     lambda s: s.replace("-", "_"), lambda s: s.replace(":", "::"),
                     lambda s: s.replace("stranger-danger:", ""), lambda s: s + "\n"]
        count = 0
        for _ in range(15):
            for mutate in mutations:
                mutated = mutate(name)
                if rng.random() < 0.5:
                    mutated = rng.choice(mutations)(mutated)
                if mutated == name:
                    continue
                count += 1
                reason = self.decide("WebSearch", {"query": "x"}, (mutated, "agent-1"))
                if reason is None:
                    self.fail(f"{mutated!r} passed as the web reader")
        self.assertGreaterEqual(count, 150)

class GenerativeShadowTests(GateCase):
    """Seeded variants of an agent file that takes a reader's name, in every
    spelling, encoding and place tried, keep the readers off; controls don't."""

    SEED = 20261010
    NAME = "stranger-danger:web-researcher"

    def name_line(self, rng) -> str:
        n = self.NAME
        k = rng.randrange(1, len(n))
        hidden = rng.choice(sorted(default_ignorables()))
        forms = [
            f"name: {n}", f'name: "{n}"', f"name: '{n}'", f"name: {n}  # comment",
            f'"name": {n}', f"'name': '{n}'", f"name: >-\n  {n}", f"name: |-\n  {n}",
            f"name: >\n  {n}\n", f"{{name: {n}, tools: Bash}}",
            'name: "' + n.replace(":", "\\x3a") + '"',
            'name: "' + n.replace(":", "\\u003a") + '"',
            'name: "' + n.replace(":", "\\U0000003A") + '"',
            'name: "' + n.replace("-", "\\x2d") + '"',
            'name: "' + "".join(f"\\x{ord(c):02x}" for c in n) + '"',
            'name: "' + n[:k] + "\\\n" + " " * rng.randrange(0, 6) + n[k:] + '"',
            f"name: {n.upper()}", f"name: {n.title()}",
            f"name: {n[:k]}{chr(hidden)}{n[k:]}",
            "name: " + n.replace(":", "\uff1a"),
            f"name: helper\ndescription: Briefs {n} for pages.",
            "name: !!binary " + base64.b64encode(n.encode()).decode(),
            "name: !!binary |\n  " + base64.b64encode(n.encode()).decode()[:k] + "\n  "
            + base64.b64encode(n.encode()).decode()[k:],
        ]
        return rng.choice(forms)

    def encode(self, text: str, rng) -> bytes:
        if rng.random() < 0.3:
            text = text.replace("\n", "\r\n")
        return rng.choice([
            lambda t: t.encode("utf-8"),
            lambda t: b"\xef\xbb\xbf" + t.encode("utf-8"),
            lambda t: t.encode("utf-16"),
            lambda t: t.encode("utf-16-le"),
            lambda t: t.encode("utf-16-be"),
            lambda t: t.encode("utf-32"),
        ])(text)

    def place(self, rng):
        """(agents folder, cwd, project_dir, config_dir) for one variant."""
        base = Path(self.tmp.name)
        where = rng.choice(["user", "project", "ancestor", "project_dir", "config_dir"])
        if where == "user":
            return self.home / ".claude" / "agents", None, None, None
        if where == "project":
            return self.home / "proj" / ".claude" / "agents", None, None, None
        if where == "ancestor":
            cwd = self.home / "proj" / "src" / "deep"
            cwd.mkdir(parents=True, exist_ok=True)
            return self.home / "proj" / "src" / ".claude" / "agents", str(cwd), None, None
        if where == "project_dir":
            project = base / "work" / "proj"
            return project / ".claude" / "agents", None, str(project), None
        return base / "alt-claude" / "agents", None, None, str(base / "alt-claude")

    def make(self, rng, text: str):
        agents, cwd, project_dir, config_dir = self.place(rng)
        depth = rng.randrange(0, 6)
        folder = agents.joinpath(*[rng.choice(["a", "B", "kit", ".hidden"]) + str(i)
                                   for i in range(depth)])
        if rng.random() < 0.25:  # reach the file through a symlinked folder
            real = Path(self.tmp.name) / "linked" / str(rng.randrange(10 ** 9))
            real.mkdir(parents=True)
            folder.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(real, folder)
            folder = real
        folder.mkdir(parents=True, exist_ok=True)
        filename = "x" + rng.choice([".md", ".MD", ".Md", ".markdown", ".yaml", ".yml", ".txt",
                                     "", ".md.bak", ".json"])
        (folder / filename).write_bytes(self.encode(text, rng))
        self.env.project_dir, self.env.config_dir = project_dir, config_dir
        return agents, cwd

    def cleanup(self, agents: Path):
        if agents.is_symlink():
            agents.unlink()
        elif agents.exists():
            shutil.rmtree(agents)
        linked = Path(self.tmp.name) / "linked"
        if linked.exists():
            shutil.rmtree(linked)
        self.env.project_dir = self.env.config_dir = None

    def test_mutated_shadow_files_keep_the_readers_off(self):
        import random
        rng = random.Random(self.SEED)
        for i in range(400):
            body = f"---\n{self.name_line(rng)}\ntools: Bash\n---\nYou help.\n"
            agents, cwd = self.make(rng, body)
            reason = self.decide("WebSearch", {"query": "x"}, "web", cwd=cwd)
            if reason is None or "reserved prefix" not in reason:
                self.fail(f"variant {i} passed: {body!r} in {agents}")
            self.cleanup(agents)

    def test_controls_stay_clean(self):
        import random
        rng = random.Random(self.SEED + 1)
        names = ["helper", "web-researcher", "stranger-danger-fan", "stranger danger: hi",
                 "strangerdanger:web", "stranger_danger:web", "stranger-dangerous:web",
                 '"stranger-danger\\x2eweb"', "danger:web", "stranger:danger"]
        for i in range(200):
            body = f"---\nname: {rng.choice(names)}\ntools: Bash\n---\nYou help.\n"
            agents, cwd = self.make(rng, body)
            reason = self.decide("WebSearch", {"query": "x"}, "web", cwd=cwd)
            if reason is not None:
                self.fail(f"control {i} was refused: {body!r}: {reason}")
            self.cleanup(agents)


class GenerativeGrepGlobTests(GateCase):
    """Seeded brace and escape spellings of globs aimed at secrets stay refused."""

    def spell(self, name: str, rng) -> str:
        decoys = ["a.py", "src/x.ts", "README.md", "*.txt", "lib/**"]
        steps = [
            lambda g: "{" + g + "," + rng.choice(decoys) + "}",
            lambda g: "{" + rng.choice(decoys) + "," + g + "}",
            lambda g: "{" + g + "}",
            lambda g: g + "{,}",
            lambda g: "**/" + g,
            # one-step escapes of a literal character (an escaped * would be literal)
            lambda g: "\\" + g if g[:1] in (".", "i") else g,
            lambda g: g if "[" in g or "\\" in g else g.replace(".", "[.]", 1),
            lambda g: g if "\\" in g else g.replace("e", "\\e", 1),
        ]
        glob = name
        for _ in range(rng.randrange(1, 4)):
            glob = rng.choice(steps)(glob)
        return glob

    def test_spelled_secret_globs_stay_refused(self):
        import random
        rng = random.Random(77)
        names = [".env", ".env.local", ".env.production", "*.pem", "*.key", "id_rsa",
                 "id_ed25519", "id_ecdsa", "*.kdbx", "*.p12", "*.pfx", "*.jks", "*keypair*.json"]
        count = 0
        for _ in range(60):
            for name in names:
                glob = self.spell(name, rng)
                count += 1
                reason = self.decide("Grep", {"pattern": "KEY", "glob": glob})
                if reason is None:
                    self.fail(f"{glob!r} passed")
        self.assertGreaterEqual(count, 700)

    def test_spelled_ordinary_globs_pass(self):
        import random
        rng = random.Random(78)
        for _ in range(300):
            glob = self.spell(rng.choice(["*.py", "*.ts", "src/*.md", "Makefile", "*.json"]), rng)
            reason = self.decide("Grep", {"pattern": "KEY", "glob": glob})
            if reason is not None:
                self.fail(f"{glob!r} was refused: {reason}")


class MainTests(unittest.TestCase):
    """The hook as Claude Code runs it: python3 -I hooks/reader_gate.py."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.home = base / "home"
        (self.home / "proj").mkdir(parents=True)
        self.plugin = base / "plugin"
        shutil.copytree(ROOT / "agents", self.plugin / "agents")
        shutil.copytree(ROOT / ".claude-plugin", self.plugin / ".claude-plugin")
        self.cfg_dir = base / "cfg"
        self.cfg_dir.mkdir(mode=0o700)
        self.cfg = self.cfg_dir / "config.json"
        self.env = dict(os.environ)
        self.env.update({"HOME": str(self.home), "CLAUDE_PLUGIN_ROOT": str(self.plugin),
                         _config.ENV_OVERRIDE: str(self.cfg)})
        self.env.pop("CLAUDE_PROJECT_DIR", None)
        self.env.pop("CLAUDE_CONFIG_DIR", None)

    def tearDown(self):
        self.tmp.cleanup()

    def write_config(self, text: str, mode=0o600):
        self.cfg.write_text(text)
        os.chmod(self.cfg, mode)

    def run_hook(self, stdin: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "reader_gate.py")],
                              input=stdin.encode(), capture_output=True, env=self.env,
                              timeout=20)

    def event(self, tool, tool_input, ident=None) -> str:
        event = {"tool_name": tool, "tool_input": tool_input, "cwd": str(self.home / "proj")}
        if ident:
            event["agent_type"], event["agent_id"] = ident
        return json.dumps(event)

    def test_pass_is_exit_0_and_silent(self):
        proc = self.run_hook(self.event("Read", {"file_path": str(self.home / "proj" / "a.py")}))
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, b"", b""))

    def test_deny_is_exit_2_with_reason_and_log(self):
        proc = self.run_hook(self.event("WebFetch", {"url": "https://example.com/?k=v"}))
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"web-researcher", proc.stderr)
        log = self.home / ".local" / "state" / "stranger-danger" / "decisions.jsonl"
        self.assertTrue(log.exists())
        self.assertEqual(stat.S_IMODE(os.stat(log).st_mode), 0o600)
        record = json.loads(log.read_text().splitlines()[-1])
        self.assertEqual((record["decision"], record["host"]), ("deny", "example.com"))
        self.assertNotIn("k=v", log.read_text())

    def test_web_reader_ip_literal_refused_without_dns(self):
        proc = self.run_hook(self.event("WebFetch", {"url": "http://127.0.0.1:8080/"}, WEB))
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"IP address", proc.stderr)

    def test_log_failure_does_not_change_the_decision(self):
        state = self.home / ".local" / "state"
        state.mkdir(parents=True)
        os.chmod(state, 0o500)
        try:
            proc = self.run_hook(self.event("WebSearch", {"query": "x"}))
        finally:
            os.chmod(state, 0o700)
        self.assertEqual(proc.returncode, 2)

    def test_bad_json_and_bad_shapes_fail_closed(self):
        for stdin in ("{not json", "[]", "\"x\"", ""):
            with self.subTest(stdin=stdin):
                self.assertEqual(self.run_hook(stdin).returncode, 2)

    def test_other_tools_pass(self):
        proc = self.run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}))
        self.assertEqual(proc.returncode, 0)

    def test_bad_config_denies(self):
        self.write_config("{oops")
        proc = self.run_hook(self.event("Read", {"file_path": str(self.home / "proj" / "a.py")}))
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"config problem", proc.stderr)

    def test_group_writable_config_denies(self):
        self.write_config('{"reader_gate": {}}', mode=0o620)
        proc = self.run_hook(self.event("Read", {"file_path": str(self.home / "proj" / "a.py")}))
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"writable by other users", proc.stderr)

    def test_config_problem_deny_is_logged(self):
        # A broken config fails every call closed (finding F1); the deny should
        # still leave a breadcrumb in the decision log, with no path or host.
        self.write_config('{"reader_gate": {}}', mode=0o620)
        proc = self.run_hook(self.event("Read", {"file_path": str(self.home / "proj" / "a.py")}))
        self.assertEqual(proc.returncode, 2)
        log = self.home / ".local" / "state" / "stranger-danger" / "decisions.jsonl"
        self.assertTrue(log.exists())
        self.assertEqual(stat.S_IMODE(os.stat(log).st_mode), 0o600)
        record = json.loads(log.read_text().splitlines()[-1])
        self.assertEqual((record["decision"], record["code"], record["tool"]),
                         ("deny", "config", "Read"))
        self.assertIsNone(record["agent_type"])
        self.assertNotIn("path", record)
        self.assertNotIn("host", record)

    def test_unknown_config_key_denies(self):
        self.write_config('{"reader_gate": {"quarantine_path": ["~/q"]}}')
        proc = self.run_hook(self.event("Glob", {"pattern": "*"}))
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"unknown reader_gate key", proc.stderr)

    def test_misspelled_config_keys_deny(self):
        (self.home / "inbox").mkdir()
        inbox_read = self.event("Read", {"file_path": str(self.home / "inbox" / "m.eml")})
        cases = {
            '{"reader-gate": {"untrusted_paths": ["~/inbox"]}}': b"unknown top-level key",
            '{"readerGate": {"untrusted_paths": ["~/inbox"]}}': b"unknown top-level key",
            '{"reader_gate": {"untrusted-paths": ["~/inbox"]}}': b"unknown reader_gate key",
            '{"launch_gate": {"alow": []}}': b"unknown launch_gate key",
            '{"reader_gate": {"untrusted_paths": ["~/inbox"]}, "reader_gate": {}}':
                b"more than once",
        }
        for text, needle in cases.items():
            with self.subTest(text=text):
                self.write_config(text)
                proc = self.run_hook(inbox_read)
                self.assertEqual(proc.returncode, 2)
                self.assertIn(needle, proc.stderr)
        self.write_config('{"reader_gate": {"untrusted_paths": ["~/inbox"]}, '
                          '"launch_gate": {"allow": []}}')
        self.assertEqual(self.run_hook(inbox_read).returncode, 2)  # the untrusted folder
        self.assertEqual(self.run_hook(self.event(
            "Read", {"file_path": str(self.home / "proj" / "a.py")})).returncode, 0)

    def test_claude_config_dir_agents_are_checked(self):
        agents = Path(self.tmp.name) / "alt-claude" / "agents"
        agents.mkdir(parents=True)
        (agents / "x.md").write_text("---\nname: stranger-danger:web-researcher\n---\n")
        search = self.event("WebSearch", {"query": "x"}, WEB)
        self.assertEqual(self.run_hook(search).returncode, 0)
        self.env["CLAUDE_CONFIG_DIR"] = str(agents.parent)
        proc = self.run_hook(search)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"reserved prefix", proc.stderr)

    def test_timeout_fails_closed(self):
        code = ("import sys, time; sys.path.insert(0, %r); import reader_gate as g; "
                "g.TIMEOUT_SECONDS = 1; g.decide = lambda e, c, env: time.sleep(10); "
                "sys.exit(g.main())" % str(ROOT / "hooks"))
        proc = subprocess.run([sys.executable, "-c", code],
                              input=self.event("Read", {"file_path": "/x"}).encode(),
                              capture_output=True, env=self.env, timeout=20)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"timed out", proc.stderr)

    def test_internal_error_fails_closed(self):
        code = ("import sys; sys.path.insert(0, %r); import reader_gate as g; "
                "g.decide = lambda e, c, env: 1 / 0; sys.exit(g.main())" % str(ROOT / "hooks"))
        proc = subprocess.run([sys.executable, "-c", code],
                              input=self.event("Read", {"file_path": "/x"}).encode(),
                              capture_output=True, env=self.env, timeout=20)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"internal error", proc.stderr)


class TranscriptTests(GateCase):
    """Claude Code writes every agent's tool results under ~/.claude/projects,
    so a reader's untrusted text is there too: a subagent transcript holds a web
    reader's fetched pages, and a large result is saved as a file. The record
    shape below is the one Claude Code 2.1.280 writes (checked 2026-10-09)."""

    SESSION = "0d5e2c1a-1111-4222-8333-944455556666"

    def setUp(self):
        super().setUp()
        self.proj = self.home / ".claude" / "projects" / "-home-me-proj"
        self.session = self.proj / self.SESSION
        self.results = self.session / "tool-results"
        (self.session / "subagents").mkdir(parents=True)
        self.results.mkdir()
        (self.proj / "memory").mkdir()
        (self.proj / "memory" / "MEMORY.md").write_text("- a note\n")
        self.main_transcript = self.proj / (self.SESSION + ".jsonl")
        self.sub_transcript = self.session / "subagents" / f"agent-{OTHER[1]}.jsonl"
        self.web_transcript = self.session / "subagents" / f"agent-{WEB[1]}.jsonl"
        for t in (self.main_transcript, self.sub_transcript, self.web_transcript):
            t.write_text(json.dumps({"type": "assistant", "message": "start"}) + "\n")
        self.mine = self.saved("bmain0001.txt", self.main_transcript)
        self.subs = self.saved("toolu_01sub.txt", self.sub_transcript)
        self.webs = self.saved("bweb00001.txt", self.web_transcript)

    @staticmethod
    def record(path, **extra) -> str:
        result = {"stdout": "", "stderr": "", "interrupted": False, "isImage": False,
                  "noOutputExpected": False, "persistedOutputPath": path,
                  "persistedOutputSize": 70123}
        result.update(extra)
        return json.dumps({"type": "user", "toolUseResult": result}, separators=(",", ":"))

    def saved(self, name, transcript, line=None) -> str:
        path = str(self.results / name)
        Path(path).write_text("big output\n")
        with open(transcript, "a") as f:
            f.write((line if line is not None else self.record(path)) + "\n")
        return path

    def read(self, path, who="main", transcript=None):
        event = self.event("Read", {"file_path": path}, who)
        event["transcript_path"] = str(transcript or self.main_transcript)
        return rg.decide(event, self.config, self.env)

    def test_transcripts_and_saved_outputs_are_closed(self):
        targets = [str(self.main_transcript), str(self.web_transcript), str(self.sub_transcript),
                   self.webs, str(self.proj), str(self.session), str(self.results),
                   str(self.home / ".claude" / "projects"),
                   str(self.session / "workflows" / "run.json")]
        for path in targets:
            for who in ("main", "other", "doc", "quar"):
                with self.subTest(path=path, who=who):
                    self.assertDenied(self.read(path, who), "rule 3")
        self.assertDenied(self.read(self.webs), "transcript folder", "own saved tool output")

    def test_memory_stays_readable(self):
        self.assertPass(self.read(str(self.proj / "memory" / "MEMORY.md")))
        self.assertPass(self.read("~/.claude/projects/-home-me-proj/memory/MEMORY.md"))

    def test_an_agent_opens_its_own_saved_output(self):
        self.assertPass(self.read(self.mine))
        self.assertPass(self.read(self.subs, "other"))
        self.assertPass(self.read("~/" + os.path.relpath(self.mine, self.home)))

    def test_no_agent_opens_another_agents_saved_output(self):
        self.assertDenied(self.read(self.subs), "own saved tool output")      # main <- subagent
        self.assertDenied(self.read(self.webs), "own saved tool output")      # main <- web reader
        self.assertDenied(self.read(self.mine, "other"), "rule 3")            # subagent <- main
        self.assertDenied(self.read(self.webs, "other"), "rule 3")            # subagent <- reader
        stranger = ("general-purpose", "agent-gp-2")
        self.assertDenied(self.read(self.subs, stranger), "rule 3")           # subagent <- subagent

    def test_only_claude_codes_own_record_counts(self):
        def denied_with(name, line_for):
            path = str(self.results / name)
            Path(path).write_text("x\n")
            with open(self.main_transcript, "a") as f:
                f.write(line_for(path) + "\n")
            return self.read(path)

        forged = {
            "quoted in text": lambda p: json.dumps({"type": "user", "toolUseResult": {
                "stdout": json.dumps({"persistedOutputPath": p, "persistedOutputSize": 1})}}),
            "a file listing": lambda p: json.dumps({"type": "user", "toolUseResult": {
                "stdout": p, "filenames": [p]}}),
            "a longer path": lambda p: self.record(p + ".bak"),
            "the wrong type": lambda p: self.record(p).replace('"type":"user"', '"type":"assistant"'),
            "no size": lambda p: json.dumps({"type": "user", "toolUseResult": {
                "persistedOutputPath": p}}, separators=(",", ":")),
            "a text size": lambda p: self.record(p, persistedOutputSize="70123"),
            "a boolean size": lambda p: self.record(p, persistedOutputSize=True),
            "spaced JSON": lambda p: json.dumps({"type": "user", "toolUseResult": {
                "persistedOutputPath": p, "persistedOutputSize": 1}}),
            "a text result": lambda p: json.dumps({"type": "user", "toolUseResult":
                                                   '"persistedOutputPath":' + json.dumps(p)}),
            "the key elsewhere": lambda p: json.dumps({"type": "user", "persistedOutputPath": p,
                                                       "persistedOutputSize": 1},
                                                      separators=(",", ":")),
            "a broken line": lambda p: self.record(p)[:-1],
        }
        for i, (label, line_for) in enumerate(forged.items()):
            with self.subTest(label):
                self.assertDenied(denied_with(f"bforged{i:02d}.txt", line_for), "rule 3")

    def test_record_forms_claude_code_writes(self):
        listed = str(self.results / "blist0001.txt")
        Path(listed).write_text("x\n")
        line = json.dumps({"type": "user", "toolUseResult": [
            {"type": "text", "text": "first"},
            {"persistedOutputPath": listed, "persistedOutputSize": 9}]}, separators=(",", ":"))
        self.main_transcript.write_text(
            "\n".join([self.record(self.mine)] * 50 + [line]) + "\n")
        self.assertPass(self.read(listed))
        self.assertPass(self.read(self.mine))
        odd = self.saved("bété résultat.txt", self.main_transcript)
        self.assertPass(self.read(odd))                                     # raw UTF-8 record
        escaped = str(self.results / "büber.txt")
        Path(escaped).write_text("x\n")
        with open(self.main_transcript, "a") as f:
            f.write(json.dumps({"type": "user", "toolUseResult": {
                "persistedOutputPath": escaped, "persistedOutputSize": 3}},
                separators=(",", ":"), ensure_ascii=True) + "\n")
        self.assertPass(self.read(escaped))                                 # \u-escaped record

    def test_a_saved_output_must_sit_in_the_tool_results_folder(self):
        link = self.results / "blink0001.txt"
        os.symlink(self.home / "inbox" / "mail.eml", link)
        with open(self.main_transcript, "a") as f:
            f.write(self.record(str(link)) + "\n")
        self.assertDenied(self.read(str(link)), "rule 3")
        nested = self.results / "deeper"
        nested.mkdir()
        deep = str(nested / "b2.txt")
        Path(deep).write_text("x\n")
        with open(self.main_transcript, "a") as f:
            f.write(self.record(deep) + "\n")
        self.assertDenied(self.read(deep), "rule 3")

    def test_the_web_reader_still_reads_no_files(self):
        self.assertDenied(self.read(self.webs, "web"), "rule 3")

    def test_the_record_search_fails_closed(self):
        cases = {
            "no transcript": lambda: self.main_transcript.unlink(),
            "an empty transcript": lambda: self.main_transcript.write_text(""),
            "a linked transcript": lambda: (self.main_transcript.rename(self.proj / "real.jsonl"),
                                            os.symlink(self.proj / "real.jsonl",
                                                       self.main_transcript)),
            "a folder": lambda: (self.main_transcript.unlink(), self.main_transcript.mkdir()),
        }
        for label, breaker in cases.items():
            with self.subTest(label):
                self.tearDown()
                self.setUp()
                breaker()
                self.assertDenied(self.read(self.mine), "rule 3")
        self.tearDown()
        self.setUp()
        old = (rg.MAX_RECORD_LINE, rg.MAX_RECORD_MATCHES)
        try:
            rg.MAX_RECORD_LINE = 64
            self.assertDenied(self.read(self.mine), "rule 3")                # line too long
            rg.MAX_RECORD_LINE = old[0]
            rg.MAX_RECORD_MATCHES = 3
            with open(self.main_transcript, "a") as f:
                f.write((self.record(self.mine).replace('"type":"user"', '"type":"x"') + "\n") * 4)
            self.main_transcript.write_text(
                self.main_transcript.read_text().replace(self.record(self.mine) + "\n", "", 1)
                + self.record(self.mine) + "\n")
            self.assertDenied(self.read(self.mine), "rule 3")                # too many matches
        finally:
            rg.MAX_RECORD_LINE, rg.MAX_RECORD_MATCHES = old

    def test_the_transcript_path_must_be_claude_codes(self):
        elsewhere = self.home / "proj" / (self.SESSION + ".jsonl")
        elsewhere.write_text(self.record(self.mine) + "\n")
        for transcript in (str(elsewhere), "relative.jsonl", str(self.proj / "notes.txt")):
            with self.subTest(transcript=transcript):
                event = self.event("Read", {"file_path": self.mine})
                event["transcript_path"] = transcript
                self.assertDenied(rg.decide(event, self.config, self.env), "rule 3")
        event = self.event("Read", {"file_path": self.mine})
        self.assertDenied(rg.decide(event, self.config, self.env), "rule 3")  # none given
        bad_id = ("general-purpose", "../" + OTHER[1])
        self.assertDenied(self.read(self.subs, bad_id), "rule 3")

    def test_an_event_that_names_the_subagent_transcript(self):
        self.assertPass(self.read(self.subs, "other", transcript=self.sub_transcript))
        self.assertDenied(self.read(self.subs, ("general-purpose", "agent-gp-2"),
                                    transcript=self.sub_transcript), "rule 3")

    def test_grep_never_searches_transcripts(self):
        for path in (str(self.home / ".claude"), str(self.home / ".claude" / "projects"),
                     str(self.proj), str(self.results), self.mine):
            with self.subTest(path=path):
                event = self.event("Grep", {"pattern": "x", "path": path})
                event["transcript_path"] = str(self.main_transcript)
                self.assertDenied(rg.decide(event, self.config, self.env), "rule 3")
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": str(self.proj / "memory")}))
        self.assertPass(self.decide("Grep", {"pattern": "x", "path": str(self.home / ".claude"),
                                             "glob": "agents/**"}))

    def test_glob_lists_no_names_in_transcripts(self):
        # Gap E (2026-10-15): this listing passed before.
        for path in (str(self.results), str(self.proj), str(self.home / ".claude" / "projects")):
            with self.subTest(path=path):
                self.assertDenied(self.decide("Glob", {"pattern": "**/*.txt", "path": path}),
                                  "rule 3", "transcripts")
        self.assertDenied(self.decide("Glob", {"pattern": "**/*.md",
                                               "path": str(self.home / ".claude")}),
                          "this Glob would")
        self.assertDenied(self.decide("Glob", {"pattern": "~/.claude/projects/*/*.jsonl"}),
                          "rule 3")
        # A project's memory folder and the rest of ~/.claude stay listable.
        self.assertPass(self.decide("Glob", {"pattern": "*.md", "path": str(self.proj / "memory")}))
        self.assertPass(self.decide("Glob", {"pattern": "agents/*.md",
                                             "path": str(self.home / ".claude")}))

    def test_claude_config_dir_transcripts_are_closed_too(self):
        other = self.home / "alt-claude"
        (other / "projects" / "p" / "s").mkdir(parents=True)
        (other / "projects" / "p" / "s.jsonl").write_text("{}\n")
        self.env.config_dir = str(other)
        self.assertDenied(self.read(str(other / "projects" / "p" / "s.jsonl")), "rule 3")
        self.assertDenied(self.read(self.webs), "rule 3")


if __name__ == "__main__":
    unittest.main()
