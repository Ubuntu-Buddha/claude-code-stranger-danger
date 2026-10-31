"""The vendored OSV core (skills/osv/core): exactly the scan's files, each as
core/SHA256SUMS lists it, and no apply path. The test pins the list, so
changing the core means updating the list on purpose."""
from __future__ import annotations

import ast
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OSV = ROOT / "skills" / "osv"
FILES = ("core/osv-scan.sh", "core/osvd.py", "core/jq/common.jq", "core/jq/gh-malware.jq",
         "core/jq/osv-batch.jq", "core/jq/osv-sev.jq", "core/jq/runtimes.jq")
NO_FIX_LANE = re.compile(r"fast[-_ ]?lane|auto[-_ ]?fix", re.I)
LINE = re.compile(r"\A([0-9a-f]{64})  (core/[a-z/.-]{1,40})\Z")
# core/SHA256SUMS as vendored: seven lines. A change to the core changes this on purpose.
VENDORED_LIST = "8d3e6ef595b3cd5049ed51a8d7e43c84648e19da742edfb089d76ca2cc543a18"
# osvd.py's shape as vendored: its top-level functions and classes, the
# functions defined inside them, its lambdas, imports and top-level statement
# kinds, and the strings its main() holds (the commands it dispatches, among
# them). A new definition, import or top-level statement fails until it's
# added here on purpose; a new branch inside an existing function doesn't.
SCAN_DEFS = frozenset({
    "Inv", "batches", "blank", "die", "enumerate_all", "expand", "flush_chunk", "ghchunks",
    "is_cve", "is_dockerfile", "is_lockfile", "join", "load_json", "main", "now_iso", "npm_name_from_key",
    "ok_data", "ok_key", "out_of_time", "pages", "parse_cargo_lock",
    "parse_go_sum", "parse_lockfile", "parse_package_lock", "parse_pipfile_lock",
    "parse_poetry_lock", "parse_requirements", "parse_uv_lock", "pep503", "placeholder",
    "prev_result", "read_go_list", "read_hits", "read_list", "read_rt", "read_sev", "read_small",
    "read_tsv", "rt_add", "rt_dockerfile", "rt_file", "rt_installs", "rt_pyvenv",
    "runtime_status", "runtimes", "safe_rel", "safe_write", "scan_cargo_installs",
    "scan_claude_versions", "scan_local_bin", "scan_mcp_config", "scan_node_modules",
    "scan_repo", "scan_site_packages", "sevq", "sizes", "src_sorted", "start", "tag", "today",
    "toml_packages", "vkey", "write_batches"})
NESTED_DEFS = frozenset({"__init__", "add", "count", "ent", "once", "root", "walk"})
LAMBDAS = 8
IMPORTS = frozenset({"datetime", "glob", "json", "os", "re", "stat", "sys", "tempfile", "time",
                     "urllib.parse"})
TOP_KINDS = {"Assign": 47, "ClassDef": 1, "FunctionDef": 62, "If": 1, "Import": 1}
MAIN_STRINGS = frozenset({"enumerate", "batches", "pages", "ghchunks", "sevq", "start",
                          "placeholder", "join", "usage", "ver", "any", "osvd: %s failed"})


class VendorTests(unittest.TestCase):
    def sums(self) -> dict:
        out = {}
        for line in (OSV / "core" / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            m = LINE.match(line)
            self.assertIsNotNone(m, line)
            self.assertNotIn(m.group(2), out)
            out[m.group(2)] = m.group(1)
        return out

    def test_the_list_is_the_vendored_one(self):
        self.assertEqual(hashlib.sha256((OSV / "core" / "SHA256SUMS").read_bytes()).hexdigest(),
                         VENDORED_LIST)

    def test_the_list_names_exactly_the_scan_files(self):
        self.assertEqual(sorted(self.sums()), sorted(FILES))

    def test_each_file_matches_the_list(self):
        for rel, want in self.sums().items():
            with self.subTest(rel=rel):
                self.assertEqual(hashlib.sha256((OSV / rel).read_bytes()).hexdigest(), want)

    def test_nothing_else_is_vendored(self):
        found = sorted(str(p.relative_to(OSV)).replace(os.sep, "/")
                       for p in (OSV / "core").rglob("*")
                       if p.is_file() and "__pycache__" not in p.parts and p.name != "SHA256SUMS")
        self.assertEqual(found, sorted(FILES))

    def test_a_settings_json_key_is_refused_before_any_work(self):
        with tempfile.TemporaryDirectory() as d:
            conf, out = Path(d, "c.json"), Path(d, "inv.json")
            conf.write_text('{"repos": {}, "settings_json": "x"}', encoding="ascii")
            r = subprocess.run([sys.executable, "-I", str(OSV / "core" / "osvd.py"),
                                "enumerate", str(conf), str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 3)
            self.assertEqual(r.stderr, "osvd: config: settings_json is not supported\n")
            self.assertFalse(out.exists())

    def test_the_scan_core_has_no_apply_path(self):
        """The core only scans: no auto-fix file or apply word, and nothing
        beyond the scan's own commands, definitions and imports."""
        for path in [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]:
            self.assertIsNone(NO_FIX_LANE.search(path.name), str(path))
        for rel in FILES:
            text = (OSV / rel).read_text(encoding="utf-8")
            with self.subTest(rel=rel):
                self.assertIsNone(re.search(r"fast[-_ ]?lane|auto[-_ ]?fix|\bapply\b", text, re.I))
        # osvd.py's commands: the scan's only.
        helper = (OSV / "core" / "osvd.py").read_text(encoding="utf-8")
        table = re.search(r"cmds = \{(.*?)\}\n", helper, re.S)
        self.assertEqual(set(re.findall(r'"([a-z-]+)": \(', table.group(1))),
                         {"enumerate", "batches", "pages", "ghchunks", "sevq", "start",
                          "placeholder", "join"})
        tree = ast.parse(helper)
        defs = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        top = {n.name for n in tree.body if isinstance(n, defs)}
        self.assertEqual(top, SCAN_DEFS)
        nested = sorted(n.name for n in ast.walk(tree) if isinstance(n, defs) and n.name not in top)
        self.assertEqual(nested, sorted(NESTED_DEFS))  # a second def of the same name fails too
        self.assertEqual(sum(isinstance(n, ast.Lambda) for n in ast.walk(tree)), LAMBDAS)
        self.assertEqual({a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names},
                         IMPORTS)
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)])
        kinds: dict = {}
        for n in tree.body:
            kinds[type(n).__name__] = kinds.get(type(n).__name__, 0) + 1
        self.assertEqual(kinds, TOP_KINDS)
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        self.assertEqual({c.value for c in ast.walk(main)
                          if isinstance(c, ast.Constant) and isinstance(c.value, str)},
                         MAIN_STRINGS)

    def test_only_the_scan_script_reaches_the_network(self):
        """Every URL osv-scan.sh holds is on one of the runner's hosts, or
        Node's schedule, which the sandbox refuses for plugin users; osvd.py
        imports no network module (its https strings are lockfile sources it
        compares, not requests)."""
        import sys
        sys.path.insert(0, str(OSV))
        import osv
        script = (OSV / "core" / "osv-scan.sh").read_text(encoding="utf-8")
        hosts = set(re.findall(r"https://([A-Za-z0-9.-]+)", script))
        self.assertLessEqual(hosts, set(osv.HOSTS) | {"raw.githubusercontent.com"})
        helper = (OSV / "core" / "osvd.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\b(socket|http\.client|urllib\.request|ssl|requests)\b", helper))
        self.assertEqual(re.findall(r"https://api\.[a-z.]+", helper), ["https://api.github.com"])


if __name__ == "__main__":
    unittest.main()
