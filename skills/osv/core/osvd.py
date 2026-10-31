#!/usr/bin/python3 -I
# OSV scan helper. Standard library only; run with python3 -I.
#
#   enumerate CONF OUT        list what is installed or locked -> inventory JSON
#   batches INV DIR VER ANY   write OSV querybatch bodies (by version, any version)
#   pages INV DIR MODE ROUND  write follow-up bodies for queries OSV paged
#   ghchunks INV DIR          GitHub malware URLs (affects= our names), by ecosystem
#   sevq INV DIR OUTDIR MAX  /v1/query bodies (our name and version) for packages with a new hit
#   start OUTDIR              keep the last daily.json as daily.prev.json; write an ERROR placeholder
#   placeholder OUTDIR        write the ERROR placeholder (a run that failed)
#   join INV DIR OUTDIR       join the extracted ids to packages -> daily.json
#
# Portable: Python 3.9+ standard library, Linux and macOS. No host path is
# built in; everything comes from the config or the arguments. This file
# holds only the scan.
#
# Text from the network never reaches this script: osv-scan.sh reduces every
# response to validated TSV with jq first, and this script validates it again.
# Names and versions printed here come from your own lockfiles and
# install folders, after the per-ecosystem grammar checks below.
import json, os, re, stat, sys, datetime, tempfile, time, urllib.parse

ECOS = ("npm", "PyPI", "crates.io", "Go")
GH_ECO = {"npm": "npm", "PyPI": "pip", "crates.io": "rust", "Go": "go"}
NAME_RE = {
    # npm's rules: no leading "." or "_"; we also refuse a leading "-" or "~";
    # at most 214 characters in all, scope included
    "npm": re.compile(r"^(?=.{1,214}\Z)(@[A-Za-z0-9][A-Za-z0-9._~-]{0,213}/)?[A-Za-z0-9][A-Za-z0-9._~-]{0,213}\Z"),
    "PyPI": re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,198}[A-Za-z0-9])?\Z"),
    "crates.io": re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}\Z"),
    # a module path: at most 300 characters and 21 segments
    "Go": re.compile(r"^(?=.{1,300}\Z)[A-Za-z0-9][A-Za-z0-9._~+-]*\.[A-Za-z0-9._~+-]+(/[A-Za-z0-9._~+-]+){0,20}\Z"),
}
VER_RE = {
    "npm": re.compile(r"^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z.+-]{1,80})?\Z"),
    "PyPI": re.compile(r"^([0-9]{1,4}!)?[0-9]{1,9}(\.[0-9]{1,9}){0,6}([abc]|rc|a|b|\.post|\.dev|post|dev)?[0-9]{0,9}(\.post[0-9]{1,9}|\.dev[0-9]{1,9})?(\+[0-9A-Za-z.]{1,40})?\Z"),
    "crates.io": re.compile(r"^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z.+-]{1,80})?\Z"),
    "Go": re.compile(r"^v[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z.+-]{1,120})?\Z"),
}
# Advisory ids printed anywhere: these shapes only; any other id is "other".
ID_RE = re.compile(r"\A(MAL-[0-9]{4}-[0-9]{1,8}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|CVE-[0-9]{4}-[0-9]{4,8}"
                   r"|PYSEC-[0-9]{4}-[0-9]{1,8}|RUSTSEC-[0-9]{4}-[0-9]{4}|GO-[0-9]{4}-[0-9]{4,8})\Z")
DATE_RE = re.compile(r"\A([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z|-)\Z")
STATUS_RE = re.compile(r"\A(osv_ver|osv_any|osv_sev|gh_npm|gh_pip|gh_rust|gh_go|rt_node|rt_node_eol|rt_python|rt_python_eol)"
                       r"=(ok|partial|unreachable|malformed|truncated|paged|skipped|capped)\Z")
# Severity: these five words only (jq maps a record's word to one of them;
# anything else is "unknown"). Worst first.
SEVS = ("critical", "high", "medium", "low", "unknown")
SEV_RANK = {s: len(SEVS) - i for i, s in enumerate(SEVS)}
MAX_ALIASES = 20
# Paths written to daily.json: no spaces, short segments (a folder name can't
# carry a sentence). Anything else is written as a fixed placeholder.
SAFE_PATH = re.compile(r"^[A-Za-z0-9/._+@~-]{1,160}\Z")
GH_URL_MAX = 6000      # characters of names per GitHub affects= query
GH_NAMES_MAX = 500     # names per query (GitHub documents up to 1000 for affects=)
GH_CALLS_MAX = 55      # calls a run, under GitHub's 60 an hour unauthenticated
MAX_FILES = 200000
MAX_LOCK_BYTES = 64 << 20
PRUNE = {"node_modules", "target", ".git", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", "dist", "build", ".next"}
LOCK_KINDS = {"package-lock.json", "npm-shrinkwrap.json", "Cargo.lock", "uv.lock", "poetry.lock", "Pipfile.lock", "go.sum"}
UNSUPPORTED = {"pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "Gemfile.lock", "composer.lock"}
HOME = os.path.expanduser("~")
DEADLINE = [None]      # enumeration stops walking past this (time.monotonic())
WORKTREES_MAX = 256       # worktrees scanned per repo; more is a major gap
DEEP_DIRS_MAX = 100000    # folders walked by name past the read depth, per scan root
# Coverage counters that mean something wasn't looked at, listed every run;
# see MAJOR_GAPS for which ones are an ERROR when they rise.
GAP_KEYS = ("repos_missing", "lockfiles_unreadable", "lockfiles_unsupported", "tree_file_cap_hit",
            "repo_lockfile_cap_hit", "repo_depth_cap_hit", "lists_unreadable", "cargo_installs_unreadable",
            "own_repos_line_unreadable", "skipped_invalid", "invalid_version", "package_json_unreadable",
            "mcp_configs_unreadable", "own_repos_line_unparsed", "runtime_pins_unparsed",
            "lockfiles_beyond_depth", "runtime_pins_beyond_depth", "repo_walk_cap_hit",
            "worktrees_unscanned", "repo_dirs_unreadable", "links_not_followed")
# Gaps that mean part of the inventory wasn't looked at: INFO on every run
# while above 0, and an ERROR (notified) when one rises over a readable
# previous run. The others are INFO only when they rise. repo_depth_cap_hit
# counts folders, not files, so it's minor: the walk goes on below the read
# depth and counts the lockfiles and runtime pins it doesn't read.
MAJOR_GAPS = ("repos_missing", "lockfiles_unreadable", "tree_file_cap_hit", "repo_lockfile_cap_hit",
              "lockfiles_beyond_depth", "runtime_pins_beyond_depth", "repo_walk_cap_hit",
              "worktrees_unscanned", "repo_dirs_unreadable", "lists_unreadable", "cargo_installs_unreadable",
              "own_repos_line_unreadable", "package_json_unreadable", "mcp_configs_unreadable")


def load_json(txt):
    """Parsed JSON, or None. A hostile file (deep nesting, huge) counts as
    unreadable; it never stops the run."""
    try:
        return json.loads(txt)
    except (ValueError, RecursionError, MemoryError):
        return None


def out_of_time(inv):
    if DEADLINE[0] is not None and time.monotonic() > DEADLINE[0]:
        inv.count("enumerate_time_cap_hit")
        return True
    return False


def die(msg):
    print("osvd: " + msg, file=sys.stderr)
    sys.exit(3)


def pep503(n):
    return re.sub(r"[-_.]+", "-", n).lower()


class Inv:
    def __init__(self):
        self.pk = {}          # (eco, name, version) -> set of source tags
        self.names_only = set()   # (eco, name) held at a version outside the grammar
        self.cov = {}
        self.rt = {}          # (runtime, version or line, exact|line) -> set of source tags

    def count(self, key, n=1):
        self.cov[key] = self.cov.get(key, 0) + n

    def add(self, eco, name, ver, src):
        if eco == "PyPI":
            name = pep503(name)
        if not (isinstance(name, str) and NAME_RE[eco].match(name)):
            self.count("skipped_invalid")
            return
        if not (isinstance(ver, str) and VER_RE[eco].match(ver)):
            # still asked about at any version, by name
            self.count("invalid_version")
            self.names_only.add((eco, name))
            return
        self.pk.setdefault((eco, name, ver), set()).add(src)


def read_small(path, cap=MAX_LOCK_BYTES, nbytes=None):
    """A regular file's text, or None. Never follows a link and never blocks
    on a FIFO or device named like a lockfile."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        with os.fdopen(fd, "rb") as f:
            fd = None
            data = f.read(nbytes if nbytes is not None else cap + 1)
        return data if nbytes is not None else data.decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)


REPO_TAGS = []   # (folder, the config's name for it): the config's own words
REPO_KEY = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 ._-]{0,60}\Z")


def safe_rel(p):
    ok = SAFE_PATH.match(p) and all(len(seg) <= 40 for seg in p.split("/"))
    return p if ok else "(path with other characters)"


def tag(path):
    """A path for daily.json. Inside a configured repo: 'repo:<config name>/<path in
    the repo>' (the name is the config's, the rest must be plain); elsewhere the
    path itself, if plain."""
    for root, key in REPO_TAGS:
        if path.startswith(root + "/"):
            return "repo:%s/%s" % (key if REPO_KEY.match(key) else "(other name)", safe_rel(path[len(root) + 1:]))
    return safe_rel(path.replace(HOME, "~", 1) if path.startswith(HOME + "/") else path)


# ---- lockfile parsers --------------------------------------------------------

def npm_name_from_key(key):
    i = key.rfind("node_modules/")
    return key[i + len("node_modules/"):] if i >= 0 else None


def parse_package_lock(inv, path, txt):
    d = load_json(txt)
    if not isinstance(d, dict):
        inv.count("lockfiles_unreadable")
        return
    src = tag(path)
    pk = d.get("packages")
    if isinstance(pk, dict):
        for key, e in pk.items():
            if not key or not isinstance(e, dict) or e.get("link"):
                continue
            name = e.get("name") if isinstance(e.get("name"), str) else npm_name_from_key(key)
            ver = e.get("version")
            res = e.get("resolved")
            if isinstance(res, str) and not res.startswith("https://registry.npmjs.org/"):
                inv.count("nonregistry_entries")
                continue
            if name is None or ver is None:
                inv.count("entries_without_version")
                continue
            inv.add("npm", name, ver, src)
        return
    def walk(deps, depth):
        if not isinstance(deps, dict) or depth > 64:
            return
        for name, e in deps.items():
            if not isinstance(e, dict):
                continue
            ver = e.get("version")
            if isinstance(ver, str) and ver.startswith("npm:"):
                alias = ver[4:]
                at = alias.rfind("@")
                name, ver = (alias[:at], alias[at + 1:]) if at > 0 else (name, None)
            res = e.get("resolved")
            if isinstance(res, str) and not res.startswith("https://registry.npmjs.org/"):
                inv.count("nonregistry_entries")
            else:
                inv.add("npm", name, ver, src)
            walk(e.get("dependencies"), depth + 1)
    walk(d.get("dependencies"), 0)


TOML_KV = re.compile(r'^([A-Za-z0-9_-]+)\s*=\s*(.*)$')


def toml_packages(txt):
    """[[package]] blocks of Cargo.lock / uv.lock / poetry.lock: name, version, source line."""
    out, cur, sub = [], None, False
    for line in txt.splitlines():
        s = line.strip()
        if s == "[[package]]":
            cur, sub = {}, False
            out.append(cur)
            continue
        if s.startswith("["):
            sub = True
            if cur is not None and s.startswith("[package.source]"):
                cur["_has_source_table"] = True
            continue
        if cur is None or sub:
            continue
        m = TOML_KV.match(s)
        if m:
            k, v = m.group(1), m.group(2).strip()
            if v.startswith('"') and v.endswith('"') and len(v) >= 2:
                v = v[1:-1]
            cur.setdefault(k, v)
    return out


def parse_cargo_lock(inv, path, txt):
    src = tag(path)
    for p in toml_packages(txt):
        s = p.get("source", "")
        if s in ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"):
            inv.add("crates.io", p.get("name"), p.get("version"), src)
        elif s:
            inv.count("nonregistry_entries")


def parse_uv_lock(inv, path, txt):
    src = tag(path)
    for p in toml_packages(txt):
        s = p.get("source", "")
        if re.match(r'^\{\s*registry\s*=\s*"https://pypi\.org/simple/?"\s*\}$', s):
            inv.add("PyPI", p.get("name"), p.get("version"), src)
        elif s:
            inv.count("nonregistry_entries")


def parse_poetry_lock(inv, path, txt):
    src = tag(path)
    for p in toml_packages(txt):
        if p.get("_has_source_table"):
            inv.count("nonregistry_entries")
            continue
        inv.add("PyPI", p.get("name"), p.get("version"), src)


REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9,._ -]*\])?\s*==\s*([^\s;#\\]+)\s*(;[^#]*)?(#.*)?\Z")


def parse_requirements(inv, path, txt):
    src = tag(path)
    for raw in txt.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-"):
            inv.count("requirements_options")
            continue
        m = REQ_LINE.match(s)
        if m:
            inv.add("PyPI", m.group(1), m.group(3), src)
        else:
            inv.count("requirements_unpinned")


def parse_pipfile_lock(inv, path, txt):
    d = load_json(txt)
    if not isinstance(d, dict):
        inv.count("lockfiles_unreadable")
        return
    src = tag(path)
    for sect in ("default", "develop"):
        s = d.get(sect) if isinstance(d, dict) else None
        if not isinstance(s, dict):
            continue
        for name, e in s.items():
            v = e.get("version") if isinstance(e, dict) else None
            if isinstance(v, str) and v.startswith("=="):
                inv.add("PyPI", name, v[2:], src)
            else:
                inv.count("nonregistry_entries")


def parse_go_sum(inv, path, txt):
    src = tag(path)
    for line in txt.splitlines():
        f = line.split()
        if len(f) == 3 and not f[1].endswith("/go.mod"):
            inv.add("Go", f[0], f[1], src)


def parse_lockfile(inv, path):
    base = os.path.basename(path)
    if base.startswith("requirements") and base.endswith(".txt"):
        kind = "requirements.txt"
    else:
        kind = base
    txt = read_small(path)
    if txt is None:
        inv.count("lockfiles_unreadable")
        return
    inv.count("lockfiles:" + kind)
    {"package-lock.json": parse_package_lock, "npm-shrinkwrap.json": parse_package_lock,
     "Cargo.lock": parse_cargo_lock, "uv.lock": parse_uv_lock, "poetry.lock": parse_poetry_lock,
     "Pipfile.lock": parse_pipfile_lock, "go.sum": parse_go_sum,
     "requirements.txt": parse_requirements}[kind](inv, path, txt)


def is_lockfile(base):
    return base in LOCK_KINDS or (base.startswith("requirements") and base.endswith(".txt"))


# ---- runtimes (Node.js, CPython) ---------------------------------------------
# A held runtime: an exact version ("22.22.0", "3.12.13") or only a line ("20",
# "3.12", from a floating pin such as a Dockerfile tag). Checked against the
# runtimes' own release data, never OSV.
RT_VER = {"node": re.compile(r"\Av?([1-9][0-9]{0,2})(\.[0-9]{1,4}){0,2}\Z"),
          "python": re.compile(r"\A3\.[0-9]{1,2}(\.[0-9]{1,3})?\Z")}
DOCKER_FROM = re.compile(r"\A\s*FROM\s+(--platform=\S+\s+)?(docker\.io/)?(library/)?(node|python):([A-Za-z0-9._-]{1,64})"
                         r"(@sha256:[0-9a-f]{64})?(\s+AS\s+\S+)?\s*\Z", re.IGNORECASE)
PYVENV_VER = re.compile(r"\A\s*version(_info)?\s*=\s*(3\.[0-9]{1,2}\.[0-9]{1,3})(\.[a-z]+\.[0-9]+)?\s*\Z")
RT_PIN_FILES = {".nvmrc": "node", ".node-version": "node", ".python-version": "python"}


def rt_add(inv, rt, v, src):
    """Record a runtime pin; anything off-shape is counted, never kept."""
    v = v.strip() if isinstance(v, str) else ""
    if rt == "node":
        v = v[1:] if v.startswith("v") else v
    if not RT_VER[rt].match(v):
        inv.count("runtime_pins_unparsed")
        return
    parts = v.split(".")
    exact = len(parts) == 3
    line = parts[0] if rt == "node" else ".".join(parts[:2])
    inv.rt.setdefault((rt, v if exact else line, "exact" if exact else "line"), set()).add(src)


def rt_file(inv, rt, path):
    txt = read_small(path, 4096)
    if txt is None:
        inv.count("runtime_pins_unparsed")
        return
    first = (txt.splitlines() or [""])[0]
    rt_add(inv, rt, first, tag(path))


def rt_dockerfile(inv, path):
    txt = read_small(path, 1 << 20)
    if txt is None:
        return
    for line in txt.splitlines():
        if not re.match(r"\A\s*FROM\s", line, re.IGNORECASE):
            continue
        m = DOCKER_FROM.match(line)
        if not m:
            continue   # another image: not a runtime this check knows
        num = re.match(r"\A([0-9]+(\.[0-9]+){0,2})(-[A-Za-z0-9._-]+)?\Z", m.group(5))
        if num:
            rt_add(inv, m.group(4).lower(), num.group(1), tag(path))
        else:
            inv.count("runtime_pins_unparsed")   # lts, latest, current-...


def rt_pyvenv(inv, path):
    txt = read_small(path, 64 << 10)
    if txt is None:
        return
    for line in txt.splitlines():
        m = PYVENV_VER.match(line)
        if m:
            rt_add(inv, "python", m.group(2), tag(path))
            return
    inv.count("runtime_pins_unparsed")


def rt_installs(inv, conf):
    """nvm's and uv's install folders (folder names only), and a NodeSource
    nodejs from dpkg's status file. Ubuntu's own packages are distro-patched
    and not compared with upstream (a known gap until the distro check)."""
    r = conf.get("runtimes") if isinstance(conf.get("runtimes"), dict) else {}
    for d in r.get("node_install_dirs", []):
        try:
            names = os.listdir(expand(d))
        except OSError:
            continue
        for n in names:
            if re.match(r"\Av[0-9]{1,3}\.[0-9]{1,4}\.[0-9]{1,4}\Z", n):
                rt_add(inv, "node", n, "global:nvm")
    for d in r.get("python_install_dirs", []):
        try:
            names = os.listdir(expand(d))
        except OSError:
            continue
        for n in names:
            m = re.match(r"\Acpython-(3\.[0-9]{1,2}\.[0-9]{1,3})([+-])", n)
            if m:
                rt_add(inv, "python", m.group(1), "global:uv-python")
    if r.get("dpkg_status"):
        txt = read_small(expand(r["dpkg_status"]), 64 << 20)
        if txt is None:
            inv.count("lists_unreadable")
            return
        for block in txt.split("\n\n"):
            f = dict(re.findall(r"^(Package|Version|Status): ([^\n]*)$", block, re.MULTILINE))
            if f.get("Package") == "nodejs" and f.get("Status", "").endswith(" installed"):
                m = re.match(r"\A([0-9]{1,3}\.[0-9]{1,4}\.[0-9]{1,4})-[0-9]+nodesource[0-9]*\Z", f.get("Version", ""))
                if m:
                    rt_add(inv, "node", m.group(1), "global:dpkg-nodesource")


def is_dockerfile(fn):
    return fn == "Dockerfile" or fn.startswith("Dockerfile.") or fn.endswith(".Dockerfile")


def src_sorted(s):
    """Where a package was found, a repo's own paths before its worktrees'
    (found_in shows the first five)."""
    return sorted(s, key=lambda x: ("/.claude/worktrees/" in x, x))


def scan_repo(inv, root, max_depth=6, walk_depth=32, seen=None, worktree=False):
    """Lockfiles, runtime pins and virtualenvs down to max_depth levels below
    root are read. Below that the walk goes on, by name only, to walk_depth
    and at most DEEP_DIRS_MAX folders, and counts what it doesn't read:
    lockfiles_beyond_depth and runtime_pins_beyond_depth (major gaps), and
    repo_walk_cap_hit (major) when that walk stops early. Each folder in
    <root>/.claude/worktrees (git worktrees: the repo on other branches) is
    scanned the same way from its own top, WORKTREES_MAX at most; a link
    there, or a folder past the cap, is worktrees_unscanned (major). Counts
    below the read depth are kept once per path relative to the scan root,
    so a worktree doesn't count the repo's own again."""
    root = root.rstrip("/") or "/"
    seen = set() if seen is None else seen
    found = deep = 0
    wts = []

    def once(key, rel):
        if (key, rel) not in seen:
            seen.add((key, rel))
            inv.count(key)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False,
                                                onerror=lambda e: inv.count("repo_dirs_unreadable")):
        if out_of_time(inv):  # the walk's own stop
            return
        rel = dirpath[len(root):]
        depth = rel.count("/")
        keep = [d for d in dirnames if d not in PRUNE]
        if not worktree and dirpath == os.path.join(root, ".claude", "worktrees"):
            for d in dirnames:
                if os.path.islink(os.path.join(dirpath, d)):
                    inv.count("worktrees_unscanned")
                else:
                    wts.append(os.path.join(dirpath, d))
            keep = []
        if not worktree and dirpath in (root, os.path.join(root, ".claude")):
            # .claude or .claude/worktrees as a link: its worktrees aren't scanned
            nxt = ".claude" if dirpath == root else "worktrees"
            if nxt in dirnames and os.path.islink(os.path.join(dirpath, nxt)):
                inv.count("worktrees_unscanned")
        for d in keep:
            if os.path.islink(os.path.join(dirpath, d)):
                once("links_not_followed", rel + "/" + d)
        if keep and depth == max_depth:
            once("repo_depth_cap_hit", rel)
        if keep and depth >= walk_depth:
            once("repo_walk_cap_hit", rel)
        capped = False
        if depth > max_depth:
            deep += 1
            if deep > DEEP_DIRS_MAX:
                # no folder below is listed, but this one's files are counted
                once("repo_walk_cap_hit", "\0folders")
                capped = True
        # a virtualenv is pruned, but its interpreter version is a held runtime
        # (looked for in dirnames before they're pruned)
        for d in dirnames:
            if d in (".venv", "venv") and not os.path.islink(os.path.join(dirpath, d)):
                p = os.path.join(dirpath, d, "pyvenv.cfg")
                if os.path.isfile(p) and not os.path.islink(p):
                    if depth <= max_depth:
                        rt_pyvenv(inv, p)
                    else:
                        once("runtime_pins_beyond_depth", rel + "/" + d)
        dirnames[:] = keep if depth < walk_depth and not capped else []
        if depth > max_depth:
            for fn in filenames:
                if os.path.islink(os.path.join(dirpath, fn)):
                    if is_lockfile(fn):
                        once("links_not_followed", rel + "/" + fn)
                    continue
                if is_lockfile(fn):
                    once("lockfiles_beyond_depth", rel + "/" + fn)
                elif fn in UNSUPPORTED:
                    once("lockfiles_unsupported", rel + "/" + fn)
                elif fn in RT_PIN_FILES or is_dockerfile(fn):
                    once("runtime_pins_beyond_depth", rel + "/" + fn)
            continue      # nothing past the read depth is read
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if is_lockfile(fn) and not os.path.islink(p):
                parse_lockfile(inv, p)
                found += 1
            elif is_lockfile(fn):
                once("links_not_followed", rel + "/" + fn)
            elif fn in UNSUPPORTED:
                inv.count("lockfiles_unsupported")
            elif fn in RT_PIN_FILES and not os.path.islink(p):
                rt_file(inv, RT_PIN_FILES[fn], p)
            elif is_dockerfile(fn) and not os.path.islink(p):
                rt_dockerfile(inv, p)
        if found > 5000:
            inv.count("repo_lockfile_cap_hit")
            break
    wts.sort()
    for wt in wts[:WORKTREES_MAX]:
        inv.count("worktrees_scanned")
        scan_repo(inv, wt, max_depth, walk_depth, seen, worktree=True)
    if len(wts) > WORKTREES_MAX:
        inv.count("worktrees_unscanned", len(wts) - WORKTREES_MAX)


# ---- installed trees ---------------------------------------------------------

def scan_node_modules(inv, root, src):
    """Every <..>/node_modules/<pkg>/package.json (and scoped) under root."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if out_of_time(inv):
            return
        n += len(filenames) + len(dirnames)
        if n > MAX_FILES:
            inv.count("tree_file_cap_hit")
            return
        dirnames[:] = [d for d in dirnames if d not in (".git", ".bin", ".cache")]
        if "package.json" not in filenames:
            continue
        parent = os.path.dirname(dirpath)
        if os.path.basename(parent) != "node_modules" and not (
                os.path.basename(parent).startswith("@") and os.path.basename(os.path.dirname(parent)) == "node_modules"):
            continue
        txt = read_small(os.path.join(dirpath, "package.json"), 4 << 20)
        d = load_json(txt) if txt is not None else None
        if isinstance(d, dict):
            inv.add("npm", d.get("name"), d.get("version"), src)
        else:
            inv.count("package_json_unreadable")


DISTINFO = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.]*)-([0-9][0-9A-Za-z.+!_]*)\.dist-info\Z")


def scan_site_packages(inv, pattern_root, src):
    import glob
    for sp in glob.glob(pattern_root):
        try:
            entries = os.listdir(sp)
        except OSError:
            continue
        for e in entries:
            m = DISTINFO.match(e)
            if m:
                inv.add("PyPI", m.group(1), m.group(2), src)


def scan_cargo_installs(inv, path):
    txt = read_small(path, 4 << 20)
    d = load_json(txt) if txt else None
    if not isinstance(d, dict) or not isinstance(d.get("installs"), dict):
        inv.count("cargo_installs_unreadable")
        return
    for k in d["installs"]:
        m = re.match(r"^([A-Za-z][A-Za-z0-9_-]{0,63}) ([0-9][0-9A-Za-z.+-]{0,80}) \((registry\+https://github\.com/rust-lang/crates\.io-index|sparse\+https://index\.crates\.io/)\)\Z", k)
        if m:
            inv.add("crates.io", m.group(1), m.group(2), "global:cargo")
        else:
            inv.count("cargo_installs_other_source")


def scan_claude_versions(inv, d):
    try:
        names = os.listdir(d)
    except OSError:
        return
    for v in names:
        inv.add("npm", "@anthropic-ai/claude-code", v, "global:claude-native")


BINNAME = re.compile(r"^[A-Za-z0-9._+-]{1,64}\Z")


def scan_local_bin(inv, d, managed_roots):
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return []
    unidentified = []
    for b in names:
        p = os.path.join(d, b)
        if os.path.islink(p):
            t = os.path.realpath(p)
            if any(t.startswith(os.path.realpath(r).rstrip("/") + "/") for r in managed_roots):
                inv.count("local_bin_managed")
                continue
        head = read_small(p, 1 << 40, 2)
        if head is None:
            inv.count("local_bin_other")
            continue
        if head == b"#!":
            inv.count("local_bin_scripts")
        else:
            inv.count("local_bin_unidentified")
            unidentified.append(b if BINNAME.match(b) else "(name with other characters)")
    return unidentified[:100]


NPM_PIN = re.compile(r"^((@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9._~-][a-z0-9._~-]*)@([0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z.-]{1,40})?)\Z")
PY_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][0-9A-Za-z.+!]{0,40})\Z")


def scan_mcp_config(inv, path):
    """Exact package pins in MCP server commands; env and other fields are never read."""
    txt = read_small(path, 4 << 20)
    if txt is None:
        return
    d = load_json(txt)
    if d is None:
        inv.count("mcp_configs_unreadable")
        return
    servers = []
    if isinstance(d, dict):
        for key in ("mcpServers", "mcp"):
            s = d.get(key)
            if isinstance(s, dict):
                servers.extend(v for v in s.values() if isinstance(v, dict))
    for s in servers:
        inv.count("mcp_servers_seen")
        toks = []
        if isinstance(s.get("command"), str):
            toks.append(s["command"])
        for k in ("args", "command"):
            if isinstance(s.get(k), list):
                toks.extend(t for t in s[k] if isinstance(t, str))
        pinned = False
        for t in toks:
            m = NPM_PIN.match(t)
            if m:
                inv.add("npm", m.group(1), m.group(3), "mcp:" + tag(path))
                pinned = True
            m = PY_PIN.match(t)
            if m:
                inv.add("PyPI", m.group(1), m.group(2), "mcp:" + tag(path))
                pinned = True
        inv.count("mcp_pinned" if pinned else "mcp_unpinned_or_local")


def read_list(inv, path, src):
    txt = read_small(path, 16 << 20)
    if txt is None:
        inv.count("lists_unreadable")
        return
    for line in txt.splitlines():
        f = line.split()
        if not f or f[0].startswith("#"):
            continue
        if len(f) >= 3 and f[0] in ECOS:
            inv.add(f[0], f[1], f[2], src)
        else:
            inv.count("list_lines_invalid")


def read_go_list(inv, path, src):
    txt = read_small(path, 16 << 20)
    if txt is None:
        inv.count("lists_unreadable")
        return
    for line in txt.splitlines():
        f = line.split()
        if len(f) == 2:
            inv.add("Go", f[0], f[1], src)
        elif f:
            inv.count("list_lines_invalid")


def expand(p):
    return os.path.expanduser(p)


def enumerate_all(conf_path, out_path):
    with open(conf_path) as f:
        conf = json.load(f)
    if "settings_json" in conf:
        die("config: settings_json is not supported")
    inv = Inv()
    secs = conf.get("enumerate_max_seconds", 900)
    DEADLINE[0] = time.monotonic() + (secs if isinstance(secs, int) and secs > 0 else 900)
    # repos: {a name for the repo: its local folder}
    repomap = conf.get("repos", {})
    if not isinstance(repomap, dict):
        die("config: repos must map names to folders")
    repos = [expand(r) for r in repomap.values()]
    REPO_TAGS[:] = sorted(((expand(r).rstrip("/"), k) for k, r in repomap.items() if isinstance(r, str)),
                          key=lambda x: -len(x[0]))
    for r in repos:
        if os.path.isdir(r) and not os.path.islink(r.rstrip("/")):
            inv.count("repos_scanned")
            scan_repo(inv, r)
        else:
            inv.count("repos_missing")
    for p in conf.get("extra_lockfiles", []):
        p = expand(p)
        if os.path.isfile(p):
            parse_lockfile(inv, p)
    for p in conf.get("vetted_lists", []):
        read_list(inv, expand(p), "vetted")
    for p in conf.get("go_module_lists", []):
        read_go_list(inv, expand(p), "vetted:go-modules")
    import glob
    for pat in conf.get("npm_global_roots", []):
        for root in glob.glob(expand(pat)):
            inv.count("npm_roots_scanned")
            scan_node_modules(inv, root, "global:npm")
    for pat in conf.get("python_site_roots", []):
        scan_site_packages(inv, expand(pat), "global:python")
    if conf.get("cargo_installs"):
        scan_cargo_installs(inv, expand(conf["cargo_installs"]))
    if conf.get("claude_versions_dir"):
        scan_claude_versions(inv, expand(conf["claude_versions_dir"]))
    for key, label in (("npx_cache_roots", "npx-cache"), ("plugin_roots", "plugins"),
                       ("opencode_roots", "opencode"), ("extension_roots", "extensions")):
        for pat in conf.get(key, []):
            for root in glob.glob(expand(pat)):
                inv.count(label + "_roots_scanned")
                scan_node_modules(inv, root, label)
                for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                    if out_of_time(inv):
                        break
                    dirnames[:] = [d for d in dirnames if d not in PRUNE]
                    for fn in filenames:
                        if fn in ("package-lock.json", "Cargo.lock", "uv.lock", "go.sum"):
                            parse_lockfile(inv, os.path.join(dirpath, fn))
    mcps = [expand(p) for p in conf.get("mcp_configs", [])]
    mcps += [os.path.join(r, ".mcp.json") for r in repos]
    for p in mcps:
        if os.path.isfile(p):
            scan_mcp_config(inv, p)
    rt_installs(inv, conf)
    unidentified = []
    if conf.get("local_bin"):
        unidentified = scan_local_bin(inv, expand(conf["local_bin"]), [expand(x) for x in conf.get("managed_bin_roots", [])])
    drift = []
    pkgs = [{"e": e, "n": n, "v": v, "src": src_sorted(s)} for (e, n, v), s in sorted(inv.pk.items())]
    for e in ECOS:
        inv.cov["packages:" + e] = sum(1 for p in pkgs if p["e"] == e)
    held = {(p["e"], p["n"]) for p in pkgs}
    out = {"packages": pkgs, "coverage": dict(sorted(inv.cov.items())),
           "runtimes": [{"rt": rt, "v": v, "pin": pin, "src": sorted(s)} for (rt, v, pin), s in sorted(inv.rt.items())],
           "names_only": sorted([e, n] for e, n in inv.names_only if (e, n) not in held),
           "local_bin_unidentified": unidentified, "own_repos_not_in_config": drift}
    with open(out_path, "w") as f:
        json.dump(out, f)
    print("packages=%d" % len(pkgs))


# ---- OSV batches -------------------------------------------------------------

def write_batches(qs, outdir, mode, size):
    n = 0
    for b in range(0, len(qs), size):
        with open(os.path.join(outdir, "q-%s-%d.json" % (mode, n)), "w") as f:
            json.dump({"queries": qs[b:b + size]}, f)
        n += 1
    return n


def sizes(outdir):
    return json.load(open(os.path.join(outdir, "sizes.json")))


def batches(inv_path, outdir, vsize, asize):
    vsize, asize = int(vsize), int(asize)
    if not (1 <= vsize <= 1000 and 1 <= asize <= 1000):
        die("batch sizes must be 1-1000")
    inv = json.load(open(inv_path))
    pk = inv["packages"]
    ver = [{"package": {"ecosystem": p["e"], "name": p["n"]}, "version": p["v"]} for p in pk]
    names = sorted({(p["e"], p["n"]) for p in pk} | {tuple(x) for x in inv.get("names_only", [])})
    anyv = [{"package": {"ecosystem": e, "name": n}} for e, n in names]
    json.dump([list(x) for x in names], open(os.path.join(outdir, "idx-any.json"), "w"))
    json.dump({"ver": vsize, "any": asize}, open(os.path.join(outdir, "sizes.json"), "w"))
    print("ver=%d any=%d" % (write_batches(ver, outdir, "ver", vsize), write_batches(anyv, outdir, "any", asize)))


TOKEN_RE = re.compile(r"^[A-Za-z0-9+/=_-]{1,1024}\Z")


def pages(inv_path, outdir, mode, rnd):
    """Follow-up bodies for queries OSV paged: tok-<mode>-<b>-r<rnd>.tsv holds 'index<TAB>token'."""
    inv = json.load(open(inv_path))
    rnd = int(rnd)
    if mode == "ver":
        qsrc = [{"package": {"ecosystem": p["e"], "name": p["n"]}, "version": p["v"]} for p in inv["packages"]]
    else:
        qsrc = [{"package": {"ecosystem": e, "name": n}} for e, n in json.load(open(os.path.join(outdir, "idx-any.json")))]
    made = 0
    for fn in sorted(os.listdir(outdir)):
        m = re.match(r"^tok-%s-([0-9]+)-r%d\.tsv$" % (mode, rnd - 1), fn)
        if not m:
            continue
        b = int(m.group(1))
        prevmap = None
        if rnd > 1:
            prevmap = json.load(open(os.path.join(outdir, "map-%s-%d-r%d.json" % (mode, b, rnd - 1))))
        qs, idx = [], []
        for line in open(os.path.join(outdir, fn)):
            f = line.rstrip("\n").split("\t")
            if len(f) != 2 or not f[0].isdigit() or not TOKEN_RE.match(f[1]):
                die("bad page token line")
            # the token line holds the query's place in the body it answered;
            # map it back to the query's place in the full list
            i = int(f[0])
            if prevmap is None:
                orig = b * sizes(outdir)[mode] + i
            elif i < len(prevmap):
                orig = prevmap[i]
            else:
                die("page token index out of range")
            if orig >= len(qsrc):
                die("page token index out of range")
            q = dict(qsrc[orig])
            q["page_token"] = f[1]
            qs.append(q)
            idx.append(orig)
        if qs:
            json.dump({"queries": qs}, open(os.path.join(outdir, "q-%s-%d-r%d.json" % (mode, b, rnd)), "w"))
            json.dump(idx, open(os.path.join(outdir, "map-%s-%d-r%d.json" % (mode, b, rnd)), "w"))
            made += 1
    print("pages=%d" % made)


def ghchunks(inv_path, outdir, names_max, calls_max):
    """For each ecosystem, chunks of our own names: ghn-<eco>-<c>.json ({name:
    [versions]}) and one line per chunk in ghurls.tsv: eco, chunk, URL. The
    URL asks only for malware advisories that name one of these packages.
    At most calls_max lines, taken round-robin (every ecosystem's first chunk,
    then every second one, ...); the ecosystems that lost a chunk go in
    gh-capped, one a line, and the planned and dropped calls in gh-counts."""
    inv = json.load(open(inv_path))
    names_max, calls_max = int(names_max), int(calls_max)
    if not 1 <= names_max <= GH_NAMES_MAX:
        die("github chunk_names must be 1-%d" % GH_NAMES_MAX)
    if not 1 <= calls_max <= GH_CALLS_MAX:
        die("github max_calls must be 1-%d" % GH_CALLS_MAX)
    lines = []
    for eco in ECOS:
        d = {}
        for p in inv["packages"]:
            if p["e"] == eco:
                d.setdefault(p["n"], []).append(p["v"])
        ge = GH_ECO[eco]
        chunk, size, c = {}, 0, 0
        for n in sorted(d):
            q = urllib.parse.quote(n, safe="")
            if chunk and (size + len(q) + 1 > GH_URL_MAX or len(chunk) >= names_max):
                lines.append(flush_chunk(outdir, ge, c, chunk))
                chunk, size, c = {}, 0, c + 1
            chunk[n] = d[n]
            size += len(q) + 1
        if chunk:
            lines.append(flush_chunk(outdir, ge, c, chunk))
    lines.sort(key=lambda ln: int(ln.split("\t", 2)[1]))  # stable: ecosystems keep their order within a round
    capped = sorted({ln.split("\t", 1)[0] for ln in lines[calls_max:]})
    with open(os.path.join(outdir, "ghurls.tsv"), "w") as f:
        f.write("".join(lines[:calls_max]))
    with open(os.path.join(outdir, "gh-capped"), "w") as f:
        f.write("".join(e + "\n" for e in capped))
    with open(os.path.join(outdir, "gh-counts"), "w") as f:
        f.write("%d %d\n" % (len(lines), max(0, len(lines) - calls_max)))
    print("chunks=%d" % len(lines))


def flush_chunk(outdir, ge, c, chunk):
    json.dump(chunk, open(os.path.join(outdir, "ghn-%s-%d.json" % (ge, c)), "w"))
    aff = ",".join(urllib.parse.quote(n, safe="") for n in chunk)
    url = ("https://api.github.com/advisories?type=malware&ecosystem=%s&per_page=100&affects=%s" % (ge, aff))
    return "%s\t%d\t%s\n" % (ge, c, url)


# ---- join --------------------------------------------------------------------

REJECTED = [0]


def read_tsv(path, nf):
    """Rows of an extracted file. A row of the wrong width (any width when nf
    is None; the caller checks it) is dropped and counted (the run is then an
    ERROR, but other rows still count)."""
    rows = []
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return rows
    for line in lines:
        f = line.split("\t")
        if nf is not None and len(f) != nf:
            REJECTED[0] += 1
            continue
        rows.append(f)
    return rows


def safe_write(outdir, name, text):
    """Write outdir/name by a new file and a rename, so a link planted at the
    name is replaced, never written through."""
    fd, tmp = tempfile.mkstemp(prefix="." + name + ".", dir=outdir)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, os.path.join(outdir, name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def placeholder(outdir, why="run"):
    if os.path.islink(outdir) or not os.path.isdir(outdir):
        die("output folder must be a real folder")
    safe_write(outdir, "daily.json", json.dumps(
        {"schema": "sd-osv/1", "level": "ERROR", "finished": now_iso(), "errors": [why]}) + "\n")


def start(outdir):
    """Before a run: keep the last result as daily.prev.json, then put an
    ERROR placeholder in daily.json, so a run that dies leaves no stale OK."""
    if os.path.islink(outdir) or not os.path.isdir(outdir):
        die("output folder must be a real folder")
    txt = read_small(os.path.join(outdir, "daily.json"), 256 << 20)
    d = load_json(txt) if txt is not None else None
    # Only a finished run is a baseline: after a run that died (a placeholder),
    # keep the older daily.prev.json, so one crash can't reset the baselines.
    if isinstance(d, dict) and isinstance(d.get("coverage"), dict):
        safe_write(outdir, "daily.prev.json", txt)
    placeholder(outdir, "incomplete")


def read_hits(wd, pk, anyidx, size):
    """OSV's extracted hits: ({package index: {id: modified}}, {any index: {id: modified}})."""
    hits_ver = {}    # package index -> {id: modified}
    hits_any = {}    # any index -> {MAL id: modified}
    for fn in sorted(os.listdir(wd)):
        m = re.match(r"^x-(ver|any)-([0-9]+)(-r([0-9]+))?\.tsv\Z", fn)
        if not m:
            continue
        mode, b = m.group(1), int(m.group(2))
        mp = None
        if m.group(3):
            mp = json.load(open(os.path.join(wd, "map-%s-%d-r%s.json" % (mode, b, m.group(4)))))
        lim = len(pk) if mode == "ver" else len(anyidx)
        for i, vid, mod in read_tsv(os.path.join(wd, fn), 3):
            if not i.isdigit() or not (ID_RE.match(vid) or vid in ("other", "MAL-other")) or not DATE_RE.match(mod):
                REJECTED[0] += 1
                continue
            i = int(i)
            if mp is not None:
                gi = mp[i] if i < len(mp) else lim
            else:
                gi = b * size[mode] + i
            if gi >= lim:
                REJECTED[0] += 1
                continue
            (hits_ver if mode == "ver" else hits_any).setdefault(gi, {})[vid] = mod
    return hits_ver, hits_any


FIXES = ("fix", "none", "unknown")
# A fixed version: digits and dots, an optional "v", and at most one
# pre-release tag from a fixed list (no build data, no free words): it is
# reply text that reaches daily.json and the journal. Same as osv-sev.jq.
FIXED_RE = re.compile(r"\Av?[0-9]{1,9}(\.[0-9]{1,9}){0,5}(-(alpha|beta|rc|pre|preview|next|canary|dev)(\.?[0-9]{1,9})?)?\Z")
DAY_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
REFRESH_DAYS = 7
RATED_LATE_DAYS = 7


def blank():
    """What is known about an id nobody asked about."""
    return {"severity": "unknown", "fix": "unknown", "fixed": "-", "asked": "-", "aliases": [], "noticed": "-"}


def ok_data(x):
    """A severity record's fields, each checked; None when any is off-shape.
    noticed (the day its issue was last notified as new or newly severe) may
    be absent: a record from before it was kept."""
    try:
        d = {"severity": x["severity"], "fix": x["fix"], "fixed": x["fixed"], "asked": x["asked"],
             "aliases": x["aliases"], "noticed": x.get("noticed", "-")}
    except (KeyError, TypeError, AttributeError):
        return None
    if d["severity"] not in SEVS or d["fix"] not in FIXES or not isinstance(d["fixed"], str) \
            or not isinstance(d["asked"], str) or not isinstance(d["aliases"], list) or not isinstance(d["noticed"], str):
        return None
    if (d["fix"] == "fix") != (d["fixed"] != "-") or (d["fixed"] != "-" and not (FIXED_RE.match(d["fixed"]) and vkey(d["fixed"]))):
        return None
    if not all(v == "-" or DAY_RE.match(v) for v in (d["asked"], d["noticed"])) or len(d["aliases"]) > MAX_ALIASES \
            or not all(isinstance(a, str) and ID_RE.match(a) for a in d["aliases"]):
        return None
    return d


def ok_key(k):
    """(ecosystem, name, version, id) in the shapes the inventory and OSV
    pass allow; anything else from a previous result is never carried."""
    return (len(k) == 4 and all(isinstance(y, str) for y in k) and k[0] in ECOS and NAME_RE[k[0]].match(k[1])
            and VER_RE[k[0]].match(k[2]) and bool(ID_RE.match(k[3])))


def prev_result(outdir):
    """The last finished run: (parsed daily.prev.json or None, {(ecosystem,
    name, version, id) it knew: (first seen, last seen)}, whether that was
    readable, {that key: its severity record}). An entry or record that is
    off-shape is dropped and counted (rejected_lines), never trusted. Dates
    are "-" when the previous result predates them."""
    pd = load_json(read_small(os.path.join(outdir, "daily.prev.json"), 256 << 20) or "")
    known, data = {}, {}
    info = pd.get("info") if isinstance(pd, dict) else None
    vav = info.get("vulns_at_version") if isinstance(info, dict) else None
    if not isinstance(vav, list):
        return pd, known, False, data
    for x in vav:
        try:
            k = (x["ecosystem"], x["package"], x["version"], x["advisory"])
        except (KeyError, TypeError):
            k = None
        if k is None or not ok_key(k):
            REJECTED[0] += 1
            continue
        known.setdefault(k, ("-", "-"))
        d = ok_data(x)
        if d is not None:
            data[k] = d
    # known_vulns: what counts as known, with first and last seen dates
    # (4 fields before the dates were added, 2026-10-27)
    kv = info.get("known_vulns", [])
    if not isinstance(kv, list):
        REJECTED[0] += 1
        kv = []
    for x in kv:
        if not (isinstance(x, list) and len(x) in (4, 6) and ok_key(tuple(x[:4]))
                and all(isinstance(d, str) and (d == "-" or DAY_RE.match(d)) for d in x[4:])):
            REJECTED[0] += 1
            continue
        known[tuple(x[:4])] = tuple(x[4:]) if len(x) == 6 else ("-", "-")
    return pd, known, True, data


def is_cve(vid):
    return vid != "other" and not vid.startswith("MAL-")


def today():
    return now_iso()[:10]


def sevq(inv_path, wd, outdir, maxq):
    """OSV /v1/query bodies, sq-<k>.json, up to MAX: each body holds only our
    own ecosystem, name and version (never an id or token from a reply).
    Packages in this order: those with a new non-malware hit at a held version;
    then those with an id never asked about (the backlog); then those with a
    held critical or high and no fixed version yet (every run); then those
    whose answer is oldest, past 7 days. sq-idx.json maps k to the package index;
    sq-capped says whether some packages with a new hit were left out."""
    maxq = int(maxq)
    if not 0 <= maxq <= 1000:
        die("severity_max must be 0-1000")
    inv = json.load(open(inv_path))
    pk = inv["packages"]
    hits_ver, _ = read_hits(wd, pk, json.load(open(os.path.join(wd, "idx-any.json"))), sizes(wd))
    _, known, _, data = prev_result(outdir)
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=REFRESH_DAYS)).strftime("%Y-%m-%d")
    key = lambda gi, vid: (pk[gi]["e"], pk[gi]["n"], pk[gi]["v"], vid)
    new, never, nofix, old = [], [], [], []
    for gi, ids in sorted(hits_ver.items()):
        cves = [vid for vid in ids if is_cve(vid)]
        recs = [data.get(key(gi, vid), blank()) for vid in cves]
        if any(key(gi, vid) not in known for vid in cves):
            new.append(gi)
        elif any(r["asked"] == "-" for r in recs):
            never.append(gi)
        elif any(r["severity"] in ("critical", "high") and r["fix"] != "fix" for r in recs):
            # a held critical or high with no fixed version yet: asked every
            # run, so the day a fix is named is the day it's reported
            nofix.append(gi)
        elif cves:
            oldest = min(r["asked"] for r in recs)
            if oldest < cutoff:
                old.append((oldest, gi))
    targets = (new + never + nofix + [gi for _, gi in sorted(old)])[:maxq]
    for k, gi in enumerate(targets):
        p = pk[gi]
        with open(os.path.join(wd, "sq-%d.json" % k), "w") as f:
            json.dump({"package": {"ecosystem": p["e"], "name": p["n"]}, "version": p["v"]}, f)
    json.dump(targets, open(os.path.join(wd, "sq-idx.json"), "w"))
    with open(os.path.join(wd, "sq-capped"), "w") as f:
        f.write("yes\n" if len(new) > maxq else "no\n")
    print("new=%d never_asked=%d severe_no_fix=%d refresh=%d queries=%d" % (len(new), len(never), len(nofix), len(old), len(targets)))


def read_sev(wd, pk):
    """The severity pass's rows: {(package index, id): severity record}."""
    out = {}
    p = os.path.join(wd, "sq-idx.json")
    idx = json.load(open(p)) if os.path.exists(p) else []
    day = today()
    for fn in sorted(os.listdir(wd)):
        m = re.match(r"^sv-([0-9]+)\.tsv\Z", fn)
        if not m:
            continue
        k = int(m.group(1))
        if k >= len(idx) or not isinstance(idx[k], int) or not 0 <= idx[k] < len(pk):
            REJECTED[0] += 1
            continue
        gi = idx[k]
        for vid, s, al, fx, fixed in read_tsv(os.path.join(wd, fn), 5):
            d = ok_data({"severity": s, "fix": fx, "fixed": fixed, "asked": day,
                         "aliases": [] if al == "-" else al.split(",")})
            if d is None or not (ID_RE.match(vid) or vid in ("other", "MAL-other")):
                REJECTED[0] += 1
                continue
            out[(gi, vid)] = d
    return out


RT_STATUS = ("ok", "ok_line", "behind", "update", "security_update", "eol", "unknown", "not_checked")
RT_FINDINGS = ("security_update", "update", "eol")
# Each runtime's two sources (v3.2): its release list, then its end-of-life data.
RT_KINDS = {"node": ("node-index", "node-sched"), "python": ("py-release", "py-cycle")}


def read_rt(wd, kind):
    """One runtime source's rows, each checked again: a release list gives
    [(version, security yes/no, or None for CPython)], an end-of-life source
    {line: (status word, end date)} (Node's word is "end"). None when the
    source was skipped or didn't finish (osv-scan.sh writes rt-KIND.tsv only
    when it did)."""
    p = os.path.join(wd, "rt-%s.tsv" % kind)
    if not os.path.exists(p):
        return None
    lines, rels = {}, []
    for f in read_tsv(p, None):
        if kind == "node-index" and f[0] == kind and len(f) == 4 and f[1] == "R" \
                and re.match(r"\A[0-9]{1,3}\.[0-9]{1,4}\.[0-9]{1,4}\Z", f[2]) and f[3] in ("yes", "no"):
            rels.append((f[2], f[3] == "yes"))
        elif kind == "node-sched" and f[0] == kind and len(f) == 4 and f[1] == "L" \
                and re.match(r"\A[1-9][0-9]{0,2}\Z", f[2]) and DAY_RE.match(f[3]):
            lines[f[2]] = ("end", f[3])
        elif kind == "py-cycle" and f[0] == kind and len(f) == 5 and f[1] == "L" \
                and re.match(r"\A3\.[0-9]{1,2}\Z", f[2]) \
                and f[3] in ("feature", "prerelease", "bugfix", "security", "end-of-life", "other") \
                and re.match(r"\A([0-9]{4}-[0-9]{2}(-[0-9]{2})?|-)\Z", f[4]):
            lines[f[2]] = (f[3], f[4])
        elif kind == "py-release" and f[0] == kind and len(f) == 3 and f[1] == "R" \
                and re.match(r"\A3\.[0-9]{1,2}\.[0-9]{1,3}\Z", f[2]):
            rels.append((f[2], None))
        else:
            REJECTED[0] += 1
    return rels if kind in ("node-index", "py-release") else lines


def runtime_status(rt, v, pin, rels, lines):
    """(status, fixed version or "-", eol) for one held runtime. rels is its
    release list and lines its end-of-life data, each None when that source
    was skipped or didn't finish.

    eol: "yes" (Node: past its line's end date; CPython: its line marked
    end-of-life or past its end date), "no", "unknown" (the line isn't in the
    data) or "not_checked" (no data). Never "no" without data.

    status: "eol" when eol is "yes". A line pin (a floating tag) is checked
    only for end of life: "ok_line" when eol is "no", else eol's word
    ("unknown", "not_checked"). An exact version, from the release list:
    "not_checked" without one; "unknown" when it has no release in the
    version's line; "ok" with no later release in the line. Node: a later
    security release is "security_update" (fixed: the newest of those), a
    later release only "behind". CPython: a later release is
    "security_update" in a line the end-of-life data says takes security
    fixes only, else "update" (bugfix lines' releases may carry security
    fixes python.org doesn't flag, and without that data the line's kind is
    unknown)."""
    line = v.split(".")[0] if rt == "node" else ".".join(v.split(".")[:2])
    info = lines.get(line) if lines is not None else None
    day = today()
    if lines is None:
        eol = "not_checked"
    elif info is None:
        eol = "unknown"
    elif rt == "node":
        eol = "yes" if info[1] < day else "no"
    else:
        eol = "yes" if info[0] == "end-of-life" or (info[1] != "-" and info[1] < day[:len(info[1])]) else "no"
    if eol == "yes":
        return "eol", "-", eol
    if pin == "line":
        return ("ok_line" if eol == "no" else eol), "-", eol
    if rels is None:
        return "not_checked", "-", eol
    lp = line.split(".")
    inline = [(r, sec) for r, sec in rels if r.split(".")[:len(lp)] == lp]
    if not inline:
        return "unknown", "-", eol
    hv = vkey(v)
    later = [(r, sec) for r, sec in inline if vkey(r) > hv]
    if not later:
        return "ok", "-", eol
    if rt == "node":
        secs = [r for r, sec in later if sec]
        return (("security_update", max(secs, key=vkey)) if secs
                else ("behind", max((r for r, _ in later), key=vkey))) + (eol,)
    newest = max((r for r, _ in later), key=vkey)
    return ("security_update" if info is not None and info[0] == "security" else "update"), newest, eol


def runtimes(inv, wd, prev):
    """Every held runtime with its status and end-of-life state, and which
    findings are new (not in the last run's findings)."""
    data = {rt: tuple(read_rt(wd, k) for k in kinds) for rt, kinds in RT_KINDS.items()}
    pf = set()
    try:
        for x in prev["runtimes"]:
            pf.add((x["rt"], x["version"], x["status"], x["fixed"]))
    except (KeyError, TypeError):
        pass
    out = []
    for r in inv.get("runtimes", []):
        st, fixed, eol = runtime_status(r["rt"], r["v"], r["pin"], *data.get(r["rt"], (None, None)))
        out.append({"rt": r["rt"], "version": r["v"], "pin": r["pin"], "status": st, "fixed": fixed, "eol": eol,
                    "found_in": r["src"][:5], "found_in_more": max(0, len(r["src"]) - 5),
                    "new": st in RT_FINDINGS and (r["rt"], r["v"], st, fixed) not in pf})
    return out


def join(inv_path, wd, outdir):
    inv = json.load(open(inv_path))
    pk = inv["packages"]
    anyidx = json.load(open(os.path.join(wd, "idx-any.json")))
    size = sizes(wd)
    status = {}
    for line in open(os.path.join(wd, "status")).read().splitlines():
        if not STATUS_RE.match(line):
            die("bad status line")
        k, v = line.split("=")
        status[k] = v
    # A missing or bad gh-counts (more dropped than planned included) is an
    # ERROR with zero counts, not a stopped run. 64 bytes is more than the shape.
    try:
        ghc = re.match(r"\A([0-9]{1,6}) ([0-9]{1,6})\n\Z",
                       open(os.path.join(wd, "gh-counts"), encoding="ascii").read(64))
    except (OSError, UnicodeDecodeError):
        ghc = None
    if ghc and int(ghc.group(2)) > int(ghc.group(1)):
        ghc = None
    gh_planned, gh_dropped = (int(ghc.group(1)), int(ghc.group(2))) if ghc else (0, 0)
    hits_ver, hits_any = read_hits(wd, pk, anyidx, size)
    answers = read_sev(wd, pk)
    pd, prev, prev_ok, prev_data = prev_result(outdir)
    alerts, at_version, any_version, other_ids, gh_info = [], [], [], 0, []

    def ent(p, vid, mod, via):
        return {"advisory": vid, "modified": mod, "ecosystem": p["e"], "package": p["n"], "version": p["v"],
                "found_in": p["src"][:5], "found_in_more": max(0, len(p["src"]) - 5), "via": via}

    mal_at_ver = set()
    first_of = {}    # (package index, id) -> its issue's first seen date
    byver_idx = {(p["e"], p["n"], p["v"]): gi for gi, p in enumerate(pk)}
    cve_ids = {}     # package index -> [ids at that version, not malware]
    ent_of = {}      # (package index, id) -> its entry in at_version
    for gi, ids in sorted(hits_ver.items()):
        p = pk[gi]
        for vid, mod in sorted(ids.items()):
            if vid == "other":
                other_ids += 1
            elif vid.startswith("MAL-"):
                alerts.append(ent(p, vid, mod, "osv"))
                mal_at_ver.add((p["e"], p["n"], vid))
            else:
                e = ent(p, vid, mod, "osv")
                # this run's answer, else the last run's, else unrated
                e.update(answers.get((gi, vid)) or prev_data.get((p["e"], p["n"], p["v"], vid)) or blank())
                at_version.append(e)
                ent_of[(gi, vid)] = e
                cve_ids.setdefault(gi, []).append(vid)
    vers_of = {}
    for p in pk:
        vers_of.setdefault((p["e"], p["n"]), []).append(p["v"])
    for ai, ids in sorted(hits_any.items()):
        e, n = anyidx[ai]
        for vid, mod in sorted(ids.items()):
            if vid.startswith("MAL-") and (e, n, vid) not in mal_at_ver:
                any_version.append({"advisory": vid, "modified": mod, "ecosystem": e, "package": n,
                                    "versions_held": sorted(vers_of.get((e, n), []))[:10], "via": "osv"})
    # GitHub malware advisories: gh-<eco>-<chunk>.tsv rows: id, updated, name
    # index, version index, in|out|unparsed (the range checked in jq).
    byver = {(p["e"], p["n"], p["v"]): p for p in pk}
    gh_seen = set()
    gh_unparsed = [0]
    for fn in sorted(os.listdir(wd)):
        m = re.match(r"^gh-(npm|pip|rust|go)-([0-9]+)\.tsv\Z", fn)
        if not m:
            continue
        eco = {v: k for k, v in GH_ECO.items()}[m.group(1)]
        names = json.load(open(os.path.join(wd, "ghn-%s-%s.json" % (m.group(1), m.group(2)))))
        keys = list(names.keys())
        for vid, upd, ni, vi, cls in read_tsv(os.path.join(wd, fn), 5):
            if not (ID_RE.match(vid) or vid in ("other", "MAL-other")) or not DATE_RE.match(upd) or not ni.isdigit() \
                    or not vi.isdigit() or cls not in ("in", "out", "unparsed") or int(ni) >= len(keys) \
                    or int(vi) >= len(names[keys[int(ni)]]):
                REJECTED[0] += 1
                continue
            n = keys[int(ni)]
            v = names[n][int(vi)]
            if cls == "unparsed":
                gh_unparsed[0] += 1
            if cls == "in":
                alerts.append(ent(byver[(eco, n, v)], vid, upd, "github"))
            elif (vid, eco, n) not in gh_seen:
                gh_seen.add((vid, eco, n))
                gh_info.append({"advisory": vid, "modified": upd, "ecosystem": eco, "package": n,
                                "versions_held": sorted(names[n])[:10], "via": "github",
                                "range": "held versions outside it" if cls == "out" else "not parsed"})
    psrc = pd.get("sources") if isinstance(pd, dict) and isinstance(pd.get("sources"), dict) else {}
    pcov = pd.get("coverage") if isinstance(pd, dict) and isinstance(pd.get("coverage"), dict) else None
    pcnt = pd.get("counts") if isinstance(pd, dict) and isinstance(pd.get("counts"), dict) else None
    # A baseline run: a previous result exists but gives no usable list of
    # what was known (unreadable, or from before known_vulns with a by-version
    # pass that didn't finish, so its list is partial). Nothing is new, so the
    # backlog never floods the notice or the journal; first seen is "-" (long
    # ago), as for issues known before dates were kept. With no previous result
    # at all (a first install) everything found counts as new, as before.
    pinfo = pd.get("info") if isinstance(pd, dict) else None
    baseline = os.path.lexists(os.path.join(outdir, "daily.prev.json")) and (
        not prev_ok or ("known_vulns" not in pinfo and psrc.get("osv_ver") != "ok"))
    new = [] if baseline else [x for x in at_version
                               if (x["ecosystem"], x["package"], x["version"], x["advisory"]) not in prev]
    # Issues: ids at one held version that name each other as aliases are one
    # issue. Every id of an issue shows the issue's severity (the worst of its
    # ids') and fix ("fix" when any id names a fixed version, the highest
    # named; else "unknown" when any is unknown; else "none").
    # - new: none of its ids or their aliases was known for that package, at
    #   any version (a version bump or a repo back from a missing drive isn't
    #   a new vulnerability);
    # - escalated: known and answered before, but now critical or high where
    #   every earlier answer was below that, or now critical or high with a
    #   fixed version where no earlier answer had one (counted with the new
    #   ones for the notice);
    # - unasked: new, and no id got a /v1/query answer this run;
    # - unrated: no id was ever answered;
    # - first_seen: the earliest date any of its ids was known for the package.
    FIX_RANK = {"fix": 3, "unknown": 2, "none": 1}
    day = today()
    # (ecosystem, name) -> {id: earliest first seen}; "-" (known before dates
    # were kept) sorts first, so it reads as "long ago"
    pkg_ids = {}
    for (e_, n_, v_, i_), (f_, _) in prev.items():
        d0 = pkg_ids.setdefault((e_, n_), {})
        d0[i_] = min(d0.get(i_, f_), f_)
    pkg_rec = {}       # (ecosystem, name, id) -> [earlier severity records]
    for (e_, n_, v_, i_), d in prev_data.items():
        pkg_rec.setdefault((e_, n_, i_), []).append(d)
    late_from = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=RATED_LATE_DAYS)).strftime("%Y-%m-%d")
    issues, held = [], []
    for gi, ids in sorted(cve_ids.items()):
        p = pk[gi]
        group = {vid: vid for vid in ids}

        def root(v):
            while group[v] != v:
                v = group[v]
            return v
        for vid in ids:
            for a in ent_of[(gi, vid)]["aliases"]:
                if a in group:
                    group[root(a)] = root(vid)
        members = {}
        for vid in ids:
            members.setdefault(root(vid), []).append(vid)
        for ms in members.values():
            es = [ent_of[(gi, v)] for v in ms]
            sv = max((e["severity"] for e in es), key=lambda w: SEV_RANK[w])
            fx = max((e["fix"] for e in es), key=lambda w: FIX_RANK[w])
            fixed = max((e["fixed"] for e in es if e["fix"] == "fix"), key=vkey, default="-")
            for e in es:
                e.update(severity=sv, fix=fx, fixed=fixed if fx == "fix" else "-")
            names = set(ms).union(*(set(e["aliases"]) for e in es))
            seen = pkg_ids.get((p["e"], p["n"]), {})
            isnew = not baseline and not any(v in seen for v in names)
            first = min((seen[v] for v in names if v in seen), default="-" if baseline else day)
            for v in ms:
                first_of[(gi, v)] = first
            # earlier answers only: an issue first rated now (the backlog after
            # an upgrade, a repo back from a missing drive) isn't an escalation
            recs = [d for v in names for d in pkg_rec.get((p["e"], p["n"], v), [])]
            olds = [d for d in recs if d["asked"] != "-"]
            hi = sv in ("critical", "high")
            escalated = bool(not isnew and hi and olds and (
                all(SEV_RANK[d["severity"]] < SEV_RANK["high"] for d in olds)
                or (fx == "fix" and not any(d["fix"] == "fix" for d in olds))))
            # rated late: held in the last run, new within the last week but
            # never rated (unasked, capped, OSV down), and rated critical or
            # high now: news, as if new. Not for a version that wasn't held
            # last run (a drive back after a run away): no record says it
            # went unrated.
            rated_late = bool(not isnew and hi and recs and not olds and first != "-" and first >= late_from)
            noticed = day if isnew or escalated or rated_late else max((d["noticed"] for d in recs), default="-")
            for e in es:
                e["noticed"] = noticed
            iss = {"ecosystem": p["e"], "package": p["n"], "version": p["v"], "severity": sv, "fix": fx,
                   "fixed": es[0]["fixed"], "advisories": sorted(ms)[:10], "found_in": p["src"][:5],
                   "new": isnew, "escalated": escalated or rated_late, "rated_late": rated_late,
                   "first_seen": first, "noticed": noticed,
                   "unasked": isnew and not any((gi, v) in answers for v in ms),
                   "unrated": all(e["asked"] == "-" for e in es)}
            held.append(iss)
            if isnew or escalated or rated_late:
                issues.append(iss)
    severe = lambda x: x["severity"] in ("critical", "high")
    by_sev = {w: sum(1 for x in issues if x["severity"] == w) for w in SEVS}
    by_eco = {w: sum(1 for x in issues if x["ecosystem"] == w) for w in ECOS}
    unasked = sum(1 for x in issues if x["unasked"])
    new_severe_fix = sum(1 for x in issues if severe(x) and x["fix"] == "fix")
    held_by_sev = {w: sum(1 for x in held if x["severity"] == w) for w in SEVS}
    held_severe_fix = [x for x in held if severe(x) and x["fix"] == "fix"]
    # first seen, escalated or rated late in the last 72 hours, so a missed
    # notification still shows
    recent_from = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=72)).strftime("%Y-%m-%d")
    recent = [x for x in held if (severe(x) or x["severity"] == "unknown")
              and (x["first_seen"] >= recent_from or x["noticed"] >= recent_from)]
    rts = runtimes(inv, wd, pd if isinstance(pd, dict) else {})
    rt_new = [x for x in rts if x["new"]]
    rt_find = [x for x in rts if x["status"] in RT_FINDINGS]
    # A new (or escalated, or rated late) critical or high with a fixed
    # version, or a runtime with a new security release: "severe" (the
    # loudest). A new critical or high without a fix, a new issue not rated
    # (unasked, or OSV's records have no word: it might be either), or a
    # runtime newly past end of life or with a bugfix release out: "notice".
    # A new medium or low only: "digest".
    cve_notice = ("severe" if new_severe_fix or any(x["status"] == "security_update" for x in rt_new)
                  else "notice" if by_sev["critical"] or by_sev["high"] or by_sev["unknown"] or rt_new
                  else "digest" if issues else "none")
    # What counts as known next time, with first and last seen dates: this
    # run's ids; the last run's for a package version this run didn't hold (a
    # missing drive, a bump), for 30 days; and all of the last run's when
    # OSV's by-version pass didn't finish, so its gaps aren't "new" tomorrow.
    held_pv = {(p["e"], p["n"], p["v"]) for p in pk}
    expire = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    known = {}
    for k, (f_, l_) in prev.items():
        if status.get("osv_ver") != "ok" or (k[:3] not in held_pv and (l_ == "-" or l_ >= expire)):
            known[k] = (f_, l_)
    for x in at_version:
        k = (x["ecosystem"], x["package"], x["version"], x["advisory"])
        gi = byver_idx[k[:3]]
        known[k] = (first_of.get((gi, k[3]), day), day)
    # OSV is the primary source: unreachable, off-shape or cut short is an ERROR.
    # GitHub is checked "if reachable": unreachable is INFO; off-shape or a
    # full page (some advisories not seen) is an ERROR.
    # GitHub unreachable two runs running (or with no previous run to compare)
    # is an ERROR: its malware path must not go quiet for days.
    # The severity pass (osv_sev) only adds detail: off-shape is an ERROR;
    # unreachable or paged is INFO once, an ERROR two runs running (or with
    # no previous run to compare), since then "severe" can't fire; capped is
    # INFO. Its issues count as unasked.
    sev_down = ("unreachable", "paged")
    errors = sorted(k for k, v in status.items()
                    if (k == "osv_sev" and (v == "malformed" or (v in sev_down and psrc.get(k, v) in sev_down)))
                    or k != "osv_sev" and (
                    v in ("malformed", "partial", "truncated", "paged")
                    or (v == "capped" and k.startswith("gh_"))
                    or (v == "unreachable" and (k.startswith("osv_")
                                                or psrc.get(k, "unreachable") in ("unreachable", "capped")))))
    if REJECTED[0]:
        errors.append("rejected_lines")
    cov = inv["coverage"]
    if not pk:
        errors.append("no_packages")
    if cov.get("repos_missing", 0) and not cov.get("repos_scanned", 0):
        errors.append("no_repos")
    if cov.get("enumerate_time_cap_hit", 0):
        errors.append("enumerate_time_cap_hit")
    # Coverage counters and unknown ids: listed every run, INFO when one rose
    # since the previous run (or there is none to compare with).
    gaps = {k: cov[k] for k in GAP_KEYS if isinstance(cov.get(k), int) and cov[k] > 0}
    if other_ids:
        gaps["other_ids"] = other_ids
    prevgaps = dict(pcov or {})
    prevgaps["other_ids"] = (pcnt or {}).get("other_ids", 0)
    gaps_rose = sorted(k for k, v in gaps.items()
                       if pcov is None or not isinstance(prevgaps.get(k, 0), int) or v > prevgaps.get(k, 0))
    major = sorted(k for k in gaps if k in MAJOR_GAPS)
    if pcov is not None and any(k in MAJOR_GAPS for k in gaps_rose):
        errors.append("coverage_gap_rose")
    ppk = (pcnt or {}).get("packages")
    if isinstance(ppk, int) and ppk > 0 and len(pk) < ppk * 0.8:
        errors.append("packages_dropped")
    # A GitHub malware advisory naming a held package with a range this check
    # can't evaluate: an ERROR (notified), never a quiet INFO.
    if gh_unparsed[0]:
        errors.append("github_malware_range_unparsed")
    if not ghc:
        errors.append("gh_counts")
    partial = sorted(k for k, v in status.items() if k not in errors and v not in ("ok", "skipped"))
    if alerts:
        level = "ALERT"
    elif errors:
        level = "ERROR"
    elif any_version or gh_info or new or partial or gaps_rose or major or inv["own_repos_not_in_config"] or rt_find:
        level = "INFO"
    else:
        level = "OK"
    out = {"schema": "sd-osv/1", "finished": now_iso(), "level": level, "sources": status,
           "errors": errors, "partial": partial,
           "counts": {"packages": len(pk), "alerts": len(alerts), "mal_any_version": len(any_version),
                      "github_not_at_held_version": len(gh_info), "vulns_at_version": len(at_version),
                      "new_vulns": len(new), "other_ids": other_ids, "rejected_lines": REJECTED[0],
                      "github_calls_planned": gh_planned, "github_calls_dropped": gh_dropped,
                      "previous_run_readable": prev_ok, "baseline_run": baseline, "new_issues": len(issues),
                      "new_issues_unasked": unasked, "new_issues_by_severity": by_sev,
                      "new_issues_by_ecosystem": by_eco, "new_severe_with_fix": new_severe_fix,
                      "new_issues_with_fix": sum(1 for x in issues if x["fix"] == "fix"),
                      "held_issues": len(held), "held_issues_by_severity": held_by_sev,
                      "held_severe_with_fix": len(held_severe_fix),
                      "held_severe_no_fix": sum(1 for x in held if severe(x) and x["fix"] == "none"),
                      "held_unrated": sum(1 for x in held if x["unrated"]),
                      "escalated_issues": sum(1 for x in issues if x["escalated"]),
                      "rated_late_issues": sum(1 for x in issues if x["rated_late"]),
                      "recent_severe": sum(1 for x in recent if severe(x)),
                      "recent_severe_with_fix": sum(1 for x in recent if severe(x) and x["fix"] == "fix"),
                      "recent_unrated": sum(1 for x in recent if x["severity"] == "unknown"),
                      "new_runtime_findings": len(rt_new),
                      # eol counts only rows found past end of life; rows whose
                      # end of life wasn't checked or isn't in the data have
                      # their own counts, so "eol 0" never reads as "none";
                      # the same for exact versions the release list didn't
                      # decide
                      "runtime_findings": dict([(s, sum(1 for x in rt_find if x["status"] == s)) for s in RT_FINDINGS]
                                               + [("eol_" + e, sum(1 for x in rts if x["eol"] == e))
                                                  for e in ("not_checked", "unknown")]
                                               + [("release_" + e, sum(1 for x in rts if x["pin"] == "exact"
                                                                       and x["status"] == e))
                                                  for e in ("not_checked", "unknown")]),
                      "runtimes_held": len(rts)},
           "cve_notice": cve_notice, "runtimes": rts,
           "coverage": inv["coverage"], "coverage_gaps": gaps, "coverage_gaps_rose": gaps_rose,
           "local_bin_unidentified": inv["local_bin_unidentified"],
           "own_repos_not_in_config": inv["own_repos_not_in_config"],
           "alerts": alerts, "info": {"mal_any_version": any_version, "github_not_at_held_version": gh_info,
                                      "new_vulns": new, "vulns_at_version": at_version,
                                      "known_vulns": sorted(list(k) + list(d) for k, d in known.items()),
                                      "severe_with_fix": held_severe_fix}}
    safe_write(outdir, "daily.json", json.dumps(out, indent=1) + "\n")
    print("level=%s alerts=%d mal_any_version=%d github_not_at_held_version=%d vulns_at_version=%d new_vulns=%d new_issues=%d other_ids=%d rejected_lines=%d packages=%d"
          % (level, len(alerts), len(any_version), len(gh_info), len(at_version), len(new), len(issues), other_ids, REJECTED[0], len(pk)))
    for a in alerts:
        print("ALERT %s %s %s %s %s via=%s" % (a["advisory"], a["modified"], a["ecosystem"], a["package"], a["version"], a["via"]))
    for x in any_version + gh_info:
        print("INFO malware-not-at-held-version %s %s %s %s via=%s" % (x["advisory"], x["modified"], x["ecosystem"], x["package"], x["via"]))
    for x in new[:50]:   # the journal gets the first 50; daily.json has them all
        print("INFO new-vuln %s %s %s %s %s severity=%s fix=%s" % (x["advisory"], x["modified"], x["ecosystem"], x["package"], x["version"], x["severity"], x["fixed"] if x["fix"] == "fix" else x["fix"]))
    if len(new) > 50:
        print("INFO new-vuln %d more in daily.json" % (len(new) - 50))
    if cve_notice != "none":
        print("INFO cve %s %s %s with_fix=%d" % (cve_notice, " ".join("%s=%d" % (k, by_sev[k]) for k in SEVS),
                                                 " ".join("%s=%d" % (k, by_eco[k]) for k in ECOS), new_severe_fix))
    if baseline:
        print("INFO baseline-run no usable previous list: nothing counts as new this run")
    for x in [x for x in held_severe_fix if x["new"] or x["escalated"]][:50]:
        print("INFO severe-fix %s %s %s -> %s %s %s" % (x["ecosystem"], x["package"], x["version"], x["fixed"], x["severity"],
                                                     "new" if x["new"] else "rated-late" if x["rated_late"] else "escalated"))
    for x in [x for x in held if (x["new"] or x["escalated"]) and severe(x) and x["fix"] != "fix"][:50]:
        print("INFO severe-nofix %s %s %s fix=%s %s %s" % (x["ecosystem"], x["package"], x["version"], x["fix"], x["severity"],
                                                        "new" if x["new"] else "rated-late" if x["rated_late"] else "escalated"))
    for x in rt_find:
        print("INFO runtime %s %s %s fixed=%s new=%s" % (x["rt"], x["version"], x["status"], x["fixed"], "yes" if x["new"] else "no"))
    # rows a status word alone would show as fine: an "ok" with its
    # end of life unchecked. Digits only, and no INFO prefix: never a level.
    rf = out["counts"]["runtime_findings"]
    if any(rf[k] for k in ("eol_not_checked", "eol_unknown", "release_not_checked", "release_unknown")):
        print("runtime-gaps eol_not_checked=%d eol_unknown=%d release_not_checked=%d release_unknown=%d"
              % (rf["eol_not_checked"], rf["eol_unknown"], rf["release_not_checked"], rf["release_unknown"]))
    for k in errors:
        if k in status:
            print("ERROR %s %s" % (k, status[k]))
        elif k == "rejected_lines":
            print("ERROR rejected_lines %d" % REJECTED[0])
        elif k == "coverage_gap_rose":
            print("ERROR coverage_gap_rose %s" % ",".join(x for x in gaps_rose if x in MAJOR_GAPS))
        else:
            print("ERROR %s" % k)
    for k in partial:
        print("INFO source %s %s" % (k, status[k]))
    for k in sorted(set(gaps_rose) | set(major)):
        print("INFO coverage-gap %s %d" % (k, gaps[k]))
    if inv["own_repos_not_in_config"]:
        print("INFO own-repos-not-in-config %d" % len(inv["own_repos_not_in_config"]))
    return {"ALERT": 1, "ERROR": 2}.get(level, 0)


# ---- version order (join and runtimes; other tools import it) ----------------

def vkey(v):
    """Six numeric parts, 1 for a release or 0 for a pre-release, then the
    pre-release identifiers (numbers before words). None when the core has
    any non-numeric part (epochs, .post, .dev): not comparable here."""
    v = v[1:] if v.startswith("v") else v
    core, dash, pre = v.split("+")[0].partition("-")
    parts = core.split(".")
    if len(parts) > 6 or not all(re.match(r"\A[0-9]{1,9}\Z", x) for x in parts):
        return None
    if dash and (not pre or "" in pre.split(".")):
        return None
    nums = [int(x) for x in parts]
    ids = [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")] if pre else []
    return [(0, x, "") for x in (nums + [0] * 6)[:6]] + [(0, 0 if pre else 1, "")] + ids


def main(a):
    cmds = {"enumerate": (enumerate_all, 2), "batches": (batches, 4), "pages": (pages, 4),
            "ghchunks": (ghchunks, 4), "sevq": (sevq, 4), "start": (start, 1), "placeholder": (placeholder, 1),
            "join": (join, 3)}
    if len(a) < 2 or a[1] not in cmds or len(a) - 2 != cmds[a[1]][1]:
        die("usage")
    if a[1] == "pages" and a[4] not in ("ver", "any"):
        die("usage")
    try:
        rc = cmds[a[1]][0](*a[2:])
    except SystemExit:
        raise
    except BaseException:
        # Never a traceback (it could quote a value); a crash is its own code,
        # never ALERT's 1 or ERROR's 2.
        print("osvd: %s failed" % a[1], file=sys.stderr)
        sys.exit(3)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main(sys.argv)
