#!/usr/bin/env python3
"""/stranger-danger:osv: check what you hold against OSV, on demand.

    osv.py run [FOLDER ...]   scan the folders (default: this one) and your
                              global installs, then print the summary
    osv.py show               print the last result's summary
    osv.py tools              check the tools the scan needs

The scan is the OSV scan core (skills/osv/core: seven files, listed in
core/SHA256SUMS). It lists the packages
your lockfiles and global installs hold, asks OSV and GitHub's malware
advisories about them by name and version, asks OSV for severity words and
fixed versions, and checks held Node.js and CPython versions against their release lists. Each reply is
saved unread and reduced by jq to ids, dates, counts and fixed words. It
writes daily.json in ~/.cache/stranger-danger/osv/.

What this prints is fixed text with only digits and fixed words filled in:
levels, counts, each source's status word, the error words the core uses and
the results path. Package names and advisory ids stay in daily.json, because
some come from packages strangers wrote (a name in an npx cache, say), so
they never reach Claude. Anything off its shape prints as "unreadable".

Run it as a sandboxed Bash call, with /usr/bin/python3. The sandbox reaches
the network only through Claude Code's proxy, so the core keeps the proxy
variables and nothing else from your environment. It needs five hosts in
your sandbox's network allowlist and the results folder in its write list,
which /stranger-danger:setup's OSV option adds; the plugin's session hook
makes the folder. The core runs system copies of bash, curl, jq (1.6 or
later) and python3 only, from /usr/bin or /bin, that you don't own and can't
write. Exit 0 OK or INFO, 1 ALERT (a malware record names something you
hold), 2 ERROR, 3 when this refused to start or couldn't write. Standard
library only.
"""
from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.join(HERE, "core")
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "setup"))

import apply  # noqa: E402  (SYSTEM_DIRS and TOP_DIRS only)

# Outside every folder setup denies sandboxed writes to (~/.cache is never one).
RESULTS = (".cache", "stranger-danger", "osv")
TOOLS = ("bash", "curl", "jq", "python3")
TOOL_DIRS = ("/usr/bin", "/bin")
HOSTS = ("api.osv.dev", "api.github.com", "nodejs.org", "peps.python.org", "www.python.org")
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy")
MAX_ROOTS = 20
MAX_NAME = 60
MAX_RESULT_BYTES = 32 << 20
MAX_COUNT = 999_999_999
# The core's enumeration (4 minutes) and severity pass (10) have budgets; its
# OSV batches don't, beyond 3 minutes a request. A run past this is stopped
# as an ERROR.
CORE_TIME_LIMIT = 30 * 60
TOOL_TIME_LIMIT = 10

LEVELS = ("OK", "INFO", "ALERT", "ERROR")
NOTICES = ("none", "digest", "notice", "severe")
SEVS = ("critical", "high", "medium", "low", "unknown")
ECOS = ("npm", "PyPI", "crates.io", "Go")
# The core's runtime_findings keys (v3.3): the findings, then the rows it
# couldn't decide, so "eol 0" never reads as "none past end of life".
RT_FINDINGS = ("security_update", "update", "eol", "eol_not_checked", "eol_unknown",
               "release_not_checked", "release_unknown")
SOURCES = ("osv_ver", "osv_any", "osv_sev", "gh_npm", "gh_pip", "gh_rust", "gh_go",
           "rt_node", "rt_node_eol", "rt_python", "rt_python_eol")
SOURCE_WORDS = ("ok", "partial", "unreachable", "malformed", "truncated", "paged",
                "skipped", "capped")
ERROR_WORDS = SOURCES + ("run", "incomplete", "rejected_lines", "no_packages", "no_repos",
                         "enumerate_time_cap_hit", "coverage_gap_rose", "packages_dropped",
                         "github_malware_range_unparsed", "gh_counts")
FINISHED = re.compile(r"\A(20[0-9]{2})-([01][0-9])-([0-3][0-9])T([0-2][0-9]):([0-5][0-9]):([0-5][0-9])Z\Z")
JQ_VERSION = re.compile(r"\Ajq-([0-9]{1,3})\.([0-9]{1,3})(?:[.-][0-9A-Za-z.-]{0,40})?\n?\Z")

# Global installs, the same patterns on Linux and macOS (missing ones count
# as nothing). ~/.claude.json is left out: it can hold secrets, and each
# folder's own .mcp.json is read by the core already.
GLOBALS = {
    "npm_global_roots": ["~/.nvm/versions/node/*/lib/node_modules", "~/.npm-global/lib/node_modules",
                         "/usr/local/lib/node_modules", "/usr/lib/node_modules",
                         "/opt/homebrew/lib/node_modules"],
    "python_site_roots": ["~/.local/lib/python3.*/site-packages",
                          "~/Library/Python/3.*/lib/python/site-packages"],
    "cargo_installs": "~/.cargo/.crates2.json",
    "claude_versions_dir": "~/.local/share/claude/versions",
    "npx_cache_roots": ["~/.npm/_npx"],
    "plugin_roots": ["~/.claude/plugins"],
    "opencode_roots": [],
    "extension_roots": ["~/.vscode/extensions", "~/.cursor/extensions"],
    "mcp_configs": [],
}
# node_schedule false: Node's end-of-life list is on raw.githubusercontent.com,
# which setup doesn't add, and the plugin runs only in the sandbox. Node's
# release list (nodejs.org) is still asked, so its security releases count.
RUNTIMES = {"node_install_dirs": ["~/.nvm/versions/node"],
            "python_install_dirs": ["~/.local/share/uv/python"],
            "dpkg_status": "/var/lib/dpkg/status",
            "node_schedule": False, "python_cycle": True}
# The upstream core's example values.
LIMITS = {"osv": {"ver_batch": 200, "any_batch": 50, "follow_page_tokens": False, "retries": 2,
                  "retry_wait": 30, "severity_max": 150},
          "github": {"chunk_names": 500, "max_calls": 40},
          "enumerate_max_seconds": 240}

# One fixed line for each error word worth explaining.
HINTS = {
    "no_packages": "nothing to check was found in these folders or your global installs.",
    "run": "the scan stopped before it finished.",
    "incomplete": "the scan stopped before it finished.",
    "enumerate_time_cap_hit": ("listing packages ran out of time; name a smaller folder, or remove "
                               "worktrees you no longer need under its .claude/worktrees."),
    "osv_ver": "OSV couldn't be asked. Is api.osv.dev in your sandbox's network allowlist?",
    "rt_node": ("Node.js's release list (nodejs.org) couldn't be read, so Node's security "
                "releases weren't checked."),
    "rt_python": "CPython's release list (www.python.org) couldn't be read.",
    "rt_python_eol": ("CPython's release-cycle data (peps.python.org) couldn't be read, so its "
                      "end of life wasn't checked."),
    "gh_counts": ("the scan's own count of GitHub calls couldn't be read, so GitHub's malware "
                  "results may be incomplete."),
    "coverage_gap_rose": ("more went unscanned than in the last run (the line naming the gaps "
                          "that rose says which). It compares with the last run whatever "
                          "folders that one checked, so running on different folders can do "
                          "this; another run on the same folders clears it unless the gap "
                          "grows again."),
}
# The vendored core's scan_repo(max_depth=6) and its MAJOR_GAPS; tests pin
# both to the core. Below the read depth the core walks on by name and counts
# the lockfiles and runtime pins it doesn't read.
DEPTH = 6
WALK_DEPTH = 32         # scan_repo's walk_depth
DEEP_DIRS = 100000      # the core's DEEP_DIRS_MAX
WORKTREES = 256         # the core's WORKTREES_MAX, which the docs quote
DEPTH_CAPPED = ("osv: the scan reads {d} folders below each folder you named; deeper down it "
                "found at least {n} lockfile(s), runtime pin(s), Dockerfile(s) or virtualenv(s) "
                "it didn't read, so those weren't checked. The check doesn't record which ones; "
                "to check them, name the folder that holds them (up to 20 per run).")
WALK_CAPPED = ("osv: the walk below the read depth stopped early in at least one folder "
               "(past {w} folders below the folder you named or a worktree's own top, or past "
               "{m:,} folders below "
               "the read depth), so there may be more files it didn't read or count.")
MAJOR_GAPS = ("repos_missing", "lockfiles_unreadable", "tree_file_cap_hit", "repo_lockfile_cap_hit",
              "lockfiles_beyond_depth", "runtime_pins_beyond_depth", "repo_walk_cap_hit",
              "worktrees_unscanned", "repo_dirs_unreadable", "lists_unreadable", "cargo_installs_unreadable",
              "own_repos_line_unreadable", "package_json_unreadable", "mcp_configs_unreadable")
# Each GitHub source fails the same ways: its host unreachable, an answer
# off its shape, a partial answer, or more names than the run's calls cover
# ("capped").
HINTS.update(dict.fromkeys(("gh_npm", "gh_pip", "gh_rust", "gh_go"), (
    "GitHub's malware advisories couldn't be asked about everything you hold (see its word on "
    f"the sources line). Capped means more names than {LIMITS['github']['max_calls']} calls "
    "cover, your global installs included; GitHub also limits calls without a token each "
    "hour, so a second large run within the hour may say unreachable.")))
# Counted from each runtime row's fixed words (rt, pin, eol), never its
# version, so the expected Node gap and a real CPython one stay apart.
NODE_EOL_NOT_CHECKED = ("osv: end of life isn't checked for the {n} Node.js version(s) you hold: "
                        "its end-of-life list is on raw.githubusercontent.com, which setup "
                        "doesn't add. That's expected here.")
NODE_LINE_NOT_CHECKED = ("osv: {n} Node.js line pin(s) (such as .nvmrc 20 or FROM node:20) "
                         "weren't checked at all: a line pin is checked only for end of life, "
                         "which isn't checked here.")
PYTHON_EOL_NOT_CHECKED = ("osv: end of life wasn't checked this run for the {n} CPython "
                          "version(s) you hold (peps.python.org). That isn't expected.")
AGAIN = " It's INFO this run, and an ERROR if it happens again next run."
STALE_RESULT = ("osv: this run left no new result. The lines below are from an earlier run, "
                "or there are none.")
NEXT_ALERT = ("A malware record names a package you hold at that version. Don't run anything "
              "from it. Remove it or move to a version the advisory doesn't list, with your own "
              "package manager. Open daily.json in your own editor for its name; it isn't "
              "printed here.")
NEXT_SEVERE = ("A fix is out for a high or critical vulnerability in something you hold. Update "
               "it with your own package manager. The 7-day lane in the rules still applies in "
               "this version: a fix younger than 7 days waits, or you decide yourself. Open "
               "daily.json in your own editor for names and fixed versions; they aren't printed "
               "here.")


class Refuse(Exception):
    """The run can't start; the message is fixed text."""


def home_dir() -> str:
    """Your home folder from the password database, not $HOME, which a
    project's settings can set."""
    import pwd
    return pwd.getpwuid(os.getuid()).pw_dir


def results_dir(home: str) -> str:
    return os.path.join(home, *RESULTS)


def make_results(home: str) -> str:
    """The results folder: made mode 700 where missing, with no link on the
    way; yours, and made private again if it isn't."""
    path = home
    if os.path.islink(home) or not os.path.isdir(home):
        raise Refuse("your home folder isn't a plain folder")
    for part in RESULTS:
        path = os.path.join(path, part)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError:
            raise Refuse(f"{results_dir(home)} doesn't exist and can't be made from the "
                         "sandbox. Start a new session after choosing setup's OSV option (the "
                         "plugin's session hook makes it), then run this again.") from None
        if os.path.islink(path) or not os.path.isdir(path):
            raise Refuse("a link or file sits on the results folder's path")
    # Checked and fixed through the folder itself, so a link swapped in after
    # the loop can't redirect the chmod.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid():
            raise Refuse("the results folder isn't yours")
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return path


def _same(a: str, b: str) -> bool:
    """The same folder on disk, whatever the spelling (macOS folds case)."""
    try:
        x, y = os.stat(a), os.stat(b)
    except OSError:
        return False
    return (x.st_dev, x.st_ino) == (y.st_dev, y.st_ino)


def _up(path: str) -> list:
    """The path and each folder above it, up to /."""
    out = [path]
    while os.path.dirname(out[-1]) != out[-1]:
        out.append(os.path.dirname(out[-1]))
    return out


def _above_or_home(real: str, home: str) -> bool:
    home = os.path.realpath(home)
    return (real == home or home.startswith(real.rstrip("/") + "/")
            or any(_same(real, h) for h in _up(home)))


def _system(real: str) -> bool:
    return (real == "/" or real in apply.TOP_DIRS
            or any(real == d or real.startswith(d + "/") for d in apply.SYSTEM_DIRS)
            or any(_same(real, d) for d in apply.TOP_DIRS)
            or any(_same(a, d) for a in _up(real) for d in apply.SYSTEM_DIRS))


def roots(folders: list, cwd: str, home: str = "/nonexistent") -> dict:
    """{config name: real folder} for the folders named, else the working one.
    Never /, your home folder or one above it, or a system or top-level
    folder: those would send every project's names, and other users'."""
    folders = folders or [cwd]
    if len(folders) > MAX_ROOTS:
        raise Refuse(f"name at most {MAX_ROOTS} folders")
    out: dict = {}
    taken: set = set()
    seen: set = set()
    for folder in folders:
        path = os.path.join(cwd, folder)
        if os.path.islink(path.rstrip("/") or "/") or not os.path.isdir(path):
            raise Refuse("each folder must exist and not be a link")
        real = os.path.realpath(path)
        if _above_or_home(real, home) or _system(real):
            raise Refuse("name a project folder, not the whole disk, your home folder, a "
                         "folder above it or a system folder")
        if real in seen:
            continue
        seen.add(real)
        out[root_name(real, taken)] = real
    return out


def root_name(path: str, taken: set) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "-", os.path.basename(path.rstrip("/")) or "root")
    base = base.strip(".-")[:MAX_NAME] or "root"
    name, n = base, 2
    while name in taken:
        name = f"{base[:MAX_NAME - 4]}-{n}"
        n += 1
    taken.add(name)
    return name


def config(folders: dict) -> dict:
    conf = {"repos": dict(folders), "repos_not_local": [], "extra_lockfiles": [],
            "vetted_lists": [], "go_module_lists": [], "runtimes": json.loads(json.dumps(RUNTIMES))}
    conf.update(json.loads(json.dumps(GLOBALS)))
    conf.update(json.loads(json.dumps(LIMITS)))
    if sys.platform == "darwin":
        conf["runtimes"]["dpkg_status"] = ""
    return conf


def tool(name: str) -> Optional[str]:
    """A system copy of `name`: in /usr/bin or /bin, resolving to a regular,
    executable file that you don't own and can't write, in a folder the same.
    (Not "owned by root": inside the sandbox on Linux, root's files show as
    owned by an unmapped user, nobody.) Returns the resolved path, so a link
    isn't followed again later. None otherwise."""
    me = os.getuid()
    for folder in TOOL_DIRS:
        real = os.path.realpath(os.path.join(folder, name))
        try:
            info = os.stat(real)
            parent = os.stat(os.path.dirname(real))
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            continue
        if me in (info.st_uid, parent.st_uid) or (info.st_mode | parent.st_mode) & 0o022:
            continue
        if os.access(real, os.W_OK) or os.access(os.path.dirname(real), os.W_OK):
            continue
        return real
    return None


def jq_ok(jq: str) -> bool:
    try:
        out = subprocess.run([jq, "--version"], capture_output=True, timeout=TOOL_TIME_LIMIT,
                             env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"},
                             stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    m = JQ_VERSION.match(out.stdout.decode("ascii", "replace"))
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (1, 6)


def tools() -> tuple:
    """({name: path}, [problem lines])."""
    found, problems = {}, []
    for name in TOOLS:
        path = tool(name)
        if path is None:
            problems.append(f"{name}: no system copy in /usr/bin or /bin that you can't change")
        else:
            found[name] = path
    if "jq" in found and not jq_ok(found["jq"]):
        problems.append("jq: version 1.6 or later is needed")
    return found, problems


def environment(env: dict, home: str) -> dict:
    """Only what the core needs, plus the sandbox's proxy variables. Caller
    CA and curl settings are dropped, as in the upstream check."""
    out = {"PATH": "/usr/bin:/bin", "HOME": home, "LC_ALL": "C"}
    tmp = env.get("TMPDIR")
    if isinstance(tmp, str) and os.path.isabs(tmp):
        out["TMPDIR"] = tmp
    for name in PROXY_VARS:
        if isinstance(env.get(name), str) and env[name]:
            out[name] = env[name]
    return out


def write_config(results: str, conf: dict) -> str:
    """config.json in the results folder, through a new file of an
    unguessable name and a rename."""
    path = os.path.join(results, "config.json")
    fd, tmp = tempfile.mkstemp(prefix=".config.json.", dir=results)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(conf, fh, indent=1)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def run_core(conf_path: str, results: str, found: dict, env: dict, core: str = CORE) -> int:
    """The core's exit code. Its own output carries package names, so none
    of it is kept."""
    argv = [found["bash"], os.path.join(core, "osv-scan.sh"), "--config", conf_path,
            "--out", results, "--curl", found["curl"], "--jq", found["jq"],
            "--python", found["python3"]]
    _SIGNALS["defer"] = True  # a TERM while the core starts waits for proc
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=env, cwd=results,
                                start_new_session=True)
    finally:
        _SIGNALS["defer"] = False
    try:
        if _SIGNALS["pending"]:
            raise SystemExit(128 + _SIGNALS["pending"])
        return proc.wait(timeout=CORE_TIME_LIMIT)
    except subprocess.TimeoutExpired:
        _stop(proc)
        return 2
    except BaseException:
        _stop(proc)
        raise


def _stop(proc) -> None:
    """TERM first, so the core's trap writes a fixed ERROR result; then KILL.
    The core runs in its own session, so curl and jq go with it."""
    for sig, wait in ((signal.SIGTERM, 30), (signal.SIGKILL, 5)):
        try:
            os.killpg(proc.pid, sig)
            proc.wait(timeout=wait)
            break
        except (OSError, subprocess.TimeoutExpired):
            continue
    try:  # anything the leader left behind in its group
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


# "defer" while Popen runs: a signal then is held in "pending" until proc
# exists, so run_core can stop it rather than leave it running.
_SIGNALS = {"defer": False, "pending": 0}


def _exit_on(signum, _frame) -> None:
    # One stop is enough: a second TERM or HUP mustn't cut _stop short.
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)
    if _SIGNALS["defer"]:
        _SIGNALS["pending"] = signum
        return
    raise SystemExit(128 + signum)


def stop_with_the_runner() -> None:
    """TERM and HUP end the runner through SystemExit, so run_core stops the
    core's process group too, rather than leaving it running on its own."""
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _exit_on)


def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constants(name):
    raise ValueError(name)


def read_result(path: str) -> Optional[dict]:
    """daily.json as parsed JSON, or None: no link followed, no FIFO waited
    on, at most 32 MiB, no duplicate keys, NaN or Infinity."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, size = [], 0
        while size <= MAX_RESULT_BYTES:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_RESULT_BYTES:
            return None
        data = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_no_constants)
    except (OSError, ValueError, RecursionError):
        return None
    finally:
        os.close(fd)
    return data if isinstance(data, dict) else None


def count(value) -> Optional[int]:
    if type(value) is int and 0 <= value <= MAX_COUNT:
        return value
    return None


def finished_at(value) -> Optional[float]:
    """Seconds since the epoch for the core's own time shape, else None."""
    if not isinstance(value, str):
        return None
    m = FINISHED.match(value)
    if not m:
        return None
    try:
        import calendar
        return float(calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")))
    except (ValueError, OverflowError):
        return None


def _num(value) -> str:
    n = count(value)
    return "unreadable" if n is None else str(n)


def _split(value, keys) -> str:
    if not isinstance(value, dict):
        return "unreadable"
    return ", ".join(f"{k} {_num(value.get(k))}" for k in keys)


def runtime_gaps(rows) -> list:
    """Fixed lines for the held runtimes this check couldn't decide, counted
    from each row's rt, pin and eol words only."""
    if not isinstance(rows, list):
        return []
    # The cap bounds the work on a forged file; the counts line isn't capped,
    # so past it these lines can undercount (digits either way).
    rows = [r for r in rows[:10000] if isinstance(r, dict)]

    def n(rt, **want):
        return sum(1 for r in rows if r.get("rt") == rt and r.get("eol") == "not_checked"
                   and all(r.get(k) == v for k, v in want.items()))
    out = []
    if n("node"):
        out.append(NODE_EOL_NOT_CHECKED.format(n=n("node")))
    if n("node", pin="line"):
        out.append(NODE_LINE_NOT_CHECKED.format(n=n("node", pin="line")))
    if n("python"):
        out.append(PYTHON_EOL_NOT_CHECKED.format(n=n("python")))
    return out


def depth_capped(data) -> int:
    """How many lockfiles and runtime pins the scan found below its read depth
    and didn't read (the core's lockfiles_beyond_depth plus
    runtime_pins_beyond_depth); 0 when none or off shape."""
    cov = data.get("coverage") if isinstance(data, dict) else None
    if not isinstance(cov, dict):
        return 0
    return sum(count(cov.get(k)) or 0 for k in ("lockfiles_beyond_depth", "runtime_pins_beyond_depth"))


def walk_capped(data) -> bool:
    """Whether the walk below the read depth stopped early (the core's
    repo_walk_cap_hit above 0)."""
    cov = data.get("coverage") if isinstance(data, dict) else None
    return bool(count(cov.get("repo_walk_cap_hit"))) if isinstance(cov, dict) else False


def gaps_rose(value) -> list:
    """One fixed line naming the major coverage gaps that rose since the last
    run (the core's coverage_gaps_rose, kept to its MAJOR_GAPS words), or []."""
    if not isinstance(value, list):
        return []
    value = value[:1000]  # bounds the work on a forged file
    words = sorted({w for w in value if isinstance(w, str) and w in MAJOR_GAPS})
    if not words:
        return []
    return ["osv: major gaps that rose since the last run (all of them when there's no "
            "earlier result to compare with): " + ", ".join(words)]


def summary(data: Optional[dict], results: str, now: Optional[float] = None) -> list:
    """Fixed lines for the model and you; only digits and fixed words vary."""
    now = time.time() if now is None else now
    lines = [f"osv: results in {os.path.join(results, 'daily.json')}"]
    if data is None:
        return lines + ["osv: no result can be read."]
    level = data.get("level") if data.get("level") in LEVELS else "unreadable"
    notice = data.get("cve_notice") if data.get("cve_notice") in NOTICES else "unreadable"
    if data.get("schema") != "sd-osv/1":
        level = notice = "unreadable"
    lines.append(f"osv: level {level}, notice {notice}")
    done = finished_at(data.get("finished"))
    if done is None:
        lines.append("osv: no valid finish time (a run that stopped, or a placeholder).")
    elif done > now + 3600:
        lines.append("osv: the finish time is in the future; this result can't be trusted.")
    else:
        lines.append(f"osv: finished {int((now - done) // 3600)} hours ago")
    errors = data.get("errors")
    if isinstance(errors, list):
        words = [e for e in errors if isinstance(e, str) and e in ERROR_WORDS]
        other = len(errors) - len(words)
        if words or other:
            lines.append("osv: errors: " + ", ".join(sorted(set(words))
                                                   + ([f"other {other}"] if other else [])))
        for word in sorted(set(words)):
            if word in HINTS:
                lines.append(f"osv: {word}: {HINTS[word]}")
    else:
        words = []
    sources = data.get("sources")
    if isinstance(sources, dict):
        shown = [f"{k} {sources[k] if sources.get(k) in SOURCE_WORDS else 'unreadable'}"
                 for k in SOURCES if k in sources]
        if shown:
            lines.append("osv: sources: " + ", ".join(shown))
        # A source down once after a good run is INFO, not an error, so its
        # hint would be missing; say it here, with what happens next. Only
        # for a readable result whose errors are a list, only "unreachable"
        # (the core always counts "malformed" as an error), and never for
        # OSV's own sources (unreachable is always an error for those).
        if isinstance(errors, list) and level != "unreadable":
            for k in SOURCES:
                if (k in HINTS and k not in words and not k.startswith("osv_")
                        and sources.get(k) == "unreachable"):
                    lines.append(f"osv: {k}: {HINTS[k]}{AGAIN}")
    counts = data.get("counts")
    gh_lost = isinstance(errors, list) and "gh_counts" in errors
    if isinstance(counts, dict) and level != "unreadable":
        lines += [
            f"osv: packages checked {_num(counts.get('packages'))}",
            f"osv: malware records at a held version {_num(counts.get('alerts'))}",
            f"osv: new issues {_num(counts.get('new_issues'))} "
            f"({_split(counts.get('new_issues_by_severity'), SEVS)}); "
            f"high or critical with a fix {_num(counts.get('new_severe_with_fix'))}",
            f"osv: new issues by ecosystem: {_split(counts.get('new_issues_by_ecosystem'), ECOS)}",
            f"osv: held issues {_num(counts.get('held_issues'))}; high or critical with a fix "
            f"{_num(counts.get('held_severe_with_fix'))}, without one "
            f"{_num(counts.get('held_severe_no_fix'))}; not rated {_num(counts.get('held_unrated'))}",
            f"osv: runtimes: {_split(counts.get('runtime_findings'), RT_FINDINGS)}",
            # With gh_counts the core writes 0 and 0: the counts were lost.
            f"osv: GitHub calls planned "
            f"{_num(None if gh_lost else counts.get('github_calls_planned'))}, dropped "
            f"{_num(None if gh_lost else counts.get('github_calls_dropped'))}",
        ]
        lines += runtime_gaps(data.get("runtimes"))
    if level != "unreadable":
        lines += gaps_rose(data.get("coverage_gaps_rose"))
        capped = depth_capped(data)
        if capped:
            lines.append(DEPTH_CAPPED.format(d=DEPTH, n=capped))
        if walk_capped(data):
            lines.append(WALK_CAPPED.format(w=WALK_DEPTH, m=DEEP_DIRS))
    if level == "ALERT":
        lines.append("osv: " + NEXT_ALERT)
    if notice == "severe" or (isinstance(counts, dict) and count(counts.get("held_severe_with_fix"))):
        lines.append("osv: " + NEXT_SEVERE)
    return lines


def run(folders: list, cwd: str, home: str, env: dict, found: Optional[dict] = None,
        core: str = CORE, make_config: Callable = config) -> int:
    folders_map = roots(folders, cwd, home)
    if found is None:
        found, problems = tools()
        if problems:
            raise Refuse("the OSV check is off: " + "; ".join(problems))
    results = make_results(home)
    conf_path = write_config(results, make_config(folders_map))
    started = time.time()
    code = run_core(conf_path, results, found, environment(env, home), core)
    data = read_result(os.path.join(results, "daily.json"))
    done = finished_at(data.get("finished")) if isinstance(data, dict) else None
    if done is None or done < int(started) or done > time.time() + 60:
        print(STALE_RESULT)
    for line in summary(data, results):
        print(line)
    return code if code in (0, 1, 2) else 2


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    if os.name != "posix":
        print("osv: not available on Windows outside WSL.")
        return 3
    try:
        home = home_dir()
    except KeyError:
        print("osv: your user has no entry in the password database, so the home folder "
              "can't be found.")
        return 3
    try:
        if args[:1] == ["run"]:
            try:
                cwd = os.getcwd()
            except OSError:
                print("osv: the working folder no longer exists. Start from a folder that does.")
                return 3
            stop_with_the_runner()
            return run(args[1:], cwd, home, dict(os.environ))
        if args == ["show"]:
            for line in summary(read_result(os.path.join(results_dir(home), "daily.json")),
                                results_dir(home)):
                print(line)
            return 0
        if args == ["tools"]:
            _found, problems = tools()
            for line in problems or ["all four tools found"]:
                print("osv: " + line)
            return 1 if problems else 0
    except Refuse as why:
        print(f"osv: {why}")
        return 3
    except OSError:
        print("osv: the results folder or the scan couldn't be written or started. Run "
              "/stranger-danger:doctor to check the OSV setup.")
        return 3
    print("usage: osv.py run [FOLDER ...] | show | tools", file=sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main())
