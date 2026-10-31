#!/usr/bin/env python3
"""terminal-gate: approve-to-run for the desktop app's Terminal panel.

A hook (PreToolUse on the desktop app's terminal tools, PostToolUse on run_in_terminal)
that holds the panel's tools to a short lane of check lines and nothing else.
The panel's shell runs outside the sandbox, so a line sent there is the user's
to approve, and the gate refuses every line that is not one of these shapes
(full paths, at most 200 characters, a new tab: no tab_id, no cwd, from the main
session of the desktop app, in a permission mode where a hook "ask" reaches the
user):

    file check:     [/usr/bin/sudo -k ]/usr/bin/sha256sum <path>
                    [/usr/bin/sudo -k ]/usr/bin/stat -c '%F %U %G %a %s %n' <path>
    unit check:     /usr/bin/systemctl [--user ]--no-pager is-active|is-enabled <unit>
    password check: /usr/bin/sudo -k /usr/bin/true

A line that passes is answered "ask", so the user's own prompt is the OK for
that one line, once. Everything else is denied: installs, unit actions, status
checks, any other terminal tool. <path> is absolute and plain (no "..", "." or
empty part), strictly under one of the lane's folders or one of its files,
as written, with its folder resolved and a last-part link followed; never a
secret's name, never a path a sandbox denyRead or Read deny rule lists, and a
regular file at the end must have exactly one hard link.

The gate is off (every line denied) while any of these holds: the settings
files can't be read, a settings file allows a terminal tool, enables a plugin
other than this one (its hooks are not read here), limits rules to managed
ones, has a PermissionRequest hook or a hook of its own on the terminal tools,
a server-managed settings cache exists, or the user settings' ask list lacks
mcp__terminal__run_in_terminal. It reads no project folder it was not given:
it needs the event's absolute cwd or CLAUDE_PROJECT_DIR.

read_terminal is allowed only on a tab this session opened through an approved
line, once, within READ_WINDOW seconds, and never on a `sudo` line's tab (a
password typed there by mistake would show). stop_terminal_tab only on such a
tab and only with close: true.

Failure: bad input or any error exits 2, which blocks; the hook command ends
`|| exit 2`, so a crash blocks too. Two timers armed first thing end a hang
below the hook timeout (a Python alarm that exits 2, and faulthandler's exit as
a C-level backstop). State (pending lines and owned tabs) lives in
~/.local/state/stranger-danger/terminal-gate/, mode 0700. Standard library
only; run as `python3 -I`.
"""
from __future__ import annotations

import faulthandler
import os
import signal
import sys

ALARM_SECONDS = 6
WATCHDOG_SECONDS = 8
_WATCHDOG_FILE = None
_ARMED = [False]


def _on_alarm(signum, frame):
    os._exit(2)


def arm_timers() -> None:
    """Arm both timers once; a second call changes nothing."""
    global _WATCHDOG_FILE
    if _ARMED[0]:
        return
    _WATCHDOG_FILE = open(os.devnull, "w")   # faulthandler keeps only the descriptor
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, ALARM_SECONDS)
    faulthandler.dump_traceback_later(WATCHDOG_SECONDS, exit=True, file=_WATCHDOG_FILE)
    _ARMED[0] = True


def disarm_timers() -> None:
    if not _ARMED[0]:
        return
    signal.setitimer(signal.ITIMER_REAL, 0)
    faulthandler.cancel_dump_traceback_later()


if __name__ == "__main__":
    try:
        arm_timers()
    except Exception as exc:  # noqa: BLE001 - no timers means no safe run: block
        os.write(2, f"terminal-gate: blocked (no watchdog: {type(exc).__name__})\n".encode())
        os._exit(2)

import fcntl
import fnmatch
import json
import re
import stat
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _config import home_dir  # noqa: E402
from _log import log_deny  # noqa: E402

PREFIX = "mcp__terminal__"
RUN = "run_in_terminal"
TTL = 1800          # an approved line waits this long for its result
READ_WINDOW = 300   # an owned tab may be read this long after its line was typed
LOCK_WAIT = 2.0     # seconds to wait for the state lock before blocking
MAX_LINE = 200
ALLOW, ASK, DENY = "allow", "ask", "deny"
ENTRYPOINTS = frozenset({"claude-desktop"})
# Modes in which a hook "ask" reaches the user as a prompt.
ASK_MODES = frozenset({"default", "acceptEdits", "auto"})
ASK_ENTRY = "mcp__terminal__run_in_terminal"
OWN_PLUGIN = "stranger-danger"
MANAGED_FILE = Path("/etc/claude-code/managed-settings.json")
MANAGED_DIR = Path("/etc/claude-code/managed-settings.d")
TERMINAL_TOOLS = tuple(PREFIX + t for t in (RUN, "read_terminal", "stop_terminal_tab"))

# Relative to the account's home folder, or absolute.
ALLOWED_DIRS = ("/usr/local/bin", "/usr/local/lib", "/etc/systemd/system", "/etc/systemd/user")
HOME_ALLOWED_DIRS = (".claude/hooks",)
HOME_ALLOWED_FILES = (".claude/settings.json",)
SECRET_NAMES = (".env", ".env.*", "*.env", "*keypair*", "*keystore*", "*.jks", "utc--*", "*credential*",
                "*secret*", "*token*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "id_ecdsa*",
                "id_dsa*", "auth.json", ".netrc", ".npmrc", ".pypirc", ".git-credentials", "*.gpg", "*.kdbx",
                "*passw*", "*apikey*", "*.p8", "*.ovpn", "*.asc", "*.age")

PATH_RE = re.compile(r"/[A-Za-z0-9._/@-]+")
UNIT_RE = re.compile(r"[A-Za-z0-9_@][A-Za-z0-9@_.-]{0,120}\.(?:service|timer|socket)")
SUDO = "/usr/bin/sudo -k "
FILE_LINE_RE = re.compile(r"(?P<sudo>/usr/bin/sudo -k )?"
                          r"(?P<tool>/usr/bin/sha256sum|/usr/bin/stat -c '%F %U %G %a %s %n') (?P<path>\S+)")
UNIT_LINE_RE = re.compile(r"/usr/bin/systemctl (?:--user )?--no-pager (?:is-active|is-enabled) (?P<unit>\S+)")
PASSWORD_LINE = "/usr/bin/sudo -k /usr/bin/true"
TITLE_RE = re.compile(r"[A-Za-z0-9 ._-]{1,40}")
TAB_RE = re.compile(r"[A-Za-z0-9_-]{1,40}")
RUN_KEYS = frozenset({"command", "title"})
READ_KEYS = frozenset({"tab_id", "lines", "wait_for_output_ms"})
STOP_KEYS = frozenset({"tab_id", "close"})


class GateError(Exception):
    pass


def _home() -> Path:
    return Path(home_dir())


def state_dir() -> Path:
    return _home() / ".local/state/stranger-danger/terminal-gate"


def read_regular(path: Path, limit: int = 1 << 20) -> bytes:
    """Read a regular file without following a symlink or blocking on a FIFO or device."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_NOCTTY)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise GateError(f"{path} is not a regular file")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            if size > limit:
                raise GateError(f"{path} is larger than {limit} bytes")
            chunks.append(chunk)
    finally:
        os.close(fd)


# ------------------------------------------------------------- settings

def _project_roots(event: dict) -> list:
    roots = []
    for value in (event.get("cwd"), os.environ.get("CLAUDE_PROJECT_DIR")):
        if isinstance(value, str) and value.startswith("/"):
            roots.append(Path(os.path.normpath(value)))
    return roots


def config_dir() -> Path:
    """The active profile folder: CLAUDE_CONFIG_DIR when set (it must be absolute), else ~/.claude."""
    value = os.environ.get("CLAUDE_CONFIG_DIR")
    if not value:
        return _home() / ".claude"
    if not value.startswith("/"):
        raise GateError("CLAUDE_CONFIG_DIR is not an absolute path, so the active settings can't be found")
    return Path(os.path.normpath(value))


def user_settings() -> Path:
    return config_dir() / "settings.json"


def _settings_files(event: dict) -> list:
    home = _home()
    files = [user_settings(), config_dir() / "settings.local.json",
             home / ".claude/settings.json", home / ".claude/settings.local.json", MANAGED_FILE]
    try:
        files += sorted(p for p in MANAGED_DIR.iterdir()
                        if p.name.endswith(".json"))
    except FileNotFoundError:
        pass
    for root in _project_roots(event):
        for folder in (root, *root.parents):
            files += [folder / ".claude/settings.json", folder / ".claude/settings.local.json"]
    seen, out = set(), []
    for path in files:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def _load(path: Path):
    try:
        raw = read_regular(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise GateError(f"cannot read {path}: {exc.__class__.__name__}") from exc
    if not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise GateError(f"cannot parse {path}") from exc
    if not isinstance(data, dict):
        raise GateError(f"{path} is not an object")
    return data


def _allows_terminal(entry) -> bool:
    if not isinstance(entry, str):
        return False
    name = entry.split("(", 1)[0].strip()
    return "terminal" in name.lower() or "*" in name


def _matches_terminal(matcher) -> bool:
    if matcher in (None, "", "*") or not isinstance(matcher, str):
        return True
    try:
        return any(re.search(matcher, name) for name in TERMINAL_TOOLS)
    except re.error:
        return True


def _hooks_problem(path: Path, hooks):
    """Another hook that could answer the user's prompt or rewrite a terminal call."""
    if hooks is None:
        return None
    if not isinstance(hooks, dict):
        return f"{path} has hooks it can't read"
    if hooks.get("PermissionRequest"):
        return f"{path} has a PermissionRequest hook, which could answer the prompt"
    entries = hooks.get("PreToolUse") or []
    if not isinstance(entries, list):
        return f"{path} has PreToolUse hooks it can't read"
    for entry in entries:
        if not isinstance(entry, dict):
            return f"{path} has PreToolUse hooks it can't read"
        if _matches_terminal(entry.get("matcher")):
            return f"{path} has a PreToolUse hook on terminal tools, which could change the line"
    return None


def _other_plugin(plugins, own_keys: set) -> bool:
    """True when enabledPlugins names a plugin other than this one; the enabled keys of this
    plugin go into own_keys, which is shared across settings files (one key in all of them)."""
    if not plugins:
        return False
    if not isinstance(plugins, dict):
        return True
    for key, value in plugins.items():
        if not value:
            continue
        if not (isinstance(key, str) and "@" in key and key.split("@", 1)[0] == OWN_PLUGIN):
            return True
        own_keys.add(key)
    return len(own_keys) > 1


def _read_denies(perms) -> list:
    deny = perms.get("deny") if isinstance(perms, dict) else None
    out = []
    for entry in deny if isinstance(deny, list) else []:
        if isinstance(entry, str) and entry.startswith("Read(") and entry.endswith(")"):
            out.append(entry[5:-1])
    return out


def settings_problem(event: dict):
    """(why approve-to-run is off or None, every sandbox denyRead and Read-deny pattern found)."""
    deny_read: list = []
    user = None
    if any(os.path.lexists(d / "remote-settings.json") for d in (_home() / ".claude", config_dir())):
        return ("a server-managed settings cache, remote-settings.json, exists; it applies as "
                "managed policy, so approve-to-run is off"), deny_read
    if not _project_roots(event):
        return ("neither the event's cwd nor CLAUDE_PROJECT_DIR is an absolute path, so project settings "
                "can't be read and approve-to-run is off"), deny_read
    own_keys: set = set()
    for path in _settings_files(event):
        data = _load(path)
        if data is None:
            continue
        if path == user_settings():
            user = data
        perms = data.get("permissions")
        if isinstance(perms, dict):
            allow = perms.get("allow")
            if isinstance(allow, list) and any(_allows_terminal(e) for e in allow):
                return f"{path} allows a terminal tool, so approve-to-run is off", deny_read
        if _other_plugin(data.get("enabledPlugins"), own_keys):
            return (f"{path} enables a plugin other than {OWN_PLUGIN}, whose hooks the gate doesn't read, "
                    "so approve-to-run is off"), deny_read
        if data.get("allowManagedPermissionRulesOnly"):
            return f"{path} limits permission rules to managed ones, so the user ask list may not apply", deny_read
        problem = _hooks_problem(path, data.get("hooks"))
        if problem:
            return problem, deny_read
        deny_read += _read_denies(perms)
        sandbox = data.get("sandbox")
        fs = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
        patterns = fs.get("denyRead") if isinstance(fs, dict) else None
        if isinstance(patterns, list):
            deny_read += [p for p in patterns if isinstance(p, str)]
    perms = user.get("permissions") if isinstance(user, dict) else None
    ask = perms.get("ask") if isinstance(perms, dict) else None
    if not (isinstance(ask, list) and ASK_ENTRY in ask):
        return f"the user settings' ask list doesn't hold {ASK_ENTRY}, so approve-to-run is off", deny_read
    return None, deny_read


def _denied_by(path: str, patterns: list) -> bool:
    home = str(_home())
    expanded = []
    for raw in patterns:
        pattern = raw[:-1] if raw.endswith("/") and len(raw) > 1 else raw
        if pattern.startswith("~/"):
            pattern = home + pattern[1:]
        elif pattern.startswith("//"):
            pattern = pattern[1:]
        elif pattern.startswith("/") and not pattern.startswith("/**/"):
            # One slash: a settings rule reads it as relative to a folder; also try it under the
            # profile and home folders, which can only refuse more.
            expanded += [str(config_dir()) + pattern, home + "/.claude" + pattern]
        expanded.append(pattern)
    for pattern in expanded:
        if not pattern.startswith("/"):
            # Relative to some project: match it anywhere, which can only refuse more.
            pattern = "/**/" + re.sub(r"^(?:\./)+", "", pattern).lstrip("/")
        if pattern.startswith("/**/"):
            tail = pattern[4:]
            parts = path.split("/")
            if any(fnmatch.fnmatchcase("/".join(parts[i:]), tail) or fnmatch.fnmatchcase(parts[i], tail)
                   for i in range(1, len(parts))):
                return True
        elif pattern.startswith("/"):
            if path == pattern or path.startswith(pattern + "/") or fnmatch.fnmatchcase(path, pattern) \
                    or fnmatch.fnmatchcase(path, pattern + "/*"):
                return True
    return False


# ------------------------------------------------------------- the line

def _lane():
    home = str(_home())
    dirs = ALLOWED_DIRS + tuple(f"{home}/{d}" for d in HOME_ALLOWED_DIRS)
    files = tuple(f"{home}/{f}" for f in HOME_ALLOWED_FILES)
    return dirs, files


def _under(path: str, roots) -> bool:
    return any(path.startswith(r + "/") for r in roots)


def _path_problem(path: str, deny_read: list, sudo: bool = False):
    if not PATH_RE.fullmatch(path) or ".." in path or "//" in path:
        return "the path isn't a plain absolute path"
    if any(seg in ("", ".") for seg in path.split("/")[1:]):
        return "the path has an empty or '.' segment"
    dirs, files = _lane()
    if not (_under(path, dirs) or path in files):
        return f"{path} isn't under a folder the lane allows"
    folder, name = os.path.split(path)
    try:
        resolved = os.path.join(os.path.realpath(folder, strict=True), name)
    except OSError as exc:
        return f"can't resolve the folder ({exc.__class__.__name__}); check it by hand"
    target = os.path.realpath(resolved)
    if sudo and any(p == home or p.startswith(home + "/") for p in (path, resolved, target)
                    for home in (str(_home()),)):
        return "sudo is only for files outside your home folder"
    for p in dict.fromkeys((path, resolved, target)):
        shown = p if p == path else "a resolved or link-target path"
        if not (_under(p, dirs) or p in files):
            return f"{shown} isn't under a folder the lane allows"
        base = p.rsplit("/", 1)[1].lower()
        if any(fnmatch.fnmatchcase(base, pat) for pat in SECRET_NAMES):
            return f"{shown} looks like a secret file"
        if _denied_by(p, deny_read):
            return f"{shown} is denied by a sandbox denyRead or Read deny rule"
    try:
        tst = os.lstat(target)
    except OSError:
        return None
    if stat.S_ISREG(tst.st_mode) and tst.st_nlink != 1:
        return "the file has more than one hard link, so it may be a second name for a protected file"
    return None


def line_problem(command, deny_read: list):
    """None when the line is one the lane allows."""
    if not isinstance(command, str):
        return "the command isn't a string"
    if len(command) > MAX_LINE:
        return f"the line is longer than {MAX_LINE} characters"
    if command == PASSWORD_LINE:
        return None
    m = UNIT_LINE_RE.fullmatch(command)
    if m:
        return None if UNIT_RE.fullmatch(m["unit"]) else "the unit name isn't a plain unit name"
    m = FILE_LINE_RE.fullmatch(command)
    if not m:
        return "the line isn't one of the approve-to-run shapes"
    problem = _path_problem(m["path"], deny_read, sudo=bool(m["sudo"]))
    if problem:
        return problem
    if m["tool"] == "/usr/bin/sha256sum":
        try:
            st = os.lstat(m["path"])
        except OSError as exc:
            return f"can't check the path is a regular file ({exc.__class__.__name__})"
        if not stat.S_ISREG(st.st_mode):
            return "a sha256sum path must be a regular file (not a link, folder or device)"
    return None


# ------------------------------------------------------------- state

def _open_dir() -> int:
    path = state_dir()
    os.makedirs(path, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if st.st_uid != os.getuid() or st.st_mode & 0o022:
        os.close(fd)
        raise GateError("the state folder isn't yours alone")
    return fd


class State:
    """The pending lines and owned tabs, under an exclusive lock."""

    def __enter__(self):
        self.dir_fd = _open_dir()
        self.lock_fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.dir_fd)
        # Never wait long: a hook that times out may let the call through, so a held lock blocks.
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    os.close(self.lock_fd)
                    os.close(self.dir_fd)
                    raise GateError("the state lock is held") from None
                time.sleep(0.05)
        try:
            fd = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.dir_fd)
        except FileNotFoundError:
            self.data = {}
        else:
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise GateError("state.json isn't a regular file")
                self.data = json.loads(os.read(fd, 1 << 20) or b"{}")
            finally:
                os.close(fd)
        if not isinstance(self.data, dict):
            raise GateError("state.json isn't an object")
        now = time.time()
        for key in ("pending", "tabs"):
            items = self.data.get(key)
            self.data[key] = [i for i in items if isinstance(i, dict) and isinstance(i.get("ts"), (int, float))
                              and 0 <= now - i["ts"] < TTL] if isinstance(items, list) else []
        return self

    def save(self) -> None:
        tmp = f"state.json.{os.getpid()}.{os.urandom(6).hex()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.dir_fd)
        try:
            os.write(fd, json.dumps(self.data).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, "state.json", src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd)

    def __exit__(self, *exc):
        os.close(self.lock_fd)
        os.close(self.dir_fd)
        return False


def _owned(state: State, session: str, tab):
    if not (isinstance(tab, str) and TAB_RE.fullmatch(tab)):
        return None
    for item in state.data["tabs"]:
        if item.get("session") == session and item.get("tab") == tab:
            return item
    return None


# ------------------------------------------------------------- decisions

def decide(event: dict):
    """(ASK | ALLOW | DENY, reason) for one PreToolUse event. Raises when it can't check."""
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.startswith(PREFIX):
        return DENY, "a terminal-like tool under a name approve-to-run doesn't cover"
    tool = tool_name[len(PREFIX):]
    if event.get("agent_id") is not None:
        return DENY, "terminal tools are for the main session only; a subagent reports BLOCKED to its parent"
    entry = os.environ.get("CLAUDE_CODE_ENTRYPOINT")
    if entry not in ENTRYPOINTS:
        return DENY, f"terminal tools are for the desktop app's interactive sessions, not entrypoint {entry!r}"
    session = event.get("session_id")
    if not (isinstance(session, str) and session):
        return DENY, "no session_id"
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return DENY, "tool_input isn't an object"

    if tool == RUN:
        extra = set(tool_input) - RUN_KEYS
        if extra:
            return DENY, f"run_in_terminal may not set {len(extra)} other key(s) (a new tab only, no cwd)"
        title = tool_input.get("title")
        if title is not None and not (isinstance(title, str) and TITLE_RE.fullmatch(title)):
            return DENY, "the tab title must be 1-40 letters, digits, spaces, '.', '_' or '-'"
        mode = event.get("permission_mode")
        if mode not in ASK_MODES:
            return DENY, f"prompts may not reach you in permission mode {mode!r}, so approve-to-run is off"
        problem, deny_read = settings_problem(event)
        if problem:
            return DENY, problem
        problem = line_problem(tool_input.get("command"), deny_read)
        if problem:
            return DENY, f"not an approve-to-run line: {problem}"
        use_id = event.get("tool_use_id")
        with State() as state:
            state.data["pending"].append({"session": session, "tool_use_id": use_id if isinstance(use_id, str)
                                          else None, "command": tool_input["command"], "ts": time.time()})
            state.save()
        root = (" Root: a password prompt comes in the new tab. Type your password only at a visible"
                " [sudo] password prompt; if there is none, close the tab without typing.") if tool_input["command"].startswith(SUDO) else ""
        return ASK, f"approve-to-run line, new tab: {tool_input['command']}{root}"

    if tool == "read_terminal":
        extra = set(tool_input) - READ_KEYS
        if extra:
            return DENY, f"read_terminal may not set {len(extra)} other key(s)"
        lines, wait = tool_input.get("lines"), tool_input.get("wait_for_output_ms")
        if lines is not None and not (type(lines) is int and 1 <= lines <= 100):
            return DENY, "lines must be 1-100"
        if wait is not None and not (type(wait) is int and 0 <= wait <= 120000):
            return DENY, "wait_for_output_ms must be 0-120000"
        with State() as state:
            item = _owned(state, session, tool_input.get("tab_id"))
            if item is None:
                return DENY, "read_terminal only on the tab this session opened for an approved line"
            if str(item.get("command") or "").startswith(SUDO):
                return DENY, ("a sudo line's tab is never read: a password typed there by mistake would "
                                "show. Close the tab and read the result another way")
            if item.get("reads", 0) >= 1:
                return DENY, "that tab was already read once; close it with stop_terminal_tab"
            if not 0 <= time.time() - item["ts"] < READ_WINDOW:
                return DENY, (f"the line was typed more than {READ_WINDOW} seconds ago, so the tab may hold "
                                "your own commands; read it yourself")
            item["reads"] = item.get("reads", 0) + 1
            state.save()
        return ALLOW, "one read of this session's approve-to-run tab"

    if tool == "stop_terminal_tab":
        extra = set(tool_input) - STOP_KEYS
        if extra:
            return DENY, f"stop_terminal_tab may not set {len(extra)} other key(s)"
        if tool_input.get("close") is not True:
            return DENY, "stop_terminal_tab only with close: true"
        with State() as state:
            item = _owned(state, session, tool_input.get("tab_id"))
            if item is None:
                return DENY, "stop_terminal_tab only on a tab this session opened for an approved line"
            state.data["tabs"].remove(item)
            state.save()
        return ALLOW, "closing this session's approve-to-run tab"

    return DENY, "this terminal tool isn't part of approve-to-run"


def _texts(resp) -> list:
    if isinstance(resp, str):
        return [resp]
    if isinstance(resp, dict):
        if "content" in resp:
            return _texts(resp["content"])
        if "text" in resp and isinstance(resp["text"], str):
            return [resp["text"]]
        return [json.dumps(resp)]
    if isinstance(resp, list):
        out = []
        for item in resp:
            out += _texts(item)
        return out
    return []


def tab_from_response(resp):
    """The one tab_id the run_in_terminal result names in a JSON object, or None."""
    found = set()
    for text in _texts(resp):
        for chunk in (text, text.split("\n", 1)[0]):
            try:
                data = json.loads(chunk)
            except ValueError:
                continue
            if isinstance(data, dict) and isinstance(data.get("tab_id"), str) and TAB_RE.fullmatch(data["tab_id"]):
                found.add(data["tab_id"])
    return found.pop() if len(found) == 1 else None


def record_tab(event: dict) -> str:
    """PostToolUse: turn the pending approved line into an owned tab."""
    if event.get("tool_name") != PREFIX + RUN or event.get("agent_id") is not None:
        return "ignored"
    session, use_id = event.get("session_id"), event.get("tool_use_id")
    command = (event.get("tool_input") or {}).get("command")
    tab = tab_from_response(event.get("tool_response"))
    with State() as state:
        match = [p for p in state.data["pending"] if p.get("session") == session and p.get("command") == command
                 and (p.get("tool_use_id") == use_id if isinstance(use_id, str) and p.get("tool_use_id") else True)]
        if not match:
            return "no pending approved line for this call"
        state.data["pending"].remove(match[0])
        if tab is None:
            state.save()
            return "the result named no single tab_id; no tab owned"
        reused = [t for t in state.data["tabs"] if t.get("tab") == tab]
        if reused:
            for t in reused:   # a reused id, in any session: own nothing, read nothing
                state.data["tabs"].remove(t)
            state.save()
            return "tab id reused; no tab owned"
        state.data["tabs"].append({"session": session, "tab": tab, "command": command, "ts": time.time(),
                                   "reads": 0})
        state.save()
    return "tab owned"


def _loggable(event: dict) -> dict:
    """The event as the log should see it: a tool name only when it is one of ours."""
    name = event.get("tool_name")
    return {"tool_name": name if name in TERMINAL_TOOLS else "other"}


def _show(text: str) -> str:
    return "".join(c if c.isprintable() and c.isascii() else "?" for c in text)[:80]


def main() -> int:
    """Run the hook; the timers are cancelled on every return."""
    try:
        rc = _main()
        sys.stdout.flush()
        sys.stderr.flush()
        return rc
    finally:
        disarm_timers()


def _main() -> int:
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise GateError("hook input is not an object")
    except Exception as exc:  # noqa: BLE001 - anything unchecked blocks the call
        print(f"terminal-gate: blocked ({type(exc).__name__})", file=sys.stderr)
        return 2
    if event.get("hook_event_name") == "PostToolUse":
        try:
            record_tab(event)
        except Exception:  # noqa: BLE001 - a failed record only means no tab is owned
            pass
        return 0
    try:
        decision, reason = decide(event)
    except Exception as exc:  # noqa: BLE001 - anything unchecked blocks the call
        log_deny("terminal-gate-internal", _loggable(event), _show)
        print(f"terminal-gate: blocked ({type(exc).__name__}: {_show(str(exc))})"[:500], file=sys.stderr)
        return 2
    if decision != ALLOW:
        log_deny("terminal-gate", _loggable(event), _show, decision=decision)
    reason = f"terminal-gate: {reason}"
    json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                      "permissionDecisionReason": reason[:1000]}}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
