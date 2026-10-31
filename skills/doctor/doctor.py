#!/usr/bin/env python3
"""stranger-danger doctor: check that the plugin and its manual pieces are in place.

It changes nothing (its pass-through run of each hook can add a line to the
decision log if a gate refuses it). It prints a PASS / WARN / FAIL checklist
and exits 1 if anything failed; ``--report`` prints a summary for a bug report
instead and exits 0, or 1 if it can't build one (see report()). It never prints a secret. Specifically:

- It reads ``~/.claude/settings.json`` only to compare rule names with the
  template, and prints only the template rules that are missing.
- It never opens an ``.npmrc`` file. It asks npm for the two safety keys
  (``npm config get min-release-age`` and ``ignore-scripts``), then asks again
  with ``--userconfig /dev/null`` to see whether they survive without
  ``~/.npmrc``, and prints only those two values.
- It confirms the rules canary is filled in but never prints it. The skill asks
  Claude to state it from its loaded context, which is the real test that the
  rules are loaded.
- It lists the paths of secret-shaped files in the project (``.env``, ``*.pem``,
  keypairs) that no exact Read deny rule covers, by name only; it never opens
  them. Glob deny rules don't reach sandboxed Bash, so those files are readable.

The hook self-test runs the gates' decision code in-process with your real
config (so nothing is written to the decision log), plus one pass-through run
of each hook script exactly as Claude Code starts it (``python3 -I``).

Standard library only.
"""
from __future__ import annotations

import fnmatch
import json
import datetime
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(os.path.dirname(HERE))
HOOKS = os.path.join(PLUGIN_ROOT, "hooks")
sys.path.insert(0, HOOKS)
sys.path.insert(0, os.path.join(PLUGIN_ROOT, "skills", "coordinator"))
sys.path.insert(0, os.path.join(PLUGIN_ROOT, "skills", "setup"))
sys.path.insert(0, os.path.join(PLUGIN_ROOT, "skills", "osv"))

import _canary  # noqa: E402
import _config  # noqa: E402
import _log  # noqa: E402
import apply  # noqa: E402
import coordinator  # noqa: E402
import launch_gate  # noqa: E402
import osv  # noqa: E402
import reader_gate  # noqa: E402

MIN_PYTHON = (3, 10)
# Where Claude Code reads managed (admin) settings on each system.
MANAGED_SETTINGS = {
    "darwin": "/Library/Application Support/ClaudeCode/managed-settings.json",
    "win32": r"C:\Program Files\ClaudeCode\managed-settings.json",
}.get(sys.platform, "/etc/claude-code/managed-settings.json")
GATE_SCRIPTS = ("reader_gate.py", "launch_gate.py", "reader_tools.py", "settings_guard.py", "terminal_gate.py")
# hooks.json as the plugin ships it, one entry per gate script, in order. Any
# change (a matcher, a command that drops the exit code, a short timeout)
# can stop a gate from refusing, so the doctor wants exactly this.
INSTR_COMMAND = (
    'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/instr_check.py" || echo \'{"systemMessage": "instr-check: did not run or did not finish; instruction files were not checked.", "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "instr-check (a hook; fixed text): did not run or did not finish; instruction files were not checked. Say in your first reply to the user that this check did not run."}}\'')
EXPECTED_HOOKS = {"PreToolUse": [
    {"matcher": matcher, "hooks": [{
        "type": "command", "timeout": 15, "onFailure": "block",
        "command": f'python3 -I "${{CLAUDE_PLUGIN_ROOT}}/hooks/{script}" || exit 2'}]}
    for script, matcher in zip(GATE_SCRIPTS, ("Read|Grep|Glob|WebFetch|WebSearch", "Bash|Monitor", "*",
                                                 "Edit|Write|MultiEdit|NotebookEdit",
                                                 "mcp__terminal__.*"))],
    # The terminal gate's after-hook records the tab an approved line opened. It
    # blocks nothing (a failed record only means no tab is owned): no onFailure.
    "PostToolUse": [{"matcher": "mcp__terminal__run_in_terminal", "hooks": [{
        "type": "command", "timeout": 10,
        "command": 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/terminal_gate.py" || exit 0'}]}],
    # The update reminder, the canary fill and the OSV check's status line:
    # none blocks, so they have no onFailure or exit 2. Only new and resumed
    # sessions: /clear and compaction keep the old process.
    "SessionStart": [{"matcher": "startup|resume", "hooks": [{
        "type": "command", "timeout": 10,
        "command": f'python3 -I "${{CLAUDE_PLUGIN_ROOT}}/hooks/{script}"'}
        for script in ("doctor_nudge.py", "canary_fill.py", "osv_status.py")]},
        # The instruction-file check also runs on /clear, compaction and fork (from the
        # docs, not tested live), and its command prints a
        # fixed line when the script can't start. Nothing here blocks.
        {"matcher": "startup|resume|clear|compact|fork", "hooks": [{
            "type": "command", "timeout": 15,
            "command": INSTR_COMMAND}]}],
    # The scan skill's hook on your typed prompt. It fails open: blocking on
    # failure would block every prompt you type. "|| exit 0" because Python
    # exits 2 when the script is missing, and exit 2 blocks the prompt.
    "UserPromptSubmit": [{"hooks": [{
        "type": "command", "timeout": 90,
        "command": 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/scan_prompt.py" || exit 0'}]}]}
START_SCRIPTS = ("doctor_nudge.py", "canary_fill.py", "_canary.py", "scan_prompt.py",
                 "trigger_scan.py", "osv_status.py", "instr_check.py")
# When the OSV check is due and stale, as hooks/osv_status.py says.
OSV_DUE_HOURS = 24
OSV_STALE_HOURS = 36
# Files outside hooks/ that a hook loads by fixed path.
LOADED_FILES = (os.path.join("skills", "scan", "scan.py"),)
ON_FAILURE_VERSION = (2, 1, 295)
RULES_IMPORTS = ("@~/.claude/stranger-danger/RULES.md",)
NPM_KEYS = ("min-release-age", "ignore-scripts")
# ASCII digits only: str.isdigit() also takes "\u00b2", which int() refuses.
NPM_SAFE = {"min-release-age": lambda v: re.fullmatch(r"[0-9]{1,6}", v) is not None
            and int(v) >= 7,
            "ignore-scripts": lambda v: v == "true"}
# The same two settings as the template's env entries, which npm reads as
# config for every command Claude Code runs.
NPM_ENV = {"npm_config_min_release_age": "min-release-age",
           "npm_config_ignore_scripts": "ignore-scripts"}
# npm added min-release-age in 11.10.0 (secondary sources; its release notes
# weren't checked). An older npm can't enforce it.
NPM_AGE_VERSION = (11, 10, 0)


@dataclass
class Check:
    status: str  # PASS, WARN, FAIL, INFO
    name: str
    detail: str
    fix: str = ""
    means: str = ""  # what it means for you, when the name's usual sentence doesn't fit


@dataclass
class Context:
    """Everything the doctor reads from the outside world, injectable for tests."""

    home: str
    plugin_root: str = PLUGIN_ROOT
    cwd: str = field(default_factory=os.getcwd)
    project_dir: Optional[str] = None
    config_dir: Optional[str] = None   # CLAUDE_CONFIG_DIR
    # STRANGER_DANGER_CONFIG, when set. The doctor never reads that file: the
    # gates in your sessions read the default one, and that's what it checks.
    config_override: Optional[str] = None
    # Set by main() when HOME isn't the account's home folder: every ~ the
    # gates and this check expand would point somewhere else.
    home_problem: Optional[str] = None
    # Takes argv and an optional cwd; returns stdout, or None if it failed.
    run: Callable[..., Optional[str]] = None
    python: str = sys.executable
    # The environment Claude Code passes to commands. Only names are read.
    env: dict = field(default_factory=lambda: dict(os.environ))
    managed_settings: str = MANAGED_SETTINGS

    def __post_init__(self) -> None:
        if self.run is None:
            self.run = _run


def _run(argv: list, cwd: Optional[str] = None) -> Optional[str]:
    if shutil.which(argv[0]) is None:
        return None
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=20,
                             stdin=subprocess.DEVNULL, cwd=cwd)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def _read_text(path: str, limit: int = 1_000_000) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return None


def _version_tuple(text: str) -> Optional[tuple]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _claude_dir(ctx: Context) -> str:
    """The active Claude config folder: CLAUDE_CONFIG_DIR when set, else
    ~/.claude. settings.json, CLAUDE.md and stranger-danger/RULES.md all live
    under it, so a run in an alternate profile checks that profile, not the
    default one. (The gate config stays at ~/.config/stranger-danger; Claude
    Code's CLAUDE_CONFIG_DIR doesn't move it.)"""
    if ctx.config_dir and os.path.isabs(ctx.config_dir):
        return ctx.config_dir
    return os.path.join(ctx.home, ".claude")


# -- checks ---------------------------------------------------------------------

# What the probe runs: the version of the python3 the hooks would start.
PYTHON_PROBE = ["python3", "-I", "-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"]


def check_python(ctx: Context) -> list:
    # The hooks start as `python3 -I`, found on PATH from the session's folder.
    # If that fails (a version-manager shim with nothing installed, say), every
    # gated tool is refused, and the reader-tools hook gates every tool. The
    # doctor itself then can't run from that session, so that shows only when
    # it runs from a terminal with another python.
    folder = ctx.project_dir or ctx.cwd
    version = _version_tuple(ctx.run(PYTHON_PROBE, cwd=folder) or "")
    if version is None:
        return [Check("FAIL", "python", "python3 doesn't start from this folder, so every "
                      "tool call in this session is refused",
                      "Make python3 start here (check pyenv, asdf or mise and .python-version), "
                      "or disable the plugin with /plugin until it does.")]
    shown = ".".join(map(str, version))
    if version[:2] >= MIN_PYTHON:
        return [Check("PASS", "python", f"python3 {shown} from this folder")]
    return [Check("FAIL", "python", f"python3 from this folder is {shown}, older than 3.10",
                  "Make python3 3.10 or newer here; the hooks need it.")]


def check_agents(ctx: Context) -> list:
    env = reader_gate.Env(home=ctx.home, plugin_root=ctx.plugin_root)
    out = []
    for reader in sorted(reader_gate.READER_TOOLS):
        problem = reader_gate._definition_problem(reader, env)
        allowed = ", ".join(sorted(reader_gate.READER_TOOLS[reader]))
        if problem:
            out.append(Check("FAIL", f"agent {reader}", problem,
                             f"Restore agents/{reader}.md: its tools must stay within {allowed}."))
        else:
            out.append(Check("PASS", f"agent {reader}", f"tools within {allowed}"))
    event = {"cwd": ctx.cwd}
    env.project_dir, env.config_dir = ctx.project_dir, ctx.config_dir
    shadow = reader_gate._shadowing(event, env, reader_gate._plugin_name(env))
    if shadow:
        out.append(Check("FAIL", "agent names", shadow,
                         "Fix that file as the message says; until then no call counts as "
                         "a reader."))
    else:
        out.append(Check("PASS", "agent names", "no file under a .claude/agents folder "
                         "mentions the readers' reserved prefix"))
    return out


def _without_block_on_failure(hooks):
    """hooks with onFailure: "block" taken out of each hook. The shipped
    hooks.json sets it (Claude Code 2.1.295 and later read it), and it only
    makes a gate stricter, so a copy without it still matches, and gets a
    WARN in check_hooks_json."""
    if not isinstance(hooks, dict):
        return hooks
    out = {}
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            out[event] = entries
            continue
        out[event] = [dict(e, hooks=[{k: v for k, v in h.items()
                                      if not (k == "onFailure" and v == "block")}
                                     if isinstance(h, dict) else h for h in e["hooks"]])
                      if isinstance(e, dict) and isinstance(e.get("hooks"), list) else e
                      for e in entries]
    return out


def check_hooks_json(ctx: Context) -> list:
    path = os.path.join(ctx.plugin_root, "hooks", "hooks.json")
    text = _read_text(path)
    try:
        data = json.loads(text) if text is not None else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return [Check("FAIL", "hooks.json", "missing or not valid JSON",
                      "Reinstall the plugin.")]
    hooks = _without_block_on_failure(data.get("hooks"))
    expected = _without_block_on_failure(EXPECTED_HOOKS)
    if hooks != expected:
        entries = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
        entries = entries if isinstance(entries, list) else []
        wrong = [f"hooks/{script}" for script, entry
                 in zip(GATE_SCRIPTS, expected["PreToolUse"]) if entry not in entries]
        return [Check("FAIL", "hooks.json",
                      ("doesn't run " + ", ".join(wrong) + " as shipped (matcher, command and "
                       "timeout), so it may not refuse") if wrong
                      else "has its entries reordered, or hooks this plugin doesn't ship",
                      "Reinstall the plugin.")]
    missing = [f"hooks/{script}" for script in GATE_SCRIPTS + START_SCRIPTS
               if not os.path.isfile(os.path.join(ctx.plugin_root, "hooks", script))]
    missing += [rel.replace(os.sep, "/") for rel in LOADED_FILES
                if not os.path.isfile(os.path.join(ctx.plugin_root, rel))]
    if missing:
        return [Check("FAIL", "hooks.json", "points at missing files: " + ", ".join(missing),
                      "Reinstall the plugin.")]
    unset = [f"hooks/{script}" for script, entry in zip(GATE_SCRIPTS, data["hooks"]["PreToolUse"])
             if entry["hooks"][0].get("onFailure") != "block"]
    if unset:
        return [Check("WARN", "hooks.json",
                      "doesn't set onFailure: block for " + ", ".join(unset) + ", so a gate "
                      "that runs past its hook timeout lets the call through",
                      "Reinstall the plugin.")]
    return [Check("PASS", "hooks.json", "matches the hooks this plugin ships")]


def load_user_config(ctx: Context) -> tuple:
    """Return (config dict or None, path, list of checks)."""
    path = os.path.join(ctx.home, ".config", "stranger-danger", "config.json")
    if not os.path.exists(path):
        return {}, path, [Check(
            "WARN", "config", f"{path} doesn't exist; using defaults",
            "Web and secret rules apply already. To route documents and strangers' code to "
            "their readers, copy templates/config.json there and run chmod 600 on it.",
            means="No folder is treated as untrusted or quarantined yet, so documents and "
                  "strangers' code there aren't kept from your acting agents.")]
    try:
        config = _config.load_config(_config.Path(path))
    except _config.ConfigError as exc:
        return None, path, [Check("FAIL", "config", str(exc),
                                  "Fix the file; until then both gates block everything they cover.")]
    out = []
    try:
        policy = reader_gate.Policy.from_config(config, reader_gate.Env(home=ctx.home))
        launch_gate._allow_prefixes(config)
        launch_gate._ssh_hosts(config)
        launch_gate._ask_for_domains(config)
    except _config.ConfigError as exc:
        return None, path, [Check("FAIL", "config", str(exc),
                                  "Fix the file; until then both gates block everything they cover.")]
    out.append(Check("PASS", "config", f"{path} parses, and only you can write it"))
    for label, roots in (("untrusted_paths", policy.untrusted),
                         ("quarantine_paths", policy.quarantine)):
        for forms in roots:
            root = forms[0] if isinstance(forms, (tuple, list)) else forms
            if not os.path.isdir(root):
                out.append(Check("WARN", f"config {label}", f"{root} doesn't exist yet",
                                 "Create it, or remove the entry."))
    try:
        out += _quarantine_root_checks(policy, ctx)
    except Exception as exc:   # one check's bug must not hide the config result
        out.append(Check("FAIL", "doctor", f"the quarantine folder check crashed: {type(exc).__name__}"))
    if not policy.untrusted and not policy.quarantine:
        out.append(Check("INFO", "config", "no untrusted or quarantine folders configured"))
    return config, path, out


def _quarantine_root_checks(policy, ctx: Context) -> list:
    """FR1-2: a quarantine folder that isn't a dedicated folder of strangers' files. The reader gate
    already drops the registry-config exception when one is at or above your home folder; a folder
    that holds the project or working folder the doctor runs in keeps it, and so would let the
    quarantine reviewer read that project's .npmrc and .yarnrc.yml."""
    env = reader_gate.Env(home=ctx.home)

    def holds(roots, inner: str) -> bool:
        return any(reader_gate._inside(i, r, env) for r in roots for i in reader_gate._forms(inner))
    out = []
    all_roots = [r if isinstance(r, (tuple, list)) else (r,) for r in policy.quarantine]
    broad = any(holds(r, ctx.home) for r in all_roots)   # the gate's flag is global across roots
    for roots in all_roots:
        root = roots[0]
        if holds(roots, ctx.home):
            out.append(Check("WARN", "config quarantine_root",
                             f"quarantine folder {root} holds your home folder: the quarantine reviewer can "
                             "read everything there that isn't on the secret list, other agents' file tools "
                             "are refused there, and no quarantine folder gets the .npmrc and .yarnrc.yml "
                             "exception",
                             "Name a folder that holds only strangers' files."))
            continue
        for what, folder in (("project folder", ctx.project_dir), ("working folder", ctx.cwd)):
            if folder and holds(roots, folder):
                risk = ("the quarantine reviewer can read their .npmrc and .yarnrc.yml" if not broad
                        else "no quarantine folder gets the .npmrc and .yarnrc.yml exception while one holds "
                             "your home folder")
                out.append(Check("WARN", "config quarantine_root",
                                 f"the {what} {folder} is inside quarantine folder {root}: either that "
                                 f"folder holds your own projects ({risk}), or you are working in strangers' files",
                                 "Name a dedicated folder of strangers' files as the quarantine folder, and "
                                 "don't open sessions inside it."))
                break
    return out


def _user_settings(ctx: Context) -> tuple:
    path = os.path.join(_claude_dir(ctx), "settings.json")
    text = _read_text(path)
    if text is None:
        return None, path
    try:
        data = json.loads(text)
    except ValueError:
        return "invalid", path
    return data if isinstance(data, dict) else "invalid", path


def _glob_regex(pattern: str, home: str):
    """A permission rule's path pattern as a regex over absolute paths, or None
    for a form this doesn't read (relative to a settings file)."""
    if pattern.startswith("//"):
        pattern = pattern[1:]
    elif pattern == "~" or pattern.startswith("~/"):
        pattern = home + pattern[1:]
    else:
        return None
    out, i = [], 0
    while i < len(pattern):
        if _segment_stars(pattern, i) == "**/":
            out.append("(?:.*/)?")
            i += 3
        elif _segment_stars(pattern, i) == "**":
            out.append(".*")
            i += 2
        elif pattern.startswith("**", i):
            out.append("[^/]*")  # gitignore: ** inside a segment is a plain *
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def _segment_stars(pattern: str, i: int) -> str:
    """"**/" or "**" when a ** at i is a whole path segment, else ""."""
    if not pattern.startswith("**", i) or (i > 0 and pattern[i - 1] != "/"):
        return ""
    if pattern.startswith("**/", i):
        return "**/"
    return "**" if i + 2 == len(pattern) else ""


def _samples(pattern: str, home: str) -> list:
    """Paths `pattern` matches, with ** at depths 0 to 3, or [] for a form
    this doesn't read."""
    out = []
    for deep in ("", "q1/", "q1/q2/", "a.b-c/d_e f/g/"):
        for word in ("q1", "a.b-c d_e"):
            s, i = [], 0
            while i < len(pattern):
                stars = _segment_stars(pattern, i)
                if stars == "**/":
                    s.append(deep)
                    i += 3
                elif stars == "**":
                    s.append(deep + word)
                    i += 2
                elif pattern.startswith("**", i):
                    s.append(word)
                    i += 2
                elif pattern[i] == "*":
                    s.append(word)
                    i += 1
                elif pattern[i] == "?":
                    s.append("z")
                    i += 1
                else:
                    s.append(pattern[i])
                    i += 1
            sample = "".join(s)
            if sample.startswith("//"):
                out.append(sample[1:])
            elif sample.startswith("~/"):
                out.append(home + sample[1:])
            else:
                return []
    return out


def _reaches_sandbox(pattern: str) -> bool:
    """Whether a Read deny pattern also stops sandboxed Bash: an exact path,
    or a folder written as X/** (see _exact_denies)."""
    if pattern.endswith("/**"):
        pattern = pattern[:-3]
    return not any(ch in pattern for ch in "*?[")


def _covered(rule: str, have, home: str) -> bool:
    """Whether a broader rule in `have` covers `rule`, judged on sample paths
    the rule matches: Read(~/.config/gh/hosts.yml) under Read(~/.config/gh/**),
    say. Same tool only, and every sample must match. A Read rule that stops
    sandboxed Bash is covered only by one that does too: Read(~/.config/gh/*)
    stops the Read tool but not `cat` in the sandbox."""
    m = re.fullmatch(r"(Read|Edit)\((.+)\)", rule)
    if not m:
        return False
    tool, pattern = m.groups()
    samples = _samples(pattern, home)
    if not samples:
        return False
    for other in have:
        o = re.fullmatch(r"(Read|Edit)\((.+)\)", other)
        if not o or o.group(1) != tool or other == rule:
            continue
        if tool == "Read" and _reaches_sandbox(pattern) and not _reaches_sandbox(o.group(2)):
            continue
        # A rule for a folder with no glob in it, Read(~/.ssh), covers what's
        # inside, as _exact_denies counts it.
        forms = [o.group(2)] + ([o.group(2).rstrip("/") + "/**"]
                                if not any(c in o.group(2) for c in "*?[") else [])
        for form in forms:
            rx = _glob_regex(form, home)
            if rx and all(rx.match(sample) for sample in samples):
                return True
    return False


def check_settings(ctx: Context) -> list:
    settings, path = _user_settings(ctx)
    template = json.loads(_read_text(os.path.join(ctx.plugin_root, "templates",
                                                  "settings.json")) or "{}")
    # Under CLAUDE_CONFIG_DIR, the profile's own CLAUDE.md, settings, hooks
    # and agents need the same rules (setup adds them; this checks them).
    template = apply.profile_rules(template, _claude_dir(ctx), ctx.home)
    # The Monitor deny has its own check (check_monitor), with its reason.
    wanted = [r for r in template.get("permissions", {}).get("deny", []) if r != "Monitor"]
    if settings is None:
        return [Check("FAIL", "settings", f"{path} doesn't exist",
                      "Merge templates/settings.json into it.")]
    if settings == "invalid":
        return [Check("FAIL", "settings", f"{path} isn't valid JSON",
                      "Fix it: Claude Code ignores a settings file it can't parse.")]
    perms = settings.get("permissions")
    perms = perms if isinstance(perms, dict) else {}

    def rules(key: str) -> set:
        value = perms.get(key)
        return {r for r in value if isinstance(r, str)} if isinstance(value, list) else set()

    deny, ask = rules("deny"), rules("ask")
    # The interactive profile keeps guardrail edits as "ask" instead of "deny".
    as_ask = [r for r in wanted if r not in deny and r.startswith("Edit(")
              and (r in ask or _covered(r, ask, ctx.home))]
    broader = [r for r in wanted if r not in deny and r not in as_ask
               and _covered(r, deny, ctx.home)]
    missing = [r for r in wanted if r not in deny and r not in as_ask and r not in broader]
    note = (f"; {len(as_ask)} guardrail edit rules are ask, not deny (interactive profile: "
            "the Edit and Write tools prompt you, unless you bypass permissions; "
            "approve only what you've read)") if as_ask else ""
    if broader:
        note += f"; {len(broader)} covered by a broader rule of yours"
    out = []
    if missing:
        shown = ", ".join(missing[:12]) + (f" and {len(missing) - 12} more" if len(missing) > 12 else "")
        out.append(Check("WARN", "settings deny rules",
                         f"{len(wanted) - len(missing)} of {len(wanted)} template rules present"
                         f"{note}; missing: {shown}",
                         "Merge the missing rules from templates/settings.json into "
                         "permissions.deny. A rule of yours counts when it covers the "
                         "same paths; for a secret file, only an exact path or a folder/** "
                         "rule counts, because other globs don't stop sandboxed commands."))
    else:
        out.append(Check("PASS", "settings deny rules",
                         f"all {len(wanted)} template rules present{note}"))
    # The ask rules: edits to a coordinator's notes, which feed its page and its
    # list, ask you first. A deny rule for the same path is stricter, so it counts.
    wanted_ask = template.get("permissions", {}).get("ask", [])
    missing_ask = [r for r in wanted_ask if r not in ask and r not in deny]
    if missing_ask:
        out.append(Check("WARN", "settings ask rules", "missing: " + ", ".join(missing_ask[:12]),
                         "Merge the missing rules from templates/settings.json into "
                         "permissions.ask (each rule's exact text is checked)."))
    elif wanted_ask:
        out.append(Check("PASS", "settings ask rules",
                         f"all {len(wanted_ask)} template ask rules present"))
    # The v0.1 template denied edits to the files setup in chat now writes; a
    # deny is stricter, so it counts above, but it keeps setup from updating them.
    stuck = [r for r in apply.moved_rules(_claude_dir(ctx), ctx.home) if r in deny]
    if stuck:
        out.append(Check("INFO", "setup in chat",
                         f"your settings deny {len(stuck)} edit rule(s) for the files setup "
                         "writes, so /stranger-danger:setup can't update them in chat",
                         "Run /stranger-danger:setup: its first step says which lines to "
                         "delete, in your own editor. Or run apply.py in a terminal, which "
                         "moves them to ask and shows you the diff first."))
    return out


def _sandbox(settings) -> tuple:
    """(enabled, npmrc hidden from sandboxed commands)"""
    if not isinstance(settings, dict):
        return False, False
    sandbox = settings.get("sandbox")
    enabled = isinstance(sandbox, dict) and sandbox.get("enabled") is True
    hidden = False
    perms = settings.get("permissions")
    if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
        hidden = any(r in ("Read(~/.npmrc)", "Read(~/.npmrc/**)") for r in perms["deny"])
    if isinstance(sandbox, dict):
        fs = sandbox.get("filesystem")
        if isinstance(fs, dict) and isinstance(fs.get("denyRead"), list):
            hidden = hidden or any(p in ("~/.npmrc", "~/") for p in fs["denyRead"])
    return enabled, hidden


def check_sandbox(ctx: Context) -> list:
    settings, _ = _user_settings(ctx)
    enabled, _hidden = _sandbox(settings)
    if enabled:
        sandbox = settings.get("sandbox")
        # A project's settings outrank yours, so one that turns retries back on wins.
        user = os.path.realpath(os.path.join(_claude_dir(ctx), "settings.json"))
        loosened = []
        for path in _settings_files(ctx):
            if os.path.realpath(path) == user:
                continue
            data = _settings_file(path)
            psandbox = data.get("sandbox") if isinstance(data, dict) else None
            if isinstance(psandbox, dict) and "allowUnsandboxedCommands" in psandbox \
                    and psandbox["allowUnsandboxedCommands"] is not False:
                loosened.append(path)
        if sandbox.get("allowUnsandboxedCommands") is False and not loosened:
            retry = Check("PASS", "sandbox retries", "a command the sandbox stops can't be "
                          "run again outside it")
        elif loosened:
            retry = Check("WARN", "sandbox retries", f"{loosened[0]} lets a command the "
                          "sandbox stops run again outside it, and a project's settings "
                          "outrank yours",
                          "Remove sandbox.allowUnsandboxedCommands from the project's settings.")
        else:
            retry = Check("WARN", "sandbox retries", "a command the sandbox stops can be run "
                          "again outside it, after a prompt (in auto mode, the classifier "
                          "decides)",
                          "Set sandbox.allowUnsandboxedCommands to false, as "
                          "templates/sandbox.json does.")
        return [Check("PASS", "sandbox", "Bash sandbox is on"), retry]
    return [Check("WARN", "sandbox", "Bash sandbox is off: Bash commands can read anything "
                  "your user can, which the reader gate doesn't cover",
                  "Merge templates/sandbox.json. When it's on, Read deny rules for exact paths "
                  "also apply to sandboxed Bash (glob rules don't), including a rule that hides "
                  "~/.npmrc from npm.")]


def _managed_files(ctx: Context) -> list:
    """managed-settings.d's .json files, then managed-settings.json."""
    folder = os.path.join(os.path.dirname(ctx.managed_settings), "managed-settings.d")
    try:
        drop_ins = sorted((os.path.join(folder, n) for n in os.listdir(folder)
                           if n.endswith(".json")), reverse=True)
    except OSError:
        drop_ins = []
    return drop_ins + [ctx.managed_settings]


def check_monitor(ctx: Context) -> list:
    """The Monitor tool runs shell commands like Bash. hooks.json registers the
    launch gate for it. Claude Code's hook docs don't list Monitor as a
    matcher; a live run (docs/VERIFY.md row M1) confirmed it on 2.1.301
    (main-session call, default mode), with step M1b again on 2.1.309, so the
    template denies Monitor until M1 passes on your version. An ask rule counts too: you see each command before it runs."""
    folder = ctx.project_dir or ctx.cwd
    project = {os.path.join(folder, ".claude", n) for n in ("settings.json", "settings.local.json")}
    files = (_managed_files(ctx) + _settings_files(ctx)
             + [os.path.join(_claude_dir(ctx), "settings.local.json")])
    asked = None
    for path in dict.fromkeys(files):
        settings = _settings_file(path)
        perms = settings.get("permissions") if isinstance(settings, dict) else None
        only = " (this project only)" if path in project else ""
        for key in ("deny", "ask"):
            rules = perms.get(key) if isinstance(perms, dict) else None
            if not (isinstance(rules, list) and "Monitor" in rules):
                continue
            if key == "deny":
                return [Check("PASS", "Monitor tool", f"denied in {path}{only}")]
            asked = asked or f"asked before each call, by {path}{only}"
    if asked:
        return [Check("PASS", "Monitor tool", asked)]
    return [Check("WARN", "Monitor tool",
                  "Monitor isn't denied or asked. It runs shell commands as Bash does; the "
                  "launch gate is registered for it, but that it runs for Monitor is "
                  "confirmed only on some Claude Code versions (docs/VERIFY.md row M1)",
                  'Add "Monitor" to permissions.deny (templates/settings.json has it). Once '
                  "docs/VERIFY.md row M1 passes on your Claude Code version, you can move it "
                  "to permissions.ask instead; M1 checks only a main-session call in default "
                  "mode, so keep the deny if subagents may use Monitor or you use another "
                  "mode. apply.py adds the deny again if you remove it.")]


def check_managed_hooks_only(ctx: Context) -> list:
    """`allowManagedHooksOnly` in managed settings stops Claude Code running any
    plugin's hooks, so every gate here, approve-to-run's included, is off."""
    unreadable = []
    for path in _managed_files(ctx):
        settings = _settings_file(path)
        if settings == "invalid" or (settings is None and os.path.lexists(path)):
            unreadable.append(path)
        if isinstance(settings, dict) and settings.get("allowManagedHooksOnly"):
            return [Check("FAIL", "Plugin hooks",
                          f"{path} sets allowManagedHooksOnly, so Claude Code doesn't run this plugin's "
                          "hooks: the reader gate, launch gate, settings guard and approve-to-run gate "
                          "are all off",
                          "Ask whoever manages that file to put the plugin's hooks in it, or to drop "
                          "the setting; until then only your rules file and the permission rules "
                          "protect you.")]
    if unreadable:
        return [Check("WARN", "Plugin hooks",
                      f"{unreadable[0]} exists but can't be read as settings, so whether it switches "
                      "off the plugin's hooks isn't known",
                      "Check that file; the gates are off if it sets allowManagedHooksOnly.")]
    return [Check("PASS", "Plugin hooks", "managed settings don't switch off the plugin's hooks")]


def check_setup_write_denies(ctx: Context) -> list:
    """The files setup changes (apply.setup_write_paths) that exist: their
    Edit rules are ask, not deny, so only a sandbox write deny keeps
    sandboxed commands from changing them."""
    settings, _ = _user_settings(ctx)
    enabled, _hidden = _sandbox(settings)
    if not enabled:
        return [Check("INFO", "setup files", "skipped: the sandbox is off (see the sandbox check)")]
    entries = apply._deny_write_entries(settings)
    paths = [p for p in apply.setup_write_paths(ctx.home, _claude_dir(ctx))
             if os.path.lexists(p) and not os.path.islink(p)]
    missing = [p for p in paths if not apply.write_denied(p, entries, ctx.home)
               and not apply.kept_writable(p, settings, ctx.home)]
    if missing:
        return [Check("WARN", "setup files",
                      f"{len(missing)} of the files setup changes aren't write-denied for "
                      "sandboxed commands: " + ", ".join(missing[:6]),
                      "Run /stranger-danger:setup again: it adds them to "
                      "sandbox.filesystem.denyWrite.")]
    return [Check("PASS", "setup files", f"the {len(paths)} setup file(s) that exist are "
                  "write-denied for sandboxed commands")] if paths else []


def check_start_paths(ctx: Context) -> list:
    """The start-up paths in your home folder (apply.start_paths) that sandboxed
    commands could write in a session whose writable folders include your home."""
    settings, _ = _user_settings(ctx)
    enabled, _hidden = _sandbox(settings)
    if not enabled:
        return [Check("INFO", "start paths", "skipped: the sandbox is off (see the sandbox check)")]
    entries = apply._deny_write_entries(settings)
    home = os.path.realpath(ctx.home)
    wanted = apply.start_paths(home, ctx.env.get("PATH", ""))
    # A path that's denied stays denied whatever allowWrite says.
    kept = [p for p in wanted if apply.kept_writable(p, settings, home)
            and not apply.write_denied(p, entries, home)]
    missing = [p for p in wanted if p not in kept and not apply.write_denied(p, entries, home)]
    shown = lambda p: "~" + p[len(home):] if p.startswith(home + os.sep) else p  # noqa: E731
    out = []
    if missing:
        out.append(Check("WARN", "start paths",
                         f"{len(missing)} start-up path(s) aren't write-denied for sandboxed "
                         "commands: " + ", ".join(shown(p) for p in missing[:12]),
                         "Run apply.py again (it adds the ones that exist), or add them to "
                         "sandbox.filesystem.denyWrite. It matters in a session whose writable "
                         "folders include your home folder (started in ~, or --add-dir ~)."))
    elif len(wanted) > len(kept):
        out.append(Check("PASS", "start paths",
                         f"the {len(wanted) - len(kept)} start-up path(s) that exist in your "
                         "home folder are write-denied (the notes below say what isn't covered)"))
    rel = {p: apply.allow_write_relation(p, settings, home) for p in kept}
    same = [p for p in kept if rel[p] == "same"]
    wider = [p for p in kept if rel[p] != "same"]
    if same:
        out.append(Check("INFO", "start paths",
                         "kept writable by your sandbox.filesystem.allowWrite: "
                         + ", ".join(shown(p) for p in same[:12])))
    if wider:
        out.append(Check("WARN", "start paths",
                         "kept writable whole, because an allowWrite entry names a folder "
                         "inside or above it: " + ", ".join(shown(p) for p in wider[:12]),
                         "Name the exact path in allowWrite if you mean to keep it writable, or "
                         "narrow the entry, then run apply.py again. An entry for your home "
                         "folder or above it keeps every start-up path writable."))
    # What a deny can't cover: a start file that doesn't exist (a placeholder
    # would change which file bash reads) and a symlink (the sandbox doesn't
    # hold one in place).
    absent = [n for n in apply.START_FILES if not os.path.lexists(os.path.join(home, n))]
    if absent:
        out.append(Check("INFO", "start paths",
                         "these shell start files don't exist, so they can't be denied, and a "
                         "sandboxed command could create one: " + ", ".join("~/" + n for n in absent)
                         + ". Keep sessions out of your home folder (don't start in ~ or "
                         "--add-dir ~)."))
    linked = [n for n in apply.START_CANDIDATES if os.path.islink(os.path.join(home, n))]
    if linked:
        out.append(Check("INFO", "start paths",
                         "symlinked start-up paths aren't denied: " + ", ".join(
                             f"~/{n} -> {shown(os.path.realpath(os.path.join(home, n)))}"
                             for n in linked[:6])
                         + ". Deny the folder the link points into, in your home folder's top "
                         "level where you can."))
    # A deny deeper than a direct child of home can be got round by renaming
    # the folder above it, in a sandbox that doesn't hold that folder in place.
    names = set(apply.START_CANDIDATES) | {os.path.basename(p) for p in wanted}
    deep = []
    for entry in entries:
        path = apply._entry_path(entry, home)
        child = apply._home_child(path, home) if path else None
        if (child in names and os.path.join(home, child) != path
                and not apply.write_denied(os.path.join(home, child), entries, home)):
            deep.append(shown(path))
    if deep:
        out.append(Check("INFO", "start paths",
                         "deeper write denies in start-up folders: " + ", ".join(deep[:6])
                         + ". Renaming the folder above one can get round it; deny the whole "
                         "folder directly in your home folder where you can."))
    return out


# Hosts where anyone can rent a subdomain: a wildcard over one lets an agent
# send data to a stranger's site there. The list is data, kept beside this file.
def _shared_hosts() -> frozenset:
    text = _read_text(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "shared_hosts.txt")) or ""
    return frozenset(line.strip().lower() for line in text.splitlines()
                     if line.strip() and not line.startswith("#"))


SHARED_HOSTS = _shared_hosts()


def _settings_files(ctx: Context) -> list:
    folder = ctx.project_dir or ctx.cwd
    files = [os.path.join(_claude_dir(ctx), "settings.json")]
    files += [os.path.join(folder, ".claude", n) for n in ("settings.json", "settings.local.json")]
    return list(dict.fromkeys(files))


def check_blast_radius(ctx: Context) -> list:
    """Settings that widen what a hijacked agent can reach: a network
    allowlist that lets data out to anyone, permissions turned off, or every
    project's MCP servers started without asking. Checks your user settings
    and this project's."""
    out = []
    for path in _settings_files(ctx):
        settings = _settings_file(path)
        if not isinstance(settings, dict):
            continue
        sandbox = settings.get("sandbox")
        network = sandbox.get("network") if isinstance(sandbox, dict) else None
        domains = network.get("allowedDomains") if isinstance(network, dict) else None
        domains = [d for d in domains if isinstance(d, str)] if isinstance(domains, list) else []
        if any(d.strip() in ("*", "*.*") for d in domains):
            out.append(Check("FAIL", "network allowlist", f"{path} lets sandboxed commands "
                             "reach every host",
                             "Remove the * entry and name the hosts your commands need."))
        shared = [d for d in domains if d.startswith("*.") and d[2:].lower() in SHARED_HOSTS]
        if shared:
            out.append(Check("WARN", "network allowlist",
                             f"{path} allows {', '.join(reader_gate._show(d, 80) for d in shared[:5])}"
                             ", where anyone can rent a subdomain",
                             "Name your own subdomain instead, such as myproject.supabase.co."))
        perms = settings.get("permissions")
        if isinstance(perms, dict) and perms.get("defaultMode") == "bypassPermissions":
            out.append(Check("FAIL", "permission mode", f"{path} turns permission prompts off",
                             "Remove permissions.defaultMode, or set it to default."))
        if settings.get("enableAllProjectMcpServers") is True:
            out.append(Check("WARN", "project MCP servers", f"{path} starts every project's "
                             ".mcp.json servers without asking",
                             "Remove enableAllProjectMcpServers, so a repo you open can't "
                             "start its own server."))
    return out or [Check("PASS", "blast radius", "no open network allowlist, permission "
                         "bypass or automatic project MCP servers in your user or project "
                         "settings")]


def check_osv(ctx: Context) -> list:
    """The OSV check (/stranger-danger:osv): whether setup's OSV part is in
    your settings, whether its tools are there, and its last result. It's
    optional, so not set up is only INFO."""
    if os.name != "posix":
        return [Check("INFO", "osv check", "not available on Windows outside WSL")]
    with open(os.path.join(ctx.plugin_root, "templates", "osv.json"), encoding="utf-8") as fh:
        template = json.load(fh)
    settings, _path = _user_settings(ctx)
    sandbox = settings.get("sandbox") if isinstance(settings, dict) else None
    net = sandbox.get("network") if isinstance(sandbox, dict) else None
    files = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
    hosts = net.get("allowedDomains") if isinstance(net, dict) else None
    writes = files.get("allowWrite") if isinstance(files, dict) else None
    hosts = [h for h in hosts if isinstance(h, str)] if isinstance(hosts, list) else []
    writes = [w for w in writes if isinstance(w, str)] if isinstance(writes, list) else []
    denies = files.get("denyWrite") if isinstance(files, dict) else None
    denies = [d for d in denies if isinstance(d, str)] if isinstance(denies, list) else []

    def written(want: str) -> bool:
        # The entry itself or its absolute form: the session hook's own test.
        target = _expand(want, ctx.home)
        return any(target == _expand(w, ctx.home) for w in writes)
    want_hosts = template["sandbox"]["network"]["allowedDomains"]
    want_writes = template["sandbox"]["filesystem"]["allowWrite"]
    missing = [h for h in want_hosts if not _host_allowed(h, hosts)]
    # Set up means setup's write entry is there, as the session hook decides
    # it (a host or a wider folder you allow for other work isn't the OSV part).
    if not any(written(w) for w in want_writes):
        return [Check("INFO", "osv check", "not set up (optional)",
                      "To check what you hold against OSV, run /stranger-danger:setup and "
                      "choose the OSV check, then /stranger-danger:osv.")]
    out = []
    if missing:
        out.append(Check("WARN", "osv check", "setup's OSV part is incomplete; missing: "
                         + ", ".join(missing), "Run /stranger-danger:setup again and choose "
                         "the OSV check."))
    results = osv.results_dir(ctx.home)
    if apply.write_denied(results, denies, ctx.home):
        out.append(Check("WARN", "osv check", "a denyWrite entry in your settings covers the "
                         "results folder, so the check can't save its result",
                         "Remove that denyWrite entry, or don't use the OSV check."))
    _found, problems = osv.tools()
    if problems:
        out.append(Check("WARN", "osv tools", "the OSV check is off: " + "; ".join(problems),
                         "Install your system's own bash, curl, jq and python3 (for jq, "
                         "your system's package, not one from your home folder or Homebrew)."))
    else:
        out.append(Check("PASS", "osv tools", "system bash, curl, jq 1.6+ and python3 found"))
    if sys.platform == "darwin":
        out.append(Check("INFO", "osv check", "not checked on a Mac yet"))
    path = os.path.join(results, "daily.json")
    if not os.path.lexists(path):
        out.append(Check("INFO", "osv result", "no result yet: run /stranger-danger:osv"))
        return out
    data = osv.read_result(path)
    level = data.get("level") if isinstance(data, dict) else None
    done = osv.finished_at(data.get("finished")) if isinstance(data, dict) else None
    now = datetime.datetime.now().timestamp()
    if (level not in osv.LEVELS or data.get("schema") != "sd-osv/1" or done is None
            or done > now + 3600):
        out.append(Check("WARN", "osv result", f"{path} can't be read or trusted",
                         "Run /stranger-danger:osv again."))
        return out
    age = max(0, now - done)
    hours = int(age // 3600)
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    severe = counts.get("held_severe_with_fix")
    severe = severe if type(severe) is int and 0 < severe <= 999_999_999 else 0
    if level == "ALERT":
        out.append(Check("WARN", "osv result", "the last check found a malware record for a "
                         "package you hold", "Run /stranger-danger:osv for the counts; "
                         "remove the package with your own package manager."))
    elif level == "ERROR":
        out.append(Check("WARN", "osv result", "the last check failed",
                         "Run /stranger-danger:osv to see why."))
    if age > OSV_STALE_HOURS * 3600:
        out.append(Check("WARN", "osv result", f"the last check is {hours} hours old",
                         "Run /stranger-danger:osv."))
    elif severe:
        out.append(Check("INFO", "osv result", f"a fix is out for {severe} high or critical "
                         "vulnerabilities in packages you hold, as of the last check",
                         "Run /stranger-danger:osv for the counts, then update with your own "
                         "package manager."))
    elif level in ("OK", "INFO"):
        out.append(Check("PASS" if age <= OSV_DUE_HOURS * 3600 else "INFO", "osv result",
                         f"level {level}, {hours} hours ago"))
    capped = osv.depth_capped(data)
    if capped:
        out.append(Check("INFO", "osv coverage",
                         f"the last check read {osv.DEPTH} folders deep; deeper down it found "
                         f"at least {capped} lockfile(s), runtime pin(s), Dockerfile(s) or "
                         "virtualenv(s) it didn't read, so those weren't checked",
                         "The check doesn't record which ones; to check them, "
                         "run /stranger-danger:osv naming the folder that holds them."))
    if osv.walk_capped(data):
        out.append(Check("INFO", "osv coverage",
                         "the last check's walk below the read depth stopped early in at least "
                         "one folder, so there may be more files it didn't read or count",
                         "Run /stranger-danger:osv naming the deeper folders you want checked."))
    return out


def check_read_denies(ctx: Context, config: Optional[dict]) -> list:
    """The gate config's untrusted, quarantine and plain secret folders that
    exist must be hidden from sandboxed commands too: the reader gate stops
    only the file tools."""
    settings, _ = _user_settings(ctx)
    enabled, _hidden = _sandbox(settings)
    if not enabled or not isinstance(config, dict):
        return []
    paths, _skipped = apply.read_deny_paths(
        config, ctx.home, apply.guarded(ctx.home, _claude_dir(ctx), ctx.plugin_root),
        tuple(dict.fromkeys(d for d in (ctx.project_dir, ctx.cwd) if d)))
    if not paths:
        return []
    covered = [os.path.realpath(c) for c in _exact_denies(settings, ctx.home)]
    open_ = []
    for p in paths:
        full = os.path.realpath(_expand(p, ctx.home))
        if not any(full == c or full.startswith(c.rstrip(os.sep) + os.sep) for c in covered):
            open_.append(p)
    if not open_:
        return [Check("PASS", "sandbox read denies", f"sandbox.filesystem.denyRead or a Read "
                      f"deny rule covers the {len(paths)} folder(s) your gate config names")]
    listed = ", ".join(open_[:10]) + (f" and {len(open_) - 10} more" if len(open_) > 10 else "")
    return [Check("WARN", "sandbox read denies",
                  f"sandboxed commands can still read {listed}",
                  "Run the one-command install again (it adds them to "
                  "sandbox.filesystem.denyRead), or add them there yourself.")]


def _npm_env(env) -> dict:
    """An env object's npm_config_* entries, by the name npm reads them as:
    npm takes the names in any case. With two spellings of one name, the
    weakest value is kept, since the doctor can't tell which npm sees."""
    out: dict = {}
    if not isinstance(env, dict):
        return out
    for name, value in env.items():
        if not isinstance(name, str):
            continue
        key = name.lower().replace("-", "_")
        if key in NPM_ENV:
            safe = isinstance(value, str) and NPM_SAFE[NPM_ENV[key]](value)
            if key not in out or not safe:
                out[key] = value
    return out


def check_package_env(ctx: Context) -> list:
    """The template's env entries: npm's two safety settings for every command
    Claude Code runs. A project's settings outrank yours, so one that sets
    either to something weaker gets a warning."""
    settings, _path = _user_settings(ctx)
    env = _npm_env(settings.get("env") if isinstance(settings, dict) else None)
    weak = [name for name, key in NPM_ENV.items()
            if not (isinstance(env.get(name), str) and NPM_SAFE[key](env[name]))]
    out = []
    if weak:
        out.append(Check("WARN", "package lane env", "your settings' env doesn't set "
                         + " and ".join(weak) + " to the template's value",
                         'Merge the "env" entries from templates/settings.json.'))
    else:
        out.append(Check("PASS", "package lane env", "your settings' env sets npm's "
                         "min-release-age to 7 or more and ignore-scripts to true for the "
                         "commands Claude Code runs"))
    user = os.path.realpath(os.path.join(_claude_dir(ctx), "settings.json"))
    for path in _settings_files(ctx):
        if os.path.realpath(path) == user:
            continue
        data = _settings_file(path)
        penv = _npm_env(data.get("env") if isinstance(data, dict) else None)
        lowered = [name for name, key in NPM_ENV.items() if name in penv
                   and not (isinstance(penv[name], str) and NPM_SAFE[key](penv[name]))]
        if lowered:
            out.append(Check("WARN", "package lane env",
                             f"{path} sets {' and '.join(lowered)} to a weaker value, and a "
                             "project's settings outrank yours",
                             "Remove those env entries from the project's settings."))
    return out


def _npm_value(ctx: Context, key: str, without_user_config: bool = False) -> str:
    argv = ["npm", "config", "get", key]
    if without_user_config:
        argv += ["--userconfig", "/dev/null"]
    return (ctx.run(argv) or "").strip()


def check_npm(ctx: Context) -> list:
    npm_version = ctx.run(["npm", "--version"])
    if npm_version is None:
        return [Check("INFO", "npm", "npm not found; skipped")]
    out = []
    parsed = _version_tuple(npm_version)
    if parsed is None:
        out.append(Check("INFO", "npm version", "couldn't read npm's version"))
    elif parsed < NPM_AGE_VERSION:
        out.append(Check("WARN", "npm version", f"npm {'.'.join(map(str, parsed))} is older "
                         "than 11.10.0, where min-release-age is said to have arrived, so it "
                         "may not wait 7 days whatever the setting says",
                         "Update npm to 11.10.0 or later."))
    values = {key: _npm_value(ctx, key) for key in NPM_KEYS}
    age, scripts = values["min-release-age"], values["ignore-scripts"]
    if NPM_SAFE["min-release-age"](age):
        out.append(Check("PASS", "npm min-release-age", f"{age} days"))
    else:
        out.append(Check("WARN", "npm min-release-age", f"is {_shown_npm(age)}",
                         "Merge the env entries from templates/settings.json, which set it "
                         "for the commands Claude Code runs, or put min-release-age=7 in the "
                         "project's .npmrc."))
    if NPM_SAFE["ignore-scripts"](scripts):
        out.append(Check("PASS", "npm ignore-scripts", "true"))
    else:
        out.append(Check("WARN", "npm ignore-scripts", f"is {_shown_npm(scripts)}",
                         "Merge the env entries from templates/settings.json, or put "
                         "ignore-scripts=true in the project's .npmrc."))
    # What npm is left with when ~/.npmrc can't be read, as in a sandbox that hides it.
    bare = {key: _npm_value(ctx, key, without_user_config=True) for key in NPM_KEYS}
    lost = [k for k in NPM_KEYS if NPM_SAFE[k](values[k]) and not NPM_SAFE[k](bare[k])]
    settings, _ = _user_settings(ctx)
    enabled, hidden = _sandbox(settings)
    keys = " and ".join(lost)
    verb = "comes" if len(lost) == 1 else "come"
    if lost and hidden and enabled:
        out.append(Check("WARN", "npm and the sandbox",
                         f"{keys} {verb} only from ~/.npmrc, which your settings hide from "
                         "sandboxed commands, so sandboxed npm runs without it",
                         "Set them in the project's .npmrc or the global npmrc as well."))
    elif lost and hidden:
        out.append(Check("WARN", "npm and the sandbox",
                         f"{keys} {verb} only from ~/.npmrc, and your settings deny reading "
                         "it; turning the sandbox on would hide it from sandboxed npm",
                         "Set them in the project's .npmrc or the global npmrc as well, "
                         "before you enable the sandbox."))
    elif lost:
        out.append(Check("INFO", "npm without ~/.npmrc",
                         f"{keys} {verb} only from ~/.npmrc; npm keeps the setting while "
                         "that file stays readable"))
    else:
        out.append(Check("INFO", "npm without ~/.npmrc",
                         f"min-release-age {_shown_npm(bare['min-release-age'])}, "
                         f"ignore-scripts {_shown_npm(bare['ignore-scripts'])}"))
    return out


def _shown_npm(value: str) -> str:
    return value if value and value not in ("undefined", "null") else "unset"


def check_rules(ctx: Context) -> list:
    base = _claude_dir(ctx)
    rules = os.path.join(base, "stranger-danger", "RULES.md")
    claude_md = os.path.join(base, "CLAUDE.md")
    out = []
    text = _read_text(rules)
    if text is None:
        return [Check("FAIL", "rules", f"{rules} doesn't exist",
                      "Copy rules/RULES.md there and fill in your repos and a canary word.")]
    if _canary.word_in(text) is None:
        out.append(Check("WARN", "rules canary", "not set",
                         f"If its line still reads {_canary.LINE}, start a new session: the "
                         "plugin fills in a word at startup. Otherwise put an unusual word "
                         "there yourself."))
    else:
        out.append(Check("PASS", "rules canary", "set (not shown; the skill asks Claude for it)"))
    md = _read_text(claude_md) or ""
    # The import must resolve to this profile's RULES.md. Under CLAUDE_CONFIG_DIR,
    # an @~/.claude/... line would load the default profile's copy instead.
    if os.path.normpath(rules) in _import_targets(md, ctx.home):
        out.append(Check("PASS", "rules import", f"{claude_md} imports RULES.md"))
    else:
        default = os.path.normpath(base) == os.path.normpath(os.path.join(ctx.home, ".claude"))
        line = RULES_IMPORTS[0] if default else "@" + rules
        out.append(Check("FAIL", "rules import", f"{claude_md} doesn't import {rules}",
                         f"Add this line to it: {line}"))
    return out


def _import_targets(md: str, home: str) -> set:
    """The absolute, normalized paths of CLAUDE.md's @ import lines, ~ expanded."""
    out = set()
    for line in md.splitlines():
        text = line.strip()
        if not text.startswith("@"):
            continue
        path = text[1:]
        if path == "~" or path.startswith("~/"):
            path = home + path[1:]
        if os.path.isabs(path):
            out.add(os.path.normpath(path))
    return out


# Folders the secret-file scan skips: dependencies and build output, not your files.
SCAN_SKIP = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", "target",
                       "dist", "build", ".tox", ".mypy_cache"})
SCAN_DEPTH = 4
SCAN_MAX_FILES = 20_000


def _secret_names() -> tuple:
    """Basename globs for secrets anywhere, from the reader gate's built-in list."""
    return tuple(g[3:] for g in reader_gate.BUILTIN_SECRETS
                 if g.startswith("**/") and "/" not in g[3:])


def _exact_denies(settings, home: str) -> list:
    """Paths that sandboxed Bash can't read: exact Read deny rules (a trailing
    /** covers a folder) and sandbox.filesystem.denyRead entries. A rule with
    any other glob is left out, because it doesn't reach sandboxed commands."""
    if not isinstance(settings, dict):
        return []
    entries = []
    perms = settings.get("permissions")
    if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
        # In a permission rule, //path is absolute and /path is relative to the
        # project, so only the // form counts here.
        for r in perms["deny"]:
            if isinstance(r, str) and r.startswith("Read(") and r.endswith(")"):
                path = r[5:-1]
                if path.startswith("//"):
                    entries.append(path[1:])
                elif path == "~" or path.startswith("~/"):
                    entries.append(path)
    sandbox = settings.get("sandbox")
    fs = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
    if isinstance(fs, dict) and isinstance(fs.get("denyRead"), list):
        # In sandbox.filesystem, /path is absolute.
        entries += [p for p in fs["denyRead"] if isinstance(p, str)]
    out = []
    for entry in entries:
        if entry.endswith("/**"):
            entry = entry[:-3]
        if any(ch in entry for ch in "*?["):
            continue
        if entry == "~" or entry.startswith("~/"):
            entry = home + entry[1:]
        if os.path.isabs(entry):
            out.append(os.path.normpath(entry))
    return out


def check_secret_files(ctx: Context) -> list:
    settings, _ = _user_settings(ctx)
    enabled, _hidden = _sandbox(settings)
    if not enabled:
        return [Check("INFO", "secret files", "skipped: the sandbox is off (see the sandbox check)")]
    root = ctx.project_dir or ctx.cwd
    names = _secret_names()
    covered = _exact_denies(settings, ctx.home)
    uncovered, seen = [], 0
    base_depth = root.rstrip(os.sep).count(os.sep)
    for folder, dirs, files in os.walk(root):
        if folder.count(os.sep) - base_depth >= SCAN_DEPTH:
            dirs[:] = []
        dirs[:] = sorted(d for d in dirs if d not in SCAN_SKIP)
        for name in sorted(files):
            seen += 1
            if name in reader_gate.ENV_TEMPLATES or not any(
                    fnmatch.fnmatchcase(name, pattern) for pattern in names):
                continue
            path = os.path.normpath(os.path.join(folder, name))
            if not any(path == c or path.startswith(c + os.sep) for c in covered):
                uncovered.append(path)
        if seen >= SCAN_MAX_FILES:
            break
    if not uncovered:
        return [Check("PASS", "secret files", f"no secret-shaped file in {root} lacks an exact "
                      "Read deny rule")]
    home = ctx.home.rstrip(os.sep) + os.sep
    shown = ["~/" + p[len(home):] if p.startswith(home) else p for p in uncovered]
    listed = ", ".join(shown[:10]) + (f" and {len(shown) - 10} more" if len(shown) > 10 else "")
    return [Check("WARN", "secret files",
                  f"{len(shown)} secret-shaped file(s) that sandboxed Bash can still read: {listed}",
                  "Glob deny rules such as Read(//**/.env) don't reach sandboxed commands. Add an "
                  f"exact rule for each, such as Read({_rule_path(shown[0])}), to "
                  "permissions.deny: only a ~/ or // path, or a folder ending in /**, counts.")]


def _rule_path(shown: str) -> str:
    """A path as a Read rule writes it: ~/ stays, and an absolute path gets
    the // that marks it absolute (a single / means the project)."""
    return shown if shown.startswith("~/") else "/" + shown


def _settings_file(path: str):
    """A settings file's dict, None when it's missing, "invalid" otherwise."""
    text = _read_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return "invalid"
    return data if isinstance(data, dict) else "invalid"


def _allow_rules(settings) -> list:
    perms = settings.get("permissions") if isinstance(settings, dict) else None
    allow = perms.get("allow") if isinstance(perms, dict) else None
    return [r for r in allow if isinstance(r, str)] if isinstance(allow, list) else []


# An allow rule whose command is a remote shell, also behind a common wrapper
# or a path. (?![\w-]) so ssh-keygen and ssh-add, which stay local, don't match.
_REMOTE_SHELL = re.compile(r"Bash\(\s*(?:(?:env|command|exec|nohup|nice|timeout\s+\S+)\s+)*"
                           r"(?:[\w.~-]*/)*(?:ssh|scp|sftp|mosh|rsync|sshpass|autossh)(?![\w-])")
_ANY_COMMAND = frozenset({"Bash", "Bash(*)", "Bash(:*)", "Bash(* *)"})
PAGE_MAX = 2_000_000  # well above any page the coordinator writes
# Settings that give a project's sessions more than the user's own: a command
# that runs on its own, other environment, other sandbox rules, MCP servers.
_POWER_KEYS = ("env", "hooks", "disableAllHooks", "sandbox", "apiKeyHelper", "awsAuthRefresh",
               "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper", "statusLine",
               "fileSuggestion", "enableAllProjectMcpServers", "enabledMcpjsonServers")


def _coordinator_fix(what: str = "") -> str:
    return (what + " " if what else "") + ("Then run the coordinator step of "
                                           "/stranger-danger:setup (step 5) again.")


def _expand(path: str, home: str) -> str:
    return os.path.normpath(home + path[1:] if path == "~" or path.startswith("~/") else path)


def check_coordinator(ctx: Context, config: Optional[dict]) -> list:
    """The coordinator, when one is set up: its config, the CLAUDE.md paragraph
    that names it, no extra permissions in its project, and an untouched page.
    A fake paragraph in a project file is reported either way."""
    if config is None:
        return []  # the config check has already failed
    md_path = os.path.join(_claude_dir(ctx), "CLAUDE.md")
    fake = _fake_paragraphs(ctx, md_path)
    md = _read_text(md_path) or ""
    blocks, problem = coordinator.find_blocks(md)
    section = config.get("coordinator")
    if problem:
        return [Check("FAIL", "coordinator", f"{md_path}: {problem}",
                      _coordinator_fix("Fix the coordinator marker lines by hand."))] + fake
    if section is None:
        if blocks:
            return [Check("WARN", "coordinator", f"{md_path} names a coordinator, but the "
                          "config doesn't set one up",
                          "Run install.py --remove (setup step 5) to take the paragraph out, "
                          "or run the step again to set the coordinator up.")] + fake
        return [Check("INFO", "coordinator", "not set up (optional; setup step 5)")] + fake
    if not isinstance(section, dict):
        return [Check("FAIL", "coordinator", "coordinator in the config must be an object",
                      _coordinator_fix("Remove it."))] + fake
    name = section.get("name", coordinator.DEFAULT_NAME)
    problem = coordinator.name_problem(name)
    if not problem and "project" not in section:
        problem = "coordinator.project isn't set"
    real = None
    if not problem:
        real, problem = coordinator.resolve_project(section["project"], ctx.home)
    if problem:
        return [Check("FAIL", "coordinator", problem, _coordinator_fix("Fix the config."))] + fake
    out = []
    if real != _expand(section["project"], ctx.home):
        out.append(Check("WARN", "coordinator", f"coordinator.project goes through a symlink; "
                         f"sessions show its real folder, {real}",
                         _coordinator_fix("Use the real folder.")))
    if not blocks:
        out.append(Check("FAIL", "coordinator", f"{md_path} has no coordinator paragraph, so "
                         "sessions can't tell which session is the coordinator",
                         _coordinator_fix()))
    elif len(blocks) > 1:
        out.append(Check("FAIL", "coordinator", f"{md_path} has {len(blocks)} coordinator "
                         "paragraphs", _coordinator_fix("Delete all but one by hand.")))
    else:
        named = coordinator.block_folder(md, blocks[0])
        if named != real:
            out.append(Check("FAIL", "coordinator", f"the paragraph in {md_path} names "
                             f"{reader_gate._show(named or 'no folder', 200)}, but the config "
                             f"names {real}", _coordinator_fix()))
        elif coordinator.block_text(md, blocks[0]) != coordinator.paragraph(name, real, md_path):
            out.append(Check("FAIL", "coordinator", f"the paragraph in {md_path} isn't the one "
                             "setup writes, so an edit may have weakened what it tells your "
                             "sessions", _coordinator_fix("Take out the edited paragraph.")))
        else:
            out.append(Check("PASS", "coordinator", f"{name} works in {real}, and {md_path} "
                             "names it"))
        twins = _key_twins(real)
        if twins:
            out.append(Check("WARN", "coordinator", f"{', '.join(twins[:3])} share the "
                             "coordinator folder's Claude Code project key, so a session there "
                             "loads the coordinator's auto-memory",
                             "Rename or remove that folder, or pick a coordinator folder whose "
                             "path holds only letters, digits and slashes."))
        outside = "\n".join(line for i, line in enumerate(md.split("\n"))
                            if not blocks[0][0] <= i <= blocks[0][1])
        if _looks_like_recognition(outside):
            out.append(Check("WARN", "coordinator", f"{md_path} also describes a coordinator "
                             "outside the marker lines, where the doctor doesn't check it",
                             "Keep everything about who the coordinator is inside the paragraph "
                             "setup writes."))
    return out + _coordinator_project_checks(real) + fake


def _coordinator_project_checks(real: str) -> list:
    """The coordinator holds no more power than any other session: its project
    adds no allow rules, settings that run commands or change the environment,
    sandbox, permission mode or MCP servers. Reported by key name only."""
    out = []
    for name in ("settings.json", "settings.local.json"):
        path = os.path.join(real, ".claude", name)
        settings = _settings_file(path)
        if not isinstance(settings, dict):
            continue
        keys = [k for k in _POWER_KEYS if k in settings]
        perms = settings.get("permissions")
        if isinstance(perms, dict):
            if perms.get("defaultMode") not in (None, "default", "plan"):
                keys.append("permissions.defaultMode")
            if perms.get("additionalDirectories"):
                keys.append("permissions.additionalDirectories")
        if keys:
            out.append(Check("FAIL", "coordinator permissions",
                             f"{path} sets {', '.join(keys)}, which give the coordinator's "
                             "sessions more than any other session has",
                             "Remove them. Anything every session needs belongs in your user "
                             "settings, where you see it."))
        allow = _allow_rules(settings)
        if allow:
            out.append(Check("WARN", "coordinator permissions",
                             f"{path} has {len(allow)} allow rule(s) only the coordinator's "
                             "project gets",
                             "The coordinator should hold no more than any other session. Move "
                             "a rule every session needs to your user settings, or remove it."))
    if os.path.lexists(os.path.join(real, ".mcp.json")):
        out.append(Check("WARN", "coordinator permissions",
                         f"{os.path.join(real, '.mcp.json')} adds MCP servers to the "
                         "coordinator's project",
                         "MCP tools bring outside text into the session that calls them. Keep "
                         "them out of the coordinator's project."))
    page = os.path.join(coordinator.notes_dir(real, real), "status.html")
    if os.path.lexists(page):
        problem = None
        if not os.path.isfile(page) or os.path.islink(page):
            problem = "a link or something other than a file in its place"
        else:
            try:
                with open(page, "rb") as fh:
                    raw = fh.read(PAGE_MAX + 1)
            except OSError:
                raw = b""
                problem = "no readable content"
            # Checked whole: a check that read only the start would miss a
            # link appended past it.
            if problem is None:
                problem = (f"more than {PAGE_MAX} bytes" if len(raw) > PAGE_MAX
                           else coordinator.page_problem(raw))
        if problem:
            out.append(Check("FAIL", "status page", f"{page} has {problem}: something else "
                             "changed it",
                             "Delete it and run the coordinator to rebuild it. Then find out "
                             "what wrote it."))
        else:
            out.append(Check("PASS", "status page", "its markup holds nothing that can act "
                             "(the doctor can't check that what it says is true)"))
    return out


def _looks_like_recognition(text: str) -> bool:
    """A coordinator paragraph, or text written to pass as one: the marker, or
    "coordinator" with "working in" near it, in any case."""
    if coordinator.BEGIN in text:
        return True
    low = text.lower()
    at = low.find("coordinator")
    while at != -1:
        if "working in" in low[max(0, at - 300):at + 300]:
            return True
        at = low.find("coordinator", at + 1)
    return False


_RULES_FILES_MAX = 200
_KEY_WALK_MAX = 2000
_IMPORT = re.compile(r"(?<![\w`])@(~?[\w.~/-]+)")


def _project_key(path: str) -> str:
    """The name Claude Code gives a folder's project data (auto-memory,
    transcripts): every character but a letter or digit becomes "-", one for
    one, with case kept. Seen on 2.1.280: ".claude/worktrees" became
    "--claude-worktrees", "my-app.old" "my-app-old", and a folder name ending
    in a space ends in "-"."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def _key_twins(real: str) -> list:
    """Other existing folders with the same project key as `real`, such as
    ~/code/my/app for ~/code/my-app."""
    key, found, budget = _project_key(real), [], [_KEY_WALK_MAX]

    def walk(folder: str, rest: str, along) -> None:
        # `along`: what's left of the real path while the walk follows it, so a
        # folder that can't be listed (/tmp/user, say) is still passed through.
        if budget[0] <= 0:
            return
        budget[0] -= 1
        try:
            entries = sorted(os.listdir(folder))
        except OSError:
            entries = along[:1] if along else []
        for entry in entries:
            part = "-" + _project_key(entry)
            if not rest.startswith(part):
                continue
            path = os.path.join(folder, entry)
            if not os.path.isdir(path):
                continue
            nxt = along[1:] if along and entry == along[0] else None
            if len(rest) == len(part):
                found.append(path)
            elif rest[len(part)] == "-" and not os.path.islink(path):
                walk(path, rest[len(part):], nxt)

    walk("/", key, [p for p in real.split("/") if p])
    return [f for f in found if os.path.realpath(f) != real]


def _project_instruction_files(folder: str) -> list:
    """The instruction files Claude Code may load for a session in `folder`:
    CLAUDE.md files there and above it, and the project's .claude/rules."""
    out, seen = [], set()
    current = folder
    while current not in seen:
        seen.add(current)
        out += [os.path.join(current, rel) for rel in
                ("CLAUDE.md", "CLAUDE.local.md", os.path.join(".claude", "CLAUDE.md"))]
        current = os.path.dirname(current)
    rules = os.path.join(folder, ".claude", "rules")
    for root, dirs, files in os.walk(rules):
        dirs[:] = sorted(dirs)
        out += [os.path.join(root, f) for f in sorted(files) if f.endswith(".md")]
        if len(out) > _RULES_FILES_MAX:
            break
    return out


def _imports(path: str, text: str, home: str) -> list:
    """The files `text` pulls in with @path, resolved as Claude Code does:
    ~ is your home folder, and anything else is relative to the file."""
    out = []
    for ref in _IMPORT.findall(text)[:50]:
        ref = home + ref[1:] if ref.startswith("~/") else ref
        out.append(os.path.normpath(os.path.join(os.path.dirname(path), ref)))
    return out


def _fake_paragraphs(ctx: Context, md_path: str) -> list:
    """A coordinator paragraph in a project's own instruction files: only the
    one in the user's CLAUDE.md counts, and a repo can ship a fake one."""
    found, seen = [], set()
    queue = [(p, 0) for p in _project_instruction_files(os.path.realpath(ctx.project_dir or ctx.cwd))]
    while queue and len(seen) < _RULES_FILES_MAX:
        path, depth = queue.pop(0)
        real = os.path.realpath(path)
        # Regular files only: a named pipe called CLAUDE.md would hang the read.
        if real in seen or not os.path.isfile(path) or real == os.path.realpath(md_path):
            continue
        seen.add(real)
        text = _read_text(path)
        if not text:
            continue
        if _looks_like_recognition(text):
            found.append(path)
        if depth < 4:  # Claude Code follows imports up to five deep
            queue += [(p, depth + 1) for p in _imports(path, text, ctx.home)]
    if not found:
        return []
    return [Check("WARN", "coordinator", "a coordinator paragraph in a project file, which "
                  "doesn't count: " + ", ".join(found[:5]),
                  f"Only the paragraph in {md_path} names the coordinator. Remove this one; "
                  "if you didn't write it, treat it as an attempt to pass as the coordinator.")]


def check_ssh_allow(ctx: Context) -> list:
    """An allow rule that runs ssh (or another remote shell) with a wildcard
    lets agents run any command on a server with no prompt. Checks your user
    settings and this project's."""
    files = [os.path.join(_claude_dir(ctx), "settings.json"),
             os.path.join(_claude_dir(ctx), "settings.local.json")]
    folder = ctx.project_dir or ctx.cwd
    files += [os.path.join(folder, ".claude", n) for n in ("settings.json", "settings.local.json")]
    hits, every = [], []
    for path in dict.fromkeys(files):
        for rule in _allow_rules(_settings_file(path)):
            if rule.replace(" ", "") in {r.replace(" ", "") for r in _ANY_COMMAND}:
                every.append(path)
            elif _REMOTE_SHELL.match(rule) and ("*" in rule or re.fullmatch(
                    r"Bash\(\s*[\w.~/-]+\s*\)", rule)):
                hits.append(f"{rule} in {path}")
    out = []
    if hits:
        out.append(Check("FAIL", "ssh allow rules",
                         "; ".join(reader_gate._show(h, 200) for h in hits[:5]),
                         "Remove them. A remote shell runs whatever it's given, so no wildcard "
                         "ssh rule is read-only. Watch a server through a fixed status script "
                         "instead."))
    if every:
        out.append(Check("WARN", "ssh allow rules", "an allow rule for every Bash command, ssh "
                         "included, in " + ", ".join(every[:3]),
                         "Remove it. With the sandbox on, sandboxed commands don't need it."))
    return out or [Check("PASS", "ssh allow rules", "no allow rule opens a remote shell")]


# Tools that can publish or reach people. The ask rules name their usual
# subcommands; a wildcard allow for the whole tool lets every other spelling
# (`npm --registry x publish`) run with no prompt.
_PUBLISHERS = ("gh", "npm", "pnpm", "yarn", "bun", "cargo", "uv", "poetry", "twine", "gem",
               "docker", "podman", "hatch", "flit", "pdm", "maturin", "vsce", "skopeo", "crane",
               "buildah", "lerna", "semantic-release", "changeset")
# Wrappers and interpreters run any command, so a wildcard allow for one
# covers every publish command too.
_RUNS_ANYTHING = ("env", "command", "exec", "nohup", "nice", "timeout", "xargs", "bash", "sh",
                  "zsh", "dash", "python", "python3", "node", "npx", "pnpx", "bunx", "deno",
                  "perl", "ruby")
# Subcommand groups that hold publish commands: Bash(gh pr *) lets
# `gh pr -R o/r create` through.
_PUBLISH_GROUPS = (r"gh\s+(?:pr|issue|repo|release|gist|workflow|secret|variable|api)",
                   r"(?:docker|podman)\s+(?:image|compose|buildx)",
                   # Forms that run whatever follows.
                   r"(?:ba|z|da)?sh\s+-c", r"python3?\s+-c", r"node\s+-e", r"uv\s+run", "find")
_BROAD_ALLOW = re.compile(
    r"Bash\(\s*(?:(?:env|command|exec|nohup|nice|timeout\s+\S+|\w+=\S*)\s+)*(?:\S*/)?"
    r"(?:" + "|".join(re.escape(n) for n in _PUBLISHERS + _RUNS_ANYTHING) + "|"
    + "|".join(_PUBLISH_GROUPS) + r")(?:\s*\*|:\s*\*)\s*\)")


def check_domains_ask(ctx: Context, config: Optional[dict]) -> list:
    """With launch_gate.ask_for_domains on (the default), a call's extra network
    hosts go to a permission prompt, which a broad Bash or Monitor allow rule
    might approve without showing you (VERIFY row M2)."""
    if config is None:
        return []   # the config check already failed or warned
    try:
        on = launch_gate._ask_for_domains(config)
    except _config.ConfigError:
        return []   # reported by the config check
    if not on:
        return [Check("INFO", "network hosts ask", "launch_gate.ask_for_domains is off: a "
                      "call's extra network hosts are refused")]
    files = [os.path.join(_claude_dir(ctx), "settings.json"),
             os.path.join(_claude_dir(ctx), "settings.local.json")]
    folder = ctx.project_dir or ctx.cwd
    files += [os.path.join(folder, ".claude", n) for n in ("settings.json", "settings.local.json")]
    files += _managed_files(ctx)
    hits = [f"{rule} in {path}" for path in dict.fromkeys(files)
            for rule in _allow_rules(_settings_file(path))
            if re.fullmatch(r"(?:Bash|Monitor)(?:\(.*\*.*\))?", rule.strip(), re.S)]
    if hits:
        return [Check("WARN", "network hosts ask",
                      "a call's extra network hosts go to a permission prompt, and these allow "
                      "rules might approve it without showing you: "
                      + "; ".join(reader_gate._show(h, 200) for h in hits[:5]),
                      "Narrow or remove these rules, or set launch_gate.ask_for_domains to "
                      "false to have such calls refused. Whether even an exact rule skips the "
                      "ask is VERIFY row M2b.")]
    return [Check("INFO", "network hosts ask", "a call's extra network hosts go to a permission "
                  "prompt. It's a request for a prompt, not a block: an allow rule that matches "
                  "the command (an exact one isn't flagged here, and isn't known to be safe), "
                  "another plugin's hook, a PermissionRequest hook or an SDK callback could "
                  "approve it unseen. If you use those, set launch_gate.ask_for_domains to "
                  "false (VERIFY row M2).")]


def check_broad_allows(ctx: Context) -> list:
    """An allow rule for a whole publishing tool (Bash(npm *)) skips the
    prompt for every spelling the ask rules don't name."""
    files = [os.path.join(_claude_dir(ctx), "settings.json"),
             os.path.join(_claude_dir(ctx), "settings.local.json")]
    folder = ctx.project_dir or ctx.cwd
    files += [os.path.join(folder, ".claude", n) for n in ("settings.json", "settings.local.json")]
    every = {r.replace(" ", "") for r in _ANY_COMMAND}
    hits = [f"{rule} in {path}" for path in dict.fromkeys(files)
            for rule in _allow_rules(_settings_file(path))
            if _BROAD_ALLOW.fullmatch(rule) or rule.replace(" ", "") in every]
    if hits:
        return [Check("WARN", "broad allow rules",
                      "; ".join(reader_gate._show(h, 200) for h in hits[:5]),
                      "Allow the exact commands you use (Bash(npm test), Bash(gh pr view *)) "
                      "instead of the whole tool.")]
    return [Check("PASS", "broad allow rules", "none of the common forms: a whole publishing "
                  "tool, a wrapper or an interpreter")]


# Environment variables that publish tools read a token from, with the hosts
# the token publishes to (None: a host of your own). Only the names are
# checked; a value is never read or shown.
_GITHUB = ("api.github.com", "github.com", "uploads.github.com", "ghcr.io")
_PYPI = ("upload.pypi.org",)
_PUBLISH_TOKENS = (
    (r"NPM_TOKEN|NODE_AUTH_TOKEN|YARN_NPM_AUTH_TOKEN|(?i:npm_config_\w*_authtoken|npm_config__auth)",
     ("registry.npmjs.org", "registry.yarnpkg.com")),
    (r"GH_TOKEN|GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|CR_PAT", _GITHUB),
    (r"GH_ENTERPRISE_TOKEN|GITHUB_ENTERPRISE_TOKEN", None),
    (r"CARGO_REGISTRY_TOKEN", ("crates.io",)),
    (r"CARGO_REGISTRIES_\w+_TOKEN", None),
    (r"TWINE_PASSWORD|PYPI_TOKEN|PYPI_API_TOKEN|UV_PUBLISH_TOKEN|UV_PUBLISH_PASSWORD"
     r"|POETRY_PYPI_TOKEN_\w+|MATURIN_PYPI_TOKEN|HATCH_INDEX_AUTH|FLIT_PASSWORD", _PYPI),
    (r"GEM_HOST_API_KEY", ("rubygems.org",)),
    (r"VSCE_PAT", ("marketplace.visualstudio.com",)),
    (r"OVSX_PAT", ("open-vsx.org",)),
    (r"DOCKER_PASSWORD", ("registry-1.docker.io", "index.docker.io", "docker.io")),
    (r"GITLAB_TOKEN", ("gitlab.com",)),
    (r"HF_TOKEN", ("huggingface.co",)),
)


def _host_allowed(host: str, domains: list) -> bool:
    for d in domains:
        d = d.strip().lower()
        if d in ("*", "*.*") or d == host or (d.startswith("*.") and host.endswith(d[1:])):
            return True
    return False


def check_publish_tokens(ctx: Context) -> list:
    """With the sandbox on, Claude Code runs a sandboxed command no deny or ask
    rule names without a prompt (sandbox.autoAllowBashIfSandboxed, on by
    default). A publish command spelled another way would then run; it can
    publish if a token is at hand and its host is on the sandbox's network
    list."""
    # Settings files, highest precedence first: managed, this project's local
    # and shared settings, then yours.
    folder = ctx.project_dir or ctx.cwd
    # managed-settings.d's files merge over managed-settings.json, later names winning.
    drop_ins = os.path.join(os.path.dirname(ctx.managed_settings), "managed-settings.d")
    try:
        drop_ins = sorted((os.path.join(drop_ins, n) for n in os.listdir(drop_ins)
                           if n.endswith(".json")), reverse=True)
    except OSError:
        drop_ins = []
    layers = [_settings_file(path) for path in dict.fromkeys(
        drop_ins + [ctx.managed_settings]
        + [os.path.join(folder, ".claude", n) for n in ("settings.local.json", "settings.json")]
        + [os.path.join(_claude_dir(ctx), n) for n in ("settings.json", "settings.local.json")])]
    layers = [s for s in layers if isinstance(s, dict)]

    def sandbox_value(key):
        for s in layers:
            sandbox = s.get("sandbox")
            if isinstance(sandbox, dict) and key in sandbox:
                return sandbox[key]
        return None

    enabled = sandbox_value("enabled") is True
    auto = sandbox_value("autoAllowBashIfSandboxed") is not False
    if not (enabled and auto):
        return [Check("INFO", "publish tokens", "skipped: no settings file the doctor reads "
                      "turns the sandbox on with sandboxed commands auto-allowed (it doesn't "
                      "see --settings, MDM or Windows registry policy)")]
    # Every place a host can be let through: the sandbox's list and WebFetch
    # domain allow rules (domain:* is every host), in every settings file. A
    # WebFetch rule with no domain: part doesn't touch the sandbox's list.
    domains = []
    for s in layers:
        net = s.get("sandbox", {}).get("network") if isinstance(s.get("sandbox"), dict) else None
        listed = net.get("allowedDomains") if isinstance(net, dict) else None
        domains += [d for d in listed if isinstance(d, str)] if isinstance(listed, list) else []
        domains += [m.group(1) for r in _allow_rules(s)
                    for m in [re.fullmatch(r"WebFetch\(\s*domain:\s*([^)\s]+)\s*\)", r)] if m]
    # A settings file's env reaches every command, like the environment itself.
    names = set(ctx.env)
    for s in layers:
        if isinstance(s.get("env"), dict):
            names.update(k for k in s["env"] if isinstance(k, str))
    reachable, held = [], []
    for name in sorted(names):
        for pattern, hosts in _PUBLISH_TOKENS:
            if re.fullmatch(pattern, name):
                if hosts is None or any(_host_allowed(h, domains) for h in hosts):
                    reachable.append(name)
                else:
                    held.append(name)
                break
    if reachable:
        return [Check("WARN", "publish tokens", "set in the environment Claude Code runs in "
                      "or a settings file's env, and their hosts are on the sandbox's network "
                      "list: "
                      + ", ".join(reachable[:8]),
                      "Start Claude Code from a shell without them (and out of settings env) "
                      "and publish from your own terminal, or set sandbox.autoAllowBashIfSandboxed to false so every "
                      "command no allow rule covers asks.")]
    if held:
        return [Check("INFO", "publish tokens", "in the environment or a settings file's env, "
                      "but their hosts aren't on "
                      "the sandbox's network list or in a WebFetch allow rule: "
                      + ", ".join(held[:8]) + ". A host you approve at a prompt later "
                      "makes them usable.")]
    return [Check("PASS", "publish tokens", "no publish token in the environment or a "
                  "settings file's env")]


def check_gates(ctx: Context, config: Optional[dict]) -> list:
    if config is None:
        return [Check("FAIL", "self-test", "skipped: the config doesn't load")]
    out = []
    env = reader_gate.Env(home=ctx.home, plugin_root=ctx.plugin_root,
                          project_dir=ctx.project_dir)
    plugin = reader_gate._plugin_name(env)
    main = {"tool_name": "WebSearch", "tool_input": {"query": "stranger-danger self-test"},
            "cwd": ctx.cwd}
    reader = dict(main, agent_type=f"{plugin}:web-researcher", agent_id="doctor-self-test")
    cases = [
        ("main session WebSearch is denied", reader_gate.decide(main, config, env), True),
        ("web reader WebSearch passes", reader_gate.decide(reader, config, env), False),
        ("`npx cowsay` is denied", launch_gate.check("npx cowsay", config), True),
        ("`ls` passes", launch_gate.check("ls", config), False),
    ]
    for label, reason, want_deny in cases:
        ok = bool(reason) == want_deny
        detail = label if ok else f"{label}: got {'deny: ' + reason if reason else 'pass'}"
        out.append(Check("PASS" if ok else "FAIL", "self-test", detail,
                         "" if ok else "The gate's decision differs from what's expected; "
                         "see docs/HOW-IT-WORKS.md."))
    # One real run of each script, as Claude Code starts it.
    runs = (("reader_gate.py", reader), ("launch_gate.py",
            {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": ctx.cwd}),
            ("reader_tools.py", {"tool_name": "Write", "tool_input": {"file_path": "x"},
                                 "cwd": ctx.cwd}))
    # And one that must refuse, so a script that passes everything shows.
    refusals = (("reader_tools.py", {"tool_name": "Write", "tool_input": {"file_path": "x"},
                                     "agent_type": f"{plugin}:web-researcher",
                                     "agent_id": "doctor-self-test"}, "reader tools (rule 3)",
                 "a reader's Write"),
                ("launch_gate.py", {"tool_name": "Monitor", "tool_input": {"command": "npx cowsay"},
                                    "cwd": ctx.cwd}, "launch gate (rule 1)", "a Monitor `npx`"))
    for script, event, words, what in refusals:
        try:
            # A throwaway home, so the probe's refusal isn't logged as a real
            # reader reaching Write.
            with tempfile.TemporaryDirectory() as probe_home:
                proc = subprocess.run([ctx.python, "-I",
                                       os.path.join(ctx.plugin_root, "hooks", script)],
                                      input=json.dumps(event), capture_output=True, text=True,
                                      timeout=20, env=_probe_env(probe_home))
            ok = proc.returncode == 2 and words in proc.stderr
            detail = f"{script} refuses {what}" if ok else (
                f"{script} didn't refuse {what} (exit {proc.returncode})")
        except (OSError, subprocess.SubprocessError) as exc:
            ok, detail = False, f"{script} didn't run: {exc}"
        out.append(Check("PASS" if ok else "FAIL", "hook script", detail))
    for script, event in runs:
        env_vars = _probe_env(ctx.home, CLAUDE_PLUGIN_ROOT=ctx.plugin_root)
        try:
            proc = subprocess.run([ctx.python, "-I", os.path.join(ctx.plugin_root, "hooks", script)],
                                  input=json.dumps(event), capture_output=True, text=True,
                                  timeout=20, env=env_vars)
            ok = proc.returncode == 0
            detail = f"{script} runs under python3 -I" if ok else (
                f"{script} exited {proc.returncode}: {proc.stderr.strip()[:200]}")
        except (OSError, subprocess.SubprocessError) as exc:
            ok, detail = False, f"{script} didn't run: {exc}"
        out.append(Check("PASS" if ok else "FAIL", "hook script", detail))
    return out


def _claude_version(text: str) -> Optional[tuple]:
    """(major, minor, patch, prerelease) from `claude --version`, or None.
    The version must lead the output."""
    m = re.match(r"\s*(\d+)\.(\d+)\.(\d+)(-\S+)?", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups()[:3]) + (bool(m.group(4)),)


def check_claude(ctx: Context) -> list:
    parsed = _claude_version(ctx.run(["claude", "--version"]) or "")
    if parsed is None:
        return [Check("WARN", "claude", "couldn't confirm Claude Code 2.1.295 or later",
                      "Run `claude --version`; update if below 2.1.295.")]
    version, prerelease = parsed[:3], parsed[3]
    shown = ".".join(map(str, version)) + ("-pre" if prerelease else "")
    # A prerelease of the minimum comes before it.
    if version < ON_FAILURE_VERSION or (prerelease and version == ON_FAILURE_VERSION):
        return [Check("FAIL", "claude",
                      f"Claude Code {shown} is older than 2.1.295, the minimum: before it, a "
                      "gate that runs past its hook timeout lets the call through, and whether "
                      "it loads hooks that set onFailure isn't known",
                      "Update Claude Code.")]
    return [Check("INFO", "claude", f"Claude Code {shown}; hooks.json's onFailure: block makes "
                  "a stalled gate block. In auto mode, a call no rule covers can go through "
                  "without a prompt, whatever a subagent's permissionMode says; deny what "
                  "you'd only approve in passing.")]


def _probe_env(home: str, **extra) -> dict:
    """The environment for one hook run with this home. The hooks take home
    from the account database and refuse a different HOME, so a throwaway or
    injected home runs them the way the tests do: with the config override
    (the real folder's HOME mismatch is reported by the home folder check)."""
    env = dict(os.environ, HOME=home, **extra)
    if _home_problem(home):
        env.pop("CLAUDE_PROJECT_DIR", None)
        env[_config.ENV_OVERRIDE] = os.path.join(home, "no-such-config.json")
    return env


def _home_problem(home: str) -> Optional[str]:
    try:
        import pwd
        account = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, AttributeError):
        return None
    if os.path.realpath(account) != os.path.realpath(home):
        return f"HOME is {home}, but your account's home folder is {account}"
    return None


def _guarded(check: Callable, *args) -> list:
    """Run one check. One that crashes becomes a FAIL that names only the
    error's type, so an odd file can't silence every other check."""
    try:
        return check(*args)
    except Exception as exc:  # noqa: BLE001 - reported, never hidden
        name = check.__name__[len("check_"):].replace("_", " ")
        return [Check("FAIL", "doctor", f"its {name} check stopped with {type(exc).__name__}",
                      "Run /stranger-danger:report and file a bug with what it prints.")]


def run_all(ctx: Context) -> list:
    checks = [Check("INFO", "plugin files", f"{ctx.plugin_root} (/stranger-danger:setup "
                    "prints the commands that copy and merge its templates)")]
    if ctx.home_problem:
        checks.append(Check("FAIL", "home folder", ctx.home_problem,
                            "Start Claude Code with your own HOME; the gates' ~ paths follow it."))
    if ctx.config_override:
        checks.append(Check("FAIL", "config", f"{_config.ENV_OVERRIDE} is set, so a gate "
                            "started from this shell reads another config than your sessions "
                            "do. The doctor checked the default one.",
                            f"Unset {_config.ENV_OVERRIDE}; only the tests use it.",
                            means="A gate started from this shell follows a config file "
                                  "someone else may have chosen, not yours."))
    checks += _guarded(check_python, ctx)
    checks += _guarded(check_agents, ctx)
    checks += _guarded(check_hooks_json, ctx)
    try:
        config, _path, config_checks = load_user_config(ctx)
    except Exception as exc:  # noqa: BLE001 - reported, never hidden
        config, config_checks = None, [Check(
            "FAIL", "doctor", f"its config check stopped with {type(exc).__name__}",
            "Run /stranger-danger:report and file a bug with what it prints.")]
    checks += config_checks
    checks += _guarded(check_settings, ctx)
    checks += _guarded(check_sandbox, ctx)
    checks += _guarded(check_monitor, ctx)
    checks += _guarded(check_managed_hooks_only, ctx)
    checks += _guarded(check_start_paths, ctx)
    checks += _guarded(check_setup_write_denies, ctx)
    checks += _guarded(check_secret_files, ctx)
    checks += _guarded(check_read_denies, ctx, config)
    checks += _guarded(check_package_env, ctx)
    checks += _guarded(check_npm, ctx)
    checks += _guarded(check_rules, ctx)
    checks += _guarded(check_ssh_allow, ctx)
    checks += _guarded(check_broad_allows, ctx)
    checks += _guarded(check_domains_ask, ctx, config)
    checks += _guarded(check_publish_tokens, ctx)
    checks += _guarded(check_blast_radius, ctx)
    checks += _guarded(check_osv, ctx)
    checks += _guarded(check_coordinator, ctx, config)
    checks += _guarded(check_gates, ctx, config)
    checks += _guarded(check_claude, ctx)
    return checks


# What each problem means for you, in one plain sentence. Every check that can
# warn or fail has one (tests/test_doctor.py checks), so no finding is only jargon.
RISK = {
    "Plugin hooks": "Claude Code isn't running this plugin's hooks, so no gate refuses anything; "
                    "only your rules file and permission rules protect you.",
    "agent": "A reader agent with more tools than it should have could act on a hostile "
             "page or file.",
    "agent names": "If the gates can't tell the reader agents apart, untrusted text can "
                   "reach an agent that can act.",
    "network hosts ask": "An agent's call could reach a host past your sandbox's network "
                         "allowlist without you seeing a prompt, if an allow rule approves "
                         "it.",
    "broad allow rules": "An agent could publish a package or post to GitHub without asking "
                         "you, by spelling the command in a way the ask rules don't name.",
    "osv check": "/stranger-danger:osv can't reach one of its sources or save its result.",
    "osv tools": "The OSV check can't run, so you won't hear of fixes or malware records "
                 "for what you hold.",
    "osv result": "A package you hold may have a malware record or a fixed vulnerability, or "
                  "the check hasn't run lately.",
    "publish tokens": "A sandboxed command runs without asking you, so one spelled in a way "
                      "the ask rules don't name could publish or post with this token.",
    "config": "A broken gate config makes both gates block everything they cover until "
              "it's fixed.",
    "config untrusted_paths": "A folder you marked untrusted doesn't exist yet, so nothing "
                              "is protected there until you create it.",
    "config quarantine_paths": "A quarantine folder you named doesn't exist yet, so nothing "
                               "is protected there until you create it.",
    "config quarantine_root": "A quarantine folder that holds your home or your project is not a dedicated "
                              "folder of strangers' files: file tools are refused there, or the reviewer "
                              "reads your project's registry settings.",
    "coordinator": "Your sessions could take the wrong session for the coordinator, or "
                   "follow a weakened description of it.",
    "coordinator permissions": "The coordinator's project gives its sessions more power than "
                               "your others, so a hijacked coordinator could do more.",
    "doctor": "One of the doctor's checks couldn't finish, so a problem it looks for may "
              "be there unreported.",
    "home folder": "Every ~ path the gates protect points at the wrong folder, so your real "
                   "secrets aren't guarded.",
    "hook script": "A gate's script is missing or changed, so the calls it covers may go "
                   "unchecked.",
    "claude": "On a Claude Code older than 2.1.295, a gate that stalls lets the call "
              "through, and the gates may not load at all.",
    "hooks.json": "If the plugin's hook list is broken, the gates may not run at all.",
    "Monitor tool": "An agent could run shell commands through Monitor that the launch gate "
                    "may never see.",
    "network allowlist": "Agents could send your data to a site a stranger controls.",
    "npm version": "This npm may not know the 7-day setting, so a package published "
                   "minutes ago could be installed.",
    "package lane env": "Commands Claude Code runs could install a package published minutes "
                        "ago, or run a package's own install code.",
    "sandbox read denies": "A sandboxed command could read files in folders you marked "
                           "untrusted, quarantined or secret, which the reader gate keeps "
                           "from the file tools.",
    "sandbox retries": "A command the sandbox stopped could be run again outside it, where "
                       "nothing limits what it reads or reaches.",
    "npm and the sandbox": "Inside the sandbox npm loses its safety settings, so a new "
                           "package's install scripts could run.",
    "npm ignore-scripts": "Installing a package could run that package's own code on your "
                          "machine.",
    "npm min-release-age": "A package published minutes ago, before anyone could spot malware "
                           "in it, could be installed.",
    "permission mode": "Agents can do anything without asking you.",
    "project MCP servers": "A repo you open could start its own MCP server: a program that "
                           "then runs with your rights.",
    "python": "The gates can't run on this Python, so they don't protect you yet.",
    "rules": "Your agents aren't loading the StrangerDanger rules, so they don't know what to "
             "refuse.",
    "rules canary": "You can't yet confirm that your agents loaded the rules.",
    "rules import": "Your agents aren't loading the StrangerDanger rules, so they don't know "
                    "what to refuse.",
    "sandbox": "Bash commands can read any file you can, including secrets the other rules "
               "hide.",
    "secret files": "A sandboxed command could read these secret files, because only a "
                    "pattern rule covers them.",
    "self-test": "A gate isn't behaving as it should, so calls it covers may go unchecked or "
                 "be blocked.",
    "settings": "Without a working settings file, none of the deny rules apply.",
    "settings ask rules": "Agents could publish, post, drive a browser or plant coordinator "
                          "notes without asking you.",
    "settings deny rules": "Agents could read secrets or change your guardrails without being "
                           "stopped.",
    "ssh allow rules": "An agent could run any command on your server with no prompt.",
    "start paths": "In a session started in your home folder, a hijacked agent could plant "
                   "code that your next shell or claude runs outside the sandbox.",
    "setup files": "In a session whose writable folders include your Claude folder, a "
                   "sandboxed command could change your settings or rules with no prompt.",
    "status page": "Something other than the coordinator changed its status page, which could "
                   "show you false information.",
}


def risk(name: str) -> str:
    return RISK.get(name) or RISK.get(name.split(" ", 1)[0], "")


def render(checks: list) -> str:
    counts = {s: sum(1 for c in checks if c.status == s) for s in ("PASS", "WARN", "FAIL")}
    problems = counts["WARN"] + counts["FAIL"]
    lines = ["stranger-danger doctor", "",
             "Nothing needs your attention." if not problems else
             f"{problems} thing(s) need your attention. Each says what it means for you and "
             "how to fix it.", ""]
    for c in checks:
        lines.append(f"{c.status:<5} {c.name}: {reader_gate._show(c.detail, 400)}")
        if c.status in ("WARN", "FAIL"):
            if c.means or risk(c.name):
                lines.append(f"      means: {c.means or risk(c.name)}")
            if c.fix:
                lines.append(f"      fix: {c.fix}")
    lines += ["", f"{counts['PASS']} pass, {counts['WARN']} warn, {counts['FAIL']} fail"]
    return "\n".join(lines)


# -- the report for a bug report ----------------------------------------------

REPORT_DAYS = 7
REPORT_LOG_BYTES = 5_000_000  # read at most the last this-many bytes of the log
# Checks about the plugin itself, shown by name: whether the gates run. The
# rest describe your setup's protections, so the report only counts them: a
# public issue that lists which protections are off tells anyone where to aim.
# The "config" check is named only when the file loads (PASS) or is broken
# (FAIL); its WARN and INFO say no folders are protected, so they're counted.
REPORT_NAMED = frozenset({
    "plugin files", "home folder", "claude", "python", "hooks.json", "hook script",
    "self-test", "agent names", "rules", "rules import", "rules canary",
} | {f"agent {reader}" for reader in reader_gate.READER_TOOLS})
_PLUGIN_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:-(?:alpha|beta|rc)\.?[0-9]{1,3})?")
_LOG_STATE = {"ok": "ok", "missing": "none yet", "full": "full (new decisions aren't logged)",
              "not-writable": "its owner or mode was changed (the hooks may not be able "
                              "to write it)",
              "unreadable": "can't be read",
              "not-regular": "not a regular file (a link, pipe, folder or hard link is in "
                             "its place)"}


def _plugin_version(ctx: Context) -> str:
    try:
        with open(os.path.join(ctx.plugin_root, ".claude-plugin", "plugin.json"),
                  encoding="utf-8") as fh:
            version = json.load(fh).get("version")
    except (OSError, ValueError, AttributeError, RecursionError):
        version = None
    return version if isinstance(version, str) and _PLUGIN_VERSION.fullmatch(version) \
        else "unknown"


def _bucket(n: int) -> str:
    # Rough counts: exact ones could carry data from anything that can write
    # the log (a token, a few bits per row) into a public issue.
    return "1" if n == 1 else "2-9" if n < 10 else "10-99" if n < 100 else "100+"


def _log_counts(home: str, today: datetime.date) -> dict:
    """The decision log over the last REPORT_DAYS days, up to today: counts by
    "decision code", lines skipped, whether only the newest part was read and
    the log's state. Only the decisions and codes the hooks write are kept;
    anything else counts as "other", so text put in the log by something else
    can't reach the report."""
    from collections import Counter
    first = (today - datetime.timedelta(days=REPORT_DAYS - 1)).isoformat()
    last = today.isoformat()
    out = {"counts": Counter(), "skipped": 0}
    path = _log.log_path(home)
    lines, out["cut"], out["state"] = coordinator.log_tail(path, REPORT_LOG_BYTES)
    for raw in lines:
        try:
            rec = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            out["skipped"] += 1
            continue
        if not isinstance(rec, dict):
            out["skipped"] += 1
            continue
        stamp = rec.get("time")
        if not (isinstance(stamp, str) and first <= stamp[:10] <= last):
            continue
        decision, code = rec.get("decision"), rec.get("code")
        words = (decision if isinstance(decision, str) and decision in _log.KNOWN_DECISIONS
                 else "other",
                 code if isinstance(code, str) and code in _log.KNOWN_CODES else "other")
        out["counts"][" ".join(words)] += 1
    return out


def report(ctx: Context, checks: list, today: Optional[datetime.date] = None) -> str:
    """A summary to paste into a bug report: versions, the plugin's own checks
    by name and result, a count of the setup checks, and a week of the decision
    log by decision and code, in rough counts. It leaves out everything that
    can name your files, hosts or projects (the checks' details, the log's
    paths, hosts and agent names) and names only the checks of whether the
    gates run; a FAIL there still shows a gate isn't working."""
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    claude = _version_tuple(ctx.run(["claude", "--version"]) or "")
    python = _version_tuple(ctx.run(PYTHON_PROBE, cwd=ctx.project_dir or ctx.cwd) or "")
    show = lambda v: ".".join(map(str, v)) if v else "unknown"  # noqa: E731
    lines = ["## stranger-danger report", "",
             f"- plugin {_plugin_version(ctx)}; Claude Code {show(claude)}; "
             f"python3 {show(python)}; {platform.system() or 'unknown'}", "",
             "### Doctor: the plugin's own checks", "", "| check | result |", "|---|---|"]
    setup = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
    for c in checks:
        if c.name in REPORT_NAMED or (c.name == "config" and c.status in ("PASS", "FAIL")):
            lines.append(f"| {c.name} | {c.status} |")
        else:
            setup[c.status] = setup.get(c.status, 0) + 1
    lines += ["", f"{sum(setup.values())} setup checks: {setup['PASS']} pass, "
              f"{setup['WARN']} warn, {setup['FAIL']} fail, {setup['INFO']} info. Their "
              "names are left out, because they show which of your protections are off."]
    log = _log_counts(ctx.home, today)
    state = _LOG_STATE.get(log["state"], "unknown")
    lines += ["", f"### Decision log, last {REPORT_DAYS} days", "", f"Log: {state}.", ""]
    if log["counts"]:
        lines += ["| decision and code | count |", "|---|---|"]
        lines += [f"| {k} | {_bucket(v)} |" for k, v in sorted(log["counts"].items())]
    else:
        lines.append("nothing logged")
    if log["cut"]:
        lines.append(f"\nOnly the newest {REPORT_LOG_BYTES // 1_000_000} MB of the log was read.")
    if log["skipped"]:
        lines.append(f"\nSome lines of the log couldn't be read ({_bucket(log['skipped'])}).")
    lines += ["", "Left out on purpose: the doctor's details, the setup checks' names, and the "
              "log's paths, hosts and agent names. Add only what you're comfortable sharing, "
              "and never a secret."]
    return "\n".join(lines)


def canary_check(ctx: Context, stated: str) -> tuple:
    """The skill's canary step: whether the word a session stated is the rules
    file's. Returns (line, exit code); the line never holds either word."""
    if not _canary.CHECKABLE.fullmatch(stated):
        return ("rules canary: can't check that word here (letters, digits, - and _ only, "
                "at most 64); compare it with your rules file yourself", 2)
    text = _read_text(os.path.join(_claude_dir(ctx), "stranger-danger", "RULES.md"))
    result = None if text is None else _canary.matches(stated, text)
    if result is None:
        return ("rules canary: not set in your rules file, so there's nothing to compare", 1)
    if result:
        return ("rules canary: matches. This session loaded your rules.", 0)
    return ("rules canary: doesn't match. This session may not have loaded your rules, "
            "or the file changed after it started.", 1)


def main(argv: Optional[list] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not (args in ([], ["--report"]) or (len(args) == 2 and args[0] == "--canary")):
        print("usage: doctor.py [--report | --canary WORD]", file=sys.stderr)
        return 2
    ctx = Context(home=os.path.expanduser("~"),
                  project_dir=os.environ.get("CLAUDE_PROJECT_DIR") or None,
                  config_dir=os.environ.get("CLAUDE_CONFIG_DIR") or None,
                  config_override=os.environ.get(_config.ENV_OVERRIDE) or None,
                  home_problem=_home_problem(os.path.expanduser("~")))
    if args and args[0] == "--canary":
        line, code = canary_check(ctx, args[1])
        print(line)
        return code
    if args == ["--report"]:
        try:
            print(report(ctx, run_all(ctx)))
        except Exception as exc:  # a traceback would print your paths
            print(f"report failed: {type(exc).__name__}", file=sys.stderr)
            return 1
        return 0
    checks = run_all(ctx)
    print(render(checks))
    return 1 if any(c.status == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    sys.exit(main())
