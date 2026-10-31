#!/usr/bin/env python3
"""stranger-danger apply: the whole baseline install in one command.

You run this yourself, in a terminal. It works out every change first, shows
each one as a diff, and writes nothing until you type "y". An agent shouldn't
run it: it changes your guardrails. It refuses to run without a terminal, and
the settings template and the sandbox keep agents out of these files anyway.

    python3 -I apply.py              settings, sandbox, rules and gate config
    python3 -I apply.py --automode   the same, plus the auto-mode rules

What it changes (``$CLAUDE_CONFIG_DIR`` when set, else ``~/.claude``):

- ``settings.json``: merges templates/settings.json and templates/sandbox.json
  (and templates/automode.json with --automode). Objects merge key by key and
  lists gain only the entries they lack; nothing you have is removed. A value
  of another type stops it, with nothing written. The old file is kept as
  ``settings.json.bak``. It also adds to ``sandbox.filesystem.denyWrite`` the
  start-up paths in your home folder that exist (see start_paths): the folders
  ``claude``, your PATH tools and your shell start from. It leaves out any your
  ``sandbox.filesystem.allowWrite`` names; that's how you keep one writable, since
  a deny you only delete comes back the next time you run it. It adds to
  ``sandbox.filesystem.denyRead`` the untrusted, quarantine and plain secret
  folders your gate config names that exist (see read_deny_paths), so sandboxed
  commands can't read what the reader gate keeps from the file tools. A
  ``sandbox.allowUnsandboxedCommands`` you've set yourself keeps your value.
- ``stranger-danger/RULES.md``: copied from rules/RULES.md if it isn't there,
  with a new random canary word in place of the placeholder. A copy that still
  has the placeholder gets a word too; any other copy is left as it is.
- ``CLAUDE.md``: gains the rules import line if it lacks it (old file kept as
  ``CLAUDE.md.bak``).
- ``~/.config/stranger-danger/config.json``: copied from templates/config.json
  if it isn't there, at mode 600 in a folder at mode 700.

Safe to run twice: the second run finds nothing to change. The coordinator is
a separate, optional step (setup step 5).

Standard library only.
"""
from __future__ import annotations

import difflib
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(PLUGIN_ROOT, "hooks"))

import _canary  # noqa: E402

DEFAULT_IMPORT = "@~/.claude/stranger-danger/RULES.md"
CANARY_PLACEHOLDER = _canary.PLACEHOLDER
CANARY_LINE = _canary.LINE
CANARY_WORDS = _canary.WORDS
# Settings the template sets only where you haven't: a value of your own stays.
KEEP_YOURS = (("sandbox", "allowUnsandboxedCommands"),)
# Edit rules that moved from the template's deny list to its ask list in
# v0.2.0, so setup in chat can update these files, one prompt each, through
# the settings guard hook (hooks/settings_guard.py). A deny would win over the
# prompt, so a merge takes each of them out of your deny list.
MOVED_TO_ASK = ("Edit(~/.claude/settings.json)", "Edit(~/.claude/CLAUDE.md)",
                "Edit(~/.claude/stranger-danger/**)")
# Gate config lists whose folders sandboxed commands mustn't read.
READ_DENY_KEYS = ("untrusted_paths", "quarantine_paths", "secret_paths")


class Stop(Exception):
    """A change that can't be made safely; nothing is written."""


def merge(into: dict, new: dict, where: str = "") -> None:
    """Objects merge key by key, lists gain the entries they lack, and other
    values take the template's value. The same rules as setup's step 1."""
    for key, value in new.items():
        old = into.get(key)
        if isinstance(value, dict) and isinstance(old, dict):
            merge(old, value, where + key + ".")
        elif isinstance(value, list) and isinstance(old, list):
            old.extend(v for v in value if v not in old)
        elif key in into and type(old) is not type(value):
            raise Stop(f"{where}{key} in your settings has another type than the template's; "
                       "merge that key by hand")
        else:
            into[key] = value


def profile_rules(template: dict, cdir: str, home: str) -> dict:
    """`template`, plus a copy of each rule that names ~/.claude/ for another
    profile folder (CLAUDE_CONFIG_DIR): its CLAUDE.md, settings, hooks and
    agents need the same protection."""
    if os.path.realpath(cdir) == os.path.realpath(os.path.join(home, ".claude")):
        return template
    perms = template.get("permissions")
    if not isinstance(perms, dict):
        return template
    # Both the path as given and its real path: a rule naming a symlink may
    # not match an edit made through the real path.
    forms = list(dict.fromkeys([cdir.rstrip("/"), os.path.realpath(cdir)]))
    for kind in ("deny", "ask"):
        rules = perms.get(kind)
        if isinstance(rules, list):
            # The profile's own .claude.json (MCP servers, account state) moves
            # into it too under CLAUDE_CONFIG_DIR.
            rules += [r.replace("(~/.claude/", "(/" + form + "/", 1)
                      .replace("(~/.claude.json)", "(/" + form + "/.claude.json)", 1)
                      for form in forms for r in rules
                      if isinstance(r, str) and ("(~/.claude/" in r or "(~/.claude.json)" in r)]
    return template


# Direct children of your home folder that hold what a later shell or `claude`
# runs: Claude Code's native launcher and versions (~/.local), the Node version
# managers an npm-installed claude lives under, other tool folders that go on
# PATH, and shell start files. In a session whose writable folders include your
# home (started in ~, or with --add-dir ~), sandboxed Bash could plant code
# there that later runs outside the sandbox. Each is denied whole: a deeper
# entry can be got round by renaming its parent folder.
START_CANDIDATES = (
    ".local", ".nvm", ".volta", ".fnm", ".npm-global", ".bun", ".deno", ".cargo", ".rustup",
    ".pyenv", ".rbenv", ".asdf", "bin", ".gitconfig", ".bashrc", ".bash_profile", ".bash_login",
    ".bash_aliases", ".profile", ".zshrc", ".zshenv", ".zprofile", ".zlogin",
)
# Never denied whole: Claude Code's own folder and the shared config folder hold
# far more than start-up code (the defaults and your deny rules cover parts),
# and a cache, venv or data folder that a PATH entry sits in is where sandboxed
# pip, npm, uv and poetry write.
START_NEVER = frozenset({".claude", ".config", ".ssh", ".gnupg", ".cache", ".npm", ".venv",
                         ".virtualenvs", ".pnpm-store", ".yarn", ".docker", ".git"})
# Shell start files that bash or zsh reads if they exist. One that doesn't
# exist can't be denied (an empty placeholder would change which file bash
# reads), so an agent could still create it; the doctor lists them.
START_FILES = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv",
               ".zprofile", ".zlogin")


def _home_child(path: str, home: str):
    """The first part of `path` below `home`, or None if it isn't below it."""
    rel = os.path.relpath(os.path.abspath(os.path.expanduser(path)), home)
    if rel == "." or rel.startswith(".." + os.sep) or rel == ".." or os.path.isabs(rel):
        return None
    return rel.split(os.sep, 1)[0]


def start_paths(home: str, path_env: str) -> list:
    """The start-up paths to deny writes to, as absolute paths: the candidates,
    plus the hidden folders (and ~/bin) that a PATH entry or `claude` itself
    sits in. Only ones that exist and aren't symlinks: on Linux, Claude Code
    holds a denied path that doesn't exist with an empty placeholder file, and an empty
    ~/.bash_profile would stop bash reading ~/.profile."""
    home = os.path.realpath(home)
    names = set(START_CANDIDATES)
    # A relative entry (`.`, node_modules/.bin) depends on the folder apply.py
    # runs in, so it says nothing about your start-up paths.
    found = [e for e in path_env.split(os.pathsep) if os.path.isabs(e)]
    claude = shutil.which("claude", path=path_env) if path_env else None
    if claude:
        found += [claude, os.path.realpath(claude)]
    for entry in found:
        for form in (entry, os.path.realpath(entry)):
            child = _home_child(form, home)
            if child and (child.startswith(".") or child == "bin"):
                names.add(child)
    out = []
    for name in sorted(names - START_NEVER):
        path = os.path.join(home, name)
        if os.path.lexists(path) and not os.path.islink(path):
            out.append(path)
    return out


def _deny_write_entries(settings) -> list:
    sandbox = settings.get("sandbox") if isinstance(settings, dict) else None
    fs = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
    entries = fs.get("denyWrite") if isinstance(fs, dict) else None
    return [e for e in entries if isinstance(e, str)] if isinstance(entries, list) else []


def write_denied(path: str, entries: list, home: str) -> bool:
    """Whether a denyWrite entry covers `path`: the path itself, or a folder
    above it, written as an absolute or ~/ path."""
    target = os.path.realpath(path)
    for entry in entries:
        e = _entry_path(entry, home)
        if e and (target == e or target.startswith(e.rstrip(os.sep) + os.sep)):
            return True
    return False


def _entry_path(entry: str, home: str):
    """A sandbox path entry as a real absolute path (~/ is your home), or None."""
    e = os.path.expanduser(entry.replace("~", home, 1) if entry.startswith("~/") else entry)
    return os.path.realpath(e) if os.path.isabs(e) else None


def _allow_write_entries(settings) -> list:
    sandbox = settings.get("sandbox") if isinstance(settings, dict) else None
    fs = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
    entries = fs.get("allowWrite") if isinstance(fs, dict) else None
    return [e for e in entries if isinstance(e, str)] if isinstance(entries, list) else []


def allow_write_relation(path: str, settings, home: str):
    """How your sandbox.filesystem.allowWrite names this path: "same", "inside"
    (an entry in a folder below it) or "above" (an entry for a folder above
    it), or None. A deny would override any of them, so apply.py leaves the path
    alone; the doctor warns for "inside" and "above", which keep the whole path
    writable."""
    target = os.path.realpath(path)
    found = None
    for entry in _allow_write_entries(settings):
        e = _entry_path(entry, home)
        if not e:
            continue
        if e == target:
            return "same"
        if e.startswith(target + os.sep):
            found = found or "inside"
        elif target.startswith(e.rstrip(os.sep) + os.sep):
            found = "above"
    return found


def kept_writable(path: str, settings, home: str) -> bool:
    """Whether your allowWrite keeps this path writable (allow_write_relation)."""
    return allow_write_relation(path, settings, home) is not None


def add_start_paths(settings: dict, home: str, path_env: str) -> list:
    """Add the missing start paths to sandbox.filesystem.denyWrite. Returns the
    ones skipped because your allowWrite keeps them writable."""
    missing, kept = [], []
    for p in start_paths(home, path_env):
        if write_denied(p, _deny_write_entries(settings), home):
            continue
        (kept if kept_writable(p, settings, home) else missing).append(p)
    if not missing:
        return kept
    sandbox = settings.setdefault("sandbox", {})
    fs = sandbox.setdefault("filesystem", {}) if isinstance(sandbox, dict) else None
    deny = fs.setdefault("denyWrite", []) if isinstance(fs, dict) else None
    if not isinstance(deny, list):
        raise Stop("sandbox.filesystem.denyWrite in your settings isn't a list; merge by hand")
    deny.extend(missing)
    return kept


def _deny_read_entries(settings) -> list:
    sandbox = settings.get("sandbox") if isinstance(settings, dict) else None
    fs = sandbox.get("filesystem") if isinstance(sandbox, dict) else None
    entries = fs.get("denyRead") if isinstance(fs, dict) else None
    return [e for e in entries if isinstance(e, str)] if isinstance(entries, list) else []


# Folders a read deny must never cover, or lie inside: system folders that
# commands load from. And top-level folders a deny mustn't be exactly.
SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/proc",
               "/sys", "/dev", "/run", "/boot", "/System", "/Library", "/Applications",
               "/private/etc")
TOP_DIRS = ("/var", "/opt", "/private", "/srv", "/mnt", "/media", "/home", "/Users", "/Volumes",
            "/tmp", "/private/var", "/private/tmp")


def _within(path: str, folder: str) -> bool:
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def off_limits(real: str, home: str, guarded=(), workdirs=()) -> bool:
    """Whether a read deny of `real` (a real path) would hide what sandboxed
    commands, Claude Code or this plugin need: the root, your home folder or
    a folder above it, a system folder or anything in one, a top-level folder,
    a temporary folder, Python's own folders, a `workdirs` folder (where you
    run it, the project) or a folder above any of them, and the `guarded`
    folders (your Claude config folder, the plugin), a folder above them or
    anything in them."""
    home = os.path.realpath(home)
    if real == os.sep or _within(home, real):
        return True
    if any(_within(real, d) for d in SYSTEM_DIRS) or real in TOP_DIRS:
        return True
    temps = {tempfile.gettempdir(), "/tmp", os.environ.get("TMPDIR") or "/tmp",
             sys.prefix, sys.base_prefix, *workdirs}
    if any(_within(os.path.realpath(t), real) for t in temps if t):
        return True
    for g in guarded:
        g = os.path.realpath(g)
        if _within(real, g) or _within(g, real):
            return True
    return False


def guarded(home: str, cdir: str, root: str) -> tuple:
    """The folders off_limits keeps whole: the Claude config folder in use,
    the default one, and the plugin's own folder."""
    return (cdir, os.path.join(home, ".claude"), root)


def read_deny_paths(config, home: str, guarded=(), workdirs=()) -> tuple:
    """(paths, skipped) from the gate config: each untrusted, quarantine and
    secret entry that's a plain path (a secret entry may end in /**, which
    means the folder), starts with ~/ or /, and exists. It's written in the
    ~/ form when its real path is in your home folder, else as its real
    absolute path. `skipped` holds the entries left out because they hold a
    pattern or are off limits (off_limits: hiding them would break sandboxed
    commands, Claude Code or this plugin); the reader gate still covers those
    for the file tools. Paths that don't exist are left out, because what the
    sandbox does with a missing denyRead path isn't documented."""
    section = config.get("reader_gate") if isinstance(config, dict) else None
    if not isinstance(section, dict):
        return [], []
    home_real = os.path.realpath(home)
    paths, skipped = [], []
    for key in READ_DENY_KEYS:
        values = section.get(key)
        for raw in values if isinstance(values, list) else []:
            if not isinstance(raw, str):
                continue
            entry = raw[:-3] if key == "secret_paths" and raw.endswith("/**") else raw
            entry = entry.rstrip("/") or entry
            if any(ch in entry for ch in "*?[]{}\\") or not (entry.startswith(("~/", "/"))):
                skipped.append(raw)
                continue
            full = os.path.normpath(home + entry[1:] if entry.startswith("~/") else entry)
            if not os.path.lexists(full):
                continue
            real = os.path.realpath(full)
            if off_limits(real, home, guarded, workdirs):
                skipped.append(raw)
                continue
            shown = "~" + real[len(home_real):] if _within(real, home_real) else real
            if shown not in paths:
                paths.append(shown)
    return paths, skipped


def add_read_denies(settings: dict, config, home: str, guarded=(), workdirs=()) -> tuple:
    """Add the config's folders (read_deny_paths) that no denyRead entry
    covers yet. Returns (added, skipped entries)."""
    paths, skipped = read_deny_paths(config, home, guarded, workdirs)
    have = _deny_read_entries(settings)
    missing = [p for p in paths
               if not write_denied(_entry_path(p, home) or p, have, home)]
    if not missing:
        return [], skipped
    sandbox = settings.setdefault("sandbox", {})
    fs = sandbox.setdefault("filesystem", {}) if isinstance(sandbox, dict) else None
    deny = fs.setdefault("denyRead", []) if isinstance(fs, dict) else None
    if not isinstance(deny, list):
        raise Stop("sandbox.filesystem.denyRead in your settings isn't a list; merge by hand")
    deny.extend(missing)
    return missing, skipped


def moved_rules(cdir: str, home: str) -> list:
    """MOVED_TO_ASK, with each ~/.claude/ rule also in its profile forms, as
    profile_rules writes them."""
    template = profile_rules({"permissions": {"ask": list(MOVED_TO_ASK)}}, cdir, home)
    return template["permissions"]["ask"]


def move_to_ask(merged: dict, settings: dict, cdir: str, home: str) -> tuple:
    """Take the moved rules out of permissions.deny, the first time only:
    while your own settings don't ask for one yet (v0.1's template). A deny
    you've kept beside the ask, after a move, is yours and stays. Returns
    (taken out, kept)."""
    perms = merged.get("permissions")
    if not isinstance(perms, dict):
        return [], []
    deny, ask = perms.get("deny"), perms.get("ask")
    if not (isinstance(deny, list) and isinstance(ask, list)):
        return [], []
    yours = settings.get("permissions") if isinstance(settings, dict) else None
    your_ask = yours.get("ask") if isinstance(yours, dict) else None
    your_ask = your_ask if isinstance(your_ask, list) else []
    both = [r for r in moved_rules(cdir, home) if r in deny and r in ask]
    gone = [r for r in both if r not in your_ask]
    perms["deny"] = [r for r in deny if r not in gone]
    return gone, [r for r in both if r in your_ask]


def setup_write_paths(home: str, cdir: str) -> list:
    """The files setup changes, as sandbox paths: the settings file, the
    CLAUDE.md that loads the rules and the rules folder, in each profile. The
    Edit deny rules the template had for them also kept sandboxed commands
    from writing them (Claude Code turns Edit denies into sandbox write
    denies); ask rules don't, so these say it directly."""
    out = []
    for base in dict.fromkeys([cdir, os.path.join(home, ".claude")]):
        out += [os.path.join(base, "settings.json"), os.path.join(base, "CLAUDE.md"),
                os.path.join(base, "stranger-danger")]
    return out


def add_setup_write_denies(settings: dict, home: str, cdir: str, created=()) -> list:
    """Add each setup path (setup_write_paths) that exists, or that `created`
    names, and isn't a link, to sandbox.filesystem.denyWrite, unless a deny
    covers it or your allowWrite keeps it writable. A path that doesn't exist
    is left out: on Linux, Claude Code holds a denied path that doesn't exist
    with an empty placeholder file, which would block the folder being made.
    Returns the entries added."""
    home_real = os.path.realpath(home)
    missing = []
    for p in setup_write_paths(home, cdir):
        if os.path.islink(p) or not (os.path.lexists(p) or p in created):
            continue
        if write_denied(p, _deny_write_entries(settings), home) or kept_writable(p, settings,
                                                                                 home):
            continue
        real = os.path.realpath(p)
        entry = "~" + real[len(home_real):] if _within(real, home_real) else real
        if entry not in missing:
            missing.append(entry)
    if not missing:
        return []
    sandbox = settings.setdefault("sandbox", {})
    fs = sandbox.setdefault("filesystem", {}) if isinstance(sandbox, dict) else None
    deny = fs.setdefault("denyWrite", []) if isinstance(fs, dict) else None
    if not isinstance(deny, list):
        raise Stop("sandbox.filesystem.denyWrite in your settings isn't a list; merge by hand")
    deny.extend(missing)
    return missing


def keep_yours(merged: dict, settings: dict) -> list:
    """Put back each KEEP_YOURS setting you'd set yourself. Returns the dotted
    names of the ones whose value differs from the template's."""
    kept = []
    for keys in KEEP_YOURS:
        old, new = settings, merged
        for key in keys[:-1]:
            old = old.get(key) if isinstance(old, dict) else None
            new = new.get(key) if isinstance(new, dict) else None
        if isinstance(old, dict) and keys[-1] in old and isinstance(new, dict):
            if new.get(keys[-1]) != old[keys[-1]]:
                kept.append(".".join(keys))
            new[keys[-1]] = old[keys[-1]]
    return kept


make_canary = _canary.make
fill_canary = _canary.fill


def _read(path: str):
    """The file's text with its line endings as they are, or None if it's missing."""
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _json_text(data) -> str:
    return json.dumps(data, indent=2) + "\n"


def _gate_config(config_path: str, root: str, notes):
    """Your gate config, checked as the gates check it, or the template's when
    you have none yet. None, with a note, when the gates would refuse yours."""
    if not os.path.lexists(config_path):
        return json.loads(_read(os.path.join(root, "templates", "config.json")))
    hooks = os.path.join(root, "hooks")
    if hooks not in sys.path:
        sys.path.insert(0, hooks)
    import _config
    try:
        return _config.load_config(_config.Path(config_path))
    except _config.ConfigError:
        if isinstance(notes, list):
            notes.append(f"The gates refuse {config_path}, so no sandbox read denies were "
                         "added for its folders. Run /stranger-danger:doctor to see why.")
        return None


def plan(root: str, home: str, cdir: str, config_path: str, automode: bool,
         path_env: str = "", notes=None, canary: str = "", fill: bool = True,
         workdir: str = "", deny_new: bool = True, osv: bool = False) -> list:
    """[(path, old text or None, new text, mode for a new file)] for each file
    that changes. Raises Stop when a change can't be made safely. Lines for
    you to read go to `notes` when it's a list. `canary` fills the rules
    file's placeholder (a new word when empty); with `fill` false the
    placeholder stays, for the canary_fill hook to fill unseen. `workdir` is
    the folder whose sandboxed work a read deny mustn't hide (where you run
    it, by default). With `deny_new`, the rules folder and CLAUDE.md this plan
    creates get sandbox write denies too (apply writes every file at once);
    setup in chat, where you may decline a file, leaves that to a later run.
    With `osv`, the settings also get the OSV check's part (templates/osv.json:
    five hosts, and its results folder under ~/.cache writable by sandboxed
    commands, outside every start path, so no write deny is lost)."""
    canary = canary or make_canary()
    rules_dir = os.path.join(cdir, "stranger-danger")
    # The settings file exists once this plan's settings change is written.
    created = [os.path.join(cdir, "settings.json")] + [
        p for p in (rules_dir, os.path.join(cdir, "CLAUDE.md")) if deny_new]
    changes = []
    templates = ["templates/settings.json", "templates/sandbox.json"]
    if automode:
        templates.append("templates/automode.json")
    if osv:
        # The OSV results folder is sandbox-writable, so it mustn't sit in a
        # folder setup write-denies (a config folder under ~/.cache, say).
        results = os.path.realpath(os.path.join(home, ".cache", "stranger-danger", "osv"))
        if any(results == os.path.realpath(w) or results.startswith(os.path.realpath(w) + os.sep)
               for w in setup_write_paths(home, cdir)):
            raise Stop("The OSV check's results folder is inside your Claude config folder's "
                       "stranger-danger folder, which setup keeps unwritable. Leave out the "
                       "OSV option, or use a config folder outside ~/.cache.")
        templates.append("templates/osv.json")
    path = os.path.join(cdir, "settings.json")
    old = _read(path)
    try:
        settings = json.loads(old) if old is not None else {}
    except ValueError:
        raise Stop(f"{path} isn't valid JSON; fix it first") from None
    if not isinstance(settings, dict):
        raise Stop(f"{path} isn't a JSON object; merge by hand")
    merged = json.loads(json.dumps(settings))
    for rel in templates:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            merge(merged, profile_rules(json.load(fh), cdir, home))
    yours = keep_yours(merged, settings)
    moved, kept_deny = move_to_ask(merged, settings, cdir, home)
    add_setup_write_denies(merged, home, cdir, created)
    kept = add_start_paths(merged, home, path_env)
    _added, skipped = add_read_denies(merged, _gate_config(config_path, root, notes), home,
                                      guarded(home, cdir, root), (workdir or os.getcwd(),))
    if isinstance(notes, list):
        if moved:
            notes.append("Moved from deny to ask: " + ", ".join(moved) + ". The settings "
                         "guard hook still refuses any edit to these files except the one "
                         "setup works out, which you then approve or decline.")
        if kept_deny:
            notes.append("Kept your deny for " + ", ".join(kept_deny) + " beside its ask "
                         "rule: setup in chat can't update those files while it stays, so "
                         "update them from this terminal install.")
        if yours:
            notes.append("Kept your own " + ", ".join(yours) + " (the template sets "
                         "allowUnsandboxedCommands to false, so a command the sandbox stops "
                         "can't be run again outside it).")
        if kept:
            notes.append("Left writable, because your sandbox.filesystem.allowWrite names them: "
                         + ", ".join(kept) + ". Sandboxed commands could plant start-up code "
                         "there in a session whose writable folders include your home folder.")
        if skipped:
            listed = ", ".join(skipped[:5]) + (f" and {len(skipped) - 5} more"
                                               if len(skipped) > 5 else "")
            notes.append(f"No sandbox read deny for {listed}: a pattern, or a folder that "
                         "sandboxed commands, Claude Code or this plugin need (your home "
                         "folder or one above it, a system or temporary folder, the folder "
                         "you ran this in, your Claude config folder, the plugin). The reader "
                         "gate still keeps the file tools out.")
    if merged != settings:
        changes.append((path, old, _json_text(merged), 0o600))

    rules = os.path.join(cdir, "stranger-danger", "RULES.md")
    if not os.path.lexists(rules):
        text = _read(os.path.join(root, "rules", "RULES.md"))
        changes.append((rules, None, (fill_canary(text, canary) if fill else None) or text,
                        0o644))
    elif fill:
        old = _read(rules)
        filled = fill_canary(old, canary) if old is not None else None
        if filled is not None:
            changes.append((rules, old, filled, 0o644))

    claude_md = os.path.join(cdir, "CLAUDE.md")
    line = DEFAULT_IMPORT if os.path.normpath(cdir) == os.path.join(home, ".claude") \
        else "@" + rules
    old = _read(claude_md)
    if line not in (old or "").splitlines():
        base = (old or "").rstrip("\n")
        changes.append((claude_md, old, (base + "\n\n" if base else "") + line + "\n", 0o644))

    if not os.path.lexists(config_path):
        changes.append((config_path, None,
                        _read(os.path.join(root, "templates", "config.json")), 0o600))
    return changes


def show(changes: list) -> str:
    out = []
    for path, old, new, _mode in changes:
        if old is None:
            out.append(f"--- new file: {path} ({len(new.splitlines())} lines)")
            if not path.endswith("RULES.md"):
                out.append(new.rstrip("\n"))
        else:
            if path.endswith(".json"):
                # Compare like with like, so the diff shows what's added, not
                # the reformatting (the file is written back with indent 2).
                old = _json_text(json.loads(old))
            out.extend(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                            fromfile=path, tofile=path + " (new)", lineterm=""))
        out.append("")
    return "\n".join(out)


def _write(path: str, text: str, mode: int) -> None:
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    real = os.path.realpath(path)  # a symlinked file is written through
    if os.path.exists(real):
        shutil.copy2(real, real + ".bak")
        mode = os.stat(real).st_mode & 0o777
    fd, tmp = tempfile.mkstemp(prefix=".sd-", dir=os.path.dirname(real))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, real)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def apply(changes: list, config_path: str) -> None:
    # The settings file goes last: its sandbox write denies name files the
    # other changes create, and a denied path that doesn't exist yet would
    # get an empty placeholder file if a write before it failed.
    changes = sorted(changes, key=lambda c: os.path.basename(c[0]) == "settings.json")
    for path, _old, new, mode in changes:
        if path == config_path:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            os.chmod(os.path.dirname(path), 0o700)
        _write(path, new, mode)


def main(argv=None, *, ask=input, isatty=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != len(set(args)) or not set(args) <= {"--automode", "--osv"}:
        print("usage: apply.py [--automode] [--osv]", file=sys.stderr)
        return 2
    if os.environ.get("CLAUDECODE") or not (isatty or sys.stdin.isatty)():
        print("stranger-danger apply: run this yourself, in a terminal. It changes your "
              "guardrails and asks before it writes.", file=sys.stderr)
        return 2
    home = os.path.expanduser("~")
    cdir = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")
    # Both forms become rule text, so neither may hold a pattern character.
    if not os.path.isabs(cdir) or any(c in form for form in (cdir, os.path.realpath(cdir))
                                      for c in "()*?[]{}\\"):
        print("stranger-danger apply: CLAUDE_CONFIG_DIR must be an absolute path with no "
              "( ) * ? [ ] { } or \\. Nothing was changed.", file=sys.stderr)
        return 2
    sys.path.insert(0, os.path.join(PLUGIN_ROOT, "hooks"))
    import _config
    if os.environ.get(_config.ENV_OVERRIDE):
        print(f"stranger-danger apply: {_config.ENV_OVERRIDE} is set; only the plugin's tests "
              "use it. Unset it. Nothing was changed.", file=sys.stderr)
        return 2
    config_path = os.path.join(home, ".config", "stranger-danger", "config.json")
    canary = make_canary()
    try:
        notes: list = []
        changes = plan(PLUGIN_ROOT, home, cdir, config_path, "--automode" in args,
                       os.environ.get("PATH", ""), notes, canary, osv="--osv" in args)
    except UnicodeDecodeError as exc:
        print(f"stranger-danger apply: a file isn't UTF-8 text ({exc.reason}). Nothing was "
              "changed.", file=sys.stderr)
        return 1
    except (Stop, OSError) as exc:
        print(f"stranger-danger apply: {exc}. Nothing was changed.", file=sys.stderr)
        return 1
    for note in notes:
        print(f"Note: {note}")
    if not changes:
        print("Nothing to change: the baseline is already in place.")
        return 0
    print(show(changes))
    print("These files change; each one that exists is kept as .bak first:")
    for path, *_ in changes:
        print(f"  {path}")
    try:
        answer = ask("Apply these changes? [y/N] ")
    except EOFError:
        answer = ""
    if answer.strip().lower() not in ("y", "yes"):
        print("Nothing was changed.")
        return 1
    try:
        apply(changes, config_path)
    except OSError as exc:
        print(f"stranger-danger apply: {exc}", file=sys.stderr)
        return 1
    rules = os.path.join(cdir, "stranger-danger", "RULES.md")
    new_canary = any(path == rules and canary in new for path, _old, new, _mode in changes)
    print("Done. Next:")
    print(f"  1. Edit {rules}: list your repos.")
    if new_canary:
        print(f"     Its rules canary is now {canary}. In a new session, ask Claude for your "
              "rules canary: if it says that word, the rules are loaded.")
    print(f"  2. Edit the folder lists in {config_path} if you use untrusted or quarantine "
          "folders, then run this again to keep sandboxed commands out of them too.")
    print("  3. Restart Claude Code and run /stranger-danger:doctor.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
