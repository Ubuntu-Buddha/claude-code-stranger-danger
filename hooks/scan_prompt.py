#!/usr/bin/env python3
"""UserPromptSubmit hook: run the scan skill when you type its line.

You type ``/stranger-danger:scan ~/quarantine/<name>``. This hook sees the line
as you typed it, scans that folder with the trigger scan, and hands Claude
only fixed-shape counts (rule ids, kinds, path groups, numbers and fixed
words). Claude then explains them, using the scan skill's text.

Why a hook: setup puts your quarantine and untrusted folders in the Bash
sandbox's ``denyRead``, so no shell command can read a stranger's files. Hooks
run outside the sandbox, so this can. And because it starts only from a line
you type, a hostile page or file can't make Claude start one (but see the
first limit below, VERIFY row S2e): the skill can't be started by the model
(``disable-model-invocation``).

What starts a scan: the whole prompt (less one trailing newline) must be
exactly ``/stranger-danger:scan `` and one folder: ``~/`` or ``/`` and then
up to 512 of ``A-Z a-z 0-9 . _ / -``, with no ``.`` or ``..`` part and no
``//``. Anything else that starts with the command gets a fixed note on what
to type; any other prompt is left alone, with no output.

What it never does: print or log your prompt, the folder, a file name, a
matched string or an error's text. Every failure is a fixed reason word.

Limits (docs/CLAIMS.md):
- Other prompt sources (a ``/loop`` turn, a background agent's report,
  another session's message) also reach this hook. If one delivered the bare
  line, it could start a scan of a folder inside your quarantine folders
  (VERIFY row S2e). The output is the same fixed-shape counts, so that's
  accepted.
- If this hook fails or times out, Claude Code goes on without it: no scan
  runs, and the skill's text says the scan isn't available. That's on
  purpose: blocking here would block every prompt you type. hooks.json ends
  the command with ``|| exit 0``, so even a missing script (exit 2, which
  would block the prompt) can't block one.
- It runs as you, outside the sandbox; on the standard track anything that can
  write the plugin folder can change it. The plugin modules it loads are
  compiled from their source, never from a cached ``.pyc``, and it writes no
  ``.pyc``; the reader gate's own imports (``_config``, ``_log``) go through
  ``sys.path``, which the reader gate puts its folder on.
- Every ordinary prompt pays one Python start-up (tens of milliseconds) to be
  told apart from the scan line.

Standard library only; run with ``python3 -I``.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(HERE)
MAX_INPUT_BYTES = 1_000_000
STDIN_LIMIT = 5          # seconds: a stdin left open costs this, never the prompt
TIME_LIMIT = 60          # seconds: the alarm, well inside hooks.json's 90
SOFT_LIMIT = 50          # seconds: the walk stops here and reports INCOMPLETE timeout

COMMAND = "/stranger-danger:scan"
# What parse() decides. (Not log codes: this hook writes no log.)
IGNORE, USAGE, SCAN = "ignore", "usage", "scan"
_LINE = re.compile(r"/stranger-danger:scan ((?:~/|/)[A-Za-z0-9._/-]{1,512})", re.ASCII)

# Fixed notes, by outcome. Plain words and ASCII; none holds anything typed or read.
NOTES = {
    "usage": "The scan line didn't match. Tell the user to type exactly "
             "/stranger-danger:scan followed by one space and a folder inside their "
             "quarantine folder, for example /stranger-danger:scan ~/quarantine/some-skill . "
             "Folder names may use only letters, digits, dot, underscore, slash and hyphen, "
             "with no spaces, no . or .. parts and no double slash. Rename the folder in "
             "their file manager if it has other characters.",
    "refused-root": "The scan refused that folder. It scans only a folder inside one of the "
                    "user's quarantine folders (not the quarantine folder itself, "
                    "not a link out of it, not a secret path, not a scan- results folder). Tell "
                    "the user why: outside quarantine, a shell agent could read the files. Ask "
                    "them to move the folder into their quarantine folder with their file "
                    "manager (you can't move it: the sandbox keeps you out), then type the scan "
                    "line again.",
    "not-a-folder": "There's no folder at that path inside the quarantine folder (it may be "
                    "missing, misspelled or a file). Ask the user to check the name in their "
                    "file manager and type the scan line again with the folder's path.",
    "broad-root": "The plugin's config lists the root folder, the home folder or a folder above "
                  "it as a quarantine folder, so the scan won't run: it would read far more "
                  "than strangers' code. Ask the user to set quarantine_paths to a folder of "
                  "its own, such as ~/quarantine, and suggest /stranger-danger:doctor.",
    "no-quarantine": "No quarantine folder is set up yet, so there is nowhere the scan may "
                     "read. A quarantine folder is where strangers' code waits to be checked; "
                     "the sandbox keeps every shell command out of it. Offer to walk the user "
                     "through /stranger-danger:setup's gate-config step.",
    "config": "The plugin's config file has a problem, so the scan didn't run. Suggest "
              "/stranger-danger:doctor, which says what's wrong.",
    "unsupported": "The scan needs a Unix alarm, which this platform lacks (native Windows). "
                   "On Windows, use the plugin under WSL2. Until then, brief the "
                   "quarantine-reviewer agent to read the folder instead.",
    "results-exist": "A results folder with this second's name already exists beside the "
                     "folder. Ask the user to wait a second and type the scan line again.",
    "unreadable": "The scan couldn't open the folder or a file in it. Some counts may be "
                  "missing. Ask the user to check the folder's permissions.",
    "internal": "The scan hit an internal error, so it shows no counts. Suggest "
                "/stranger-danger:report and a GitHub issue.",
    "timeout": "The scan ran out of time before it finished; the counts cover only part of "
               "the folder. Suggest scanning a smaller sub-folder.",
    "file-cap": "The folder has more than 20,000 entries; the scan stopped there. Suggest "
                "scanning a smaller sub-folder.",
    "byte-cap": "The scan read 200 MB and stopped. Suggest scanning a smaller sub-folder.",
    "depth-cap": "Folders deeper than 32 levels weren't scanned. Suggest scanning the deep "
                 "part on its own.",
    "hits": "Explain the counts in plain words, as the scan skill says: a hit is a pattern to "
            "look at, not a verdict, and the per-file detail is in the results folder beside "
            "the scanned folder. Offer to brief the quarantine-reviewer agent with the results "
            "folder's scan.out and paths.map, so the two methods are compared.",
    "clean": "No rule matched. That is not a verdict that the folder is safe: the scan counts "
             "patterns and misses paraphrase, other languages and code behaviour. Offer to "
             "brief the quarantine-reviewer agent to read the folder too.",
}


class _Timeout(BaseException):
    pass


def _load(path: str, name: str):
    """A plugin module by its fixed path, never through sys.path, compiled from
    its source (no .pyc is read or written). It's registered under its own
    name first: dataclasses look a class's module up there while the module
    runs."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        with open(path, "rb") as fh:
            code = compile(fh.read(), path, "exec", dont_inherit=True)
        exec(code, module.__dict__)  # noqa: S102 - the plugin's own module, by fixed path
    except BaseException:
        del sys.modules[name]
        raise
    return module


def parse(prompt) -> tuple:
    """("ignore", None), ("usage", None) or ("scan", folder as typed)."""
    if not isinstance(prompt, str):
        return IGNORE, None
    line = prompt[:-1] if prompt.endswith("\n") else prompt
    if not line.startswith(COMMAND):
        return IGNORE, None
    rest = line[len(COMMAND):]
    if rest and not rest.startswith((" ", "\t", "\n", "\r")):
        return IGNORE, None           # another command, such as /stranger-danger:scanner
    m = _LINE.fullmatch(line)
    if not m:
        return USAGE, None
    folder = m.group(1)
    parts = folder.split("/")
    if "//" in folder or any(p in (".", "..") for p in parts[1:]):
        return USAGE, None
    return SCAN, folder


def _reply(lines: list, note: str) -> str:
    context = "\n".join(lines) + "\n" + NOTES[note]
    return json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                              "additionalContext": context}})


def _error_lines(engine_version: str, reason: str) -> list:
    return ["PROMPT-SCAN START engine=%s" % engine_version, "ERROR %s" % reason, "PROMPT-SCAN END"]


def run_scan(folder: str, home: str, deadline: float) -> tuple:
    """(lines, note) for one typed folder."""
    engine = _load(os.path.join(HERE, "trigger_scan.py"), "sd_trigger_scan")
    tree = _load(os.path.join(PLUGIN_ROOT, "skills", "scan", "scan.py"), "sd_scan_tree")
    gate = _load(os.path.join(HERE, "reader_gate.py"), "sd_reader_gate")
    version = engine.ENGINE_VERSION
    try:
        config = gate.load_config()
        env = gate.Env(home=home, plugin_root=PLUGIN_ROOT,
                       config_dir=os.environ.get("CLAUDE_CONFIG_DIR") or None)
        policy = gate.Policy.from_config(config, env)
    except gate.ConfigError:
        return _error_lines(version, "config"), "config"
    # Quarantine only: the note after a scan briefs the quarantine reviewer,
    # which the reader gate keeps inside quarantine.
    roots = tuple(policy.quarantine)
    if not roots:
        return _error_lines(version, "no-quarantine"), "no-quarantine"
    if _broad(roots, home):
        return _error_lines(version, "broad-root"), "broad-root"
    target = home.rstrip("/") + "/" + folder[2:] if folder.startswith("~/") else folder

    def is_secret(path: str) -> bool:
        return gate._secret_match(gate._forms(path), policy) is not None

    # From here the alarm raises the tree module's Timeout, which its walk
    # catches: the counts so far come back as INCOMPLETE timeout.
    signal.signal(signal.SIGALRM, _raise(tree.Timeout))
    # Once the walk ends the alarm stops, so the results are never cut off
    # half written; the hook's own 90 s timeout still bounds what's left.
    lines = tree.run(target, roots, is_secret, engine, deadline=deadline,
                     casefold=env.casefold, walked=lambda: signal.alarm(0))
    closing = lines[-2]
    if closing.startswith("ERROR "):
        return lines, closing.split(" ", 1)[1]
    if closing.startswith("INCOMPLETE "):
        return lines, closing.split(" ", 1)[1]
    return lines, "hits" if closing.startswith("HITS ") else "clean"


def _broad(roots, home: str) -> bool:
    """Whether a root is /, the home folder or a folder above it."""
    homes = {os.path.normpath(home), os.path.realpath(home)}
    for forms_of_root in roots:
        for r in forms_of_root:
            r = r.rstrip("/")
            if not r or any(h == r or h.startswith(r + "/") for h in homes):
                return True
    return False


def _raise(exc_type):
    def handler(signum, frame):  # pragma: no cover - exercised in a subprocess
        raise exc_type()
    return handler


def main() -> int:
    sys.dont_write_bytecode = True
    alarm = hasattr(signal, "SIGALRM")
    if alarm:
        signal.signal(signal.SIGALRM, _raise(_Timeout))
        signal.alarm(STDIN_LIMIT)
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if alarm:
            signal.alarm(0)
        if len(raw) > MAX_INPUT_BYTES:
            return 0
        event = json.loads(raw.decode("utf-8"))
        prompt = event.get("prompt") if isinstance(event, dict) else None
    except (_Timeout, UnicodeDecodeError, ValueError, OSError, RecursionError):
        return 0
    finally:
        if alarm:
            signal.alarm(0)
    action, folder = parse(prompt)
    if action == IGNORE:
        return 0
    version = "0"
    try:
        version = _load(os.path.join(HERE, "trigger_scan.py"), "sd_trigger_scan").ENGINE_VERSION
    except Exception:
        pass
    if action == USAGE:
        print(_reply(["PROMPT-SCAN START engine=%s" % version, "ERROR usage", "PROMPT-SCAN END"],
                     "usage"))
        return 0
    if not hasattr(signal, "SIGALRM"):
        print(_reply(_error_lines(version, "unsupported"), "unsupported"))
        return 0
    signal.signal(signal.SIGALRM, _raise(_Timeout))
    signal.alarm(TIME_LIMIT)
    try:
        cfg = _load(os.path.join(HERE, "_config.py"), "sd_config")
        try:
            home = cfg.home_dir()
        except cfg.ConfigError:  # HOME moved, or no account entry: a config problem
            lines, note = _error_lines(version, "config"), "config"
        else:
            lines, note = run_scan(folder, home, time.monotonic() + SOFT_LIMIT)
    except BaseException as exc:  # never a traceback or an error's text
        late = type(exc).__name__ in ("_Timeout", "Timeout")
        lines, note = _error_lines(version, "timeout" if late else "internal"), \
            "timeout" if late else "internal"
    finally:
        signal.alarm(0)
    print(_reply(lines, note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
