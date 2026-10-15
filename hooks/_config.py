"""Shared config loader for the StrangerDanger hooks.

The config lives in one user-scope file, ``~/.config/stranger-danger/config.json``.
Nothing in a project folder is ever read: a stranger's repo could ship a config
that loosens the gates. Tests (and only tests) point ``STRANGER_DANGER_CONFIG``
at another file; a hook that sees it fails closed.

A missing file means "use the defaults". Anything else that is wrong fails
closed: the caller turns a ``ConfigError`` into a deny with a fix-it message.
That includes a key this file doesn't know, at the top level or inside a
section, so a typo such as ``reader-gate`` can't quietly switch a rule off.
Only key names are checked here; each gate checks its own values, and the
coordinator skill checks the ``coordinator`` section's.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

ENV_OVERRIDE = "STRANGER_DANGER_CONFIG"
MAX_BYTES = 1_000_000
# Every key the gates read, by section.
KNOWN_KEYS = {
    "reader_gate": frozenset({"untrusted_paths", "quarantine_paths", "secret_paths",
                              "private_hosts"}),
    "launch_gate": frozenset({"allow", "ssh_hosts"}),
    # Read by the coordinator skill and the doctor, never by a gate: a bad
    # value there is the doctor's to report, not a reason to block every call.
    "coordinator": frozenset({"project", "name"}),
}


class ConfigError(Exception):
    """The config file exists but can't be trusted or parsed."""


def config_path() -> Path:
    """The config file to read: the env override, else the user-scope default.

    Claude Code gives every hook CLAUDE_PROJECT_DIR. A hook that also sees the
    override got it from a project's settings ``env`` or a leftover shell
    variable, never from the tests, so it fails closed instead of reading
    another config."""
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        if os.environ.get("CLAUDE_PROJECT_DIR"):
            raise ConfigError(f"{ENV_OVERRIDE} is set in a Claude Code session; only the "
                              "plugin's tests use it. Remove it from the shell or the "
                              "project settings' env")
        return Path(override)
    return Path.home() / ".config" / "stranger-danger" / "config.json"


def _check_mode(path: Path, st: os.stat_result, what: str) -> None:
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(
            f"{what} {path} is writable by other users; run: chmod go-w '{path}'"
        )
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise ConfigError(f"{what} {path} is owned by another user; it must be yours")


def _no_duplicates(pairs: list) -> dict:
    seen, repeated = set(), set()
    for key, _ in pairs:
        (repeated if key in seen else seen).add(key)
    if repeated:
        raise ConfigError(f"key {_names(repeated)} appears more than once in one object")
    return dict(pairs)


def _names(keys) -> str:
    keys = sorted(keys)
    shown = ", ".join(json.dumps(k, ensure_ascii=True)[:80] for k in keys[:5])
    return shown + (f" and {len(keys) - 5} more" if len(keys) > 5 else "")


def check_keys(data: dict) -> None:
    """Raise ConfigError for a key no gate reads, at the top level or in a section."""
    unknown = set(data) - set(KNOWN_KEYS)
    if unknown:
        raise ConfigError(f"unknown top-level key(s): {_names(unknown)}; "
                          f"the known ones are {', '.join(sorted(KNOWN_KEYS))}")
    for section, known in KNOWN_KEYS.items():
        value = data.get(section)
        if isinstance(value, dict):  # a non-object section is the gate's to refuse
            unknown = set(value) - known
            if unknown:
                raise ConfigError(f"unknown {section} key(s): {_names(unknown)}; "
                                  f"the known ones are {', '.join(sorted(known))}")


def load_config(path: Path | None = None) -> dict:
    """Return the parsed config dict, ``{}`` when the file doesn't exist.

    Raises ConfigError when the file (or its folder) is writable by others,
    owned by someone else, not a regular file, too large, unreadable, not
    valid JSON, not a JSON object, repeats a key, or has a key no gate reads.
    """
    path = config_path() if path is None else path
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ConfigError(f"can't read {path}: {exc.strerror or exc}") from None
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{path} is not a regular file")
    _check_mode(path, st, "config file")
    parent = path.parent
    try:
        _check_mode(parent, os.stat(parent), "config folder")
    except OSError as exc:
        raise ConfigError(f"can't check {parent}: {exc.strerror or exc}") from None
    if st.st_size > MAX_BYTES:
        raise ConfigError(f"{path} is larger than {MAX_BYTES} bytes")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"can't read {path}: {exc.strerror or exc}") from None
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must hold a JSON object")
    check_keys(data)
    return data
