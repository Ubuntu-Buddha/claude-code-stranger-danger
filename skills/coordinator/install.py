#!/usr/bin/env python3
"""stranger-danger coordinator install: name the coordinator's folder.

You run this yourself, in a terminal, from the command /stranger-danger:setup
prints (step 5, the coordinator). An agent shouldn't: it changes your CLAUDE.md and gate config,
which every session trusts. The settings template denies agents the Edit tool
on both files, and the sandbox keeps Bash out of them.

    python3 -I install.py FOLDER NAME     set up, rename or move the coordinator
    python3 -I install.py --remove        take it out again

It writes three things, and checks everything before writing any of them:

- ``coordinator.project`` (the folder's real path) and ``coordinator.name`` in
  ``~/.config/stranger-danger/config.json``, kept at mode 600;
- the recognition paragraph in your CLAUDE.md (``$CLAUDE_CONFIG_DIR`` when
  set, else ``~/.claude``), between two marker lines, replaced in place when
  you run it again;
- a notes folder, ``FOLDER/.stranger-danger``, with a ``.gitignore`` and the
  note templates. Existing notes are never overwritten, and --remove keeps them.

Safe to run twice. Standard library only.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(PLUGIN_ROOT, "hooks"))

import _config  # noqa: E402
import coordinator as co  # noqa: E402

TEMPLATES = os.path.join(PLUGIN_ROOT, "templates", "coordinator")


def claude_md_path(home: str):
    """(path, problem): the CLAUDE.md Claude Code loads for you. A relative
    CLAUDE_CONFIG_DIR would depend on the folder this runs from, so it's
    refused."""
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    if base and not os.path.isabs(base):
        return None, f"CLAUDE_CONFIG_DIR is {base!r}, which isn't an absolute path"
    return os.path.join(base or os.path.join(home, ".claude"), "CLAUDE.md"), None


def _write(path: str, text: str, mode: int) -> None:
    """Replace `path` atomically: a private temp file beside it, then a rename."""
    folder = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".sd-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def new_claude_md(text: str, block) -> tuple:
    """(new text, problem): `text` with its recognition block replaced by
    `block`, or removed when `block` is None, or `block` added at the end."""
    found, problem = co.find_blocks(text)
    if problem:
        return None, problem
    if len(found) > 1:
        return None, f"it has {len(found)} coordinator paragraphs; keep one"
    # Split exactly as find_blocks does: splitlines() also breaks at form
    # feeds and other separators, which would shift the block's line numbers.
    lines = co._lines(text)
    if found:
        start, end = found[0]
        keep = lines[:start] + ([block] if block else []) + lines[end + 1:]
        if not block and start and not lines[start - 1].strip():
            del keep[start - 1]  # the blank line this script put before it
        return "\n".join(keep), None
    if not block:
        return text, None
    base = text.rstrip("\n")
    return (base + "\n\n" if base else "") + block + "\n", None


def _folder_problem(folder: str, bits: int = stat.S_IWGRP | stat.S_IWOTH):
    """Why a folder this script writes into can't be trusted, or None."""
    try:
        st = os.stat(folder)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"can't check {folder}: {exc.strerror or exc}"
    if st.st_mode & bits:
        return f"{folder} is writable by other users; run: chmod go-w '{folder}'"
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        return f"{folder} is owned by another user"
    return None


def _create(path: str, data: bytes) -> None:
    """A new private file; never follows a link and never replaces a file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def install(folder, name, *, home: str, remove: bool = False, out=print) -> int:
    config_path = str(_config.config_path())
    md_path, problem = claude_md_path(home)
    if problem:
        out(f"coordinator: {problem}. Nothing was changed.")
        return 1
    project = None
    if not remove:
        problem = co.name_problem(name)
        if problem:
            out(f"coordinator: {problem}")
            return 1
        project, problem = co.resolve_project(folder, home)
        if problem:
            out(f"coordinator: {problem}")
            return 1
    # The config folder is held to the gates' own rule (yours alone). ~/.claude
    # is often group-writable under a umask of 002, where the group is you.
    for folder_to_write, bits in ((os.path.dirname(config_path), stat.S_IWGRP | stat.S_IWOTH),
                                  (os.path.dirname(md_path), stat.S_IWOTH)):
        problem = _folder_problem(folder_to_write, bits)
        if problem:
            out(f"coordinator: {problem}. Nothing was changed.")
            return 1
    try:
        config = _config.load_config(_config.Path(config_path))
        old_config = (_config.Path(config_path).read_bytes()
                      if os.path.lexists(config_path) else None)
    except (_config.ConfigError, OSError) as exc:
        out(f"coordinator: {exc}. Nothing was changed.")
        return 1
    md_real = os.path.realpath(md_path)  # a symlinked CLAUDE.md is written through
    try:
        st = os.stat(md_real)
    except FileNotFoundError:
        st = None
    except OSError as exc:
        out(f"coordinator: can't read {md_path}: {exc.strerror or exc}. Nothing was changed.")
        return 1
    problem = _folder_problem(os.path.dirname(md_real), stat.S_IWOTH)
    if problem:
        out(f"coordinator: {problem}. Nothing was changed.")
        return 1
    if st is not None and not stat.S_ISREG(st.st_mode):
        # A named pipe would hang the read; anything else isn't a CLAUDE.md.
        out(f"coordinator: {md_path} isn't a regular file. Nothing was changed.")
        return 1
    try:
        if st is None:
            text, mode = "", 0o644
        else:
            with open(md_real, encoding="utf-8", newline="") as fh:
                text = fh.read()
            mode = st.st_mode & 0o777
    except (OSError, UnicodeDecodeError) as exc:
        out(f"coordinator: can't read {md_path}: {exc}. Nothing was changed.")
        return 1
    block = None if remove else co.paragraph(name, project, md_path)
    new_text, problem = new_claude_md(text, block)
    if problem:
        out(f"coordinator: {md_path}: {problem}. Fix it by hand; nothing was changed.")
        return 1

    if remove:
        config.pop("coordinator", None)
    else:
        config["coordinator"] = {"project": project, "name": name}
    if config or old_config is not None:
        os.makedirs(os.path.dirname(config_path), mode=0o700, exist_ok=True)
        _write(config_path, json.dumps(config, indent=2) + "\n", 0o600)
    if new_text != text:
        try:
            os.makedirs(os.path.dirname(md_real), exist_ok=True)
            _write(md_real, new_text, mode)
        except OSError as exc:
            # Put the config back, so the two never disagree.
            try:
                if old_config is None:
                    os.unlink(config_path)
                else:
                    _write(config_path, old_config.decode("utf-8"), 0o600)
            except OSError:
                pass
            out(f"coordinator: can't write {md_path}: {exc.strerror or exc}. The config was "
                "put back; nothing was changed.")
            return 1
    if remove:
        out(f"coordinator: removed from {config_path} and {md_path}. Its notes stay where they were.")
        return 0

    notes = co.notes_dir(project, project)
    if os.path.islink(notes):
        out(f"coordinator: {notes} is a symlink; the notes folder must be a real folder. "
            "The config and paragraph are written; remove the link and run this again.")
        return 1
    os.makedirs(notes, mode=0o700, exist_ok=True)
    ignore = os.path.join(notes, ".gitignore")
    if not os.path.lexists(ignore):
        _create(ignore, b"# The coordinator's notes and status page stay out of git.\n*\n")
    for note in co.NOTE_FILES:
        target = os.path.join(notes, note)
        if not os.path.lexists(target):
            with open(os.path.join(TEMPLATES, note), "rb") as fh:
                _create(target, fh.read())
    out(f"coordinator: {name}, working in {project}.")
    out(f"  config: {config_path}")
    out(f"  recognition paragraph: {md_path}")
    out(f"  notes: {notes}")
    out("Restart your Claude Code sessions so they load the paragraph, then run "
        "/stranger-danger:doctor.")
    return 0


def main(argv=None, *, isatty=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    home = os.path.expanduser("~")
    if os.environ.get("CLAUDECODE") or not (isatty if isatty is not None else sys.stdin.isatty()):
        print("coordinator: run this in your own terminal, not from a Claude Code session: it "
              "changes the CLAUDE.md every session trusts.", file=sys.stderr)
        return 2
    problem = co.environment_problem(home)
    if problem:
        print(f"coordinator: {problem}. Nothing was changed.", file=sys.stderr)
        return 2
    if args == ["--remove"]:
        return install(None, None, home=home, remove=True)
    if len(args) != 2 or args[0].startswith("-"):
        print("usage: install.py FOLDER NAME   or   install.py --remove", file=sys.stderr)
        return 2
    return install(args[0], args[1], home=home)


if __name__ == "__main__":
    sys.exit(main())
