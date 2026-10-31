"""The scan skill's tree module: run the trigger scan over one folder.

``hooks/scan_prompt.py`` calls ``run()`` when you type
``/stranger-danger:scan <folder>``. Hooks run outside Claude Code's Bash
sandbox, so this can read a quarantine folder that the sandbox keeps every
shell command out of. That's why it does so little: it only reads files and
matches fixed patterns on their text. It never runs, imports, unpacks or
follows anything it finds.

- **Where it reads:** only a folder inside one of your ``quarantine_paths``
  folders (not the folder itself), at every spelling of its path, so a link
  out of quarantine is refused. Once the folder is open, the folders above it
  are checked again by device and inode, so a parent swapped for a link after
  the path check, or a case-insensitive spelling of another folder, is refused.
- **How it walks:** each folder is opened relative to the one above it with
  ``O_NOFOLLOW``, so a link is never followed, even one swapped in mid-scan.
  Files that match the reader gate's secret patterns, files with more than one
  hard link, links and anything that isn't a regular file are counted and
  never opened.
- **Caps:** 20,000 entries (files and folders), 200 MB read in all, 5 MB a
  file, 32 folders deep, and a deadline. At most one open folder per level. Any cap makes the result INCOMPLETE, never "no rule matched".
- **What comes back:** fixed-shape lines only (rule ids, kinds, path groups,
  counts and fixed words), checked against a grammar before anyone sees them.
  No file name, matched text or error text. A results folder beside the
  target holds the per-file detail (``scan.out``) and the id-to-path table
  (``paths.map``) for the quarantine reviewer; on the hook's path both stay
  inside quarantine, where the sandbox keeps shell commands out. A failed or
  interrupted write removes what it wrote. A caller other than the hook may
  pass an open folder for the results instead (``run()``'s ``results_fd``);
  the checks on the target stay the same, and keeping that folder away from
  agents is the caller's job.

Standard library only. The engine is passed in (``hooks/trigger_scan.py``,
loaded by fixed path), so this file imports nothing from the plugin.
"""
from __future__ import annotations

import os
import re
import stat
import time

MAX_ENTRIES = 20_000
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_DEPTH = 32
MAX_ANCESTORS = 256
# Per-line detail kept for scan.out; past these only the counts go on, so a
# file of short hit lines can't fill memory.
MAX_DETAIL_PER_FILE = 1_000
MAX_DETAIL = 100_000
HEAD_BYTES = 8192

REASONS = ("timeout", "file-cap", "byte-cap", "depth-cap", "unreadable", "internal",
           "refused-root", "not-a-folder", "broad-root", "no-quarantine", "config",
           "results-exist", "unsupported", "usage")
KINDS = ("binary", "nul-in-text", "utf16", "invalid-utf8", "too-large", "link", "special",
         "oddname", "skipped-secret", "hardlink", "trigger-path", "unreadable")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_NOCTTY", 0)
               | getattr(os, "O_CLOEXEC", 0))

_Q = r"(?:\.quarantined)?"
# Path groups, on the path relative to the target. Every group but skill-md is
# also a trigger-path file: those files steer an agent or run on load.
PATH_GROUPS = (
    ("agent-md", re.compile(r"(?:^|/)(?:CLAUDE|CLAUDE\.local|AGENTS|GEMINI)\.md" + _Q + r"\Z", re.I)),
    ("agent-rules", re.compile(r"(?:^|/)(?:\.cursorrules|\.windsurfrules|\.clinerules"
                               r"|\.github/copilot-instructions\.md)" + _Q + r"\Z", re.I)),
    ("agents-dir", re.compile(r"(?:^|/)\.agents" + _Q + "/", re.I)),
    ("claude-dir", re.compile(r"(?:^|/)\.claude" + _Q + "/", re.I)),
    ("codex-gemini", re.compile(r"(?:^|/)\.(?:codex|gemini|windsurf|continue|aider)[^/]{0,255}"
                                r"(?:/|\Z)", re.I)),
    ("cursor-dir", re.compile(r"(?:^|/)\.cursor" + _Q + "/", re.I)),
    ("mcp-json", re.compile(r"(?:^|/)\.mcp\.json" + _Q + r"\Z", re.I)),
    ("opencode", re.compile(r"(?:^|/)(?:\.opencode" + _Q + r"/|opencode\.jsonc?" + _Q + r"\Z)",
                            re.I)),
    ("skill-md", re.compile(r"(?:^|/)SKILL\.md" + _Q + r"\Z", re.I)),
)
# Inside a plugin: the files a Claude Code plugin loads or runs, on the path
# relative to the plugin's own folder.
PLUGIN_GROUPS = (
    ("plugin-manifest", re.compile(r"(?:^|/)\.claude-plugin/(?:plugin|marketplace)\.json\Z")),
    ("hooks-json", re.compile(r"(?:^|/)hooks/hooks\.json\Z")),
    ("plugin-bin", re.compile(r"(?:^|/)bin/")),
    ("plugin-output-styles", re.compile(r"(?:^|/)output-styles/")),
    ("plugin-monitors", re.compile(r"(?:^|/)monitors/monitors\.json\Z")),
    ("plugin-lsp", re.compile(r"(?:^|/)\.lsp\.json\Z")),
    ("plugin-settings", re.compile(r"\Asettings\.json\Z")),
    ("plugin-workflows", re.compile(r"(?:^|/)workflows/")),
)
NOT_A_TRIGGER = frozenset({"skill-md"})
# The target is a plugin when its top level holds one of these; a folder below
# it is a plugin's own folder when it holds .claude-plugin.
PLUGIN_MARKERS = frozenset({".claude-plugin", "agents", "commands", "skills", "output-styles"})

_TEXT_EXT = re.compile(
    r"\.(?:js|mjs|cjs|ts|mts|cts|jsx|tsx|py|pyw|sh|bash|zsh|ps1|bat|cmd|go|rs|rb|php|pl|lua"
    r"|java|kt|c|h|cc|cpp|json|jsonc|md|mdc|markdown|txt|yml|yaml|toml|ini|cfg|conf|xml|html?"
    r"|svg|css|mod|sum|lock|env)\Z", re.I)
_ODD_NAME = re.compile(r"[^\x21-\x7e]|[`$;|&()'\"\\<>*?!{}\[\]]")
_MAP_SAFE = re.compile(r"[A-Za-z0-9._/@+,=~-]")
_RESULTS_NAME = re.compile(r"scan-[0-9]{8}T[0-9]{6}Z")

# The grammar every line shown to the model must match.
_LINE_GRAMMAR = re.compile(
    r"PROMPT-SCAN START engine=[0-9A-Za-z.-]{1,20}|PROMPT-SCAN END|FILES \d{1,9}"
    r"|PATH [a-z][a-z0-9-]{1,31} \d{1,9}|KIND [a-z][a-z0-9-]{1,31} \d{1,9}"
    r"|RULE [a-z][a-z0-9-]{1,31} \d{1,9}|RESULTS (?:scan-\d{8}T\d{6}Z|not-written)"
    r"|HITS \d{1,9}|NO RULE MATCHED \(not a verdict that the folder is safe\)"
    r"|INCOMPLETE [a-z-]{1,20}|ERROR [a-z-]{1,20}")


class Timeout(BaseException):
    """Raised by the caller's alarm. A BaseException, so the engine's
    never-raise net (``except Exception``) doesn't swallow it."""


class _Stop(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _key(path: str, casefold: bool) -> str:
    return path.casefold() if casefold else path


def _inside(path: str, root: str, casefold: bool) -> bool:
    """Strictly inside, by spelling. casefold only widens this first check:
    run() then checks the folders above the target by device and inode."""
    p, r = _key(path, casefold), _key(root, casefold).rstrip("/")
    return p.startswith(r + "/") and len(p) > len(r) + 1


def _forms(path: str) -> tuple:
    norm = os.path.normpath(path)
    out = []
    for form in (norm, os.path.realpath(path), os.path.realpath(norm)):
        if form not in out:
            out.append(form)
    return tuple(out)


def target_problem(target: str, roots, is_secret, casefold: bool = False):
    """None when target is a folder strictly inside one of roots (tuples of
    each root's spellings) at every spelling of its own path, isn't a secret
    and isn't a results folder; else a reason word: refused-root, or
    not-a-folder for a path inside quarantine that isn't a folder."""
    if not os.path.isabs(target):
        return "refused-root"
    forms = _forms(target)
    root_forms = [r for forms_of_root in roots for r in forms_of_root]
    for form in forms:
        if not any(_inside(form, r, casefold) for r in root_forms):
            return "refused-root"
    real = os.path.realpath(target)
    if is_secret(target) or is_secret(real) or os.path.basename(real).startswith("scan-"):
        return "refused-root"
    if not os.path.isdir(real):
        return "not-a-folder"
    return None


def _ids(roots) -> set:
    """(device, inode) of each root spelling that exists now."""
    out = set()
    for forms_of_root in roots:
        for r in forms_of_root:
            try:
                st = os.stat(r)
            except OSError:
                continue
            out.add((st.st_dev, st.st_ino))
    return out


def _below(fd: int, root_ids: set, unknown: bool = False) -> bool:
    """Whether a folder in root_ids lies strictly above the open folder fd,
    found by climbing .. from fd itself (.. never follows a link). A climb
    that can't finish (an error, or too many levels) answers unknown: False
    for a target, which then is refused; True for a results folder, which
    then is refused too."""
    st = os.fstat(fd)
    here = (st.st_dev, st.st_ino)
    for k in range(1, MAX_ANCESTORS + 1):
        try:
            up_st = os.stat("/".join([".."] * k), dir_fd=fd, follow_symlinks=False)
        except OSError:
            return unknown
        up = (up_st.st_dev, up_st.st_ino)
        if up in root_ids:
            return True
        if up == here:              # / is its own parent
            return False
        here = up
    return unknown


def _is_parent(parent_fd: int, fd: int) -> bool:
    """Whether parent_fd, the folder the target was opened from, is the
    folder above fd."""
    p = os.fstat(parent_fd)
    up = os.stat("..", dir_fd=fd, follow_symlinks=False)
    return (p.st_dev, p.st_ino) == (up.st_dev, up.st_ino)


def _esc(rel: str) -> str:
    """A path as printable ASCII for paths.map; a long name keeps its tail."""
    out = []
    for b in os.fsencode(rel):
        ch = chr(b)
        out.append(ch if _MAP_SAFE.match(ch) else "\\x%02x" % b)
    s = "".join(out)
    return "..." + s[-400:] if len(s) > 400 else s


def _utf16_kind(head: bytes, texty: bool) -> str:
    if head.startswith(b"\xff\xfe"):
        return "le"
    if head.startswith(b"\xfe\xff"):
        return "be"
    if not texty or b"\x00" not in head:
        return ""
    even = sum(1 for i in range(0, len(head), 2) if head[i] == 0)
    odd = sum(1 for i in range(1, len(head), 2) if head[i] == 0)
    pairs = len(head) // 2
    if odd * 4 >= pairs and even * 8 <= odd:
        return "le"
    if even * 4 >= pairs and odd * 8 <= even:
        return "be"
    return ""


class _Dir:
    """An open folder, closed once nothing it lists waits on the stack."""

    __slots__ = ("fd", "owned", "waiting")

    def __init__(self, fd: int, owned: bool) -> None:
        self.fd, self.owned, self.waiting = fd, owned, 1   # 1: its own listing

    def release(self) -> None:
        self.waiting -= 1
        if self.waiting <= 0:
            self.close()

    def close(self) -> None:
        if self.owned and self.fd >= 0:
            os.close(self.fd)
        self.fd = -1


class _Scan:
    def __init__(self, engine, plugin: bool, deadline: float, clock) -> None:
        self.engine, self.plugin, self.deadline, self.clock = engine, plugin, deadline, clock
        self.ids: dict = {}           # rel path -> f<N>
        self.order: list = []
        # Every non-folder entry and every empty folder (rel path, with a
        # trailing / for a folder), with its plugin's folder ("" for the
        # target, None outside a plugin).
        self.listed: list = []
        self.files = 0
        self.entries = 0
        self.total = 0
        self.kinds: dict = {}         # kind -> set of rel paths
        self.hits: set = set()        # (rule id, rel path, line), capped: see hit()
        self.counts: dict = {}        # rule id -> hits, every one
        self.per_file: dict = {}      # rel path -> detail lines kept
        self.capped = False
        self.incomplete = None

    def fid(self, rel: str) -> str:
        if rel not in self.ids:
            self.order.append(rel)
            self.ids[rel] = "f%d" % len(self.order)
        return self.ids[rel]

    def flag(self, kind: str, rel: str) -> None:
        self.kinds.setdefault(kind, set()).add(rel)
        self.fid(rel)

    def note(self, reason: str) -> None:
        if self.incomplete is None:
            self.incomplete = reason

    def check_clock(self) -> None:
        if self.clock() > self.deadline:
            raise _Stop("timeout")

    # --- one file ---------------------------------------------------------------
    def read_file(self, dir_fd: int, name: str, rel: str, st, is_secret, abs_path: str,
                  plugin: bool) -> None:
        self.files += 1
        if is_secret(abs_path):
            self.flag("skipped-secret", rel)
            return
        if st.st_nlink > 1:
            self.flag("hardlink", rel)
            return
        if st.st_size > MAX_FILE_BYTES:
            self.flag("too-large", rel)
            return
        if self.total + st.st_size > MAX_TOTAL_BYTES:
            raise _Stop("byte-cap")
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
        except OSError:
            self.flag("unreadable", rel)
            self.note("unreadable")
            return
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                self.flag("special", rel)
                return
            # The same file, checked again as opened: it may have grown or
            # gained a link since the listing.
            if fst.st_nlink > 1:
                self.flag("hardlink", rel)
                return
            if fst.st_size > MAX_FILE_BYTES:
                self.flag("too-large", rel)
                return
            if self.total + fst.st_size > MAX_TOTAL_BYTES:
                raise _Stop("byte-cap")
            chunks, got = [], 0
            while got <= fst.st_size:
                block = os.read(fd, min(1 << 20, fst.st_size + 1 - got))
                if not block:
                    break
                chunks.append(block)
                got += len(block)
            data = b"".join(chunks)
        except OSError:
            self.flag("unreadable", rel)
            self.note("unreadable")
            return
        finally:
            os.close(fd)
        if len(data) != fst.st_size:
            self.flag("unreadable", rel)
            self.note("unreadable")
            return
        self.total += len(data)
        self.scan_data(rel, data, plugin)

    def scan_data(self, rel: str, data: bytes, plugin: bool = False) -> None:
        head = data[:HEAD_BYTES]
        base = rel[:-len(".quarantined")] if rel.lower().endswith(".quarantined") else rel
        texty = bool(_TEXT_EXT.search(base)) or self._instruction_file(rel, plugin)
        second = None
        kind16 = _utf16_kind(head, texty)
        if kind16:
            self.flag("utf16", rel)
            raw = data[2:] if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data
            second = raw.replace(b"\x00", b"").decode("utf-8", "surrogateescape")
            even = data[:len(data) - (len(data) % 2)]
            text = even.decode("utf-16-le" if kind16 == "le" else "utf-16-be", "surrogatepass")
            if text.startswith("\ufeff"):
                text = text[1:]
            if len(data) % 2:
                self.flag("invalid-utf8", rel)
        else:
            if b"\x00" in head:
                if not texty:
                    self.flag("binary", rel)
                    return
                self.flag("nul-in-text", rel)
                data = data.replace(b"\x00", b"")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                self.flag("invalid-utf8", rel)
                text = data.decode("utf-8", "surrogateescape")
        first = self.engine.scan_lines(text, rel, plugin=plugin)
        self.add_hits(rel, first)
        if second is not None:
            # The bytes as a UTF-8 reader sees them: extra hits only, and not
            # control-char, which here only means "UTF-16".
            seen: dict = {}
            for rule_id, _ in first:
                seen[rule_id] = seen.get(rule_id, 0) + 1
            extra = []
            done = set(first)         # hit() counts each pair once; don't repeat one
            for rule_id, line in self.engine.scan_lines(second, rel, plugin=plugin):
                if rule_id == "control-char":
                    continue
                seen[rule_id] = seen.get(rule_id, 0) - 1
                if seen[rule_id] < 0 and (rule_id, line) not in done:
                    extra.append((rule_id, line))
            self.add_hits(rel, extra)

    def _instruction_file(self, rel: str, plugin: bool) -> bool:
        # The engine's own path scope decides which files are agent instruction
        # files; a <!-- line only hits in those.
        return bool(self.engine.scan_lines("<!--", rel, plugin=plugin))

    def hit(self, rule_id: str, rel: str, line: int) -> None:
        """Count one (rule, file, line); each comes once (the engine's pairs
        are unique, names are line 0). The detail is kept up to the caps."""
        if rule_id in ("scan-error", "input-invalid"):
            self.note("internal")
        self.fid(rel)
        self.counts[rule_id] = self.counts.get(rule_id, 0) + 1
        kept = self.per_file.get(rel, 0)
        if kept < MAX_DETAIL_PER_FILE and len(self.hits) < MAX_DETAIL:
            self.hits.add((rule_id, rel, line))
            self.per_file[rel] = kept + 1
        else:
            self.capped = True

    def add_hits(self, rel: str, pairs) -> None:
        for rule_id, line in pairs:
            self.hit(rule_id, rel, line)

    # --- the walk -----------------------------------------------------------------
    # Depth first. A folder stays open while subfolders listed in it wait on
    # the stack, and is opened only when popped, so at most one folder per
    # level is open at a time, whatever a folder holds.
    def walk(self, root_fd: int, target: str, is_secret) -> None:
        opened: list = []
        stack: list = []                      # (parent _Dir, name, rel, depth, plugin folder)
        try:
            root = _Dir(root_fd, owned=False)
            self.walk_one(root, "", 0, "" if self.plugin else None, target, is_secret, stack)
            root.release()
            while stack:
                parent, name, rel, depth, prefix = stack.pop()
                try:
                    fd = os.open(name, _DIR_FLAGS, dir_fd=parent.fd)
                except OSError:
                    fd = -1
                    self.note("unreadable")
                parent.release()
                if fd < 0:
                    continue
                here = _Dir(fd, owned=True)
                opened.append(here)
                self.walk_one(here, rel, depth, prefix, target, is_secret, stack)
                here.release()
        finally:
            for d in opened:
                d.close()

    def walk_one(self, here, rel_dir: str, depth: int, prefix, target: str, is_secret,
                 stack: list) -> None:
        try:
            names = sorted(e.name for e in os.scandir(here.fd))
        except OSError:
            self.note("unreadable")
            return
        if prefix is None and rel_dir and ".claude-plugin" in names:
            prefix = rel_dir
        if not names and rel_dir:
            self.listed.append((rel_dir + "/", prefix))
        subdirs = []
        for name in names:
            self.check_clock()
            rel = name if not rel_dir else rel_dir + "/" + name
            try:
                st = os.stat(name, dir_fd=here.fd, follow_symlinks=False)
            except OSError:
                self.note("unreadable")
                continue
            self.entries += 1
            if self.entries > MAX_ENTRIES:
                raise _Stop("file-cap")
            if stat.S_ISDIR(st.st_mode):
                subdirs.append((name, rel))
                continue
            self.listed.append((rel, prefix))
            if stat.S_ISLNK(st.st_mode):
                self.flag("link", rel)
            elif not stat.S_ISREG(st.st_mode):
                self.flag("special", rel)
            else:
                self.read_file(here.fd, name, rel, st, is_secret, target + "/" + rel,
                               prefix is not None)
        for name, rel in reversed(subdirs):
            if depth + 1 > MAX_DEPTH:
                self.note("depth-cap")
                continue
            here.waiting += 1
            stack.append((here, name, rel, depth + 1, prefix))

    # --- after the walk -------------------------------------------------------------
    def classify(self) -> dict:
        groups: dict = {}
        for rel, prefix in self.listed:
            matched = [g for g, rx in PATH_GROUPS if rx.search(rel)]
            if prefix is not None:
                inner = rel[len(prefix) + 1:] if prefix else rel
                matched += [g for g, rx in PLUGIN_GROUPS if rx.search(inner)]
            for group in matched:
                groups[group] = groups.get(group, 0) + 1
                if group not in NOT_A_TRIGGER:
                    self.flag("trigger-path", rel)
            if _ODD_NAME.search(rel):
                self.flag("oddname", rel)
            for rule_id in self.engine.scan_name(rel):
                self.hit(rule_id, rel, 0)
        return groups


def _summary(engine, sc: _Scan, groups: dict, results: str, error=None) -> list:
    lines = ["PROMPT-SCAN START engine=%s" % engine.ENGINE_VERSION]
    if error:
        return lines + ["ERROR %s" % error, "PROMPT-SCAN END"]
    lines.append("FILES %d" % sc.files)
    for group in sorted(groups):
        lines.append("PATH %s %d" % (group, groups[group]))
    flagged = 0
    for kind in sorted(sc.kinds):
        lines.append("KIND %s %d" % (kind, len(sc.kinds[kind])))
        flagged += len(sc.kinds[kind])
    counts = sc.counts
    for rule_id in sorted(counts):
        lines.append("RULE %s %d" % (rule_id, counts[rule_id]))
    lines.append("RESULTS %s" % results)
    if sc.incomplete:
        lines.append("INCOMPLETE %s" % sc.incomplete)
    elif counts or flagged:
        lines.append("HITS %d" % (sum(counts.values()) + flagged))
    else:
        lines.append("NO RULE MATCHED (not a verdict that the folder is safe)")
    lines.append("PROMPT-SCAN END")
    return lines


_RANK = {"FILES": 0, "PATH": 1, "KIND": 2, "RULE": 3}


_GROUP_NAMES = frozenset(g for g, _ in PATH_GROUPS + PLUGIN_GROUPS)


def check_output(lines: list, engine_version: str, rule_ids=None) -> bool:
    """Every line matches the grammar, START and END come once each at the
    ends, there's exactly one closing line, HITS adds up, the lines come in
    order (an ERROR alone, else one FILES, then PATH, KIND and RULE lines,
    then one RESULTS line before the closing one), and every PATH group,
    KIND and (when rule_ids is given) RULE id is a known one."""
    if len(lines) < 3 or lines[0] != "PROMPT-SCAN START engine=%s" % engine_version \
            or lines[-1] != "PROMPT-SCAN END":
        return False
    closing = [ln for ln in lines if ln.startswith(("HITS ", "NO RULE MATCHED", "INCOMPLETE ",
                                                    "ERROR "))]
    if len(closing) != 1 or lines[-2] != closing[0]:
        return False
    total = 0
    for ln in lines:
        if not _LINE_GRAMMAR.fullmatch(ln) or not ln.isascii() or not ln.isprintable():
            return False
        if ln.startswith(("KIND ", "RULE ")):
            total += int(ln.rsplit(" ", 1)[1])
        if ln.startswith(("INCOMPLETE ", "ERROR ")) and ln.split(" ", 1)[1] not in REASONS:
            return False
        if ln.startswith("KIND ") and ln.split(" ")[1] not in KINDS:
            return False
        if ln.startswith("PATH ") and ln.split(" ")[1] not in _GROUP_NAMES:
            return False
        if rule_ids is not None and ln.startswith("RULE ") and ln.split(" ")[1] not in rule_ids:
            return False
    if closing[0].startswith("HITS ") and int(closing[0].split(" ")[1]) != total:
        return False
    if closing[0].startswith("NO RULE MATCHED") and total:
        return False
    if sum(1 for ln in lines if ln.startswith("PROMPT-SCAN ")) != 2:
        return False
    body = lines[1:-2]
    if closing[0].startswith("ERROR "):
        return not body
    if len(body) < 2 or not body[0].startswith("FILES ") or not body[-1].startswith("RESULTS "):
        return False
    rank = 0
    for i, ln in enumerate(body[:-1]):
        word = ln.split(" ", 1)[0]
        if _RANK.get(word, -1) < rank or (word == "FILES") != (i == 0):
            return False
        rank = _RANK[word]
    return True


def _write_results(parent_fd: int, name: str, sc: _Scan, summary: list) -> None:
    """Both files, or nothing: any failure or interruption removes what was
    written, and then raises."""
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    try:
        out_fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except BaseException:
        os.rmdir(name, dir_fd=parent_fd)
        raise
    made: list = []
    try:
        detail = [summary[0]]
        if sc.capped:
            detail.append("NOTE detail-capped %d-per-file %d-in-all" % (MAX_DETAIL_PER_FILE,
                                                                         MAX_DETAIL))
        for kind in sorted(sc.kinds):
            for rel in sorted(sc.kinds[kind], key=lambda r: int(sc.ids[r][1:])):
                detail.append("FILE %s %s" % (kind, sc.ids[rel]))
        for rule_id, rel, line in sorted(sc.hits, key=lambda h: (int(sc.ids[h[1]][1:]), h[2], h[0])):
            detail.append("HIT %s %s:%d" % (rule_id, sc.ids[rel], line))
        detail += summary[1:]
        mapping = ["%s %s" % (sc.ids[rel], _esc(rel)) for rel in sc.order]
        for fname, body in (("scan.out", detail), ("paths.map", mapping)):
            made.append(fname)        # before the open: an interruption mid-open still cleans up
            fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=out_fd)
            with os.fdopen(fd, "w", encoding="ascii", newline="\n") as fh:
                fh.write("".join(line + "\n" for line in body))
    except BaseException:
        for fname in made:
            try:
                os.unlink(fname, dir_fd=out_fd)
            except OSError:
                pass
        os.close(out_fd)
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    os.close(out_fd)


def run(target: str, roots, is_secret, engine, *, deadline: float, clock=time.monotonic,
        now=time.time, casefold: bool = False, walked=None, results_fd=None,
        results_name=None) -> list:
    """Scan target and return the checked lines for the model. target is an
    absolute path; roots holds each quarantine folder's spellings;
    is_secret(path) says whether the reader gate treats a path as a secret.
    walked(), if given, is called once the walk ends (the hook stops its
    alarm there, so the results are never cut off half written).

    results_fd and results_name, given together or not at all, send the
    results folder somewhere else: results_name (shaped scan-YYYYMMDDTHHMMSSZ)
    is made inside the open folder results_fd, which the caller keeps and
    closes. Every check on the target is the same either way, including that
    the folder above it is the one it was opened from. A results_fd that is
    one of roots' folders, lies inside one, or can't be shown outside them
    gives refused-root; one that no longer names the same folder, or has
    moved inside a root, when the results are written gives not-written. paths.map holds names from the scanned tree, so the caller
    keeps results_fd where no agent with a shell or file tools can read it.
    A bad results_fd or results_name raises ValueError before anything is
    read; a name already there gives results-exist. The hook passes neither,
    so the results go beside the target."""
    if (results_fd is None) != (results_name is None):
        raise ValueError("results_fd and results_name go together")
    out_id = None
    if results_fd is not None:
        if not (isinstance(results_name, str) and _RESULTS_NAME.fullmatch(results_name)):
            raise ValueError("results_name isn't scan-YYYYMMDDTHHMMSSZ")
        st = None
        if (isinstance(results_fd, int) and not isinstance(results_fd, bool)
                and 0 <= results_fd <= 2**31 - 1):
            try:
                st = os.fstat(results_fd)
            except OSError:
                pass
        if st is None or not stat.S_ISDIR(st.st_mode):
            raise ValueError("results_fd isn't an open folder")
        out_id = (st.st_dev, st.st_ino)
    sc = _Scan(engine, False, deadline, clock)
    if any(not r.rstrip("/") for forms_of_root in roots for r in forms_of_root):
        return _summary(engine, sc, {}, "not-written", "broad-root")
    problem = target_problem(target, roots, is_secret, casefold)
    if problem:
        return _summary(engine, sc, {}, "not-written", problem)
    root_ids = _ids(roots)
    if out_id is not None:
        try:
            out_in_root = out_id in root_ids or _below(results_fd, root_ids, True)
        except OSError:
            out_in_root = True
        if out_in_root:
            return _summary(engine, sc, {}, "not-written", "refused-root")
    real = os.path.realpath(target)
    parent, base = os.path.split(real)
    try:
        parent_fd = os.open(parent, _DIR_FLAGS)
    except OSError:
        return _summary(engine, sc, {}, "not-written", "unreadable")
    try:
        try:
            root_fd = os.open(base, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError:
            return _summary(engine, sc, {}, "not-written", "unreadable")
        try:
            try:
                below = _below(root_fd, root_ids) and _is_parent(parent_fd, root_fd)
            except OSError:
                below = False
            if not below:
                return _summary(engine, sc, {}, "not-written", "refused-root")
            try:
                top = {e.name for e in os.scandir(root_fd)}
            except OSError:
                return _summary(engine, sc, {}, "not-written", "unreadable")
            sc.plugin = bool(top & PLUGIN_MARKERS)
            try:
                sc.walk(root_fd, real, is_secret)
            except _Stop as stop:
                sc.note(stop.reason)
            except Timeout:
                sc.note("timeout")
        finally:
            os.close(root_fd)
        if walked is not None:
            walked()
        groups = sc.classify()
        if results_fd is None:
            out_fd, name = parent_fd, time.strftime("scan-%Y%m%dT%H%M%SZ", time.gmtime(now()))
        else:
            out_fd, name = results_fd, results_name
        summary = _summary(engine, sc, groups, name)
        try:
            if out_id is not None:
                now_st = os.fstat(results_fd)
                if ((now_st.st_dev, now_st.st_ino) != out_id
                        or _below(results_fd, root_ids, True)):
                    raise OSError("results_fd changed or moved into a root")
            _write_results(out_fd, name, sc, summary)
        except FileExistsError:
            return _summary(engine, sc, {}, "not-written", "results-exist")
        except OSError:
            summary = _summary(engine, sc, groups, "not-written")
    finally:
        os.close(parent_fd)
    if not check_output(summary, engine.ENGINE_VERSION, engine.RULE_IDS):
        return _summary(engine, sc, {}, "not-written", "internal")
    return summary
