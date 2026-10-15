"""Every regular expression in the gates is linear on hostile input.

The gates (reader_gate.py, launch_gate.py, _config.py) run regexes over
attacker-controlled text: the Bash command the launch gate parses, the paths,
hosts and YAML the reader gate checks, and the glob->regex it compiles from a
trusted config and then runs against a path. One pattern that backtracks lets a
crafted *subject* stall the hook. (An earlier version of this file was a false
alarm: it fed 2000-asterisk globs -- the trusted config side -- instead of the
attacker-controlled subject. This one feeds the subject.)

Two checks, each a backstop for the other:

- A static lint over each pattern's parse tree. Two unbounded one-character
  repeats that meet with only empty items between them, and share a character,
  trade that character back and forth: quadratic, or worse with three. What it
  leaves to the timing run is in _Lint's docstring. Reviewed exceptions go on
  LINT_OK with their reason.
- A timing run. Each pattern (run the way its callers run it) and each gate
  entry point runs on 200,000-character inputs: uniform runs, structured
  prefixes before a gap to the end, and each of the pattern's own words before
  a gap of spaces, letters or commas that ends in a character the pattern
  refuses (so the match fails and backtracks; an input ending in an accepted
  character would succeed at once and hide the blowup). Python can't interrupt
  a running regex, so the runs happen in child processes; the parent kills a
  child when one run overruns and records it.

Patterns are found, not listed: every compiled pattern reachable from the three
modules, and every literal pattern passed to an re call in their source. A
pattern built from data, and every way around that scan, must be on DYNAMIC_OK
with its reason.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:  # Python 3.11+
    import re._constants as _C
    import re._parser as _sre_parse
except ImportError:  # 3.10
    import sre_constants as _C
    import sre_parse as _sre_parse

TESTS = Path(__file__).resolve().parent
HOOKS = TESTS.parent / "hooks"
for _p in (str(TESTS), str(HOOKS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SOURCES = ("reader_gate.py", "launch_gate.py", "_config.py")
# CPU seconds per (check, input). A linear check costs milliseconds of CPU on
# SIZE; a superlinear one burns seconds-to-minutes once its gap is ~SIZE long.
# The completed-check budget is measured in CPU time (time.process_time), so a
# child that a loaded machine deschedules mid-run is not mistaken for a slow
# regex. The kill is still wall-clock -- the parent can't see a child's CPU
# time while it is stuck in an uninterruptible regex -- and a wall-clock kill
# under load is re-run alone (see _confirm) before it counts.
BUDGET = 2.0
STARTUP = 60.0        # wall seconds for a child to import and plan
KILL = BUDGET * 4     # wall seconds before the parent kills a running check
CONFIRM_WALL = 30.0   # wall seconds a killed check gets, alone, to prove itself
SIZE = 200_000
SHARDS = max(1, min(8, (os.cpu_count() or 2) // 2))
RE_CALLS = {"compile", "search", "match", "fullmatch", "finditer", "findall", "sub", "subn", "split"}
HOME = "/home/sd-test"
# Trusted globs (config side, fixed) whose compiled regex the reader gate runs
# against attacker paths. Representative of the secret patterns it compiles.
GLOBS = ("**/*", "//**/*.pem", "//**/*keypair*.json", "~/.ssh/**", "//**/.env*", "~/x/**/*.key",
         # _glob_escape's output for a literal folder named "[a*" (a resolved base
         # or CLAUDE_CONFIG_DIR): its "[" and "*" become classes.
         "/h/[][]a[*]/**")
# Helpers a built pattern's text comes from. Their source is part of that
# pattern's digest, so a change to one is reviewed again too.
DIGEST_HELPERS = {("reader_gate.py", "_compile_secret"): ("_glob_regex", "_glob_escape")}

# Patterns a function builds from data, each linear by construction. Keyed by
# (file, scope, digest of the enclosing statement/function). A new built
# pattern, or any change to the builder, fails NoUnreviewedBuiltPatterns until
# reviewed here (the failure prints the call and the digest).
DYNAMIC_OK = {
    ("launch_gate.py", "_ansi_c", "7984f2eac4f8"):
        "re.match(r'[0-9A-Fa-f]{1,%d}' % width): width is the literal 2/4/8 for \\x/\\u/\\U, so the "
        "run is bounded; one char class, no second repeat, linear.",
    ("reader_gate.py", "_compile_secret", "cf8e3e07a41c"):
        "re.compile(_glob_regex(expanded) + r'\\Z', ...): the glob comes from a trusted config (a secret "
        "pattern or quarantine root), or from _glob_escape of a resolved secret base or CLAUDE_CONFIG_DIR "
        "(literal text with '*', '?' and '[' turned into one-character classes), never the subject. "
        "_glob_regex and _glob_escape are part of this digest (DIGEST_HELPERS). The "
        "reader_gate-glob-match timing checks run its output on hostile paths; the GLOBS list covers **, "
        "//**, ~/, *keypair*, .env, *.key and escaped-class shapes.",
}
# Lint findings reviewed as safe, keyed by the digest of the pattern's text.
# Both were confirmed linear by the timing run (the lint is conservative about
# greedy shared-tail and end-anchor resolution; see each reason).
LINT_OK: dict[str, str] = {
    "553b4b34e89f":
        "_YAML_BINARY: the flagged repeats (\\s*, [-+0-9]*, [A-Za-z0-9+/=\\s]+) all feed the final "
        "greedy [A-Za-z0-9+/=\\s]+ with nothing after it, so a give-back is absorbed by that tail in one "
        "step; no trailing anchor can force the O(n^2) split. Timed linear on !!binary + 200k of vtab / "
        "digits / '+0123456', with and without a NUL tail.",
    "197a2c104765":
        "_frontmatter key line re.match(r'([A-Za-z_][A-Za-z0-9_-]*)\\s*:\\s*(.*)$'): the \\s*/.* overlap "
        "ends in (.*)$ on a line from str.splitlines(), which never contains \\n, so .* always reaches the "
        "end and $ matches on the first greedy try; no backtracking. Timed linear on 'key:' + 200k of vtab.",
}


def _digest(text) -> str:
    return hashlib.sha256(text if isinstance(text, bytes) else text.encode("utf-8")).hexdigest()[:12]


# ------------------------------------------------------------- discovery ----

def source_calls() -> tuple[list[dict], list[tuple]]:
    """The re calls in SOURCES (see _calls_in)."""
    literal, built = [], []
    for rel in SOURCES:
        lit, bad = _calls_in(rel, (HOOKS / rel).read_text(encoding="utf-8"))
        literal += lit
        built += bad
    return literal, built


def _calls_in(rel: str, source: str) -> tuple[list[dict], list[tuple]]:
    """Literal patterns as {name, pattern, flags_src, kind, rel}; everything
    else as (file, scope, digest, text, line): a pattern a function or lambda
    builds; a module- or class-level compile of a built pattern whose result
    the walk can't reach (only NAME = re.compile(...), or an item of a literal
    list/tuple/set/dict so assigned, is reachable); and every way past the
    re.<call> this scan reads (from re import, getattr on re, an re call passed
    as a value, a call with no pattern argument). The digest covers the whole
    enclosing function (or statement), so a changed builder is reviewed again."""
    tree = ast.parse(source)
    literal, built = [], []
    functions = {n.name: ast.get_source_segment(source, n) for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    flag_pos = {"compile": 1, "sub": 4, "subn": 4, "split": 3}
    aliases = {"re"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases |= {a.asname for a in node.names if a.name == "re" and a.asname}
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) and node.value.id in aliases:
            aliases |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    reachable = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            values = [node.value]
            if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                values += node.value.elts
            elif isinstance(node.value, ast.Dict):
                values += node.value.values
            reachable |= {id(v) for v in values if isinstance(v, ast.Call)}

    def is_re(node) -> bool:
        return isinstance(node, ast.Name) and node.id in aliases

    def escape(node, scope, owner, why):
        text = ast.get_source_segment(source, node) or ast.unparse(node)
        whole = ast.get_source_segment(source, owner) or ast.unparse(owner)
        for helper in DIGEST_HELPERS.get((rel, scope), ()):
            if helper not in functions:
                raise AssertionError(f"{rel}: digest helper {helper} not found")
            whole += "\n" + functions[helper]
        built.append((rel, scope, _digest(whole), f"{why}: {text}", node.lineno))

    def visit(node, scope, owner, in_fn, parent):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            name = getattr(node, "name", "<lambda>")
            scope = name if scope == "<module>" else f"{scope}.{name}"
            if not isinstance(node, ast.ClassDef):
                in_fn, owner = True, node
        elif isinstance(node, ast.stmt) and not in_fn:
            owner = node
        if isinstance(node, ast.ImportFrom) and node.module == "re":
            escape(node, scope, owner, "from re import")
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
              and node.args and is_re(node.args[0])):
            escape(node, scope, owner, "getattr on re")
        elif (isinstance(node, ast.Attribute) and is_re(node.value) and node.attr in RE_CALLS
              and not (isinstance(parent, ast.Call) and parent.func is node)):
            escape(node, scope, owner, "re call passed as a value")
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and is_re(node.func.value)
              and node.func.attr in RE_CALLS):
            kw = {k.arg: k.value for k in node.keywords}
            arg = node.args[0] if node.args else kw.get("pattern")
            pos = flag_pos.get(node.func.attr, 2)
            flags = node.args[pos] if len(node.args) > pos else kw.get("flags")
            if arg is None:
                escape(node, scope, owner, "no pattern argument")
            elif isinstance(arg, ast.Constant) and isinstance(arg.value, (str, bytes)):
                literal.append({"name": f"{rel}:{node.lineno} {scope}", "pattern": arg.value, "rel": rel,
                                "flags_src": ast.unparse(flags) if flags is not None else None,
                                "kind": node.func.attr})
            elif in_fn or node.func.attr != "compile" or id(node) not in reachable:
                escape(node, scope, owner, "built pattern")
        for child in ast.iter_child_nodes(node):
            visit(child, scope, owner, in_fn, node)

    visit(tree, "<module>", tree, False, None)
    return literal, built


def _var_ops(source: str) -> dict[str, set[str]]:
    """name -> the re ops its callers use (NAME.search(...), NAME.sub(...)),
    so each module pattern is timed the way it is really run, not with
    finditer (which restarts at every position and invents false alarms)."""
    ops: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.attr in RE_CALLS):
            ops.setdefault(node.func.value.id, set()).add(node.func.attr)
    return ops


def _walk(obj, path: str, out: list, module: str, depth: int = 0) -> None:
    if isinstance(obj, re.Pattern):
        out.append((path, obj))
    elif depth >= 3:
        return
    elif isinstance(obj, (list, tuple)):
        for i, x in enumerate(obj):
            _walk(x, f"{path}[{i}]", out, module, depth + 1)
    elif isinstance(obj, (set, frozenset)):
        for i, x in enumerate(sorted(obj, key=repr)):
            _walk(x, f"{path}{{{i}}}", out, module, depth + 1)
    elif isinstance(obj, dict):
        for k, x in obj.items():
            _walk(x, f"{path}[{k!r}]", out, module, depth + 1)
    elif isinstance(obj, type) and obj.__module__ == module:
        for k in sorted(vars(obj)):
            _walk(vars(obj)[k], f"{path}.{k}", out, module, depth + 1)
    elif inspect.isfunction(obj) and obj.__module__ == module:
        _walk(tuple(obj.__defaults__ or ()), f"{path}()", out, module, depth + 1)
        _walk(dict(obj.__kwdefaults__ or {}), f"{path}()", out, module, depth + 1)


def _op_kinds(ops: set[str]) -> tuple[str, ...]:
    """Timing kinds for the re ops a caller uses. search/finditer/sub/split
    scan; match/fullmatch anchor. With no traced caller (a pattern held in a
    tuple and run through a loop variable, say), both a scan and a full match:
    better a reviewed false alarm than a missed scan."""
    kinds = []
    if ops & {"search", "finditer", "findall", "sub", "subn", "split"}:
        kinds.append("search")
    if "match" in ops:
        kinds.append("match")
    if "fullmatch" in ops:
        kinds.append("fullmatch")
    return tuple(kinds) or ("search", "fullmatch")


def discover() -> list[tuple[str, re.Pattern, tuple[str, ...]]]:
    """(name, pattern, timing kinds) for every pattern, in a fixed order. A
    pattern found twice keeps every kind it is called with."""
    import _config  # noqa: F401
    import launch_gate
    import reader_gate

    modules = {"reader_gate.py": reader_gate, "launch_gate.py": launch_gate, "_config.py": _config}
    ops = {rel: _var_ops((HOOKS / rel).read_text(encoding="utf-8")) for rel in SOURCES}
    out: list = []
    index: dict = {}

    def add(name, p, kinds):
        key = (type(p.pattern), p.pattern, p.flags)
        if key in index:
            i = index[key]
            out[i] = (out[i][0], out[i][1], tuple(dict.fromkeys(out[i][2] + tuple(kinds))))
        else:
            index[key] = len(out)
            out.append((name, p, tuple(kinds)))

    for rel, mod in modules.items():
        short = rel[:-3]
        for name in sorted(vars(mod)):
            found: list = []
            _walk(getattr(mod, name), f"{short}.{name}", found, mod.__name__)
            for path, p in found:
                add(path, p, _op_kinds(ops[rel].get(name, set())))
    literal, _ = source_calls()
    for item in literal:
        flags = 0
        if item["flags_src"]:
            flags = int(eval(item["flags_src"], dict(vars(modules[item["rel"]]))))  # noqa: S307
        p = re.compile(item["pattern"], flags)
        if item["kind"] == "compile":
            # A compile isn't a run. A compiled pattern a global holds is timed
            # the way its callers run it (found above through _var_ops); timing
            # an anchored .match() pattern with search restarts it at every
            # position and reports a linear pattern as quadratic.
            if (type(p.pattern), p.pattern, p.flags) in index:
                continue
            kinds = _op_kinds(set())
        else:
            kinds = _op_kinds({item["kind"]})
        add(item["name"], p, kinds)
    return out


# ------------------------------------------------------------------ lint ----

_BASE_PROBE = [chr(c) for c in range(256)] + [chr(c) for c in (0x2028, 0x2029, 0x3000, 0x200B, 0x2022, 0xFEFF,
                                                               0x0660, 0x4E00, 0x20E3, 0x2019, 0x201C, 0x2014)]
_CATS = {
    _C.CATEGORY_DIGIT: r"\d", _C.CATEGORY_NOT_DIGIT: r"\D", _C.CATEGORY_SPACE: r"\s", _C.CATEGORY_NOT_SPACE: r"\S",
    _C.CATEGORY_WORD: r"\w", _C.CATEGORY_NOT_WORD: r"\W", _C.CATEGORY_LINEBREAK: r"\n",
    _C.CATEGORY_NOT_LINEBREAK: r"[^\n]",
}
_SINGLE = (_C.LITERAL, _C.NOT_LITERAL, _C.ANY, _C.IN)
_REPEATS = (_C.MAX_REPEAT, _C.MIN_REPEAT)
_POSSESSIVE = getattr(_C, "POSSESSIVE_REPEAT", None)
_ATOMIC = getattr(_C, "ATOMIC_GROUP", None)
_AT_TEXT = {_C.AT_BOUNDARY: r"\b", _C.AT_NON_BOUNDARY: r"\B", _C.AT_BEGINNING: "^", _C.AT_END: "$",
            _C.AT_BEGINNING_STRING: r"\A", _C.AT_END_STRING: r"\Z"}


def _variants(ch: str, flags: int) -> set[str]:
    return {v for v in (ch, ch.lower(), ch.upper()) if len(v) == 1} if flags & re.I else {ch}


def _in_class(items, ch: str, flags: int) -> bool:
    neg = bool(items) and items[0][0] is _C.NEGATE
    hit = False
    for op, av in items:
        for v in _variants(ch, flags):
            if op is _C.LITERAL and ord(v) == av or op is _C.RANGE and av[0] <= ord(v) <= av[1]:
                hit = True
            elif op is _C.CATEGORY and re.fullmatch(_CATS[av], v, flags & re.A):
                hit = True
    return hit != neg


def _probe(tree) -> list[str]:
    """The base probe, plus the pattern's own literal characters and both ends
    of each of its ranges: two classes that overlap anywhere share one of
    these, so classes outside the base probe still meet."""
    extra: set[int] = set()

    def walk(sub):
        for op, av in sub:
            if op in (_C.LITERAL, _C.NOT_LITERAL):
                extra.add(av)
            elif op is _C.IN:
                for iop, iav in av:
                    if iop is _C.LITERAL:
                        extra.add(iav)
                    elif iop is _C.RANGE:
                        extra.update(iav)
            elif op in _REPEATS or (op is _POSSESSIVE and op is not None):
                walk(av[2])
            elif op is _C.SUBPATTERN:
                walk(av[3])
            elif op is _C.BRANCH:
                for alt in av[1]:
                    walk(alt)
            elif op in (_C.ASSERT, _C.ASSERT_NOT):
                walk(av[1])
            elif op is _C.GROUPREF_EXISTS:
                walk(av[1])
                if av[2] is not None:
                    walk(av[2])
            elif _ATOMIC is not None and op is _ATOMIC:
                walk(av)

    walk(tree)
    return _BASE_PROBE + [chr(c) for c in sorted(extra) if c >= 256 and chr(c) not in _BASE_PROBE]


def _text(sub) -> str:
    """A short readable form of a parsed piece, for the failure message."""
    out = []
    for op, av in sub:
        if op is _C.LITERAL:
            out.append(re.escape(chr(av)))
        elif op is _C.NOT_LITERAL:
            out.append("[^%s]" % re.escape(chr(av)))
        elif op is _C.ANY:
            out.append(".")
        elif op is _C.IN:
            parts = []
            for iop, iav in av:
                if iop is _C.NEGATE:
                    parts.append("^")
                elif iop is _C.LITERAL:
                    parts.append(re.escape(chr(iav)))
                elif iop is _C.RANGE:
                    parts.append("%s-%s" % (chr(iav[0]), chr(iav[1])))
                elif iop is _C.CATEGORY:
                    parts.append(_CATS.get(iav, "?"))
            text = "".join(parts)
            out.append(text if len(av) == 1 and av[0][0] is _C.CATEGORY else "[%s]" % text)
        elif op in _REPEATS or (op is _POSSESSIVE and op is not None):
            lo, hi, body = av
            inner = _text(body)
            if len(body) > 1 or (body and body[0][0] is _C.BRANCH):
                inner = "(?:%s)" % inner
            q = {(0, _C.MAXREPEAT): "*", (1, _C.MAXREPEAT): "+", (0, 1): "?"}.get((lo, hi))
            q = q or ("{%d,}" % lo if hi == _C.MAXREPEAT else "{%d,%d}" % (lo, hi))
            out.append(inner + q + ("?" if op is _C.MIN_REPEAT else "+" if op is _POSSESSIVE else ""))
        elif op is _C.SUBPATTERN:
            out.append("(%s)" % _text(av[3]))
        elif op is _C.BRANCH:
            out.append("|".join(_text(alt) for alt in av[1]))
        elif op is _C.AT:
            out.append(_AT_TEXT.get(av, "@"))
        elif op in (_C.ASSERT, _C.ASSERT_NOT):
            out.append("(?%s%s%s)" % ("<" if av[0] < 0 else "", "=" if op is _C.ASSERT else "!", _text(av[1])))
        else:
            out.append("...")
    s = "".join(out)
    return s if len(s) <= 48 else s[:45] + "..."


class _Lint:
    r"""Walks a parse tree. Each sequence reports the unbounded one-character
    repeats it can start and end in (its heads and tails), with whether a word
    boundary lies between the repeat and that end; a tail that meets the next
    item's head shares characters with it, or doesn't.

    What it models: adjacent unbounded one-character repeats (a class, a group
    or alternation of classes, one behind lookarounds), across empty items,
    optional groups, lookaheads (which rescan) and backreferences (which may be
    empty), possessive and atomic ones as the later partner. What it leaves to
    the timing run: bounded repeats ((?:\s\s?)*), an ambiguous alternation
    ((a|aa)*), a repeated multi-character body ((?:ab)*(?:ab)*) and a scan's
    restarts (\s*x under search)."""

    def __init__(self, probe: list[str], word: set[str]):
        self.found: list[str] = []
        self.probe = probe
        self.word = word

    def single(self, op, av, flags: int) -> set[str]:
        if op is _C.LITERAL:
            return {ch for ch in self.probe if any(ord(v) == av for v in _variants(ch, flags))}
        if op is _C.NOT_LITERAL:
            return {ch for ch in self.probe if all(ord(v) != av for v in _variants(ch, flags))}
        if op is _C.ANY:
            return set(self.probe) if flags & re.S else set(self.probe) - {"\n"}
        return {ch for ch in self.probe if _in_class(av, ch, flags)}

    def one_char(self, sub, flags: int):
        items = [(op, av) for op, av in sub if op not in (_C.ASSERT, _C.ASSERT_NOT)]
        if len(items) != 1:
            return None
        op, av = items[0]
        if op in _SINGLE:
            return self.single(op, av, flags)
        if op is _C.SUBPATTERN:
            return self.one_char(av[3], (flags | av[1]) & ~av[2])
        if op is _C.BRANCH:
            sets = [self.one_char(alt, flags) for alt in av[1]]
            return set().union(*sets) if all(s is not None for s in sets) else None
        return None

    def check(self, tails, heads, why: str) -> None:
        for a, a_crossed, a_text in tails:
            for b, b_crossed, b_text in heads:
                both = a & b
                if (a_crossed or b_crossed) and not (both & self.word and both - self.word):
                    continue
                if both:
                    sample = "".join(sorted(repr(c)[1:-1] for c in both)[:8])
                    self.found.append(f"{why} {a_text} and {b_text} can trade {sample}")

    def seq(self, sub, flags: int):
        nullable, crossed, heads, tails = True, False, [], []
        for op, av in sub:
            if op is _C.AT and av == _C.AT_BOUNDARY:
                tails = [(s, True, t) for s, _, t in tails]
                crossed = crossed or nullable
                continue
            n, h, t = self.item(op, av, flags)
            self.check(tails, h, "repeats")
            if nullable:
                heads += [(s, c or crossed, x) for s, c, x in h]
            tails = tails + t if n else list(t)
            nullable = nullable and n
        return nullable, heads, tails

    def item(self, op, av, flags: int):
        if op in _SINGLE:
            return False, [], []
        if op is _C.AT:
            return True, [], []
        if op in (_C.ASSERT, _C.ASSERT_NOT):
            _, h, _ = self.seq(av[1], flags)
            return True, (h if av[0] > 0 else []), []
        if op in _REPEATS or (op is _POSSESSIVE and op is not None):
            lo, hi, body = av
            n, h, t = self.seq(body, flags)
            if hi > 1:
                self.check(t, h, "a repeated group's")
            one = self.one_char(body, flags)
            if one is not None and hi == _C.MAXREPEAT:
                me = [(one, False, _text([(op, av)]))]
                return lo == 0, me, ([] if op is _POSSESSIVE else me)
            return lo == 0 or n, h, ([] if op is _POSSESSIVE else t)
        if _ATOMIC is not None and op is _ATOMIC:
            n, h, _ = self.seq(av, flags)
            return n, h, []
        if op is _C.SUBPATTERN:
            return self.seq(av[3], (flags | av[1]) & ~av[2])
        if op is _C.BRANCH:
            nullable, heads, tails = False, [], []
            for alt in av[1]:
                n, h, t = self.seq(alt, flags)
                nullable, heads, tails = nullable or n, heads + h, tails + t
            return nullable, heads, tails
        if op is _C.GROUPREF_EXISTS:
            return self.item(_C.BRANCH, (None, [av[1], av[2] if av[2] is not None else []]), flags)
        if op is _C.GROUPREF:
            return True, [], []
        raise ValueError(f"the lint does not know {op}")


def lint(p: re.Pattern) -> list[str]:
    """Pairs of unbounded repeats in `p` that can trade characters."""
    is_bytes = isinstance(p.pattern, bytes)
    src = p.pattern.decode("latin-1") if is_bytes else p.pattern
    tree = _sre_parse.parse(src, (p.flags & ~re.U) | re.A if is_bytes else p.flags)
    flags = tree.state.flags | (re.A if is_bytes else 0)
    probe = _probe(tree)
    word = {c for c in probe if re.match(r"\w", c, re.A if flags & re.A else 0)}
    walker = _Lint(probe, word)
    walker.seq(tree, flags)
    return sorted(set(walker.found))


# ---------------------------------------------------------------- timing ----

def _scan(p: re.Pattern, kind: str):
    """The pattern run the way its caller runs it (one anchored attempt for
    match and fullmatch, a scan for the rest), as bytes for a bytes pattern."""
    def run(s):
        data = s.encode("utf-8") if isinstance(p.pattern, bytes) else s
        if kind == "match":
            return p.match(data)
        if kind == "fullmatch":
            return p.fullmatch(data)
        return p.finditer(data)
    return run


def _tokens(p: re.Pattern) -> list[str]:
    """Literal pieces of the pattern: words (escapes taken out first, so
    \\bhello gives hello, not bhello), and the punctuation it looks for."""
    src = p.pattern if isinstance(p.pattern, str) else p.pattern.decode("latin-1")
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_-]+", re.sub(r"\\.", " ", src))
    puncts = re.findall(r"\\([^A-Za-z0-9])|([^\\\w\s()\[\]{}?*+|^$.])", src)
    return sorted(set(words + [a or b for a, b in puncts])) or ["x"]


def _fill(unit: str) -> str:
    return (unit * (SIZE // max(1, len(unit)) + 1))[:SIZE]


def _gap(prefix: str, filler: str = " ", end: str = "\x00") -> str:
    """`prefix`, then `filler` to the end, then one character that ends it: a
    NUL by default, which nearly every pattern refuses, so the match fails and
    backtracks (an "x" lets a pattern ending in \\w succeed at once)."""
    return prefix + filler * (SIZE - len(prefix) - 1) + end


_WORDS = "abandon ability able about above absent absorb abstract absurd abuse access accident".split()
_FIXED: list = []


def fixed_inputs() -> list[tuple[str, str]]:
    if _FIXED:
        return _FIXED
    base = [
        ("spaces", " " * SIZE),
        ("blank lines", "\n" * SIZE),
        ("letters", "a" * SIZE),
        ("digits", "1" * SIZE),
        ("hex", _fill("4c08aa019b7d ")),
        ("backslashes", "\\" * SIZE),
        ("escapes", _fill("\\x41")),
        ("dollars", "$" * SIZE),
        ("dollar vars", _fill("${abc}")),
        ("dollar names", _fill("$abc ")),
        ("equals assignments", _fill("ab=cd ")),
        ("placeholders", _fill("__sdc12__")),
        ("slashes", "/" * SIZE),
        ("dots", "." * SIZE),
        ("colons", ":" * SIZE),
        ("dashes", "-" * SIZE),
        ("underscores", "_" * SIZE),
        ("at signs", "@" * SIZE),
        ("asterisks", "*" * SIZE),
        ("question marks", "?" * SIZE),
        ("brackets", _fill("[]")),
        ("braces", _fill("{}")),
        ("angle brackets", "<" * SIZE),
        ("quotes", '"' * SIZE),
        ("backticks", "`" * SIZE),
        ("paths", _fill("a/b/c/")),
        ("home paths", _fill("~/a/")),
        ("deep glob paths", _fill("x/" * 1)),
        ("dotfiles", _fill("/.env.")),
        ("pem paths", _fill("a/b.pem/")),
        ("keypair paths", _fill("keypair1.json/")),
        ("ssh paths", _fill("/.ssh/")),
        ("numeric host", _fill("1.2.3.4.")),
        ("hex host", _fill("0x1.0x2.")),
        ("dotted hex", _fill("0xff.")),
        ("npx words", _fill("npx ")),
        ("download words", _fill("curl ")),
        ("sudo words", _fill("sudo ")),
        ("python names", _fill("python3.9 ")),
        ("pipes to sh", _fill("| sh ")),
        ("subshells", _fill("$(x)")),
        ("yaml keys", _fill("key: value\n")),
        ("yaml list", _fill(" - a\n")),
        ("yaml binary", _fill("!!binary ")),
        ("yaml escapes", _fill("\\x41\\u4e00 ")),
        ("plugin names", _fill("a-b.c_d ")),
        ("agent ids", _fill("Ab9_-" * 1)),
        ("tabs and NBSP", _fill("\t\N{NO-BREAK SPACE}")),
        ("ssh options", "ssh " + _fill("-o ConnectTimeout=1 ")),
        ("ssh glued options", "ssh " + _fill("-oProxyJump=a,b,c ")),
        ("ssh bundled flags", "ssh " + _fill("-vvvvtt ")),
        ("scp operands", "scp " + _fill("u@[::1]:/a ")),
        ("ssh brackets", "ssh " + _fill("[[[[")),
        ("ssh at signs", "ssh " + _fill("a@b@")),
    ]
    gaps = [(f"{label}, then a gap", _gap(s[:2000])) for label, s in base if s[:2000].strip()]
    gaps += [(f"{label}, then a letter gap", _gap(s[:2000], "a", "\x00")) for label, s in base[:16] if s[:2000].strip()]
    _FIXED.extend(base + gaps)
    return _FIXED


def pattern_inputs(p: re.Pattern):
    """(label, maker) for the pattern's own words: together, and each one
    before a gap to the end of spaces, letters or commas."""
    toks = _tokens(p)
    yield "its words, spaced", lambda: _fill(" ".join(toks) + " ")
    yield "its words, glued", lambda: _fill("".join(toks))
    yield "its words, one per line", lambda: _fill("\n".join(toks) + "\n")
    for t in toks:
        for filler, end, what in ((" ", "\x00", "spaces"), (" ", "x", "spaces and an x"), ("a", "\x00", "letters"),
                                  (",", "\x00", "commas")):
            yield f"{t!r}, then {what}", (lambda t=t, filler=filler, end=end: _gap(t, filler, end))


def _glob_match(glob: str):
    """The reader gate's glob->regex, compiled from a trusted glob the way
    _compile_secret does, run against an attacker path (the subject)."""
    import reader_gate
    rx = re.compile(reader_gate._glob_regex(reader_gate._expand(glob, HOME)) + r"\Z", re.IGNORECASE | re.DOTALL)
    return lambda s: rx.fullmatch(s)


def checks() -> tuple[list, int]:
    """(name, function of one string, pattern or None) for each timed check,
    and how many patterns they cover."""
    import launch_gate

    found = discover()
    out = [(f"{name} ({kind})", _scan(p, kind), p) for name, p, kinds in found for kind in kinds]
    # The gate entry points, on hostile commands and paths (the attacker side).
    # check() refuses anything over MAX_COMMAND_CHARS before parsing, so cut the
    # input to just under it, or the parser is never timed at all.
    cap = launch_gate.MAX_COMMAND_CHARS - 1
    out.append(("launch_gate.check", lambda s: launch_gate.check(s[:cap], {}), None))
    out.append(("launch_gate.check with ssh_hosts",
                lambda s: launch_gate.check(s[:cap], {"launch_gate": {"ssh_hosts": ["h"]}}), None))
    for glob in GLOBS:
        out.append((f"reader_gate glob match {glob!r}", _glob_match(glob), None))
    return out, len(found)


def plan() -> tuple[list, int]:
    """[(check, function, input label, input maker)] in a fixed order, and the
    number of patterns."""
    timed, patterns = checks()
    out = []
    for name, fn, p in timed:
        for label, s in fixed_inputs():
            out.append((name, fn, label, (lambda s=s: s)))
        if p is not None:
            for label, make in pattern_inputs(p):
                out.append((name, fn, label, make))
    return out, patterns


CHILD = r'''
import hashlib, json, sys, time
sys.path.insert(0, sys.argv[1])
import test_regex_linear_time as meta
start, shard, shards = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
runs, patterns = meta.plan()
digest = hashlib.sha256(json.dumps([(name, label) for name, _, label, _ in runs]).encode()).hexdigest()
mine = [k for k in range(len(runs)) if k % shards == shard]
print(json.dumps({"total": len(mine), "patterns": patterns, "plan": digest}), flush=True)
for k in mine:
    if k < start:
        continue
    name, fn, label, make = runs[k]
    print(json.dumps({"start": k, "name": name, "input": label}), flush=True)
    s = make()
    t = time.process_time()
    out = fn(s)
    if hasattr(out, "__next__"):
        for _ in out:
            pass
    print(json.dumps({"done": k, "secs": time.process_time() - t}), flush=True)
print(json.dumps({"end": True}), flush=True)
'''

# Runs one plan item alone and prints its CPU seconds; used to re-check a check
# the parent killed on wall-clock, which under load may have only been starved.
ONE = r'''
import sys, time
sys.path.insert(0, sys.argv[1])
import test_regex_linear_time as meta
runs, _ = meta.plan()
name, fn, label, make = runs[int(sys.argv[2])]
s = make()
t = time.process_time()
out = fn(s)
if hasattr(out, "__next__"):
    for _ in out:
        pass
print(time.process_time() - t, flush=True)
'''


def _reader(proc, q):
    for line in proc.stdout:
        q.put(line)
    q.put(None)


def _run_shard(shard: int) -> dict:
    """Runs one shard's share of the plan, restarting after each kill. `slow`
    holds checks that finished but burned more than BUDGET of CPU (a real
    signal, immune to descheduling). `killed` holds (index, label) for checks
    the parent killed on wall-clock -- re-checked alone by _confirm, since a
    loaded machine can starve even a linear check past the wall deadline."""
    slow, killed, errors, ran, start, total, patterns, plans = [], [], [], 0, 0, None, 0, set()
    env = dict(os.environ, PYTHONHASHSEED="0")
    while True:
        with tempfile.TemporaryFile("w+") as err:
            proc = subprocess.Popen([sys.executable, "-c", CHILD, str(TESTS), str(start), str(shard), str(SHARDS)],
                                    stdout=subprocess.PIPE, stderr=err, text=True, env=env)
            q: queue.Queue = queue.Queue()
            threading.Thread(target=_reader, args=(proc, q), daemon=True).start()
            current, timeout, finished = None, STARTUP, False
            try:
                while True:
                    try:
                        line = q.get(timeout=timeout)
                    except queue.Empty:
                        proc.kill()
                        if current is None:
                            errors.append(f"shard {shard}: the child stalled before its first check")
                            finished = True
                        else:
                            killed.append((current["start"], f"{current['name']} on {current['input']}"))
                            start = current["start"] + 1
                        break
                    if line is None:
                        code = proc.wait()
                        if code != 0:
                            err.seek(0)
                            errors.append(f"shard {shard}: exit {code}: {err.read()[-2000:]}")
                        finished = True
                        break
                    msg = json.loads(line)
                    if "total" in msg:
                        total, patterns = msg["total"], msg["patterns"]
                        plans.add(msg["plan"])
                    elif "start" in msg:
                        current, timeout = msg, KILL
                    elif "done" in msg:
                        ran += 1
                        if msg["secs"] > BUDGET:
                            slow.append(f"{current['name']} on {current['input']}: {msg['secs']:.2f} s CPU")
                    elif msg.get("end"):
                        timeout = STARTUP
            finally:
                proc.kill()
                proc.wait()
                proc.stdout.close()
        if finished:
            return {"slow": slow, "killed": killed, "errors": errors, "ran": ran, "total": total,
                    "patterns": patterns, "plans": plans}


def _confirm(items) -> list:
    """Re-run each killed (index, label) alone with a generous wall deadline.
    Catastrophic backtracking still overruns CONFIRM_WALL or burns > BUDGET of
    CPU; a check the first run only starved finishes in milliseconds now and is
    dropped. Returns the labels that are still too slow."""
    env = dict(os.environ, PYTHONHASHSEED="0")
    still = []
    for k, label in items:
        try:
            r = subprocess.run([sys.executable, "-c", ONE, str(TESTS), str(k)],
                               capture_output=True, text=True, timeout=CONFIRM_WALL, env=env)
        except subprocess.TimeoutExpired:
            still.append(f"{label}: still running after {CONFIRM_WALL:.0f} s alone (killed)")
            continue
        if r.returncode != 0:
            still.append(f"{label}: retry failed: {(r.stderr or '').strip()[-300:]}")
            continue
        try:
            secs = float(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            still.append(f"{label}: retry produced no timing")
            continue
        if secs > BUDGET:
            still.append(f"{label}: {secs:.2f} s CPU alone")
    return still


class LinearRegexes(unittest.TestCase):
    maxDiff = None

    def test_every_pattern_and_check_is_linear_on_hostile_input(self):
        with ThreadPoolExecutor(SHARDS) as pool:
            shards = list(pool.map(_run_shard, range(SHARDS)))
        self.assertEqual([e for s in shards for e in s["errors"]], [])
        self.assertEqual(len({p for s in shards for p in s["plans"]}), 1)
        for s in shards:
            self.assertEqual(s["ran"] + len(s["killed"]), s["total"])
        # Checks that burned > BUDGET of CPU are real; checks the parent killed
        # on wall-clock are re-run alone and only count if they are still slow.
        slow = sorted(x for s in shards for x in s["slow"])
        confirmed = _confirm([item for s in shards for item in s["killed"]])
        self.assertEqual(slow + confirmed, [])
        # Discovered, so the count only grows; this floor catches a discovery
        # that silently stops finding them.
        self.assertGreaterEqual(shards[0]["patterns"], 18)


class StaticLint(unittest.TestCase):
    maxDiff = None
    # Known quadratic shapes, and rewrites with the same meaning that are safe.
    BAD = (r"\s*,?\s*[\]})]", r"<\s*/?\s*untrusted\b", r"(\s+)+x", r"(?:\s*x?)+y", r"a\s*(?:\s+x)?",
           r"a\s*(?=\s*x)", r"(\w+\s?)*$", r".*\b.*x", r"x\s*(?:(?!y).)*z", r"\s*()\1\s*x",
           r"x\s*(?:(?<!y).)*z", r"[丁-丅]*[七-三]*x", r"(?a)[\wé]*\b[\wé]*x",
           rb"\s*,?\s*x") + ((r"\s*\s*+x", r"\s*(?>\s*)x") if sys.version_info >= (3, 11) else ())
    GOOD = (r"\s*(?:,\s*)?[\]})]", r"<\s*(?:/\s*)?untrusted\b", r"a\s*,\s*b", r"(?:x\s*)+", r"\w+\b\w+",
            r"^(?:\w+\s+)*x", r"x\s*\S+", r"[丁-丂]*[七-三]*x")

    def test_the_lint_flags_known_shapes_and_passes_their_fixes(self):
        for bad in self.BAD:
            with self.subTest(bad=bad):
                self.assertTrue(lint(re.compile(bad)))
        for good in self.GOOD:
            with self.subTest(good=good):
                self.assertEqual(lint(re.compile(good)), [])

    def test_no_pattern_has_repeats_that_trade_characters(self):
        problems = []
        for name, p, _ in discover():
            if _digest(p.pattern) not in LINT_OK:
                problems += [f"{name} [{_digest(p.pattern)}]: {f}" for f in lint(p)]
        self.assertEqual(problems, [])

    def test_every_lint_exception_is_still_needed(self):
        flagged = {_digest(p.pattern) for _, p, _ in discover() if lint(p)}
        self.assertEqual(sorted(set(LINT_OK) - flagged), [])


class NoUnreviewedBuiltPatterns(unittest.TestCase):
    """A pattern built from data inside a function escapes both tests."""

    maxDiff = None

    def test_every_built_pattern_is_listed_with_its_reason(self):
        _, built = source_calls()
        unknown = [f"{rel}:{line} {scope} [{d}]: {text[:120]}" for rel, scope, d, text, line in built
                   if (rel, scope, d) not in DYNAMIC_OK]
        self.assertEqual(unknown, [])

    def test_every_listed_built_pattern_still_exists(self):
        _, built = source_calls()
        self.assertEqual(sorted(set(DYNAMIC_OK) - {(rel, scope, d) for rel, scope, d, _, _ in built}), [])

    def test_every_way_past_the_scan_is_reported(self):
        sources = {
            "from re import": "from re import compile\n",
            "an alias of re": "import re as rx\ndef f(x):\n    return rx.sub(x, '', 's')\n",
            "a name bound to re": "import re\nrx = re\ndef f(x):\n    return rx.search(x, 's')\n",
            "getattr on re": "import re\ndef f():\n    return getattr(re, 'sub')\n",
            "re.sub as a value": "import functools, re\ndef f(p):\n    return functools.partial(re.sub, p)\n",
            "a pattern keyword": "import re\ndef f(x):\n    return re.compile(pattern=x)\n",
            "an unreachable module compile": "import re\nA = 'a'\n_IS = re.compile(A + 'b').fullmatch\n",
        }
        for why, src in sources.items():
            with self.subTest(why):
                literal, built = _calls_in("x.py", src)
                self.assertEqual(len(built), 1, (literal, built))
        for src in ("import re\nA = 'a'\nX = re.compile(A + 'b')\n", "import re\nXS = [re.compile('a' + 'b')]\n",
                    "import re\ndef f(s):\n    return re.search(r'ab', s, flags=re.I)\n"):
            with self.subTest(src):
                self.assertEqual(_calls_in("x.py", src)[1], [])
        a = _calls_in("x.py", "import re\ndef f(w):\n    return re.compile(re.escape(w))\n")[1][0]
        b = _calls_in("x.py", "import re\ndef f(w):\n    return re.compile(w)\n")[1][0]
        self.assertEqual(a[:2], b[:2])
        self.assertNotEqual(a[2], b[2])

    def test_the_inline_patterns_are_found(self):
        literal, _ = source_calls()
        self.assertGreaterEqual(len(literal), 6)

    def test_discovery_reaches_every_module(self):
        found = discover()
        names = [name for name, _, _ in found]
        for prefix in ("reader_gate.", "launch_gate.", "reader_gate.py:", "launch_gate.py:"):
            with self.subTest(prefix=prefix):
                self.assertTrue(any(n.startswith(prefix) for n in names))


if __name__ == "__main__":
    unittest.main()
