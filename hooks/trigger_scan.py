"""trigger scan: the plugin's deterministic trigger inventory, as a pure core.

Fixed rules, so it can't be talked out of a finding. It reads text and returns
rule ids (and, for a file, line numbers), never the matched text. Two callers
use it:

- the scan skill's tree module (``skills/scan/scan.py``), which walks a
  folder you've put in quarantine and feeds each file and each file name here;
- a reader tripwire, which calls ``scan(report)`` on a reader's report
  and holds the report when an id outside ``COUNT_ONLY`` comes back.

It's a fresh port of an inventory script,
limited to the model-facing rules: tool-poisoning and injection text, hidden
text and markup, invisible and bidi characters, controls, plus the
download-and-run, Discord webhook and paste-site rules. Calls, encodings,
secret reads and install scripts are left for a later version.

It counts; it doesn't judge. No hit isn't a verdict that the text is safe:
paraphrase, other languages, encodings it doesn't decode and text built at run
time all get past it.

The contract:

- ``scan`` and ``scan_lines`` never raise. Bad input gives ``input-invalid``,
  text over the cap gives ``input-too-large`` (nothing is scanned), and any
  internal error gives ``scan-error``. A caller that holds on any id outside
  ``COUNT_ONLY`` fails closed.
- No I/O, no network, no environment reads, no clock: the caller owns the
  time limit, and must hold when a call raises anyway, times out or is killed.
- Standard library only (``re``), and no imports from the plugin, so a copy
  loads by fixed path with ``importlib`` and no ``sys.path`` change.

Speed: every pattern is bounded (no open-ended repeat that can trade
characters with its neighbour), and lines over 4,096 characters are matched in
4,096-character windows that overlap by 256, wider than any pattern's longest
match, so a window edge can't hide one. Whole-line rules (long lines, space
runs, the download and shell words) look at the whole line.
"""
from __future__ import annotations

import re

ENGINE_VERSION = "0.2.0-1"
RULE_ID_RE = r"[a-z][a-z0-9-]{1,31}"

DEFAULT_MAX_CHARS = 200_000
CHUNK = 4096            # characters matched at a time on a long line
OVERLAP = 256           # wider than any windowed pattern's longest match
LONG_LINE = 500         # characters
SPACE_RUN = 50          # space-like characters before more text
CONTINUATION_CAP = 65536
TAIL = 256              # characters of a line kept for the wrapped-prose window

_A = re.ASCII
_AI = re.ASCII | re.IGNORECASE

# --- Rules matched on the raw line and its decoded, comment-stripped and -------
# --- padding-collapsed copies ---------------------------------------------------

# Where an MCP tool, prompt or resource is defined, so its text gets read.
_MCP_TOOL = re.compile(
    r"@\s{0,16}(?:\w{1,64}\.){1,3}(?:tool|prompt|resource|call_tool|list_tools)\b"
    r"|(?<![\w.])@tool\b(?!\.)|\b(?:FastMCP|McpServer|MCPServer)\b"
    r"|\.(?:tool|registerTool|registerPrompt|registerResource)\s{0,16}\("
    r"|\b(?:ListTools|CallTool)RequestSchema\b|\btypes\.Tool\s{0,16}\("
    r"|\bTool\s{0,16}\(\s{0,16}name\s{0,16}="
    r"|\b(?:inputSchema|input_schema)\b[\"']?\s{0,16}[:=]|\bmcp\.NewTool\s{0,16}\("
    r"|\bWithDescription\s{0,16}\(|#\[tool\b|@Tool\s{0,16}\(|\[McpServerTool\b", _A)
# Credential and agent-config file names.
_SECRET_FILE = re.compile(
    r"(?<![\w-])(?:\.aws\b|\.azure\b|\.config/gcloud\b|application_default_credentials\.json\b"
    r"|\.vault-token\b|\.cargo/credentials\b|\.git-credentials\b|\.netrc\b|\.pgpass\b"
    r"|\.pypirc\b|\.docker/config\.json\b|\.kube/config\b|\.gnupg\b|\.config/gh\b"
    r"|\.?mcp\.json\b|claude_desktop_config\.json\b|\.claude\.json\b|\.?credentials\.json\b"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)\b|/etc/(?:shadow|passwd|sudoers)\b"
    r"|\.(?:bash|zsh)_history\b|Login Data\b|cookies\.sqlite\b|logins\.json\b|key4\.db\b"
    r"|\.keychain(?:-db)?\b)", _A)
# A Latin letter next to a Cyrillic letter or a Greek lookalike (one word, two
# scripts), fullwidth letters and digits, mathematical alphanumerics.
_CONFUSABLE = re.compile(
    r"[A-Za-z][\u0400-\u052f\u0391\u0392\u0395-\u0397\u0399\u039a\u039c\u039d\u039f\u03a1"
    r"\u03a4\u03a5\u03a7\u03b1\u03b9\u03ba\u03bd\u03bf\u03c1\u03c4\u03c5\u03c7]"
    r"|[\u0400-\u052f\u0391\u0392\u0395-\u0397\u0399\u039a\u039c\u039d\u039f\u03a1"
    r"\u03a4\u03a5\u03a7\u03b1\u03b9\u03ba\u03bd\u03bf\u03c1\u03c4\u03c5\u03c7][A-Za-z]"
    r"|[\uff10-\uff19\uff21-\uff3a\uff41-\uff5a]|[\U0001d400-\U0001d7ff]", _A)
_DATA_URI = re.compile(r"\bdata:(?:(?:text|application)/[\w.+-]{1,60}|image/svg\+xml)?[;,]", _AI)
# Printable ASCII written as an escape, a common way to hide the words above.
_ESCAPED_ASCII = re.compile(
    r"\\u00[2-7][0-9A-Fa-f]|\\u\{0{0,32}[2-7][0-9A-Fa-f]\}|\\x[2-7][0-9A-Fa-f]"
    r"|&#x0{0,32}[2-7][0-9A-Fa-f];|&#(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6]);", _A)
_DISCORD_WEBHOOK = re.compile(r"discord(?:app)?\.com/api/(?:v\d{1,4}/)?webhooks", _AI)
_PASTE_HOST = re.compile(
    r"\b(?:jsonkeeper|pastebin|hastebin|jsonsilo|npoint\.io|paste\.ee|ghostbin|rentry\.co"
    r"|dpaste|pastes\.io|controlc\.com)\b", _AI)
# The naming half of the original ai-addressed rule: model and agent names.
_AI_NAME = re.compile(
    r"\b(?:ai|coding|llm) (?:agents?|assistants?)\b|\bllms?\b|\bclaude\b|\bchatgpt\b|\bcopilot\b",
    _AI)

_RAW_RULES = (
    ("mcp-tool", _MCP_TOOL),
    ("secret-file", _SECRET_FILE),
    ("confusable-unicode", _CONFUSABLE),
    ("data-uri", _DATA_URI),
    ("escaped-ascii", _ESCAPED_ASCII),
    ("discord-webhook", _DISCORD_WEBHOOK),
    ("paste-host", _PASTE_HOST),
    ("ai-name", _AI_NAME),
)

# --- Rules matched on whitespace-collapsed copies ------------------------------
# Every run of whitespace (Unicode spaces too) is one space in these copies, so
# the patterns use one space between words and padding can't push words apart.

# Instruction-style text with no AI word: tool shadowing, hiding from the user,
# "the tool will not work", passing file contents or the conversation,
# precedence and override claims.
_AI_DIRECTIVE = re.compile(
    r"\b(?:before|prior to|after|instead of) (?:using|calling|invoking|running|executing"
    r"|you (?:use|call|invoke|run)) (?:this|the|that|any|other|each|every|another|a)\b"
    r"[^\n]{0,40}?\b(?:tools?|plugins?|skills?)\b"
    r"|\bwhen(?:ever)? (?:(?:the|this|a|any|another) (?:[\w./-]{1,40} )?tool is"
    r" (?:used|called|invoked|available)|(?:using|calling|invoking|you (?:use|call|invoke|run))"
    r" (?:the|this|any|another) (?:[\w./-]{1,40} )?tool)\b"
    r"|\b(?:do not|don'?t|never|must not|should not)\b[^\n]{0,30}?"
    r"\b(?:mention|tell|reveal|inform|notify|disclose|alert)\b[^\n]{0,60}?\busers?\b"
    r"|\bwithout (?:telling|informing|notifying|alerting|asking|warning) (?:the |your )?users?\b"
    r"|\b(?:hide|conceal)\b[^\n]{0,40}?\bfrom (?:the |your )?users?\b"
    r"|\busers? (?:must|should|need|needs) (?:not|never) (?:know|see|notice|be told)\b"
    r"|\b(?:the|this) tool will (?:not work|fail|break|crash)\b"
    r"|\b(?:pass|send|include|put|insert|embed|append|attach|forward|upload|post)\b[^\n]{0,20}?"
    r"\b(?:its|their|the file'?s?|the whole|the full|the entire|the raw|all) contents?\b"
    r"|\b(?:send|forward|upload|exfiltrate|leak|include|append)\b[^\n]{0,30}?"
    r"\b(?:conversation history|chat history|system prompt|previous messages|message history"
    r"|full context|entire conversation)\b"
    r"|\b(?:these|this|the following) (?:instructions?|rules?|notes?) (?:take|takes|have|has)"
    r" (?:precedence|priority)\b"
    r"|\b(?:override|overrides|supersede|supersedes) (?:all |any )?(?:other|previous|prior"
    r"|earlier|system|existing) (?:instructions|rules|tools?|prompts?)\b", _AI)
# Pseudo-markup aimed at a model.
_DIRECTIVE_TAG = re.compile(
    r"< ?(?:/ ?)?(?i:important|system|instructions?|critical|hidden|secret"
    r"|system[_ -]?(?:prompt|message|instructions?)|user[_ -]?instructions?) ?>"
    r"|\[/?INST\]|\[/?SYSTEM\]"
    r"|<\|(?:im_start|im_end|system|endoftext|eot_id|start_header_id|end_header_id)\|>"
    r"|<</?SYS>>", _A)
# The injection half of the original ai-addressed rule.
_AI_OVERRIDE = re.compile(
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|rules)"
    r"|\byou are (?:an? )?(?:ai|llm|assistant|agent|claude)\b|\bsystem prompt\b"
    r"|\bdeveloper message\b", _AI)

_PROSE_RULES = (
    ("ai-directive", _AI_DIRECTIVE),
    ("directive-tag", _DIRECTIVE_TAG),
    ("ai-override", _AI_OVERRIDE),
)

# --- Character rules ---------------------------------------------------------

# Invisible and bidi characters: zero-width, bidi controls, tag characters,
# variation selectors, BOM, soft hyphen and the rest of the original list.
_INVISIBLE = re.compile(
    r"[\u00ad\u115f\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u3164"
    r"\ufe00-\ufe0f\ufeff\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
# The original's extra list, outside the first.
_INVISIBLE_EXTRA = re.compile(
    r"[\u034f\u061c\u1160\u17b4\u17b5\u180b-\u180d\u180f\u2028\u2029\uffa0\ufff9-\ufffb]")
# C0 controls other than tab and line feed, DEL, and C1 controls: terminal escapes.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# Space-like characters: space, tab, NBSP, U+2000-200A, U+202F, U+205F, U+3000.
_SPACEU = re.compile(r"[ \t\u00a0\u2000-\u200a\u202f\u205f\u3000]")
_SPACES = re.compile(r"[ \t\n\r\f\v\u00a0\u2000-\u200a\u202f\u205f\u3000]+")
_NEEDS_COLLAPSE = re.compile(r"[\t\n\r\f\v\u00a0\u2000-\u200a\u202f\u205f\u3000]|  ")
_PLAIN_RUN = re.compile(r" {50,}")

# --- Download and run ----------------------------------------------------------
# A downloader word and a shell or interpreter word on one line, or across
# lines joined by a trailing \, | or &&. Each is searched for over the whole line.
_DOWNLOADER = re.compile(
    r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile"
    r"|DownloadData)\b|\bbase64\s{1,64}(?:-d|--decode)\b", _AI)
_SHELL = re.compile(
    r"\b(?:sh|bash|zsh|dash|ksh|fish|iex|Invoke-Expression|pwsh|powershell|python[23]?|node"
    r"|perl|ruby|php)\b", _AI)

# --- Hidden markup -------------------------------------------------------------
# HTML comments; link definitions whose target is # or <> or that carry a title
# (not footnotes or plain reference links); hidden or display:none tags (not
# aria-hidden). Matched on the raw line only: an escaped "<!--" renders visibly.
_HIDDEN_COMMENT = re.compile(
    r"<!--|^\s{0,3}\[(?!\^)[^\]\n]{1,100}\]:\s{0,16}(?:#|<>|\S{1,500}\s{1,16}[\"'(])"
    r"|<[A-Za-z][^>]{0,200}?(?<![\w-])(?:hidden\b|display\s{0,8}:\s{0,8}none)", _A)
# Agent instruction files, where an HTML comment is text the agent reads and a
# rendered view hides. Each name may carry a .quarantined suffix.
_INSTRUCTION_PATH = re.compile(
    r"(?:^|/)(?:SKILL|CLAUDE|CLAUDE\.local|AGENTS|GEMINI|copilot-instructions)\.md"
    r"(?:\.quarantined)?\Z"
    r"|\.(?:instructions|prompt)\.md(?:\.quarantined)?\Z"
    r"|(?:^|/)\.(?:cursorrules|windsurfrules|clinerules)(?:\.quarantined)?\Z"
    r"|(?:^|/)\.(?:agents|claude|cursor|windsurf|continue|codex|gemini|opencode)"
    r"(?:\.quarantined)?/(?:[^/\n]{1,255}/){0,32}[^/\n]{0,255}\.(?:md|mdc|markdown|txt)"
    r"(?:\.quarantined)?\Z", _AI)
# In a plugin: the files Claude Code loads as instructions.
_PLUGIN_INSTRUCTION_PATH = re.compile(
    r"(?:^|/)(?:agents|commands|skills|output-styles)/(?:[^/\n]{1,255}/){0,32}[^/\n]{0,255}"
    r"\.md(?:\.quarantined)?\Z|(?:^|/)\.claude-plugin/", _AI)
_PROSE_FILE = re.compile(r"\.(?:md|mdc|markdown|txt)(?:\.quarantined)?\Z", _AI)
_JS_FILE = re.compile(r"\.(?:[mc]?[jt]sx?)(?:\.quarantined)?\Z", _AI)

# --- Copies of a line ------------------------------------------------------------

_NEEDS_DECODE = re.compile(r"\\[uUx0-7]|&#|[\"'`]\s{0,16}\+\s{0,16}[\"'`]|[\"']\s{0,16}[\"']")
_DEC_U_BRACE = re.compile(r"\\u\{([0-9A-Fa-f]{1,6})\}")
_DEC_U8 = re.compile(r"\\U([0-9A-Fa-f]{8})")
_DEC_U4 = re.compile(r"\\u([0-9A-Fa-f]{4})")
# A run of \\x and octal escapes is bytes, decoded together as UTF-8, so
# "\\xe2\\x80\\x8b" is one zero-width space (bytes that aren't UTF-8 stay
# undecoded, as lone surrogates no rule matches). Runs are joined in Python
# from single matches: a repeated group in the pattern keeps state for every
# repeat, hundreds of MB on one long run.
_DEC_BYTE = re.compile(r"\\x([0-9A-Fa-f]{2})|\\([0-3][0-7]{2})")
_DEC_HEX_ENT = re.compile(r"&#x([0-9A-Fa-f]{1,6});")
_DEC_DEC_ENT = re.compile(r"&#([0-9]{1,7});")
_DEC_PLUS = re.compile(r"[\"'`]\s{0,16}\+\s{0,16}[\"'`]")   # 'a'+"b"
_DEC_ADJACENT = re.compile(r"([\"'])\s{0,16}\1")             # "a" "b", cu""rl

_NEEDS_PROSE = re.compile(r"[*_`~\\&\x00-\x08\x0a-\x1f\u0080-\U0010ffff]")
_PROSE_ESCAPES = re.compile(r"\\[ntrfv]|&nbsp;|&#160;|&#xa0;|[\x00-\x08\x0a-\x1f]", _AI)
_PROSE_MARKS = re.compile(r"[*_`~]+")
_HEAD_QUOTE = re.compile(r"\A\s{0,16}[+,]?\s{0,16}[\"'`]")
_TAIL_QUOTE = re.compile(r"[\"'`]\s{0,16}[+,\\]?\s{0,16}\Z")

# The wrapped-prose window: a line can end an ai-directive match begun on the
# lines before it only if it holds one of the rule's last words.
_WINDOW_CROSS = re.compile(
    r"\b(?:tools?|plugins?|skills?|used|called|invoked|available|users?|know|see|notice|told"
    r"|work|fail|break|crash|contents?|history|prompts?|messages|context|conversation"
    r"|precedence|priority|instructions|rules)\b", _AI)
# A trailing // or # comment, dropped from a code line's tail.
_TAIL_COMMENT_JS = re.compile(r"(?:\A|\s)(?://|#(?=\s|\Z))")
_TAIL_COMMENT_ANY = re.compile(r"(?:\A|\s)(?://|#)")

# --- The ids ---------------------------------------------------------------------

_LINE_IDS = tuple(i for i, _ in _RAW_RULES) + tuple(i for i, _ in _PROSE_RULES) + (
    "hidden-comment", "invisible-unicode", "invisible-extra", "control-char",
    "space-run-then-code", "long-line-500", "download-to-shell", "continuation-cap")
_META_IDS = ("input-too-large", "input-invalid", "scan-error")
RULE_IDS = frozenset(_LINE_IDS + _META_IDS)
# Ids an ordinary reader's report trips (it names Claude, MCP code, credential
# file names and escapes, and has long lines): counted, but not a reason to hold
# a report. Every other id holds, so a rule added later holds until it's moved here.
COUNT_ONLY = frozenset({"ai-name", "mcp-tool", "secret-file", "escaped-ascii", "long-line-500"})


# --- Helpers ---------------------------------------------------------------------

def _char(code: int) -> str:
    return chr(code) if 0 <= code <= 0x10FFFF else ""


def _decode_bytes(s: str) -> str:
    """s with each run of adjacent \\x and octal escapes decoded as UTF-8."""
    out, run, pos = [], bytearray(), 0
    for e in _DEC_BYTE.finditer(s):
        if run and e.start() != pos:
            out.append(run.decode("utf-8", "surrogateescape"))
            run = bytearray()
        if not run:
            out.append(s[pos:e.start()])
        h = e.group(1)
        run.append(int(h, 16) if h else int(e.group(2), 8))
        pos = e.end()
    if run:
        out.append(run.decode("utf-8", "surrogateescape"))
    out.append(s[pos:])
    return "".join(out)


def _decoded(s: str):
    """The line with \\u, \\u{}, \\U, \\x and octal escapes and HTML entities
    expanded and joined string literals closed up, or None if that changes nothing."""
    if not _NEEDS_DECODE.search(s):
        return None
    n = _DEC_U_BRACE.sub(lambda m: _char(int(m.group(1), 16)), s)
    n = _DEC_U8.sub(lambda m: _char(int(m.group(1), 16)), n)
    n = _DEC_U4.sub(lambda m: _char(int(m.group(1), 16)), n)
    n = _decode_bytes(n)
    n = _DEC_HEX_ENT.sub(lambda m: _char(int(m.group(1), 16)), n)
    n = _DEC_DEC_ENT.sub(lambda m: _char(int(m.group(1))), n)
    n = _DEC_PLUS.sub("", n)
    n = _DEC_ADJACENT.sub("", n)
    return None if n == s else n


def _prose(s: str):
    """A copy for prose rules, or None if it's the same: Unicode spaces, literal
    \\n \\t \\r \\f \\v escapes, &nbsp; and controls become spaces, and Markdown
    emphasis and code marks (* _ ` ~) go."""
    if not _NEEDS_PROSE.search(s):
        return None
    n = _SPACEU.sub(" ", s)
    n = _PROSE_ESCAPES.sub(" ", n)
    n = _PROSE_MARKS.sub("", n)
    return None if n == s else n


def _collapse(s: str) -> str:
    return _SPACES.sub(" ", s) if _NEEDS_COLLAPSE.search(s) else s


def _collapse_inner(s: str):
    """The line with whitespace runs after its indent made one space, or None
    if that changes nothing: padding can't push a raw rule's parts apart, and
    the indent stays for rules anchored at the line start."""
    body = s.lstrip()
    lead = s[:len(s) - len(body)]
    c = _collapse(body)
    return None if c == body else lead + c


def _strip_comments(s: str):
    """The line with /* ... */ comments made one space each, or None if it has
    none (linear: each close is searched once; an unclosed one stops it)."""
    out, pos = [], 0
    while True:
        start = s.find("/*", pos)
        if start < 0:
            break
        close = s.find("*/", start + 2)
        if close < 0:
            break
        out.append(s[pos:start])
        out.append(" ")
        pos = close + 2
    return "".join(out) + s[pos:] if pos else None


def _search(rx, s: str) -> bool:
    """rx anywhere in s; a long line in overlapping windows. search() with a
    start and end, not a slice, so ^ and lookbehinds see the real line."""
    n = len(s)
    if n <= CHUNK:
        return rx.search(s) is not None
    start = 0
    while True:
        end = min(start + CHUNK, n)
        m = rx.search(s, start, end)
        # A match that touches a window's end may owe its \b or (?!...) to the
        # cut; it starts within OVERLAP of the end, so the next window has it.
        if m is not None and (end >= n or m.end() < end):
            return True
        if end >= n:
            return False
        start = end - OVERLAP


def _ends_continued(line: str) -> bool:
    body = line.rstrip(" \t\x0b\x0c\r")
    return body.endswith(("\\", "|", "&&"))


class _File:
    """Per-text state: the wrapped-prose window and the continued command."""

    __slots__ = ("mode", "hidden", "window", "cont_len", "cont_dl", "cont_sh")

    def __init__(self, path, plugin: bool, report: bool) -> None:
        if report or path is None:
            self.mode, self.hidden = "text", report
        else:
            agent_file = bool(_INSTRUCTION_PATH.search(path)) or (
                plugin and bool(_PLUGIN_INSTRUCTION_PATH.search(path)))
            self.hidden = agent_file
            if agent_file or _PROSE_FILE.search(path):
                self.mode = "text"
            elif _JS_FILE.search(path):
                self.mode = "js"
            else:
                self.mode = "code"
        self.window: list = []      # up to two (tail as is, tail with a trailing comment dropped)
        self.cont_len = None        # length of the continued command so far, or None
        self.cont_dl = self.cont_sh = False


def _prose_copies(line: str, dec, cmt) -> list:
    copies = []
    for c in (line, dec, cmt):
        if c is None:
            continue
        for v in (c, _prose(c)):
            if v is not None:
                v = _collapse(v)
                if v not in copies:
                    copies.append(v)
    return copies


def _window_hit(st: _File, line: str) -> bool:
    """ai-directive on a join of the two lines before (their tails) and this
    line's head, counted only when a match crosses into this line."""
    hit = False
    head = line[:TAIL]
    head_prose = _HEAD_QUOTE.sub("", _prose(head) or head, count=1)
    cross_raw = bool(_WINDOW_CROSS.search(head))
    cross_prose = bool(_WINDOW_CROSS.search(head_prose))
    if not (st.window and (cross_raw or cross_prose)):
        return False
    tries = []
    for k in (0, 1):
        before = " ".join(t[k] for t in st.window)
        pairs = []
        if cross_raw:
            pairs.append((before, head))
        if cross_prose:
            pairs.append((_TAIL_QUOTE.sub("", _prose(before) or before, count=1), head_prose))
        for a, b in pairs:
            pair = (_collapse(a).rstrip(" "), _collapse(b).lstrip(" "))
            if pair not in tries:
                tries.append(pair)
    for a, b in tries:
        joined, bnd = a + " " + b, len(a) + 1
        # A crossing match starts within OVERLAP of the join: no pattern's
        # match is wider (a test checks).
        for m in _AI_DIRECTIVE.finditer(joined, max(0, bnd - OVERLAP)):
            if m.start() < bnd < m.end():
                return True
    return False


def _remember(st: _File, line: str) -> None:
    tail = line[-TAIL:]
    longer = line[-2 * TAIL:]
    m = (_TAIL_COMMENT_JS if st.mode == "js" else _TAIL_COMMENT_ANY).search(longer)
    stripped = longer[:m.start()] if (m and st.mode != "text") else longer
    st.window.append((tail, stripped[-TAIL:]))
    del st.window[:-2]


def _skipped_by_window(st: _File, line: str) -> bool:
    """Blank lines everywhere, and // or # comment lines in code (in JS-like
    files a # is a comment only before whitespace or the end)."""
    body = line.lstrip()
    if not body:
        return True
    if st.mode == "js":
        return body.startswith("//") or (body.startswith("#")
                                         and (len(body) == 1 or body[1].isspace()))
    if st.mode == "code":
        return body.startswith(("//", "#"))
    return False


def _line_ids(st: _File, line: str) -> set:
    found = set()
    dec = _decoded(line)
    cmt = _strip_comments(line)
    padded = _collapse_inner(line)
    copies = (line,) if dec is None else (line, dec)
    raw = tuple(c for c in (line, dec, cmt, padded) if c is not None)
    for rule_id, rx in _RAW_RULES:
        if any(_search(rx, c) for c in raw):
            found.add(rule_id)
    prose = _prose_copies(line, dec, cmt)
    for rule_id, rx in _PROSE_RULES:
        if any(_search(rx, c) for c in prose):
            found.add(rule_id)
    if st.hidden and any(_search(_HIDDEN_COMMENT, c) for c in (line, padded) if c is not None):
        found.add("hidden-comment")
    if any(_INVISIBLE.search(c) for c in copies):
        found.add("invisible-unicode")
    if any(_INVISIBLE_EXTRA.search(c) for c in copies):
        found.add("invisible-extra")
    if _CONTROL.search(line):
        found.add("control-char")
    if len(line) > LONG_LINE:
        found.add("long-line-500")
    spaced = _SPACEU.sub(" ", line)
    for m in _PLAIN_RUN.finditer(spaced):
        if m.end() < len(spaced):
            found.add("space-run-then-code")
            break
    # Download and run: the two words on one copy of the line, or on the
    # continued command this line ends.
    dl, sh = bool(_DOWNLOADER.search(line)), bool(_SHELL.search(line))
    if (dl and sh) or (dec is not None and _DOWNLOADER.search(dec) and _SHELL.search(dec)):
        found.add("download-to-shell")
    if st.cont_len is not None and (st.cont_dl or dl) and (st.cont_sh or sh):
        found.add("download-to-shell")
    if _ends_continued(line):
        total = (st.cont_len or 0) + 1 + len(line)
        if total > CONTINUATION_CAP:
            found.add("continuation-cap")
            st.cont_len, st.cont_dl, st.cont_sh = None, False, False
        else:
            st.cont_len, st.cont_dl, st.cont_sh = total, st.cont_dl or dl, st.cont_sh or sh
    else:
        st.cont_len, st.cont_dl, st.cont_sh = None, False, False
    # Prose wrapped over lines.
    if not _skipped_by_window(st, line):
        if "ai-directive" not in found and _window_hit(st, line):
            found.add("ai-directive")
        _remember(st, line)
    return found


def _lines(text: str) -> list:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()               # the final newline ends a line
    return [ln[:-1] if ln.endswith("\r") else ln for ln in lines]


def _scan_lines(text: str, path, plugin: bool, report: bool) -> list:
    st = _File(path, plugin, report)
    out = set()
    for n, line in enumerate(_lines(text), 1):
        for rule_id in _line_ids(st, line):
            out.add((rule_id, n))
    return sorted(out)


# --- The API ----------------------------------------------------------------------

def scan(text, max_chars: int = DEFAULT_MAX_CHARS) -> list:
    """The rule ids that hit anywhere in text, sorted and unique. For a
    reader's report: hidden markup counts on every line. Never raises."""
    try:
        if not isinstance(text, str) or not isinstance(max_chars, int) or isinstance(max_chars, bool):
            return ["input-invalid"]
        if len(text) > max_chars:
            return ["input-too-large"]
        return sorted({rule_id for rule_id, _ in _scan_lines(text, None, False, True)})
    except Exception:
        return ["scan-error"]


def scan_lines(text, path=None, *, plugin: bool = False) -> list:
    """(rule id, line) pairs for one file's text, lines numbered from 1 and
    split on "\\n" only, sorted. path is the file's path relative to the scan
    root; it only switches path-scoped rules on (hidden markup in agent
    instruction files, and with plugin=True in a plugin's agents, commands,
    skills and output styles), and is never scanned here. No size cap: the
    caller bounds the text. Never raises."""
    try:
        if not isinstance(text, str) or (path is not None and not isinstance(path, str)):
            return [("input-invalid", 0)]
        return _scan_lines(text, path, bool(plugin), False)
    except Exception:
        return [("scan-error", 0)]


def scan_name(name) -> list:
    """The rule ids that hit in a file or folder name (a path relative to the
    scan root): the text rules on the name as it is, plus the invisible-
    character check. Never raises."""
    try:
        if not isinstance(name, str):
            return ["input-invalid"]
        found = set()
        for rule_id, rx in _RAW_RULES:
            if _search(rx, name):
                found.add(rule_id)
        collapsed = _collapse(name)
        for rule_id, rx in _PROSE_RULES:
            if _search(rx, collapsed):
                found.add(rule_id)
        if _DOWNLOADER.search(name) and _SHELL.search(name):
            found.add("download-to-shell")
        if _INVISIBLE.search(name):
            found.add("invisible-unicode")
        return sorted(found)
    except Exception:
        return ["scan-error"]
