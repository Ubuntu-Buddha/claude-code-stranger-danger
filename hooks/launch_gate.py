#!/usr/bin/env python3
"""launch gate: a Claude Code PreToolUse hook for Bash and Monitor.

It blocks the shell commands that bring strangers' code onto the machine or
take the guardrails off:

- fetch-and-run launchers (``npx`` without ``--no``, ``npm exec``, ``pnpm dlx``,
  ``yarn dlx``, ``bunx``, ``uvx``, ``uv tool run``, ``uv run --with``, ``pipx run``,
  ``cargo install``, ``go install pkg@version``, ``gh extension install``,
  ``deno run https://...``);
- a download fed into an interpreter: piped into a shell or Python, passed
  through process substitution, or run through command substitution; or a
  file downloaded earlier in the same command and then run;
- encoded text decoded straight into an interpreter (``... | base64 -d | sh``);
- agent launches with the guardrails off (``claude --dangerously-skip-permissions``,
  ``codex --yolo``, ``gemini --yolo``);
- a session forged open (``claude --resume``/``--continue`` with ``-p``/``--print``),
  which writes a turn into an existing session as if the owner had typed it;
- privilege escalation (``sudo``, ``su``, ``doas``, ``pkexec``, ``run0``);
- ``ssh``/``scp``/``sftp`` beyond plain remote access. A sandbox config often
  excludes them so agents can reach your servers with your keys, and an
  excluded command runs outside the sandbox. So the gate refuses options that
  run a local command or load a library (``-o ProxyCommand``, ``LocalCommand``,
  ``KnownHostsCommand``, ``-F <file>``, ``-I``, ``scp -S``/``-D``), port
  forwarding and tunnels, log and known-hosts files outside the sandbox,
  ``SendEnv``, and ``sftp`` (its batch input runs ``!commands`` locally). At
  the top level the command must be the whole call, with no pipe, ``;``,
  ``$(...)``, wrapper, assignment or file redirect. When ``launch_gate.ssh_hosts``
  is set, only the hosts listed there can be reached. Text that names ssh, scp
  or sftp and has a second line, ``<<``, ``$((`` or ``$[``, or doesn't parse,
  is refused, since the parser could be misled about what runs beside them.

Monitor commands get the same checks: Monitor runs its command in the same
shell as Bash, under Bash's permission rules and sandbox. A Monitor input
field the gate doesn't know, or a WebSocket watch (``ws``), is refused.

THIS IS A TRIPWIRE, NOT A SANDBOX. It reads the command text the model wrote.
A model that is determined to hide what it runs can: build names at run time
(``$(printf 'n%sx' p)``, ``${X:0:3}``), use variables or functions defined
outside this command, put the launcher inside a script, a Makefile, a
package.json script or code passed to ``python -c``, write a script with the
Write tool and run it in a later call, or split download and run across two
tool calls (each call is checked on its own). The real controls for Bash are
Claude Code's sandbox and your permission rules; this gate catches the
obvious and the injected cases early, with a message that says what to do
instead.

Decisions: a deny prints one line to stderr and exits 2 (Claude Code blocks
the call and shows the reason to the model). A pass exits 0 with no output,
so the normal permission rules and the auto-mode classifier still apply.
Errors fail closed: bad input, a config problem, any exception, or running
past TIMEOUT_SECONDS exits 2.

Config, in ~/.config/stranger-danger/config.json: ``launch_gate.allow`` is a
list of exact command prefixes that pass the launcher, privilege and
agent-launch checks, for example ``[["npx", "prettier"]]`` (it never relaxes
the ssh checks). ``launch_gate.ssh_hosts`` is a list of the hosts (as you type
them: a ~/.ssh/config alias or a host name) that ssh and scp may reach,
including jump hosts. Standard library only; run with ``python3 -I``.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import signal
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _config import ConfigError, load_config  # noqa: E402
from _log import log_deny  # noqa: E402

TIMEOUT_SECONDS = 3
MAX_COMMAND_CHARS = 100_000
MAX_DEPTH = 4
# Bash brace-expands a word before it runs (`{npx,cowsay}` is `npx cowsay`), so
# the gate expands it too, up to these limits.
MAX_BRACE_WORDS = 1024      # from one word
MAX_BRACE_TOTAL = 4096      # from all the words in one text
MAX_BRACE_CHARS = 1024      # the longest word it expands
MAX_BRACE_WORK = 200_000    # characters it scans while expanding, per check
# What's left of MAX_BRACE_WORK for the check running now (one hook call
# checks one command at a time).
_BRACE_BUDGET = [MAX_BRACE_WORK]
MAX_INPUT_BYTES = 4_000_000

PRIVILEGE = frozenset({"sudo", "su", "doas", "pkexec", "run0"})
DOWNLOADERS = frozenset({
    "curl", "wget", "wget2", "fetch", "iwr", "irm", "invoke-webrequest",
    "invoke-restmethod", "nc", "ncat", "netcat", "socat", "http", "https", "xh",
})
DECODERS = frozenset({
    "base64", "base32", "basenc", "xxd", "openssl", "gzip", "gunzip", "zcat",
    "bzip2", "bunzip2", "bzcat", "xz", "unxz", "xzcat", "zstd", "unzstd",
    "zstdcat", "rev", "uudecode",
})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash",
                    "fish", "csh", "tcsh"})
OTHER_INTERPRETERS = frozenset({"node", "nodejs", "perl", "ruby", "php", "pwsh",
                                "powershell", "pwsh.exe", "powershell.exe",
                                "iex", "invoke-expression", "source", "."})
RESERVED_WORDS = frozenset({"{", "}", "!", "if", "then", "else", "elif", "fi",
                            "do", "done", "while", "until", "time", "coproc"})
# Names that, produced by a command substitution in command position, mean
# the substitution is hiding a blocked command.
HIDDEN_NAME_TRIGGERS = frozenset({"npx", "pnpx", "bunx", "uvx", "pipx"}) | PRIVILEGE | DOWNLOADERS
SSH_FAMILY = frozenset({"ssh", "scp", "sftp"})
# The parser can be misled: an unparseable tail, `$(( $(cmd) ))`, or a fake
# heredoc such as `${x#<<E}` can hide a second command beside ssh, which then
# runs outside the sandbox with it. So text that names the ssh family anywhere
# (raw, or with quotes and backslashes taken out) is refused when it has one of
# these shapes or a second line, instead of trusting the parse.
_SSH_NAME_RE = re.compile(r"(?<![\w.-])(?:ssh|scp|sftp)(?![\w-])")
_TRICKY_RE = re.compile(r"\$\(\(|\$\[|<<")
# A $'...' escape that can spell a letter: \x73, s, \U00000073, \163, \cX.
_ANSI_LETTER_RE = re.compile(r"\\(?:[xuU0-7]|c)")
# Monitor runs its command in the same shell as Bash, under Bash's permission
# rules and sandbox, so the gate checks it the same way.
SHELL_TOOLS = frozenset({"Bash", "Monitor"})
# Monitor's input fields as Claude Code sends them. Any other field fails
# closed, since a new one could change what runs or where.
MONITOR_FIELDS = frozenset({"command", "description", "timeout_ms", "allowed_domains", "ws"})
# Per-call network hosts are asked about (launch_gate.ask_for_domains, on by
# default), or refused when it's off; the gate never grants them. An ask is a
# request for a prompt, not a block: an allow rule, another hook or an SDK
# callback might approve it unseen (VERIFY row M2). The names go into the prompt, so
# each must fit a strict grammar: a host name of two or more labels whose last
# label is letters only (or punycode, xn--), so no numeric form such as
# 0x7f.0.0.1 passes as a name, or a public IPv4 address, either with an
# optional port. ASCII only.
# No wildcards, no internal names or addresses. Only characters a host name can
# hold reach the prompt, though a host name can still be made of words.
MAX_DOMAINS = 10
MAX_DOMAIN_TEXT = 300      # all the names together, as the prompt shows them
_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(
    rf"(?P<name>(?:{_HOST_LABEL}\.)+(?:[A-Za-z]{{2,63}}|xn--[A-Za-z0-9-]{{1,59}})"
    r"|(?P<ip>(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))"
    r"(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}))?", re.ASCII)
# Names that reach this machine or its own network whatever DNS says.
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
# Permission modes where Claude Code shows a hook's "ask" as a prompt. In any
# other mode, or when the event doesn't say, the call is refused instead.
ASK_MODES = frozenset({"default", "acceptEdits", "plan", "auto"})
# A file descriptor before a redirect: `2>` or bash's `{name}>`, which stores
# the new descriptor in a variable. Neither is a command word.
_FD_WORD_RE = re.compile(r"\d+|\{[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\}")
# Downloader and network-client names as words, and bash's network paths, for
# the Monitor feed scan. `http`/`https` are left to the parse: URLs hold them.
_FEED_NAME_RE = re.compile(r"(?<![\w.-])(?:curl|wget2?|fetch|iwr|irm|invoke-webrequest|"
                           r"invoke-restmethod|nc(?:\.openbsd|\.traditional)?|ncat|netcat|socat|xh|"
                           r"telnet|aria2c|lftp|lynx|w3m)(?![\w.-])|/dev/(?:tcp|udp)/",
                           re.IGNORECASE)
# Flags that take a value (OpenSSH 9.x).
_SSH_VALUE_FLAGS = {"ssh": frozenset("BbcDEeFIiJLlmOoPpQRSWw"),
                    "scp": frozenset("cDFiJloPSX")}
_SSH_DENY_FLAGS = {
    "ssh": {"D": "opens a SOCKS proxy", "L": "forwards a port", "R": "forwards a port",
            "W": "forwards its input and output to another host", "w": "opens a tunnel",
            "E": "writes a log file outside the sandbox", "I": "loads a PKCS#11 library",
            "O": "sends a control command to a shared connection",
            "M": "starts a shared connection that outlives the call",
            "S": "uses a shared-connection socket"},
    "scp": {"S": "runs a program of the command's choosing",
            "D": "runs a local SFTP server program"},
}
# -o options (case-insensitive) that run or load something locally, forward
# ports, or move local data or the connection somewhere else.
_SSH_DENY_OPTIONS = {
    "proxycommand": "runs a local command", "localcommand": "runs a local command",
    "permitlocalcommand": "lets it run a local command",
    "knownhostscommand": "runs a local command", "match": "can run a local command",
    "pkcs11provider": "loads a library", "securitykeyprovider": "loads a library",
    "xauthlocation": "runs a local program",
    "controlmaster": "starts a shared connection that outlives the call",
    "controlpersist": "keeps a shared connection running after the call",
    "controlpath": "uses a shared-connection socket",
    "include": "reads another config file, which can run local commands",
    "hostname": "changes the host it connects to",
    "localforward": "forwards a port", "remoteforward": "forwards a port",
    "dynamicforward": "opens a SOCKS proxy", "tunnel": "opens a tunnel",
    "tunneldevice": "opens a tunnel", "permitremoteopen": "opens forwarded connections",
    "sendenv": "sends local environment variables, which can hold secrets",
}
_SSH_FILE_OPTIONS = frozenset({"userknownhostsfile", "globalknownhostsfile"})

_PYTHON_RE = re.compile(r"(?:python|pypy)[0-9.]*")
_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_VAR_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_PLACEHOLDER_RE = re.compile(r"__sd([cp])(\d+)__")
_NO_FETCH_FLAGS = frozenset({"--no", "--no-install", "--yes=false", "--no-yes"})

_OPS = ("<<<", "&>>", "&&", "||", "|&", ";;", ";&", ">>", ">|", ">&", "<&", "<>",
        "&>", ";", "&", "|", "(", ")", "<", ">")
_REDIRS = frozenset({"<<<", "&>>", ">>", ">|", ">&", "<&", "<>", "&>", "<", ">"})
_PIPES = frozenset({"|", "|&"})
_OUTPUT_REDIRS = frozenset({">", ">>", ">|", "&>", "&>>"})


# -- reasons ---------------------------------------------------------------

# The plugin's readers, by the name after the plugin prefix. Any agent with
# one of these names gets no shell, whichever plugin or folder defines it.
READER_NAMES = frozenset({"web-researcher", "document-reader", "quarantine-reviewer"})


class _Reason(str):
    """A refusal message with a short code for the decision log. The code
    names the kind of refusal, never anything from the command."""
    code = "launch-other"


def _coded(code: str, text: str) -> str:
    reason = _Reason(text)
    reason.code = code
    return reason


def _r_launch(what: str) -> str:
    return _coded("launch-launcher", (f"launch gate (rule 1): `{what}` fetches and runs a package that isn't "
            "installed in this project. Run an installed binary by path "
            "(e.g. node_modules/.bin/<bin>) or with `npx --no <bin>`; add new tools "
            "as pinned dependencies through the 7-day lane, or ask the user."))


def _r_pipe(interp: str) -> str:
    return _coded("launch-download-pipe", (f"launch gate (rule 1): this feeds downloaded content into `{interp}`, "
            "which runs code nobody has read. Save it to a file, have it reviewed "
            "(quarantine-reviewer), and run strangers' code only in a disposable VM."))


def _r_decode(interp: str) -> str:
    return _coded("launch-decode-run", (f"launch gate (rule 1): this decodes hidden text and runs it with "
            f"`{interp}`. Write the command out in plain text instead."))


def _r_downloaded(path: str) -> str:
    return _coded("launch-download-run", (f"launch gate (rule 1): `{path}` is downloaded earlier in this command "
            "and then run. Review downloaded scripts first, and run strangers' code "
            "only in a disposable VM."))


def _r_priv(name: str) -> str:
    return _coded("launch-privilege", (f"launch gate (rule 6): `{name}` would give an agent root. Ask the user "
            "to run privileged commands in their own terminal."))


def _r_reader(agent: str) -> str:
    return _coded("launch-reader-shell", (f"launch gate (rule 3): {_printable(agent)} is a reader agent, and readers "
            "never run commands. Its tools are fixed in its definition; if it got a "
            "shell anyway, stop and tell the user (rule 7)."))


def _r_agent(name: str, flag: str) -> str:
    return _coded("launch-guardrails-off", (f"launch gate (rule 6): `{name} {flag}` starts an agent with its "
            "guardrails off. Start agents with their normal permission settings."))


def _r_forge(name: str) -> str:
    return _coded("launch-session-forge", (f"launch gate (owner input): `{name}` resumes or continues an existing "
            "session together with `-p`/`--print`, which writes a turn into that "
            "session as if the owner had typed it. Resume your own sessions "
            "interactively; start automated runs fresh, without --resume or --continue."))


def _r_hidden(word: str) -> str:
    return _coded("launch-hidden-command", (f"launch gate (rule 1): a command substitution in command position "
            f"produces `{word}` at run time, which hides what runs. Write the "
            "command out directly."))


_R_BRACE = _coded("launch-hidden-command", ("launch gate (rule 1): a brace expansion here "
            f"makes more than {MAX_BRACE_WORDS} words ({MAX_BRACE_TOTAL} in one call), or sits "
            f"in a word longer than {MAX_BRACE_CHARS} characters, too many to check what runs; "
            "blocked to be safe. "
            "Write the words out, or use a loop."))
_R_EMPTY_WORDS = _coded("launch-hidden-command", ("launch gate (rule 1): more than "
            "16 words at the start of this command are built at run time, and bash drops any "
            "that come out empty, so the gate can't tell which word runs; blocked to be safe. "
            "Write the command out directly."))
_R_SUBST_DOWNLOAD = _coded("launch-download-subst", ("launch gate (rule 1): this runs the output of a download as a "
                     "command. Save it, have it reviewed, and run strangers' code "
                     "only in a disposable VM."))
_R_DEPTH = _coded("launch-too-deep", (f"launch gate: the command nests shells or substitutions more than "
            f"{MAX_DEPTH} levels deep, too deep to check; blocked to be safe. "
            "Simplify it."))
_R_LONG = _coded("launch-too-long", (f"launch gate: the command is longer than {MAX_COMMAND_CHARS} characters, "
           "too long to check; blocked to be safe. Write long content with the "
           "Write tool."))


def _printable(text: str, limit: int = 100) -> str:
    return "".join(c if c.isprintable() else "?" for c in text[:limit])


def _r_ssh(name: str, what: str) -> str:
    return _coded("launch-ssh-option", (f"launch gate (ssh): `{name}` runs outside the sandbox, and {what}. Keep "
            "it to plain remote access: `ssh <host> '<command>'` or `scp`; ask the "
            "user if you need more."))


def _r_ssh_host(name: str, host: str) -> str:
    return _coded("launch-ssh-host", (f"launch gate (ssh): `{name}` would connect to `{_printable(host)}`, which "
            "isn't in launch_gate.ssh_hosts. Agents may reach only the hosts listed "
            "there; ask the user to add one."))


_R_SSH_ALONE = _coded("launch-ssh-alone", ("launch gate (ssh): ssh, scp and sftp run outside the sandbox, so each "
                "must be a whole call on its own: no pipe, `;` or `&&`, `$(...)`, "
                "wrapper or variable assignment, and no file redirect except /dev/null. "
                "Put filters in the remote command (`ssh host 'cmd | tail'`), use "
                "`-o ConnectTimeout=N` instead of `timeout`, and run local steps as a "
                "separate call."))
_R_SSH_TRICKY = _coded("launch-ssh-tricky", ("launch gate (ssh): this call names ssh, scp or "
                  "sftp (or has a $'...' string that could spell one) and has a second line, "
                  "a carriage return, `<<`, `$((` or `$[`, or doesn't parse, so the gate can't "
                  "tell what runs beside it outside the sandbox; blocked to be safe. Run ssh "
                  "as one line on its own: join remote commands with `;` inside the quoted "
                  "remote command, or write a script file with the Write tool, copy it with "
                  "scp and run it with ssh. To mention these names in a long text (a commit "
                  "message), write the text to a file with the Write tool first."))
_R_MONITOR_WS = _coded("launch-monitor-ws", ("launch gate (rule 3): a Monitor WebSocket watch "
                  "streams outside text into this agent, and only the web reader reads the "
                  "web. Ask the user, or watch a command's output instead."))
_R_DOMAINS = _coded("launch-domains", ("launch gate (network): this call asks for extra "
                  "network hosts (`allowed_domains`), which reach past your sandbox's network "
                  "allowlist for this one command. They're refused from a subagent, where "
                  "nobody can be asked (dontAsk or bypassPermissions mode, or a mode the gate "
                  "doesn't know), and when the user has set launch_gate.ask_for_domains to "
                  "false. Run it without them, or ask the user to add the host to "
                  "sandbox.network.allowedDomains themselves."))
_R_DOMAINS_BAD = _coded("launch-domains-host", ("launch gate (network): `allowed_domains` must "
                  f"be a list of at most {MAX_DOMAINS} host names, {MAX_DOMAIN_TEXT} characters "
                  "in all: a name of two or more labels or a public IPv4 address, each with an "
                  "optional :port, and no wildcards or local names. This one isn't, so it's "
                  "refused rather than shown in a prompt."))


def _domains_prompt(tool: str, hosts: list[str]) -> str:
    return ("launch gate (network): approve only if you expected this. The call reaches past "
            "your sandbox's network allowlist for this one command, and the gate can't tell "
            "whether a host is safe. To trust a host for good, add it yourself to "
            "sandbox.network.allowedDomains in your Claude Code settings; don't let an agent "
            f"do it for you. The {tool} call asks to reach these hosts: "
            + ", ".join(f"`{h}`" for h in hosts))


def _host_ok(host) -> bool:
    """Whether one allowed_domains entry may be shown in a prompt."""
    if not isinstance(host, str) or len(host) > 253:
        return False
    m = _DOMAIN_RE.fullmatch(host)
    if not m:
        return False
    if m.group("ip"):
        ip = ipaddress.ip_address(m.group("ip"))
        return ip.is_global and not ip.is_multicast
    name = m.group("name").lower()
    return name != "localhost" and not name.endswith(_LOCAL_SUFFIXES)


def _ask_for_domains(config: dict) -> bool:
    """launch_gate.ask_for_domains: ask about per-call hosts (the default) or,
    when false, refuse them."""
    section = config.get("launch_gate", {})
    if not isinstance(section, dict):
        raise ConfigError("'launch_gate' must be a JSON object")
    value = section.get("ask_for_domains", True)
    if not isinstance(value, bool):
        raise ConfigError("'launch_gate.ask_for_domains' must be true or false")
    return value


_R_MONITOR_HIDDEN = _coded("launch-monitor-feed", ("launch gate (rule 3): this Monitor watch "
            "has a command name built at run time (a variable, a glob or a $'...' escape), so "
            "the gate can't tell whether it streams outside text into this agent; blocked to "
            "be safe. Write the command name out."))


def _r_monitor_feed(name: str) -> str:
    return _coded("launch-monitor-feed", (f"launch gate (rule 3): `{_printable(name, 40)}` in a "
            "Monitor watch streams outside text into this agent for as long as it runs, and "
            "only the web reader reads the web. Ask the user, or have the web reader fetch "
            "what you need."))
_R_SFTP = _coded("launch-sftp",("launch gate (ssh): `sftp` runs outside the sandbox and runs local commands "
           "from its batch input (`!command`). Use `scp` to copy files, or "
           "`ssh <host> '<command>'`."))


def _r_ssh_expand(name: str, char: str) -> str:
    return _coded("launch-ssh-expand", (f"launch gate (ssh): `{name}` runs outside the sandbox, "
            f"and a word in this call holds `{char}`, which bash expands before {name} sees "
            "it, so the gate can't check the result. Write the arguments out plainly, and put "
            "anything for the remote side inside single quotes: `ssh host 'echo $HOME'`."))


def _r_marker(marker: str) -> str:
    return _coded("launch-marker", (f"launch gate: the command contains `{_printable(marker, 40)}`, which is the "
            "gate's own marker for a substitution, so it can't be checked; blocked to be "
            "safe. Rename it."))


def _r_parse(word: str) -> str:
    return _coded("launch-unparseable", (f"launch gate (rule 1): couldn't parse this command, and it mentions "
            f"`{word}`; blocked to be safe. Fix the quoting."))


def _r_config(err: str) -> str:
    return _coded("launch-config", (f"launch gate: config problem: {err}. Fix "
            "~/.config/stranger-danger/config.json; until then the gate blocks "
            "Bash and Monitor commands."))


# -- lexer -----------------------------------------------------------------

class _TooManyWords(Exception):
    """A brace expansion past MAX_BRACE_WORDS or MAX_BRACE_CHARS."""


class _Unparseable(Exception):
    pass


class _Ctx:
    """State shared across one check() call, including nested payloads."""

    def __init__(self, allow: list[list[str]], ssh_hosts: frozenset = frozenset()):
        self.allow = allow
        self.ssh_hosts = ssh_hosts   # empty: any host
        self.subs: list[tuple[str, str]] = []   # (kind, body); kind c=$(), p=<()
        self.vars: dict[str, str] = {}
        self.downloads: set[str] = set()

    def add_sub(self, kind: str, body: str) -> str:
        self.subs.append((kind, body))
        return f"__sd{kind}{len(self.subs) - 1}__"


def _paren_end(text: str, i: int) -> int:
    """Index of the ``)`` closing a group whose ``(`` ends just before i."""
    n, depth = len(text), 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                raise _Unparseable("unbalanced single quote")
            i = j + 1
            continue
        if c == '"':
            i = _skip_double(text, i + 1)
            continue
        if c == "`":
            _, i = _backtick(text, i + 1)
            continue
        if c == "#" and (i == 0 or text[i - 1] in " \t\n;&|("):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise _Unparseable("unbalanced parenthesis")


def _skip_double(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and i + 1 < n and text[i + 1] == "(":
            i = _paren_end(text, i + 2) + 1
            continue
        if c == "`":
            _, i = _backtick(text, i + 1)
            continue
        i += 1
    raise _Unparseable("unbalanced double quote")


def _backtick(text: str, i: int) -> tuple[str, int]:
    n, buf = len(text), []
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n and text[i + 1] in "`\\$":
            buf.append(text[i + 1])
            i += 2
            continue
        if c == "`":
            return "".join(buf), i + 1
        buf.append(c)
        i += 1
    raise _Unparseable("unbalanced backtick")


_ANSI_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
                "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\",
                "'": "'", '"': '"', "?": "?"}


def _ansi_c(text: str, i: int) -> tuple[str, int]:
    """Decode a $'...' string starting after the opening quote."""
    n, out = len(text), []
    while i < n:
        c = text[i]
        if c == "'":
            return "".join(out), i + 1
        if c == "\\" and i + 1 < n:
            e = text[i + 1]
            i += 2
            if e in _ANSI_SIMPLE:
                out.append(_ANSI_SIMPLE[e])
            elif e in "01234567":
                m = re.match(r"[0-7]{0,2}", text[i:i + 2])
                out.append(chr(int(e + m.group(), 8)))
                i += len(m.group())
            elif e in "xuU":
                width = {"x": 2, "u": 4, "U": 8}[e]
                m = re.match(r"[0-9A-Fa-f]{1,%d}" % width, text[i:i + width])
                if m:
                    cp = int(m.group(), 16)
                    out.append(chr(cp) if cp <= 0x10FFFF else chr(0xFFFD))
                    i += len(m.group())
                else:
                    out.append("\\" + e)
            elif e == "c" and i < n:
                out.append(chr(ord(text[i]) & 0x1F))
                i += 1
            else:
                out.append("\\" + e)
            continue
        out.append(c)
        i += 1
    raise _Unparseable("unbalanced $'...' quote")


def _squote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _double(text: str, i: int, ctx: _Ctx) -> tuple[str, int]:
    """Content of a "..." string (substitutions replaced), index after it."""
    n, buf = len(text), []
    while i < n:
        c = text[i]
        if c == "\\":
            buf.append(text[i:i + 2])
            i += 2
            continue
        if c == '"':
            return "".join(buf), i + 1
        if c == "$" and text.startswith("$((", i):
            i = _paren_end(text, i + 2) + 1
            buf.append("0")
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "(":
            j = _paren_end(text, i + 2)
            buf.append(ctx.add_sub("c", text[i + 2:j]))
            i = j + 1
            continue
        if c == "`":
            body, i = _backtick(text, i + 1)
            buf.append(ctx.add_sub("c", body))
            continue
        buf.append(c)
        i += 1
    raise _Unparseable("unbalanced double quote")


def _collect_subs(body: str, ctx: _Ctx) -> None:
    """Register the substitutions in an unquoted heredoc body (they run)."""
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\":
            i += 2
            continue
        if c == "$" and body.startswith("$((", i):
            i = _paren_end(body, i + 2) + 1
            continue
        if c == "$" and i + 1 < n and body[i + 1] == "(":
            j = _paren_end(body, i + 2)
            ctx.add_sub("c", body[i + 2:j])
            i = j + 1
            continue
        if c == "`":
            sub, i = _backtick(body, i + 1)
            ctx.add_sub("c", sub)
            continue
        i += 1


def _heredoc_spec(text: str, i: int) -> tuple[int, tuple[str, bool, bool, list]]:
    n, strip = len(text), False
    if i < n and text[i] == "-":
        strip, i = True, i + 1
    while i < n and text[i] in " \t":
        i += 1
    quoted, delim = False, []
    while i < n and text[i] not in " \t\n;&|<>()":
        ch = text[i]
        if ch in "'\"":
            quoted = True
            j = text.find(ch, i + 1)
            if j < 0:
                raise _Unparseable("unbalanced quote in heredoc delimiter")
            delim.append(text[i + 1:j])
            i = j + 1
        elif ch == "\\":
            quoted = True
            delim.append(text[i + 1:i + 2])
            i += 2
        else:
            delim.append(ch)
            i += 1
    d = "".join(delim)
    if not d:
        raise _Unparseable("heredoc without a delimiter")
    return i, (d, strip, quoted, [None])


def _read_heredocs(text: str, i: int, pending: list, ctx: _Ctx) -> int:
    n = len(text)
    for delim, strip, quoted, holder in pending:
        lines = []
        while i < n:
            j = text.find("\n", i)
            end = n if j < 0 else j
            line = text[i:end]
            i = n if j < 0 else j + 1
            if (line.lstrip("\t") if strip else line) == delim:
                break
            lines.append(line)
        body = "\n".join(lines)
        holder[0] = body
        if not quoted:
            _collect_subs(body, ctx)
    return i


def _lex(text: str, ctx: _Ctx) -> list[tuple[str, object]]:
    """Split shell text into ("w", raw word), ("o", operator) and
    ("h", heredoc holder) tokens. Quotes stay in the raw words; substitutions
    become placeholder words registered in ctx."""
    toks: list[tuple[str, object]] = []
    word: list[str] = []
    pending: list = []
    i, n = 0, len(text)

    def flush() -> None:
        if word:
            toks.append(("w", "".join(word)))
            word.clear()

    while i < n:
        c = text[i]
        if c == "\\":
            if i + 1 < n and text[i + 1] == "\n":
                i += 2
                continue
            word.append(text[i:i + 2])
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                raise _Unparseable("unbalanced single quote")
            word.append(text[i:j + 1])
            i = j + 1
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "'":
            decoded, i = _ansi_c(text, i + 2)
            word.append(_squote(decoded))
            continue
        if c == "$" and i + 1 < n and text[i + 1] == '"':
            i += 1      # $"..." is a locale string: read it as "..."
            continue
        if c == '"':
            seg, i = _double(text, i + 1, ctx)
            word.append('"' + seg + '"')
            continue
        if c == "$" and text.startswith("$((", i):
            i = _paren_end(text, i + 2) + 1
            word.append("0")
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "(":
            j = _paren_end(text, i + 2)
            word.append(ctx.add_sub("c", text[i + 2:j]))
            i = j + 1
            continue
        if c == "`":
            body, i = _backtick(text, i + 1)
            word.append(ctx.add_sub("c", body))
            continue
        if c in "<>" and i + 1 < n and text[i + 1] == "(":
            j = _paren_end(text, i + 2)
            flush()
            toks.append(("w", ctx.add_sub("p", text[i + 2:j])))
            i = j + 1
            continue
        if c == "#" and not word:
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "\n":
            flush()
            toks.append(("o", ";"))
            i += 1
            if pending:
                i = _read_heredocs(text, i, pending, ctx)
                pending.clear()
            continue
        if c in " \t\r":
            flush()
            i += 1
            continue
        if text.startswith("<<", i) and not text.startswith("<<<", i):
            if _FD_WORD_RE.fullmatch("".join(word)):
                word.clear()
            flush()
            i, spec = _heredoc_spec(text, i + 2)
            pending.append(spec)
            toks.append(("h", spec[3]))
            continue
        op = next((o for o in _OPS if text.startswith(o, i)), None)
        if op:
            if op[0] in "<>" and _FD_WORD_RE.fullmatch("".join(word)):
                word.clear()            # a file descriptor, as in 2> or {fd}>
            flush()
            toks.append(("o", op))
            i += len(op)
            continue
        word.append(c)
        i += 1
    flush()
    if pending:   # heredoc operator on the last line: no body follows
        for spec in pending:
            spec[3][0] = ""
    return toks


def _unquote(raw: str) -> str:
    try:
        parts = shlex.split(raw, comments=False, posix=True)
    except ValueError as exc:
        raise _Unparseable(str(exc)) from None
    return parts[0] if parts else ""


class _Cmd:
    __slots__ = ("argv", "raw", "rawx", "redirs", "heredocs", "assigns")

    def __init__(self) -> None:
        self.argv: list[str] = []
        # Each word as written, quotes kept and braces not expanded, so it
        # doesn't line up with argv.
        self.raw: list[str] = []
        self.rawx: list[str] = []   # the raw words after brace expansion, lined up with argv
        self.redirs: list[tuple[str, str]] = []
        self.heredocs: list[list] = []
        self.assigns = 0    # leading assignments, which bash doesn't brace-expand

    def empty(self) -> bool:
        return not (self.argv or self.redirs or self.heredocs)


def _parse(toks: list[tuple[str, object]]) -> list[list[_Cmd]]:
    """Group tokens into pipelines of simple commands."""
    pipelines: list[list[_Cmd]] = [[]]
    cur = _Cmd()
    target_for: str | None = None
    expanded = 0
    for typ, val in toks:
        if typ == "w":
            if target_for:
                cur.redirs.append((target_for, _unquote(val)))  # type: ignore[arg-type]
                target_for = None
            elif len(cur.argv) == cur.assigns and _ASSIGN_RE.match(val):  # type: ignore[arg-type]
                cur.argv.append(_unquote(val))  # type: ignore[arg-type]
                cur.raw.append(val)  # type: ignore[arg-type]
                cur.rawx.append(val)  # type: ignore[arg-type]
                cur.assigns += 1
            else:
                words = _brace_expand(val, _BRACE_BUDGET)  # type: ignore[arg-type]
                if len(words) > 1:
                    expanded += len(words)
                    if expanded > MAX_BRACE_TOTAL:
                        raise _TooManyWords
                    # Bash drops an unquoted empty word an expansion makes
                    # (`{,} npx` runs npx); a quoted one ('') stays.
                    words = [w for w in words if w]
                cur.argv.extend(_unquote(w) for w in words)
                cur.raw.append(val)  # type: ignore[arg-type]
                cur.rawx.extend(words)
        elif typ == "h":
            cur.heredocs.append(val)  # type: ignore[arg-type]
        elif val in _REDIRS:
            target_for = val  # type: ignore[assignment]
        elif val in _PIPES:
            pipelines[-1].append(cur)
            cur = _Cmd()
            target_for = None
        else:
            pipelines[-1].append(cur)
            cur = _Cmd()
            pipelines.append([])
            target_for = None
    pipelines[-1].append(cur)
    return [[c for c in p if not c.empty()] for p in pipelines if any(not c.empty() for c in p)]


# -- argv helpers ----------------------------------------------------------

def _split(s: str) -> list[str]:
    try:
        return shlex.split(s, comments=False, posix=True)
    except ValueError:
        return [s]


def _base(word: str) -> str:
    return os.path.basename(word) if word not in (".", "..") else word


def _skip_opts(args: list[str], value_opts: frozenset | set = frozenset()) -> list[str]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1:]
        if not a.startswith("-") or a == "-":
            return args[i:]
        i += 2 if a in value_opts else 1
    return []


def _strip_env(args: list[str]) -> list[str]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1:]
        if a in ("-u", "--unset", "-C", "--chdir"):
            i += 2
            continue
        if a in ("-S", "--split-string") and i + 1 < len(args):
            return _split(args[i + 1]) + args[i + 2:]
        if a.startswith("--split-string="):
            return _split(a.split("=", 1)[1]) + args[i + 1:]
        if a.startswith("-S") and len(a) > 2:
            return _split(a[2:]) + args[i + 1:]
        if a.startswith("-"):
            i += 1
            continue
        return args[i:]
    return []


def _strip_wrappers(argv: list[str]) -> list[str]:
    """Drop leading assignments, reserved words and wrapper commands."""
    argv = list(argv)
    for _ in range(32):
        while argv and _ASSIGN_RE.match(argv[0]):
            argv.pop(0)
        if not argv:
            return argv
        if argv[0] in RESERVED_WORDS:
            argv.pop(0)
            continue
        name = _base(argv[0])
        rest = argv[1:]
        if name == "env":
            argv = _strip_env(rest)
        elif name == "command":
            opts = []
            while rest and rest[0].startswith("-") and rest[0] != "--":
                opts.append(rest.pop(0))
            if rest and rest[0] == "--":
                rest.pop(0)
            if any("v" in o or "V" in o for o in opts):
                return []           # command -v only looks a name up
            argv = rest
        elif name == "exec":
            argv = _skip_opts(rest, {"-a"})
        elif name in ("nohup", "builtin"):
            argv = rest
        elif name == "time":
            argv = _skip_opts(rest, {"-f", "-o", "--format", "--output"})
        elif name == "nice":
            if rest and rest[0] in ("-n", "--adjustment"):
                rest = rest[2:]
            elif rest and (re.fullmatch(r"-n?-?\d+", rest[0]) or rest[0].startswith("--adjustment=")):
                rest = rest[1:]
            argv = rest
        elif name == "timeout":
            rest = _skip_opts(rest, {"-s", "--signal", "-k", "--kill-after"})
            argv = rest[1:]
        elif name == "xargs":
            rest = _skip_opts(rest, {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a",
                                     "--arg-file", "--delimiter", "--max-args",
                                     "--max-procs", "--max-lines", "--eof",
                                     "--max-chars", "--replace"})
            argv = rest or ["echo"]
        elif name == "stdbuf":
            argv = _skip_opts(rest, {"-i", "-o", "-e", "--input", "--output", "--error"})
        else:
            return argv
    return argv


def _positionals(args: list[str], value_opts: frozenset | set = frozenset()) -> list[str]:
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out.extend(args[i + 1:])
            break
        if a.startswith("-") and a != "-":
            i += 2 if a in value_opts else 1
            continue
        out.append(a)
        i += 1
    return out


def _is_python(name: str) -> bool:
    return bool(_PYTHON_RE.fullmatch(name))


def _is_interpreter(name: str) -> bool:
    return name in SHELLS or name.lower() in OTHER_INTERPRETERS or _is_python(name)


# -- ssh, scp, sftp --------------------------------------------------------

def _ssh_args(name: str, args: list[str]) -> tuple[list[tuple[str, str | None]], list[str]]:
    """(options as (flag, value), operands) for ssh or scp. Flags bundle
    (-vvv, -p22, -oKey=value); a value flag takes the rest of its word or the
    next word. ssh reads options before and after the destination and stops at
    the remote command, which ends the operands; scp, parsed by glibc's
    permuting getopt, reads options anywhere."""
    takes = _SSH_VALUE_FLAGS[name]
    opts: list[tuple[str, str | None]] = []
    operands: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            operands.extend(args[i + 1:])
            break
        if a.startswith("-") and len(a) > 1:
            for k in range(1, len(a)):
                if a[k] in takes:
                    value = a[k + 1:]
                    if not value and i + 1 < len(args):
                        i += 1
                        value = args[i]
                    opts.append((a[k], value))
                    break
                opts.append((a[k], None))
            i += 1
            continue
        operands.append(a)
        i += 1
        if name == "ssh" and len(operands) > 1:
            operands.extend(args[i:])   # the remote command
            break
    return opts, operands


def _ssh_option(value: str) -> tuple[str, str]:
    """(lowercased key, value) of an -o option: Key=Value or Key Value."""
    text = value.strip()
    end = 0
    while end < len(text) and not (text[end].isspace() or text[end] == "="):
        end += 1
    rest = text[end:].lstrip()
    if rest.startswith("="):
        rest = rest[1:].lstrip()
    return text[:end].lower(), rest


def _uri_host(uri: str) -> str:
    """The host of ssh://[user@]host[:port][/path] (or scp://)."""
    authority = uri.split("://", 1)[1].split("/", 1)[0]
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")].lower()
    return host.split(":", 1)[0].lower()


def _ssh_dest_host(dest: str) -> str:
    """The host of an ssh destination: [user@]host or ssh://..."""
    if dest.startswith("ssh://"):
        return _uri_host(dest)
    host = dest.rsplit("@", 1)[-1]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.lower()


def _jump_hosts(spec: str) -> list[str]:
    """Hosts in a -J / ProxyJump list: [user@]host[:port] or ssh://..., comma-separated."""
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part or part.lower() == "none":
            continue
        if part.startswith("ssh://"):
            out.append(_uri_host(part))
            continue
        host = part.rsplit("@", 1)[-1]
        if host.startswith("[") and "]" in host:
            out.append(host[1:host.index("]")].lower())
        else:
            out.append(host.split(":", 1)[0].lower())
    return out


def _scp_host(arg: str) -> str | None:
    """The host of a remote scp operand ([user@]host:path, [user@][v6]:path or
    scp://...), or None for a local path, following scp's own colon() rule: a
    colon before any slash, outside brackets, and not first."""
    if arg.startswith("scp://"):
        return _uri_host(arg)
    bracket = arg.startswith("[")
    for i, c in enumerate(arg):
        if c == "@" and arg[i + 1:i + 2] == "[":
            bracket = True
        elif c == "]":
            bracket = False
        elif c == "/" and not bracket:
            return None
        elif c == ":" and not bracket:
            if i == 0:
                return None
            host = arg[:i].rsplit("@", 1)[-1]
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            return host.lower()
    return None


def _ssh_check(name: str, args: list[str], ctx: _Ctx) -> str | None:
    """A reason if this ssh, scp or sftp does more than plain remote access, or
    reaches a host outside launch_gate.ssh_hosts."""
    if name == "sftp":
        return _R_SFTP
    opts, operands = _ssh_args(name, args)
    hosts: list[str] = []
    for flag, value in opts:
        if flag in _SSH_DENY_FLAGS[name]:
            return _r_ssh(name, f"`-{flag}` {_SSH_DENY_FLAGS[name][flag]}")
        if flag == "F" and value not in ("none", "/dev/null"):
            return _r_ssh(name, "`-F` reads a config file, which can run local commands")
        if flag == "J":
            hosts += _jump_hosts(value or "")
        if flag == "o":
            key, val = _ssh_option(value or "")
            if key in _SSH_DENY_OPTIONS:
                return _r_ssh(name, f"`-o {key}` {_SSH_DENY_OPTIONS[key]}")
            if key in _SSH_FILE_OPTIONS and val != "/dev/null":
                return _r_ssh(name, f"`-o {key}` writes a file outside the sandbox")
            if key == "proxyjump":
                hosts += _jump_hosts(val)
    if name == "ssh":
        hosts += [_ssh_dest_host(operands[0])] if operands else []
    else:
        hosts += [h for h in map(_scp_host, operands) if h is not None]
    if ctx.ssh_hosts:
        for host in hosts:
            if host not in ctx.ssh_hosts:
                return _r_ssh_host(name, host)
    return None


def _quiet_redir(op: str, target: str) -> bool:
    """A redirect that reads or writes no file: an fd copy, /dev/null, or a here-string."""
    if op in (">&", "<&"):
        return target.isdigit() or target in ("-", "/dev/null")
    if op in _OUTPUT_REDIRS or op == "<":
        return target == "/dev/null"
    return op == "<<<"


def _expansion(raw: str) -> str | None:
    """The first character in a raw word that bash would expand before the
    command sees it: outside quotes `$`, `{`, `}`, `*`, `?` or `[`; inside
    double quotes `$`. Single-quoted text and backslash escapes are literal."""
    i, n, dq = 0, len(raw), False
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 2
        elif c == "'" and not dq:
            j = raw.find("'", i + 1)
            i = n if j < 0 else j + 1
        elif c == '"':
            dq = not dq
            i += 1
        elif c == "$" or (not dq and c in "{}*?["):
            return c
        else:
            i += 1
    return None


def _brace_scan(raw: str):
    """Yield (index, char) for the characters of a raw word that brace
    expansion sees: unquoted and unescaped."""
    i, n, dq = 0, len(raw), False
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 2
        elif c == "'" and not dq:
            j = raw.find("'", i + 1)
            i = n if j < 0 else j + 1
        elif c == '"':
            dq = not dq
            i += 1
        else:
            if not dq:
                yield i, c
            i += 1


def _brace_group(raw: str):
    """The first brace group bash would expand in a raw word, as (start, end,
    the raw alternatives), or None. A group is a balanced, unquoted `{...}`
    holding an unquoted comma at its own level, or a sequence such as `{1..5}`
    or `{a..e}`. A `${...}` is a parameter, never a group, but its braces
    still balance."""
    stack: list[list] = []   # [start, is a parameter, comma positions]
    best = None              # the expandable group that starts first
    prev, empty_pair, listy = -2, False, False
    for i, c in _brace_scan(raw):
        if c == "{":
            stack.append([i, prev == i - 1 and raw[i - 1] == "$", []])
        elif c == "}" and stack and stack[-1][0] == i - 1 and not stack[-1][1]:
            # Bash reads a `}` right after `{` as text in some places and not
            # others (find's `{}`); where a list is near, fail closed.
            empty_pair = True
            stack.pop()
        elif c == "}" and stack:
            start, param, commas = stack.pop()
            if param or (best and best[0] < start):
                continue
            # A sequence is short, so only short groups are tried as one.
            if commas or (i - start <= 40 and _SEQ_RE.fullmatch(raw[start + 1:i])):
                best = (start, i, commas)
        elif c == "," and stack and not stack[-1][1]:
            stack[-1][2].append(i)
        if c == ",":
            listy = True
        prev = i
    if empty_pair and listy:
        raise _TooManyWords
    if best is None:
        return None
    start, end, commas = best
    if commas:
        cuts = [start] + commas + [end]
        return start, end, [raw[a + 1:b] for a, b in zip(cuts, cuts[1:])]
    return start, end, _brace_sequence(raw[start + 1:end])


_SEQ_RE = re.compile(r"([-+]?\d{1,19})\.\.([-+]?\d{1,19})(?:\.\.([-+]?\d{1,19}))?|"
                     r"([A-Za-z])\.\.([A-Za-z])(?:\.\.([-+]?\d{1,19}))?")


def _brace_sequence(text: str):
    """The words of a sequence expression (`1..5`, `01..10..3`, `a..e`), or
    None if the text isn't one. Raises _TooManyWords for a long one."""
    m = _SEQ_RE.fullmatch(text)
    if not m:
        return None
    if m.group(1) is not None:
        a, b, step = int(m.group(1)), int(m.group(2)), abs(int(m.group(3) or 1)) or 1
        if abs(b - a) // step + 1 > MAX_BRACE_WORDS:
            raise _TooManyWords
        pad = max(len(m.group(1)), len(m.group(2))) if (
            m.group(1).lstrip("-+").startswith("0") or m.group(2).lstrip("-+").startswith("0")) else 0
        nums = range(a, b + (1 if b >= a else -1), step if b >= a else -step)
        return [str(v).zfill(pad) if pad else str(v) for v in nums]
    a, b, step = ord(m.group(4)), ord(m.group(5)), abs(int(m.group(6) or 1)) or 1
    if abs(b - a) // step + 1 > MAX_BRACE_WORDS:
        raise _TooManyWords
    chars = range(a, b + (1 if b >= a else -1), step if b >= a else -step)
    # A letter range can pass through [ \ ] ^ _ and `: quote each one.
    return [_squote(chr(v)) for v in chars]


def _brace_expand(raw: str, budget: list | None = None) -> list[str]:
    """The raw words bash makes of one raw word by brace expansion, in order.
    Raises _TooManyWords past MAX_BRACE_WORDS words, MAX_BRACE_CHARS, or the
    characters left in `budget` (a one-item list, shared across a text)."""
    budget = [MAX_BRACE_WORK] if budget is None else budget
    if "{" not in raw or "}" not in raw:
        return [raw]
    if len(raw) > MAX_BRACE_CHARS and _brace_group(raw) is not None:
        raise _TooManyWords
    out: list[str] = []
    todo = [raw]
    while todo:
        word = todo.pop()
        budget[0] -= len(word)
        if budget[0] < 0:
            raise _TooManyWords
        group = _brace_group(word)
        if group is None:
            out.append(word)
            continue
        start, end, parts = group
        if len(out) + len(todo) + len(parts) > MAX_BRACE_WORDS:
            raise _TooManyWords
        todo.extend(word[:start] + p + word[end + 1:] for p in reversed(parts))
    return out


def _ssh_alone(pipelines: list[list[_Cmd]], ctx: _Ctx, first: int) -> str | None:
    """At the top level, an ssh-family command must be the whole call. Claude
    Code runs an excluded command outside the sandbox, and anything run with
    it (a pipe stage, a `;` neighbour, a substitution, a wrapper, an assignment
    such as LD_PRELOAD, a file redirect) could run or read out there too."""
    found = wrapped = noisy = False
    for pipe in pipelines:
        for cmd in pipe:
            words = list(cmd.argv)
            assigned = bool(words) and bool(_ASSIGN_RE.match(words[0]))
            while words and _ASSIGN_RE.match(words[0]):
                words.pop(0)
            stripped = _strip_wrappers(words)
            if not stripped or _base(stripped[0]) not in SSH_FAMILY:
                continue
            found = True
            wrapped = wrapped or assigned or _base(cmd.argv[0]) not in SSH_FAMILY
            noisy = noisy or not all(_quiet_redir(op, t) for op, t in cmd.redirs)
            # The gate checks the words as written; bash expands them first, so
            # `-o {ProxyCommand=x,}`, `${P:-ProxyCommand}=x`, `${x@P}` or a `*`
            # that picks up a planted `-oProxyCommand=x` file would get past it.
            for raw in cmd.raw:
                char = _expansion(raw)
                if char:
                    return _r_ssh_expand(_base(cmd.argv[0]), char)
    if not found:
        return None
    alone = len(pipelines) == 1 and len(pipelines[0]) == 1 and len(ctx.subs) == first
    return None if alone and not wrapped and not noisy else _R_SSH_ALONE


# -- what each command does ------------------------------------------------

def _launcher(name: str, args: list[str]) -> str | None:
    """A reason if this command fetches and runs a package."""
    if name in ("npx",):
        for a in args:
            if a in _NO_FETCH_FLAGS:
                return None
            if a == "--" or not a.startswith("-"):
                break
        return _r_launch("npx")   # even bare: xargs or a pipe can supply the package
    if name in ("pnpx", "bunx", "uvx"):
        return _r_launch(name)
    if name == "npm":
        pos = _positionals(args, {"--prefix", "-w", "--workspace", "--registry",
                                  "--cache", "--userconfig", "--globalconfig",
                                  "--loglevel"})
        sub = pos[0] if pos else ""
        if sub in ("exec", "x"):
            if any(a in _NO_FETCH_FLAGS for a in args):
                return None
            return _r_launch(f"npm {sub}")
        if sub == "create" or (sub == "init" and len(pos) > 1):
            return _r_launch(f"npm {sub} {pos[1] if len(pos) > 1 else ''}".strip())
        return None
    if name in ("pnpm", "yarn"):
        pos = _positionals(args, {"--dir", "-C", "--filter", "-F", "--cwd"})
        if pos and pos[0] in ("dlx", "create"):
            return _r_launch(f"{name} {pos[0]}")
        return None
    if name == "bun":
        pos = _positionals(args, {"--cwd"})
        if pos and pos[0] in ("x", "create"):
            return _r_launch(f"bun {pos[0]}")
        return None
    if name == "uv":
        pos = _positionals(args, {"--directory", "--project", "--cache-dir",
                                  "--config-file", "--color", "--python", "-p"})
        if len(pos) >= 2 and pos[0] == "tool" and pos[1] in ("run", "install", "upgrade"):
            return _r_launch(f"uv tool {pos[1]}")
        if pos and pos[0] == "run":
            after = args[args.index("run") + 1:] if "run" in args else []
            for a in after:
                if a == "--":
                    break
                if a.startswith("--with"):
                    return _r_launch("uv run --with")
            run_pos = _positionals(after, {"--python", "-p", "--directory", "--project",
                                           "--env-file", "--extra", "--group",
                                           "--package", "--index"})
            if run_pos and run_pos[0].startswith(("http://", "https://")):
                return _r_launch("uv run <url>")
        return None
    if name == "pipx":
        pos = _positionals(args)
        if pos and pos[0] in ("run", "install", "inject", "upgrade", "upgrade-all",
                              "reinstall", "reinstall-all", "runpip", "install-all"):
            return _r_launch(f"pipx {pos[0]}")
        return None
    if name == "cargo":
        pos = [p for p in _positionals(args, {"--manifest-path", "-Z", "--config"})
               if not p.startswith("+")]
        if pos and pos[0] in ("install", "binstall"):
            return _r_launch(f"cargo {pos[0]}")
        return None
    if name == "go":
        pos = _positionals(args)
        if pos and pos[0] in ("install", "run") and any("@" in p for p in pos[1:]):
            return _r_launch(f"go {pos[0]} <pkg>@<version>")
        return None
    if name == "gh":
        pos = _positionals(args, {"-R", "--repo", "--hostname"})
        if len(pos) >= 2 and pos[0] in ("extension", "extensions", "ext") and \
                pos[1] in ("install", "upgrade"):
            return _r_launch(f"gh extension {pos[1]}")
        return None
    if name == "deno":
        pos = _positionals(args)
        if pos and pos[0] in ("run", "install", "x", "compile") and any(
                a.startswith(("http://", "https://", "npm:", "jsr:")) for a in args):
            return _r_launch(f"deno {pos[0]} <remote>")
        return None
    return None


def _agent_launch(name: str, args: list[str]) -> str | None:
    if name == "claude":
        resume = print_ = False
        for k, a in enumerate(args):
            if a in ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions"):
                return _r_agent(name, a)
            if a == "--permission-mode=bypassPermissions" or (
                    a == "--permission-mode" and k + 1 < len(args)
                    and args[k + 1] == "bypassPermissions"):
                return _r_agent(name, "--permission-mode bypassPermissions")
            if a in ("--resume", "-r", "--continue", "-c", "--fork-session", "--teleport") or \
                    a.startswith(("--resume=", "--continue=", "--from-pr", "--teleport=")):
                resume = True
            if a in ("-p", "--print") or a.startswith("--print="):
                print_ = True
        if resume and print_:
            return _r_forge(name)
    if name == "codex":
        for a in args:
            if a in ("--dangerously-bypass-approvals-and-sandbox", "--yolo"):
                return _r_agent(name, a)
    if name == "gemini":
        for k, a in enumerate(args):
            if a in ("--yolo", "-y", "--approval-mode=yolo") or (
                    a == "--approval-mode" and k + 1 < len(args) and args[k + 1] == "yolo"):
                return _r_agent(name, a)
    return None


def _reads_program_from_stdin(name: str, args: list[str]) -> bool:
    lname = name.lower()
    if lname in ("iex", "invoke-expression"):
        return True
    if name in ("source", "."):
        return bool(args) and args[0] in ("/dev/stdin", "/dev/fd/0", "/proc/self/fd/0", "-")
    if name in SHELLS:
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-":
                return True
            if a == "--":
                return i + 1 >= len(args)
            if a.startswith("--"):
                if a == "--command":
                    return False
                i += 2 if a in ("--rcfile", "--init-file") else 1
                continue
            if a[:1] in "-+" and len(a) > 1:
                flags = a[1:]
                if "c" in flags:
                    return False
                if "s" in flags and a[0] == "-":
                    return True
                i += 2 if flags in ("o", "O") else 1
                continue
            return False
        return True
    if _is_python(name):
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-":
                return True
            if a == "--":
                return i + 1 >= len(args)
            if a.startswith("--"):
                i += 1
                continue
            if a.startswith("-") and len(a) > 1:
                step = 1
                for k, f in enumerate(a[1:]):
                    if f in "cm":
                        return False
                    if f in "WX":
                        if k == len(a) - 2:
                            step = 2
                        break
                i += step
                continue
            return False
        return True
    if name in ("node", "nodejs"):
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-":
                return True
            if a in ("-e", "--eval", "-p", "--print") or a.startswith(("--eval=", "--print=")):
                return False
            if a in ("-r", "--require", "--import", "--loader", "--experimental-loader",
                     "-C", "--conditions", "--input-type"):
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            return False
        return True
    if name in ("perl", "ruby", "php"):
        program_flags = {"perl": "eE", "ruby": "e", "php": "rf"}[name]
        attached = {"perl": "MmIxid0l", "ruby": "rIEC", "php": "dcz"}[name]
        for a in args:
            if a == "-":
                return True
            if a.startswith("--"):
                continue
            if a.startswith("-") and len(a) > 1:
                for f in a[1:]:
                    if f in program_flags:
                        return False
                    if f in attached:
                        break
                continue
            return False
        return True
    if lname in ("pwsh", "powershell", "pwsh.exe", "powershell.exe"):
        largs = [a.lower() for a in args]
        for k, a in enumerate(largs):
            if a in ("-file", "-f", "-command", "-c", "-encodedcommand", "-e", "-ec"):
                return k + 1 < len(largs) and largs[k + 1] == "-"
            if a == "-":
                return True
        return True
    return False


def _script_arg(name: str, args: list[str]) -> str | None:
    """The program file an interpreter would run, if any."""
    if name in ("source", "."):
        return args[0] if args else None
    if not _is_interpreter(name):
        return None
    for a in args:
        if a == "--":
            continue
        if a.startswith("-") or a.startswith("+"):
            flags = a.lstrip("-+")
            if name in SHELLS and "c" in flags and not a.startswith("--"):
                return None
            if _is_python(name) and not a.startswith("--") and ("c" in flags or "m" in flags):
                return None
            if a in ("-e", "--eval", "-p", "--print", "-r", "-E"):
                return None
            continue
        return a
    return None


def _shell_payload(name: str, args: list[str]) -> str | None:
    """The command string of sh -c '...' (and friends)."""
    if name not in SHELLS:
        return None
    for k, a in enumerate(args):
        if a == "--command" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]):
            return args[k + 1] if k + 1 < len(args) else ""
        if not a.startswith(("-", "+")):
            return None
    return None


def _download_outputs(name: str, args: list[str], redirs: list[tuple[str, str]]) -> list[str]:
    outs: list[str] = []
    urls = [a for a in args if a.startswith(("http://", "https://", "ftp://"))]
    remote_name = False
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if name == "curl":
            if a in ("-o", "--output") and nxt is not None:
                outs.append(nxt)
                i += 2
                continue
            if a.startswith("--output="):
                outs.append(a.split("=", 1)[1])
            elif a in ("--remote-name", "--remote-name-all"):
                remote_name = True
            elif a.startswith("-") and not a.startswith("--"):
                for k, f in enumerate(a[1:]):
                    if f == "O":
                        remote_name = True
                    if f == "o":
                        rest = a[k + 2:]
                        if rest:
                            outs.append(rest)
                        elif nxt is not None:
                            outs.append(nxt)
                            i += 1
                        break
                    if f in "HdduxAeXEKbcwrTFmY":
                        break
        elif name in ("wget", "wget2"):
            if a in ("-O", "--output-document") and nxt is not None:
                outs.append(nxt)
                i += 2
                continue
            if a.startswith("--output-document="):
                outs.append(a.split("=", 1)[1])
            elif a.startswith("-") and not a.startswith("--") and "O" in a:
                k = a.index("O")
                rest = a[k + 1:]
                if rest:
                    outs.append(rest)
                elif nxt is not None:
                    outs.append(nxt)
                    i += 1
        i += 1
    if name in ("wget", "wget2") and not outs:
        remote_name = True
    if remote_name:
        for u in urls:
            leaf = os.path.basename(urlsplit(u).path)
            outs.append(leaf or "index.html")
    outs.extend(t for op, t in redirs if op in _OUTPUT_REDIRS)
    return [o for o in outs if o and o not in ("-", "/dev/null", "/dev/stdout", "/dev/stderr")]


def _norm(path: str) -> str:
    return os.path.normpath(path)


# -- the checks ------------------------------------------------------------

def _sub_body(word: str, ctx: _Ctx) -> tuple[str, str] | None:
    m = _PLACEHOLDER_RE.search(word)
    if not m:
        return None
    k = int(m.group(2))
    if k >= len(ctx.subs) or ctx.subs[k][0] != m.group(1):
        return None     # not one of ours; check() refuses forged markers anyway
    return ctx.subs[k]


def _body_commands(body: str, ctx: _Ctx) -> list[list[_Cmd]] | None:
    try:
        return _parse(_lex(body, ctx))
    except (_Unparseable, _TooManyWords):
        return None


def _is_download(body: str, ctx: _Ctx) -> bool:
    pipelines = _body_commands(body, ctx)
    if pipelines is None:
        return bool(re.search(r"(?<![\w-])(?:curl|wget|iwr|irm|fetch)(?![\w-])", body, re.I))
    for pipe in pipelines:
        for cmd in pipe:
            argv = _strip_wrappers(cmd.argv)
            if argv and _base(argv[0]).lower() in DOWNLOADERS:
                return True
    return False


def _static_output(body: str, ctx: _Ctx) -> list[str] | None:
    """What a trivial substitution prints: echo, printf without %, which, command -v."""
    pipelines = _body_commands(body, ctx)
    if not pipelines or len(pipelines) != 1 or len(pipelines[0]) != 1:
        return None
    argv = pipelines[0][0].argv
    if not argv:
        return None
    name, args = _base(argv[0]), argv[1:]
    if name == "echo":
        return _split(" ".join(a for a in args if a not in ("-n", "-e", "-E")))
    if name == "printf" and args and "%" not in args[0]:
        return _split(args[0].replace("\\n", " "))
    if name in ("which", "type") or (name == "command" and args[:1] in (["-v"], ["-V"])):
        names = [a for a in args if not a.startswith("-")]
        return names[:1] or None
    return None


def _allowed(argv: list[str], ctx: _Ctx) -> bool:
    words = [_base(argv[0])] + argv[1:]
    for prefix in ctx.allow:
        if len(words) >= len(prefix) and words[:len(prefix)] == [_base(prefix[0])] + prefix[1:]:
            return True
    return False


def _resolve_command_word(argv: list[str], ctx: _Ctx, depth: int) -> tuple[list[str], str | None]:
    """Expand a known $VAR or a trivial substitution in command position."""
    if not argv:
        return argv, None
    m = _VAR_RE.fullmatch(argv[0])
    if m:
        name = m.group(1) or m.group(2)
        if name in ctx.vars:
            argv = _split(ctx.vars[name]) + argv[1:]
    if argv and _PLACEHOLDER_RE.search(argv[0]):
        kind, body = _sub_body(argv[0], ctx) or ("c", "")
        if _is_download(body, ctx):
            return argv, _R_SUBST_DOWNLOAD
        out = _static_output(body, ctx) if _PLACEHOLDER_RE.fullmatch(argv[0]) else None
        if out:
            return out + argv[1:], None
        pipelines = _body_commands(body, ctx) or []
        for pipe in pipelines:
            for cmd in pipe:
                for w in cmd.argv:
                    if _base(w) in HIDDEN_NAME_TRIGGERS:
                        return argv, _r_hidden(_base(w))
    return argv, None


def _check_command(cmd: _Cmd, argv: list[str], ctx: _Ctx, depth: int) -> str | None:
    if not argv:
        return None
    name = _base(argv[0])
    lname = name.lower()
    args = argv[1:]

    if name in SSH_FAMILY:      # never relaxed by launch_gate.allow
        reason = _ssh_check(name, args, ctx)
        if reason:
            return reason

    if not _allowed(argv, ctx):
        if name in PRIVILEGE:
            return _r_priv(name)
        reason = _agent_launch(name, args) or _launcher(name, args)
        if reason:
            return reason

    if name == "eval":
        for a in args:
            sub = _sub_body(a, ctx)
            if sub and _is_download(sub[1], ctx):
                return _r_pipe("eval")
        return _check_text(" ".join(args), ctx, depth + 1)

    if name == "find":
        for k, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                sub = []
                for b in args[k + 1:]:
                    if b in (";", "+"):
                        break
                    sub.append(b)
                inner = _Cmd()
                inner.argv = list(sub)
                inner.rawx = [w if _PLACEHOLDER_RE.search(w) or w in ("[", "[[")
                              or not any(c in w for c in "$*?[") else "$" for w in sub]
                reason = _check_simple(inner, ctx, depth + 1)[1]
                if reason:
                    return reason

    if _is_interpreter(name):
        for a in args:
            sub = _sub_body(a, ctx)
            if sub and _is_download(sub[1], ctx):
                return _r_pipe(name)
        script = _script_arg(name, args)
        if script and _norm(script) in ctx.downloads:
            return _r_downloaded(script)
        payload = _shell_payload(name, args)
        if payload is not None:
            reason = _check_text(payload, ctx, depth + 1)
            if reason:
                return reason
        if _reads_program_from_stdin(name, args):
            for op, target in cmd.redirs:
                if op == "<":
                    sub = _sub_body(target, ctx)
                    if sub and _is_download(sub[1], ctx):
                        return _r_pipe(name)
                    if _norm(target) in ctx.downloads:
                        return _r_downloaded(target)
                if op == "<<<" and name in SHELLS:
                    reason = _check_text(target, ctx, depth + 1)
                    if reason:
                        return reason
            if name in SHELLS:
                for holder in cmd.heredocs:
                    reason = _check_text(holder[0] or "", ctx, depth + 1)
                    if reason:
                        return reason
    elif lname not in DOWNLOADERS and _norm(argv[0]) in ctx.downloads:
        return _r_downloaded(argv[0])
    return None


def _command_argv(argv: list[str], ctx: _Ctx, depth: int) -> tuple[list[str], str | None]:
    """The argv from its command word on: assignments and wrappers dropped,
    a known variable or trivial substitution in command position resolved."""
    k = 0
    while k < len(argv) and _ASSIGN_RE.match(argv[k]):
        k += 1
    argv, reason = _resolve_command_word(argv[k:], ctx, depth)
    if reason:
        return argv, reason
    return _resolve_command_word(_strip_wrappers(argv), ctx, depth)


# The most words built at run time, up to the command word, that the gate
# tries dropping; past it, the call is refused. Up to MAX_EMPTY_SUBSETS of
# them, every combination is tried; above that, each alone and all together.
MAX_EMPTY_WORDS = 16
MAX_EMPTY_SUBSETS = 6


def _maybe_empty(cmd: _Cmd) -> list:
    """Sets of argv positions to drop, for the words up to the command word
    that are built at run time; a None item means there are too many to try.
    The command word is found again after each round of drops, so run-time
    words in front of a wrapper, and in its operands, all count."""
    words, raws = cmd.argv, cmd.rawx
    if len(raws) != len(words):
        # _parse keeps them in line; if they ever aren't, fail closed as an
        # internal error rather than guess.
        raise RuntimeError("rawx out of line with argv")
    found: set = set()
    while True:
        kept = [k for k in range(len(words)) if k not in found]
        off = len(kept) - len(_strip_wrappers([words[k] for k in kept]))
        limit = kept[off] if off < len(kept) else len(words) - 1
        new = {k for k in range(cmd.assigns, min(limit + 1, len(words) - 1))
               if k not in found and _run_time_name(raws[k])}
        if not new:
            break
        found |= new
        if len(found) > MAX_EMPTY_WORDS:
            return [None]
    order = sorted(found)
    if not order:
        return []
    if len(order) <= MAX_EMPTY_SUBSETS:
        return [{order[i] for i in range(len(order)) if mask >> i & 1}
                for mask in range(1, 1 << len(order))]
    return [{k} for k in order] + [set(order)]


def _check_shifted(cmd: _Cmd, argv: list[str], ctx: _Ctx, depth: int) -> str | None:
    """When the resolved command word still holds a `$` or a substitution (it
    came from inside a wrapper's string, or a variable's value), bash may
    drop it as empty: check the next word as the command too, up to
    MAX_EMPTY_WORDS times."""
    for _ in range(MAX_EMPTY_WORDS):
        if not (len(argv) > 1 and ("$" in argv[0] or _PLACEHOLDER_RE.search(argv[0]))):
            return None
        argv, reason = _command_argv(argv[1:], ctx, depth)
        reason = reason or _check_command(_Cmd(), argv, ctx, depth)
        if reason:
            return reason
    return _R_EMPTY_WORDS if len(argv) > 1 and "$" in argv[0] else None


def _check_simple(cmd: _Cmd, ctx: _Ctx, depth: int) -> tuple[list[str], str | None]:
    """(the argv from its command word on, a reason or None) for one simple
    command, including the forms bash would run if words built at run time
    come out empty: bash drops those (an unset variable, `$@`, an empty
    substitution, a glob under nullglob), and the gate can't tell which."""
    argv, reason = _command_argv(cmd.argv, ctx, depth)
    if reason:
        return argv, reason
    reason = _check_command(cmd, argv, ctx, depth) or _check_shifted(cmd, argv, ctx, depth)
    if reason:
        return argv, reason
    for drop in _maybe_empty(cmd):
        if drop is None:
            return argv, _R_EMPTY_WORDS
        other, reason = _command_argv([w for k, w in enumerate(cmd.argv) if k not in drop],
                                      ctx, depth)
        reason = (reason or _check_command(cmd, other, ctx, depth)
                  or _check_shifted(cmd, other, ctx, depth))
        if reason:
            return argv, reason
    return argv, None


def _check_pipeline(pipe: list[_Cmd], ctx: _Ctx, depth: int, variant: bool = False) -> str | None:
    argvs: list[list[str]] = []
    for cmd in pipe:
        argv = cmd.argv
        # In the variant pass a stage may be shortened to words that look like
        # assignments (`$e v=ls` to `v=ls`). Bash decides that when it parses, so
        # only a stage that was all assignments as written sets variables.
        if argv and all(_ASSIGN_RE.match(w) for w in argv) and (not variant or cmd.assigns == len(argv)):
            for w in argv:
                key, value = w.split("=", 1)
                ctx.vars[key] = value
            argvs.append([])
            continue
        # The first pass checked each stage in every form _maybe_empty gives,
        # this one among them, so the variant pass only needs the command word
        # for the pipe checks below.
        if variant:
            argv, reason = _command_argv(cmd.argv, ctx, depth)
        else:
            argv, reason = _check_simple(cmd, ctx, depth)
        if reason:
            return reason
        argvs.append(argv)

    # Pipe-to-interpreter: an earlier stage downloads, decodes or echoes text,
    # and a later stage runs its program from stdin. One pass: first_bad keeps
    # the kind of the first earlier stage that downloads or decodes, so a long
    # pipeline costs linear time, not one scan of all earlier stages per stage.
    first_bad: str | None = None   # "pipe" or "decode"
    for k in range(1, len(pipe)):
        earlier = argvs[k - 1]
        if earlier and first_bad is None:
            ename = _base(earlier[0]).lower()
            if ename in DOWNLOADERS or any(_norm(a) in ctx.downloads for a in earlier[1:]):
                first_bad = "pipe"
            elif ename in DECODERS:
                first_bad = "decode"
        argv = argvs[k]
        if not argv:
            continue
        name = _base(argv[0])
        if not (_is_interpreter(name) and _reads_program_from_stdin(name, argv[1:])):
            continue
        if first_bad == "pipe":
            return _r_pipe(name)
        if first_bad == "decode":
            return _r_decode(name)
        if not earlier:
            continue
        ename = _base(earlier[0]).lower()
        if ename in ("echo", "printf") and name in SHELLS:
            text = " ".join(a for a in earlier[1:] if a not in ("-n", "-e", "-E"))
            reason = _check_text(text.replace("\\n", "\n"), ctx, depth + 1)
            if reason:
                return reason
        if ename == "cat" and name in SHELLS:
            for holder in pipe[k - 1].heredocs:
                reason = _check_text(holder[0] or "", ctx, depth + 1)
                if reason:
                    return reason

    # Record what this pipeline downloaded, for later commands in the same call.
    for cmd, argv in zip(pipe, argvs):
        if argv and _base(argv[0]).lower() in DOWNLOADERS:
            for out in _download_outputs(_base(argv[0]).lower(), argv[1:], cmd.redirs):
                ctx.downloads.add(_norm(out))
    # The stage checks above read each stage's command word as written. Where
    # words up to it are built at run time, run them once more with all those
    # words gone, as bash runs them if they come out empty (`$e bash`).
    if not variant:
        alt = [_all_dropped(cmd) for cmd in pipe]
        if any(a is not c for a, c in zip(alt, pipe)):
            return _check_pipeline(alt, ctx, depth, variant=True)
    return None


def _all_dropped(cmd: _Cmd) -> _Cmd:
    """The command with every word _maybe_empty would drop gone, or the same
    command if there are none."""
    drops = [d for d in _maybe_empty(cmd) if d is not None]
    if not drops:
        return cmd
    gone = set().union(*drops)
    out = _Cmd()
    out.argv = [w for k, w in enumerate(cmd.argv) if k not in gone]
    out.rawx = [w for k, w in enumerate(cmd.rawx) if k not in gone]
    out.raw, out.redirs, out.heredocs, out.assigns = cmd.raw, cmd.redirs, cmd.heredocs, cmd.assigns
    return out


_FALLBACK_WORDS = re.compile(r"(?<![\w./-])(npx|pnpx|bunx|uvx|pipx|sudo|doas|pkexec|run0)(?![\w-])")
_FALLBACK_PHRASES = re.compile(
    r"\b(npm\s+(?:exec|x|create)|pnpm\s+(?:dlx|create)|yarn\s+(?:dlx|create)|"
    r"bun\s+(?:x|create)|uv\s+tool\s+(?:run|install|upgrade)|uv\s+run\s+--with|"
    r"cargo\s+b?install|gh\s+(?:extensions?|ext)\s+install)\b|"
    r"(--dangerously-skip-permissions|bypassPermissions|--yolo\b|"
    r"--dangerously-bypass-approvals-and-sandbox)")
_FALLBACK_DOWNLOAD = re.compile(r"(?<![\w-])(curl|wget|iwr|irm|fetch)(?![\w-])", re.I)
_FALLBACK_INTERP = re.compile(
    r"\s*(?:sudo\s+)?(?:\S*/)?((?:ba|z|da|k|mk|fi|a)?sh|python[0-9.]*|node|perl|ruby|php|iex|pwsh|powershell)\b",
    re.I)


def _fallback(text: str) -> str | None:
    """Unparseable text: deny only if it mentions something we'd block."""
    m = _FALLBACK_WORDS.search(text)
    if m:
        return _r_parse(m.group(1))
    m = _FALLBACK_PHRASES.search(text)
    if m:
        return _r_parse(m.group(0))
    segments = text.split("|")
    seen_download = False
    for seg in segments:
        if seen_download and _FALLBACK_INTERP.match(seg):
            return _r_parse("a download piped into an interpreter")
        if _FALLBACK_DOWNLOAD.search(seg):
            seen_download = True
    if _FALLBACK_DOWNLOAD.search(text) and re.search(r"[<$]\(|`", text):
        return _r_parse("a download inside a substitution")
    return None


def _name_norm(text: str) -> str:
    """The text as the shell would join its words: backslash-newlines, quotes
    and backslashes taken out, so `ss''h`, `s\\sh` and `ss$''h` read as ssh."""
    t = re.sub(r"\\\n", "", text)
    t = re.sub(r"\$(?=['\"])", "", t)
    return re.sub(r"['\"\\]", "", t)


def _names_ssh(text: str) -> bool:
    """Whether the text may name ssh, scp or sftp anywhere, even inside a
    $'...' string that spells the name with escapes."""
    return bool(_SSH_NAME_RE.search(text) or _SSH_NAME_RE.search(_name_norm(text))
                or ("$'" in text and _ANSI_LETTER_RE.search(text)))


def _check_text(text: str, ctx: _Ctx, depth: int) -> str | None:
    if depth > MAX_DEPTH:
        return _R_DEPTH
    names_ssh = depth == 0 and _names_ssh(text)
    # The lexer splits words at a carriage return; bash doesn't.
    if names_ssh and (_TRICKY_RE.search(text) or "\n" in text.rstrip() or "\r" in text):
        return _R_SSH_TRICKY
    first = len(ctx.subs)
    try:
        pipelines = _parse(_lex(text, ctx))
    except _TooManyWords:
        return _R_BRACE
    except _Unparseable:
        return _R_SSH_TRICKY if names_ssh else _fallback(text)
    if depth == 0:
        reason = _ssh_alone(pipelines, ctx, first)
        if reason:
            return reason
    # Every substitution in this text runs as a command of its own.
    for _kind, body in list(ctx.subs[first:]):
        reason = _check_text(body, ctx, depth + 1)
        if reason:
            return reason
    for pipe in pipelines:
        reason = _check_pipeline(pipe, ctx, depth)
        if reason:
            return reason
    return None


def _allow_prefixes(config: dict) -> list[list[str]]:
    section = config.get("launch_gate", {})
    if not isinstance(section, dict):
        raise ConfigError("'launch_gate' must be a JSON object")
    allow = section.get("allow", [])
    if not isinstance(allow, list) or not all(
            isinstance(p, list) and p and all(isinstance(t, str) and t for t in p)
            for p in allow):
        raise ConfigError("'launch_gate.allow' must be a list of non-empty lists of "
                          'strings, like [["npx", "prettier"]]')
    return [list(p) for p in allow]


def _ssh_hosts(config: dict) -> frozenset:
    """launch_gate.ssh_hosts, lowercased; empty when unset (any host)."""
    section = config.get("launch_gate", {})
    if not isinstance(section, dict):
        raise ConfigError("'launch_gate' must be a JSON object")
    hosts = section.get("ssh_hosts", [])
    if not isinstance(hosts, list) or not all(isinstance(h, str) and h.strip() for h in hosts):
        raise ConfigError("'launch_gate.ssh_hosts' must be a list of host names, "
                          'like ["myserver", "deploy.example.com"]')
    return frozenset(h.strip().lower() for h in hosts)


def _run_time_name(raw: str) -> bool:
    """Whether a raw command word is built at run time: an unquoted `$`, `*`,
    `?` or `[` anywhere in it, a `$` in double quotes, or a substitution
    placeholder. The test commands `[` and `[[` are words, not globs."""
    if raw in ("[", "[["):
        return False
    if _PLACEHOLDER_RE.search(raw):
        return True
    i, n, dq = 0, len(raw), False
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 2
        elif c == "'" and not dq:
            j = raw.find("'", i + 1)
            i = n if j < 0 else j + 1
        elif c == '"':
            dq = not dq
            i += 1
        elif c == "$" or (not dq and c in "*?["):
            return True
        else:
            i += 1
    return False


def _monitor_feed(text: str, depth: int = 0) -> str | None:
    """A reason if a Monitor command may run a downloader or a raw network
    client. A tripwire: it scans the text and the words bash would make for
    their names, follows shell payloads and eval, and refuses a command name
    built at run time."""
    if depth > MAX_DEPTH:
        return _R_DEPTH
    if depth == 0:
        _BRACE_BUDGET[0] = MAX_BRACE_WORK
    for form in (text, _name_norm(text)):
        found = _FEED_NAME_RE.search(form)
        if found:
            return _r_monitor_feed(found.group(0).lower())
    if "$'" in text and _ANSI_LETTER_RE.search(text):
        return _R_MONITOR_HIDDEN
    ctx = _Ctx([], frozenset())
    try:
        pipelines = _parse(_lex(text, ctx))
    except _TooManyWords:
        return _R_BRACE if depth else None
    except _Unparseable:
        # check() has judged the whole text; a payload inside it is ours.
        return _R_MONITOR_HIDDEN if depth else None
    for pipe in pipelines:
        for cmd in pipe:
            found = _FEED_NAME_RE.search(" ".join(cmd.argv))
            if found:
                return _r_monitor_feed(found.group(0).lower())
            argv = _strip_wrappers(cmd.argv)
            if not argv:
                continue
            name = _base(argv[0]).lower()
            if name in DOWNLOADERS:
                return _r_monitor_feed(name)
            off = len(cmd.argv) - len(argv)
            raw = (cmd.rawx[off] if cmd.argv[off:] == argv and len(cmd.rawx) == len(cmd.argv)
                   else argv[0])
            if _run_time_name(raw):
                return _R_MONITOR_HIDDEN
            payload = (" ".join(argv[1:]) if name == "eval"
                       else _shell_payload(_base(argv[0]), argv[1:]))
            if payload:
                reason = _monitor_feed(payload, depth + 1)
                if reason:
                    return reason
    for _kind, body in ctx.subs:
        reason = _monitor_feed(body, depth + 1)
        if reason:
            return reason
    return None


def check(command: str, config: dict) -> str | None:
    """Return a one-line deny reason for this Bash command, or None to pass."""
    if not isinstance(command, str):
        return "launch gate: the Bash command isn't a string; blocked to be safe."
    if not isinstance(config, dict):
        return _r_config("the config must be a JSON object")
    try:
        allow = _allow_prefixes(config)
        ssh_hosts = _ssh_hosts(config)
    except ConfigError as exc:
        return _r_config(str(exc))
    if len(command) > MAX_COMMAND_CHARS:
        return _R_LONG
    forged = _PLACEHOLDER_RE.search(command)
    if forged:
        return _r_marker(forged.group(0))
    _BRACE_BUDGET[0] = MAX_BRACE_WORK
    return _check_text(command, _Ctx(allow, ssh_hosts), 0)


# -- hook entry point ------------------------------------------------------

def _on_alarm(signum, frame):  # pragma: no cover - exercised in a subprocess
    os.write(2, b"launch gate: timed out while checking; blocked to be safe.\n")
    os._exit(2)


def _deny(reason: str, *, event=None, code: str = "") -> int:
    log_deny(code or getattr(reason, "code", "launch-other"), event, _printable)
    print(reason.replace("\n", " "), file=sys.stderr)
    return 2


def _ask(reason: str, *, event=None, code: str) -> int:
    """Have Claude Code ask the user, with `reason` in the prompt."""
    log_deny(code, event, _printable, decision="ask")
    # Written and flushed here, inside main's try, so a failed write is
    # refused rather than left to the interpreter's exit.
    sys.stdout.write(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "ask",
        "permissionDecisionReason": reason}}) + "\n")
    sys.stdout.flush()
    return 0


def main() -> int:
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(TIMEOUT_SECONDS)
    event = None
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            return _deny("launch gate: hook input too large; blocked to be safe.",
                         code="launch-bad-input")
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return _deny("launch gate: hook input isn't valid JSON; blocked to be safe.",
                         code="launch-bad-input")
        if not isinstance(event, dict):
            return _deny("launch gate: hook input isn't a JSON object; blocked to be safe.",
                         code="launch-bad-input")
        tool = event.get("tool_name")
        if tool is not None and tool not in SHELL_TOOLS:
            return 0
        tool_input = event.get("tool_input")
        if tool == "Monitor" and isinstance(tool_input, dict):
            unknown = set(tool_input) - MONITOR_FIELDS
            if unknown:
                names = ", ".join(sorted(re.sub(r"[^A-Za-z0-9_]", "?", str(k))[:40]
                                         for k in unknown)[:10])
                return _deny(f"launch gate (Monitor): unknown input field ({names}); blocked "
                             "to be safe. A Claude Code update may have added it: update the "
                             "plugin, or report it.", event=event, code="launch-monitor-field")
            if "ws" in tool_input:
                return _deny(_R_MONITOR_WS, event=event)
        # Per-call hosts reach past the sandbox's network allowlist, for Bash
        # and Monitor alike: their names are checked here, and the user is asked
        # once every other check has passed.
        hosts = tool_input.get("allowed_domains") if isinstance(tool_input, dict) else None
        if hosts is not None and hosts != []:
            if not (isinstance(hosts, list) and 0 < len(hosts) <= MAX_DOMAINS
                    and all(_host_ok(h) for h in hosts)
                    and len(", ".join(hosts)) <= MAX_DOMAIN_TEXT):
                return _deny(_R_DOMAINS_BAD, event=event)
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        if not isinstance(command, str):
            return _deny(f"launch gate: no {tool or 'Bash'} command in the hook input; blocked "
                         "to be safe.", event=event, code="launch-bad-input")
        # A reader has no shell. If one ever reaches Bash (a tool loaded on
        # demand, a changed definition), it's refused whatever the command.
        agent = event.get("agent_type")
        if isinstance(agent, str) and agent.rsplit(":", 1)[-1] in READER_NAMES:
            return _deny(_r_reader(agent), event=event)
        config = load_config()
        reason = check(command, config)
        if not reason and tool == "Monitor":
            reason = _monitor_feed(command)
        # Refused inside the alarm, so a log write that stalls still blocks.
        if reason:
            return _deny(reason, event=event)
        if hosts:
            # Asked unless the user turned it off, only in a mode that shows the
            # prompt, and only from the main session: a subagent's own mode may
            # not be the one the event reports.
            if (not _ask_for_domains(config) or event.get("permission_mode") not in ASK_MODES
                    or event.get("agent_type")):
                return _deny(_R_DOMAINS, event=event)
            return _ask(_domains_prompt(tool or "Bash", sorted(set(hosts))), event=event,
                        code="launch-domains")
        return 0
    except ConfigError as exc:
        return _deny(_r_config(str(exc)), event=event)
    except Exception as exc:  # fail closed on anything unexpected
        return _deny(f"launch gate: internal error ({type(exc).__name__}); blocked to be safe.",
                     event=event, code="launch-internal")
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
