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
- the 7-day package lane turned off, shortened or cleared in the command's
  own words, judged by value (the common spellings): npm's
  ``min-release-age``, ``before`` and ``ignore-scripts`` as options, as
  ``npm config set``/``delete``/``edit``, or as ``npm_config_*`` variables
  (assigned or exported with a value it judges, passed through ``env``,
  unset, or dropped with ``env -i``, ``exec -c`` and the like; any other
  mention of a lane variable's name but a plain ``$NAME`` read is refused);
  uv's ``--exclude-newer`` or ``UV_EXCLUDE_NEWER`` under 7 days (a bare date
  as the end of that day); pip's and uv's options that turn on builds from
  source; pnpm, Yarn and Bun's own age settings, whose units differ, and
  their ways to let install scripts run; and such an option whose name is
  built at run time. ``--exclude-newer "7 days"``, a uv date 9 days ago and an
  npm ``--before`` date 8 days ago pass (the gate's margins: it can't know
  your time zone, so it reads a bare date at the latest zone that could hurt);
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
package.json script or code passed to ``python -c``, change the package
lane in an ``.npmrc`` or ``uv.toml`` file, write a script with the
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
the ssh or package-lane checks). ``launch_gate.ssh_hosts`` is a list of the hosts (as you type
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
from datetime import datetime, timedelta, timezone
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
# `+=` appends, and bash takes it before a command as it does `=`; `a[i]=`
# sets an element.
_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
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


_R_PRINT_UNREAD = _coded("launch-hidden-command", ("launch gate (rule 1): a command "
            "substitution in command position prints text the gate can't read (a "
            "`printf` or `echo` with an escape it doesn't decode, a `%` format, `\\c`, "
            "a NUL, a `printf` option such as `-v`, or a backslash in an `echo` with no "
            "`-e`), which hides what runs. Write the command out directly."))
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
_R_ARITH_UNREAD = _coded("launch-unparseable", ("launch gate (rule 1): a `$(( ))` here holds "
            "text the gate can't parse (an unbalanced quote or parenthesis), so it can't tell "
            "which commands the substitutions in it run; blocked to be safe. Fix the quoting."))
_R_ARITH_LONG = _coded("launch-too-deep", ("launch gate: the arithmetic in this command "
            "(`$(( ))`) is too long to read; blocked to be safe. Shorten it, or split it "
            "over several commands."))
_R_ARITH_COMMENT = _coded("launch-unparseable", ("launch gate (rule 1): arithmetic here "
            "(`$(( ))`, `(( ))` or `$[ ]`) holds a `#` that isn't a base prefix (`16#ff`), "
            "a line break, or (in `$[ ]`) a quote, which bash and the gate may read "
            "differently; blocked to be safe. Keep arithmetic on one line, with no `#` "
            "comment or quote in it."))
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


class _Refused(Exception):
    """A refusal found deep in parsing; check() returns its reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_R_WRAPPERS = _coded("launch-hidden-command", ("launch gate (rule 1): 32 or more wrappers "
            "or reserved words in a row, or 64 or more `env -S` strings, too many to check "
            "what runs; blocked to be safe. Write the command out directly."))
_R_ENV_SPLIT = _coded("launch-hidden-command", ("launch gate (rule 1): this `env -S` "
            "string holds `\\`, `#` or `$`, which env reads by its own rules, so the gate "
            "can't tell what runs. Write the command out directly."))


class _Ctx:
    """State shared across one check() call, including nested payloads."""

    def __init__(self, allow: list[list[str]], ssh_hosts: frozenset = frozenset()):
        self.allow = allow
        self.ssh_hosts = ssh_hosts   # empty: any host
        self.subs: list[tuple[str, str]] = []   # (kind, body); kind c=$(), p=<()
        self.vars: dict[str, str] = {}
        self.downloads: set[str] = set()
        self.date_defined = False   # the text defines its own `date`
        self.ifs_set = False        # the text sets IFS (other than as a plain read)
        # Substitutions that are whole arguments of an eval: the text eval
        # runs is their output, which the gate reads only if it can decode it
        # (see _hidden_in_substitutions; some forms stay a known gap under
        # `eval`).
        self.eval_args: set[str] = set()
        # Bash splits a word at IFS and at a space, tab or newline, and not at
        # a carriage return, a form feed or a vertical tab. The gate reads the
        # text that way first. Where a finer split (those three characters,
        # and white space IFS leaves out, also split) would read different
        # words, it sets `reread`, and check() reads the whole text again with
        # `fine` on, so a refusal in either reading stands. The same goes for
        # a printf format whose `\0ddd` reads differently as printf's (3 octal
        # digits) and as `echo -e`'s and %b's (a 0 and 3 more).
        self.fine = False
        self.reread = False
        self.dparen_work = 0    # characters read to tell `$(( ))` from `$( () )`

    def add_sub(self, kind: str, body: str) -> str:
        self.subs.append((kind, body))
        return f"__sd{kind}{len(self.subs) - 1}__"


def _paren_end(text: str, i: int, arith: bool = False) -> int:
    """Index of the ``)`` closing a group whose ``(`` ends just before i.
    Inside a ``((`` (and from the start with `arith`, for the text of an
    arithmetic expansion or command) bash reads no comments, so a ``#`` the
    scan would take as one, or a line break, is refused there; so is
    a ``$[ ]`` that holds one, which the scan steps over whole."""
    n, depth = len(text), 1
    regions = [1] if arith else []      # depths inside which the text is arithmetic
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "\n" and regions:
            raise _Refused(_R_ARITH_COMMENT)
        if c == "$" and text.startswith("$[", i):
            j = _bracket_end(text, i + 2)
            if _arith_unread(text[i + 2:j], bracket=True):
                raise _Refused(_R_ARITH_COMMENT)
            i = j + 1
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
            if regions:
                raise _Refused(_R_ARITH_COMMENT)
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "(":
            if text.startswith("((", i):
                regions.append(depth + 2)
            depth += 1
        elif c == ")":
            depth -= 1
            while regions and depth < regions[-1]:
                regions.pop()
            if depth == 0:
                return i
        i += 1
    raise _Unparseable("unbalanced parenthesis")


def _dollar_paren_end(text: str, i: int) -> int:
    """The index just past the `$( )` or `$(( ))` whose `$` is at i, read as
    _dparen reads it: arithmetic (no comment in it) when the second `(`'s
    closer is followed by a `)`, else a command substitution."""
    if text.startswith("$((", i):
        first = _paren_end(text, i + 3, arith=True)
        if _arith_unread(text[i + 3:first]):
            raise _Refused(_R_ARITH_COMMENT)
        if text[first + 1:first + 2] == ")":
            return first + 2
    return _paren_end(text, i + 2) + 1


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
            i = _dollar_paren_end(text, i)
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


def _arith_subs(body: str, ctx: _Ctx) -> None:
    """Register the substitutions inside the text of a `$(( ))`, as the shell
    runs them before it does the arithmetic (`$(( $(npx x) ))`). Quotes are
    not read: a substitution in single quotes inside arithmetic is a syntax
    error, and one the gate registers anyway can only make it refuse more. A
    piece it can't parse (an unbalanced quote or parenthesis) is refused: the
    gate can't tell which commands the substitutions in it run."""
    i, n = 0, len(body)
    try:
        while i < n:
            c = body[i]
            if c == "\\":
                i += 2
            elif c == "$" and body.startswith("$((", i):
                # A nested one is arithmetic or a command substitution, by
                # the same rule as the outer one.
                _, i = _dparen(body, i, ctx)
            elif c == "$" and body.startswith("$(", i):
                j = _paren_end(body, i + 2)
                ctx.add_sub("c", body[i + 2:j])
                i = j + 1
            elif c == "`":
                sub, i = _backtick(body, i + 1)
                ctx.add_sub("c", sub)
            else:
                i += 1
    except _Unparseable:
        raise _Refused(_R_ARITH_UNREAD) from None


_ARITH_WORD = "0"       # what an arithmetic expansion is read as: a number


def _arith_unread(body: str, bracket: bool = False) -> bool:
    """Whether the text of an arithmetic expansion or command holds what the
    gate and bash may read differently: a line break, or a `#` where one of
    the gate's two readers would take it as a comment and arithmetic has
    none: at the start of the body or after a blank, `\\r`, `;`, `&`, `|`,
    `(`, `)`, `<` or `>` (_paren_end reads one after a blank, `;`, `&`, `|`
    or `(`; _lex, for a `((` command, one wherever its word is empty).
    After any other character it passes (`16#ff`, `$#`, `${#x}`, `${x#0}`,
    `${n##0}`, `${base}#ff`). With `bracket` (a `$[ ]`, whose closer
    the gate finds without reading quotes), a quote too."""
    if "\n" in body or (bracket and any(q in body for q in "'\"`")):
        return True
    for k, c in enumerate(body):
        if c == "#" and (k == 0 or body[k - 1] in _ARITH_COMMENT_AFTER):
            return True
    return False


_ARITH_COMMENT_AFTER = frozenset(" \t\r\n;&|()<>")


def _bracket_end(text: str, i: int) -> int:
    """Index of the `]` closing the `$[` whose `[` ends just before i (the
    brackets counted, nothing else read)."""
    depth, n = 1, len(text)
    while i < n:
        c = text[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise _Unparseable("unbalanced $[")


def _dparen(text: str, i: int, ctx: _Ctx) -> tuple[str, int]:
    """(the word text it makes, the index after) for the `$((` at i. Bash
    reads `$((` as arithmetic only when the `)` that closes the second `(` is
    followed at once by a `)`; otherwise the whole `$( ... )` is a command
    substitution that runs as a command (`$((npx x) )`, `$((1)+(2))`).
    Arithmetic is "0", with the substitutions in it registered; a command
    substitution is registered whole and gives its placeholder."""
    first = _paren_end(text, i + 3, arith=True)     # closes the second `(`
    ctx.dparen_work += first - i
    if ctx.dparen_work > MAX_ARITH_WORK:
        raise _Refused(_R_ARITH_LONG)
    # _paren_end reads a `#` after a blank as a comment, and bash's arithmetic
    # doesn't: the closer it finds may be lines later. Text with such
    # a `#`, or a line break, is refused, whichever way it ends.
    if _arith_unread(text[i + 3:first]):
        raise _Refused(_R_ARITH_COMMENT)
    if text[first + 1:first + 2] == ")":
        _arith_subs(text[i + 3:first], ctx)
        return _ARITH_WORD, first + 2
    j = _paren_end(text, i + 2)
    return ctx.add_sub("c", text[i + 2:j]), j + 1


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
            made, i = _dparen(text, i, ctx)
            buf.append(made)
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
            _, i = _dparen(body, i, ctx)
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
            made, i = _dparen(text, i, ctx)
            word.append(made)
            continue
        if c == "$" and text.startswith("$[", i):
            # Old-style arithmetic: bash reads it to its `]` with no comment
            # in it; the gate reads it as a number, with its substitutions
            # registered.
            j = _bracket_end(text, i + 2)
            if _arith_unread(text[i + 2:j], bracket=True):
                raise _Refused(_R_ARITH_COMMENT)
            _arith_subs(text[i + 2:j], ctx)
            word.append(_ARITH_WORD)
            i = j + 1
            continue
        if c == "(" and text.startswith("((", i):
            # An arithmetic command (or two subshells): bash reads no comment
            # and no line break in it. The words are read as before.
            first = _paren_end(text, i + 2, arith=True)
            ctx.dparen_work += first - i
            if ctx.dparen_work > MAX_ARITH_WORK:
                raise _Refused(_R_ARITH_LONG)
            if _arith_unread(text[i + 2:first]):
                raise _Refused(_R_ARITH_COMMENT)
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
        if c == "\r" and not ctx.fine:
            # Bash doesn't split a word at a carriage return: it is part of
            # the word. check() also reads the text with it as a separator.
            ctx.reread = True
            word.append(c)
            i += 1
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
    # One raw word: only a space, tab or newline (none outside quotes) would
    # end it, so a carriage return stays in it, as it does in bash.
    lexer = shlex.shlex(raw, posix=True)
    lexer.whitespace_split = True
    lexer.whitespace = " \t\n"
    lexer.commenters = ""
    try:
        parts = list(lexer)
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


_ENV_LONG = ("--ignore-environment", "--null", "--unset", "--chdir", "--split-string",
             "--argv0", "--block-signal", "--default-signal", "--ignore-signal",
             "--list-signal-handling", "--debug", "--help", "--version")


def _strip_env(args: list[str], seen: list | None = None) -> list[str]:
    """env's words from the command on. env takes every word with a `=` before
    the command as an assignment, whatever its name (`env a-b=1 cmd`). When
    `seen` is a list, the assignments, unsets and environment clears go in it
    as ("set", word), ("unset", name) and ("clear", "")."""
    def note(kind: str, word: str = "") -> None:
        if seen is not None:
            seen.append((kind, word))

    i = 0
    for _ in range(64):     # each -S takes the place of its own words
        split = None
        while i < len(args):
            a = args[i]
            if a == "--":
                i += 1
                break
            if a == "-":
                note("clear")
                i += 1
            elif a.startswith("--"):
                opt, eq, value = a.partition("=")
                # env takes a long option by any prefix only one option has.
                names = [o for o in _ENV_LONG if o.startswith(opt)]
                if len(names) == 1:
                    opt = names[0]
                if opt == "--ignore-environment":
                    note("clear")
                if opt in ("--unset", "--chdir", "--split-string", "--argv0") and not eq:
                    value = args[i + 1] if i + 1 < len(args) else ""
                    i += 1
                i += 1
                if opt == "--unset":
                    note("unset", value)
                elif opt == "--split-string":
                    split = value
                    break
            elif a.startswith("-"):
                i += 1
                for j in range(1, len(a)):
                    c = a[j]
                    if c == "i":
                        note("clear")
                    elif c in "uCSaPLU":    # P, L, U: BSD env's options with a value
                        value = a[j + 1:]
                        if not value:
                            value = args[i] if i < len(args) else ""
                            i += 1
                        if c == "u":
                            note("unset", value)
                        elif c == "S":
                            split = value
                        break
                if split is not None:
                    break
            else:
                break
        if split is None:
            break
        if any(c in split for c in "\\#$") or _PLACEHOLDER_RE.search(split):
            raise _Refused(_R_ENV_SPLIT)
        args, i = _split(split) + args[i:], 0
    else:
        raise _Refused(_R_WRAPPERS)
    while i < len(args) and "=" in args[i]:
        note("set", args[i])
        i += 1
    return args[i:]


def _strip_exec(args: list[str], seen: list | None = None) -> list[str]:
    """exec's words from the command on: `-a name` takes a value, also at the
    end of a group (`-ca name`), and `-c` runs the command with an empty
    environment."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1:]
        if not a.startswith("-") or a == "-":
            return args[i:]
        i += 1
        for j in range(1, len(a)):
            if a[j] == "c" and seen is not None:
                seen.append(("clear", ""))
            elif a[j] == "a":
                if j == len(a) - 1:
                    i += 1
                break
    return []


def _strip_wrappers(argv: list[str], seen: list | None = None) -> list[str]:
    """Drop leading assignments, reserved words and wrapper commands. When
    `seen` is a list, the assignments dropped go in it as ("set", word), with
    env's unsets and environment clears (see _strip_env)."""
    argv = list(argv)
    for _ in range(32):
        while argv and _ASSIGN_RE.match(argv[0]):
            word = argv.pop(0)
            if seen is not None:
                seen.append(("set", word))
        if not argv:
            return argv
        if argv[0] in RESERVED_WORDS:
            if argv.pop(0) == "time":
                while argv and argv[0] in ("-p", "--"):
                    argv.pop(0)         # the keyword's own options
            continue
        name = _base(argv[0])
        rest = argv[1:]
        if name == "env":
            argv = _strip_env(rest, seen)
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
            argv = _strip_exec(rest, seen)
        elif name in ("nohup", "builtin", "busybox"):
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
    # Out of rounds with a wrapper still in front: what runs is unchecked.
    raise _Refused(_R_WRAPPERS)


# -- the 7-day package lane (rule 2) -----------------------------------------
#
# The settings template sets npm_config_min_release_age=7 and
# npm_config_ignore_scripts=true for the commands Claude Code runs. These
# checks refuse a command whose own words turn that off, shorten it or clear
# it, judged by value: the same setting with a value that keeps the lane
# passes, and so does uv's `--exclude-newer "7 days"`. A value the gate can't
# read (a `$`, a substitution, a form it doesn't parse) is refused.
# launch_gate.allow never relaxes them. They read no files and no run-time
# values, so a script, a Makefile, a package.json script, an .npmrc or
# uv.toml, pnpm, Yarn and Bun's config files, and a command built at run
# time all get past them; the tests list the rows.

LANE_DAYS = 7


def _now() -> datetime:
    """The time the lane's ages count back from; the tests replace it."""
    return datetime.now(timezone.utc)


_DAYS_RE = re.compile(r"\d{1,6}(?:\.\d{1,6})?")
_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?"
                      r"(?:([Zz])|([+-])(\d{2}):?(\d{2}))?)?")
_SPAN_RE = re.compile(r"(\d{1,7}) ?(h|hours?|d|days?|w|weeks?)", re.I)
_ISO_SPAN_RE = re.compile(r"P(?:(\d{1,6})([DW])|T(\d{1,7})H)", re.I)
_SPAN_HOURS = {"h": 1, "d": 24, "w": 168}


def _lane_days(value: str) -> bool:
    return bool(_DAYS_RE.fullmatch(value)) and float(value) >= LANE_DAYS


def _lane_date(value: str, day_end: bool = False) -> bool:
    """A date or time at least LANE_DAYS ago, read the latest way the tool
    could read it. A time with no offset is local, so it's read as the
    latest zone's (UTC-12). A bare date is midnight UTC, as npm read it
    (a probe of npm 11.20.0, 2026-10-28), or with `day_end` the
    end of that day in the latest zone, as uv 0.11.32 read it (the end of
    the local day; a probe, 2026-10-28)."""
    m = _DATE_RE.fullmatch(value)
    if not m:
        return False
    y, mo, d, hh, mi, ss, z, sign, oh, om = m.groups()
    try:
        when = datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0),
                        int(ss or 0), tzinfo=timezone.utc)
        if sign:
            if int(oh) > 14 or int(om) > 59:
                return False
            offset = timedelta(hours=int(oh), minutes=int(om))
            when = when - offset if sign == "+" else when + offset
        elif hh is not None and not z:
            when += timedelta(hours=12)
        elif hh is None and day_end:
            when += timedelta(days=1, hours=12)
    except (ValueError, OverflowError):
        return False
    return when <= _now() - timedelta(days=LANE_DAYS)


def _lane_uv(value: str) -> bool:
    """uv's --exclude-newer: a span of at least LANE_DAYS days (`7 days`,
    `1 week`, `168h`, `P7D`, `PT168H`), or a date."""
    value = value.strip()
    m = _SPAN_RE.fullmatch(value)
    if m:
        hours = int(m.group(1)) * _SPAN_HOURS[m.group(2)[0].lower()]
        return hours >= LANE_DAYS * 24
    m = _ISO_SPAN_RE.fullmatch(value)
    if m:
        hours = (int(m.group(3)) if m.group(3)
                 else int(m.group(1)) * _SPAN_HOURS[m.group(2).lower()])
        return hours >= LANE_DAYS * 24
    return _lane_date(value, day_end=True)


def _lane_true(value: str) -> bool:
    # npm read `TRUE` from the environment as not true (a probe of
    # npm 11.20.0, 2026-10-28), so only the exact word passes.
    return value == "true"


def _lane_false(value: str) -> bool:
    return value == "false"


def _lane_all(value: str) -> bool:
    return value == ":all:"


# npm's settings: the test a value must pass, or None to refuse every value.
_NPM_LANE = {"min-release-age": _lane_days, "before": _lane_date,
             "ignore-scripts": _lane_true, "min-release-age-exclude": None}
# Environment names, lower-cased with `-` read as `_` (npm reads its names
# that way): (the setting's name for the refusal, the test).
_LANE_ENV = {"npm_config_" + k.replace("-", "_"): (k, t) for k, t in _NPM_LANE.items()}
_LANE_ENV.update({
    "uv_exclude_newer": ("exclude-newer", _lane_uv),
    "uv_exclude_newer_package": ("exclude-newer-package", None),
    # pip and uv building from source, which runs the package's own code
    "pip_no_binary": ("no-binary", None), "pip_only_binary": ("only-binary", _lane_all),
    "uv_no_binary": ("no-binary", None), "uv_no_binary_package": ("no-binary", None),
    # pnpm, Yarn and Bun count age in other units, and the lane sets none of
    # them, so any age setting of theirs is refused; their scripts stay off.
    "pnpm_config_ignore_scripts": ("ignore-scripts", _lane_true),
    "pnpm_config_dangerously_allow_all_builds": ("dangerously-allow-all-builds", None),
    "npm_config_dangerously_allow_all_builds": ("dangerously-allow-all-builds", None),
    "npm_config_minimum_release_age": ("minimum-release-age", None),
    "npm_config_minimum_release_age_exclude": ("minimum-release-age", None),
    "pnpm_config_minimum_release_age": ("minimum-release-age", None),
    "pnpm_config_minimum_release_age_exclude": ("minimum-release-age", None),
    "yarn_npm_minimal_age_gate": ("npmMinimalAgeGate", None),
    "yarn_enable_scripts": ("enableScripts", _lane_false),
    # bash starts in `keyword` mode from it, which makes a `NAME=x` word
    # anywhere in a command an assignment (see _keyword_mode)
    "shellopts": ("SHELLOPTS", None),
})
_NPM_FAMILY = frozenset({"npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx"})
_UV_FAMILY = frozenset({"uv", "uvx"})
_PIP_RE = re.compile(r"pip[0-9.]*")
_DECLARE = frozenset({"export", "declare", "typeset", "readonly", "local", "unset"})
# Builtins that set the variables they name: read, mapfile and the rest.
_NAME_SETTERS = frozenset({"read", "mapfile", "readarray", "getopts", "let"})
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Any lane variable's name in the text, `-` or `_`, any case, as a whole word.
_LANE_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    + "|".join(k.replace("_", "[-_]") for k in sorted(_LANE_ENV, key=len, reverse=True))
    + r")(?![A-Za-z0-9_])", re.I)
# Arithmetic, `let`, `[[ ]]`, an array subscript and a ${x:offset:length}
# assign through a `$` expansion of any kind (`$1`, `${!p}`, `$a$b`) that is
# followed by `=` (or `+=`, `++`, `--` and the like), so a lane name built from
# parts is set without being in the text. Only the text inside the construct
# itself is read (see _arith_spans), not what follows it. In `[[ ]]` a spaced
# `=` compares strings, so there only a glued one counts, or one inside a
# quoted word (a `-eq` operand is arithmetic: `[[ "$a$b = 0" -eq 0 ]]`).
_DYN_EXPANSION = (r"(?:\$(?:\{[^}]{0,256}\}|\([^()]{0,256}\)|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])"
                  r"|`[^`]{0,256}`)")
_DYN_ASSIGN_RE = re.compile(
    _DYN_EXPANSION + r"\s*(?:(?:[-+*/%&|^]|<<|>>)?=(?!=)|\+\+|--)|(?:\+\+|--)\s*" + _DYN_EXPANSION)
_DYN_GLUED_RE = re.compile(_DYN_EXPANSION + r"(?:[-+*/%&|^]|<<|>>)?=(?!=)")
# A `${` whose braces are too long to read with the patterns above is refused.
_LONG_BRACE_RE = re.compile(r"\$\{[^}]{257}")
_OPENER_RE = re.compile(
    r"\(\(|\$\[|\[\[|(?<!\w)let(?=[\s\"'$\\])|(?<!\w)[A-Za-z_]\w*\[|"
    r"\$\{[!#]?[A-Za-z_]\w*:(?![-+=?])")
MAX_ARITH_WORK = 300_000    # characters of arithmetic and tests it reads; past it, refused
# Words that a `let` may follow and still be a command (`then let ...`).
_LET_AFTER = frozenset({"then", "do", "else", "elif", "if", "while", "until", "time",
                        "builtin", "command", "exec", "eval", "nohup", "trap", "!", "-c"})
_LET_BREAK = " \t\n;&|(){}\"'`"
# Text that may change which `date` runs: a function (also one a quoted
# string defines, for `eval` to run), PATH, `hash -p`, an alias or `enable`.
# (Some other ways to define one stay a known gap, since ordinary work
# sources files.)
_DATE_FUNC_RE = re.compile(r"(?:^|[\s;&|(){}'\"`])(?:function\s+date\b|date\s*\(\s*\))"
                           r"|\bPATH\+?=|\bhash\b[^;&|\n]*\s-p|\balias\b|\benable\b")
_TEST_STOP_RE = re.compile(r"\]\]|\$'|\$\(|[\\\"'`]")
_TEST_UNREAD = []       # _arith_spans' answer for a `[[` it can't step through
_R_TEST_UNREAD = _coded("launch-unparseable", ("launch gate (rule 1): a `[[ ]]` test here "
            "holds a `$'..'`, a substitution or a quoted string the gate can't step over "
            "exactly, so it can't tell where the test ends; blocked to be safe. Put the "
            "value in a variable first, or end the test before it."))
_LET_STOP_RE = re.compile(r"[;&|\n)\\\"']")


def _after_quotes(text: str, i: int) -> int:
    """The index just past the quoted string whose opening quote is at i, or
    len(text) if it never closes."""
    q = text[i]
    n = len(text)
    i += 1
    while i < n:
        j = text.find(q, i)
        if j < 0:
            return n
        if q == '"':
            k, back = j - 1, 0
            while k >= i and text[k] == "\\":
                k, back = k - 1, back + 1
            if back % 2:
                i = j + 1
                continue
        return j + 1
    return n


_BRACKET_STOP_RE = re.compile(r"[\[\]\"'`]")
_PAREN_STOP_RE = re.compile(r"[()\"'`]")
_BRACE_STOP_RE = re.compile(r"[{}\"'`]")


def _balanced_end(text: str, i: int, depth: int, stop: re.Pattern, up: str, down: str,
                  quotes_end: bool) -> int:
    """The index past the closer that ends `depth` open brackets, from i. A
    quote or backtick inside either ends the span at the end of the text
    (`quotes_end`: arithmetic holds none, so what it holds is not read), or
    is skipped (a subscript or a ${x:..}, where quotes are ordinary)."""
    n = len(text)
    while True:
        m = stop.search(text, i)
        if not m:
            return n
        c = m.group(0)
        if c == up:
            depth += 1
        elif c == down:
            depth -= 1
            if depth <= 0:
                return m.end()
        elif quotes_end or c == "`":
            return n
        else:
            i = _after_quotes(text, m.start())
            continue
        i = m.end()


def _let_is_command(text: str, i: int) -> int | None:
    """Where the quoted string that `let` opens starts (the index of the quote,
    -1 for none) if `let` at i is a command word, else None."""
    k, quote = i, -1
    if k > 0 and text[k - 1] in "\"'":
        quote = k - 1
        k -= 1
    while k > 0 and text[k - 1] in " \t":
        k -= 1
    if k == 0 or text[k - 1] in ";&|(\n{`":
        return quote
    j = k
    while j > 0 and k - j < 12 and text[j - 1] not in _LET_BREAK:
        j -= 1
    return quote if text[j:k] in _LET_AFTER else None


def _arith_spans(text: str) -> list[tuple[int, int, str]] | None:
    """(start, end, kind) of each place the text does arithmetic or a test
    with operands that bash evaluates as arithmetic: `(( ))` and `$(( ))`,
    `$[ ]`, `[[ ]]`, the words of `let`, an array subscript (`x[...]`) and
    a substring's offset (`${x: ...}`). kind is "a" (arithmetic) or "t" (a
    test). Only the ones that hold a `$` or a lane name are returned. None
    if they add up to more than MAX_ARITH_WORK characters. A span that never
    closes runs to the end of the text and is read as arithmetic, the
    strictest kind. What follows it is inside it, so it ends the search only
    because a later span could add nothing. (A `[[` that never closes is not
    such a span: it is text, or a syntax error that runs nothing, and the
    search goes on past it.)"""
    spans: list[tuple[int, int, str]] = []
    n = len(text)
    work = 0
    for m in _OPENER_RE.finditer(text):
        o = m.group(0)
        s = m.start()
        if o == "((":
            end, kind = _balanced_end(text, m.end(), 2, _PAREN_STOP_RE, "(", ")", True), "a"
        elif o == "$[":
            end, kind = _balanced_end(text, m.end(), 1, _BRACKET_STOP_RE, "[", "]", True), "a"
        elif o == "[[":
            end, i, kind = n, m.end(), None
            while True:
                q = _TEST_STOP_RE.search(text, i)
                if not q:
                    break
                c = q.group(0)
                if c == "]]":
                    end, kind = q.end(), "t"
                    break
                if c == "\\":
                    i = q.end() + 1
                    continue
                if c == "'":
                    i = _after_quotes(text, q.start())
                    continue
                # A `$'..'`, a substitution or a double-quoted string (which
                # may hold one) is stepped over the way the gate's parser
                # reads it, never by a guess. One that never closes
                # makes a `[[` that never closes (below); one the parser
                # refuses is refused.
                try:
                    if c == "$'":
                        i = _ansi_c(text, q.end())[1]
                    elif c == "$(":
                        i = _dollar_paren_end(text, q.start())
                    elif c == "`":
                        i = _backtick(text, q.end())[1]
                    else:
                        i = _skip_double(text, q.end())
                except _Unparseable:
                    break
                except _Refused:
                    return _TEST_UNREAD
            if kind is None:
                # One that never closes is text (`echo [[`, a grep for it) or
                # a syntax error that runs nothing, so it holds nothing: the
                # search goes on for later openers (`echo [[; (( $a$b = 0 ))`
                # is still read at its `((`). What it read counts as work.
                work += n - s
                if work > MAX_ARITH_WORK:
                    return None
                continue
        elif o == "let":
            quote = _let_is_command(text, s)
            if quote is None:
                continue
            if quote >= 0:
                end = _after_quotes(text, quote)
            else:
                end, i = n, m.end()
                while True:
                    q = _LET_STOP_RE.search(text, i)
                    if not q:
                        break
                    c = q.group(0)
                    if c == "\\":
                        i = q.end() + 1
                    elif c in "\"'":
                        i = _after_quotes(text, q.start())
                    else:
                        end = q.start()
                        break
            kind = "a"
        elif o.startswith("${"):
            end, kind = _balanced_end(text, m.end(), 1, _BRACE_STOP_RE, "{", "}", False), "a"
            s = m.end()
        else:       # name[
            end, kind = _balanced_end(text, m.end(), 1, _BRACKET_STOP_RE, "[", "]", False), "a"
            s = m.end() - 1
        work += end - s
        if work > MAX_ARITH_WORK:
            return None
        if "$" in text[s:end] or _LANE_NAME_RE.search(text, s, end):
            spans.append((s, end, kind))
        if end >= n and kind == "a":
            # A span that never closes, or that ends the text, is arithmetic
            # to the end of the text, which holds every opener after it: none
            # needs a span of its own.
            break
    return spans


def _lane_text(text: str) -> str | None:
    """A lane variable's name anywhere in the text is judged here first. It
    may appear only as a plain read (`$NAME`, `${NAME}`) or at the start of
    an assignment-shaped word (`NAME=`, `NAME+=`, `NAME[`), which the checks
    below judge where bash would assign it. Any other mention (a loop or
    `read` naming it, arithmetic, `${NAME:=x}`, a reference, coproc, `wait
    -p`, an element index, a name glued to a `$`) is refused: bash has too
    many ways to set a variable to list them all. Text that merely mentions
    a name (a grep, a heredoc, a commit message) is refused too; the tests
    list that trade."""
    spans = _arith_spans(text)
    if spans is None:
        return _R_LANE_NAME
    if spans is _TEST_UNREAD:
        return _R_TEST_UNREAD
    for s, e, kind in spans:
        if _LONG_BRACE_RE.search(text, s, e):
            return _R_LANE_NAME
        if kind == "a":
            if _DYN_ASSIGN_RE.search(text, s, e):
                return _R_LANE_NAME
        else:
            if _DYN_GLUED_RE.search(text, s, e):
                return _R_LANE_NAME
            for q in re.finditer(r"\"[^\"]*\"|'[^']*'", text[s:e]):
                if _DYN_ASSIGN_RE.search(q.group(0)):
                    return _R_LANE_NAME
    # Inside arithmetic, `[[ ]]` or `let`, `NAME=` assigns too
    # (`[[ 1 -eq NAME=1 ]]`), so only a plain read passes there.
    for m in _LANE_NAME_RE.finditer(text):
        s, e = m.start(), m.end()
        before, after = text[s - 1:s], text[e:e + 2]
        if before == "$" and not text[e:e + 1] == "[":
            continue                                    # $NAME
        if text[s - 2:s] == "${" and (after[:1] == "}" or after in (":-", ":+", ":?")
                                      or after[:1] in ("-", "+", "?", "#", "%", "/", "^", ",", "@")):
            # ${NAME}, and the forms that only read it: ${NAME:-x}, ${NAME+x},
            # ${NAME#p}, ${NAME/a/b}. ${NAME:=x} and ${NAME=x} assign, so
            # they fall through. (A nested ${NAME:=x} is judged on its own.)
            continue
        arith = any(a <= s < b for a, b, _k in spans)
        if not arith and (before in ("", ";", "&", "|", '"', "'") or before.isspace()) and (
                after[:1] in ("=", "[") or after == "+="):
            continue                                    # NAME=..., judged below
        return _R_LANE_NAME
    return None


def _r_lane(setting: str) -> str:
    return _coded("launch-lane-override", (f"launch gate (rule 2): this turns off, shortens or "
            f"clears `{setting}`, a setting of the 7-day package lane (release age, install "
            "scripts, source builds), or gives it a value the gate can't read. Keep the "
            "lane's settings; for uv use `--exclude-newer \"7 days\"` or, on a uv that "
            "doesn't take durations, a date 9 days ago (`\"$(date -d '9 days ago' +%F)\"`). "
            "A package that can't wait, or needs its install scripts or a source "
            "build, is the user's call: ask them."))


_R_LANE_CLEAR = _coded("launch-lane-override", ("launch gate (rule 2): this runs a command "
            "with its environment cleared (`env -i`, `exec -c`), which drops the 7-day "
            "package lane's settings. Run it without clearing, or remove only the names "
            "you need with `env -u`."))
_R_LANE_UNREAD = _coded("launch-lane-override", ("launch gate (rule 2): an option of this "
            "package manager is built at run time (a `$` or a substitution), so the gate "
            "can't tell whether it turns off the 7-day package lane. Write the option out."))
_R_LANE_NAME = _coded("launch-lane-override", ("launch gate (rule 2): this names a variable "
            "of the 7-day package lane (`npm_config_*`, `UV_EXCLUDE_NEWER` and the like) "
            "other than as a plain read (`$NAME`) or an assignment the gate can judge, or "
            "assigns through a name built at run time, and bash has many ways to set a "
            "variable. Read it as `$NAME`, or ask the user."))
_R_LANE_ATTR = _coded("launch-lane-override", ("launch gate (rule 2): `declare`, `typeset` or "
            "`local` with `-i` or `-n` makes later assignments arithmetic or follow a name, "
            "which can set a variable of the 7-day package lane by a name the gate can't read. "
            "Don't use those options, or ask the user."))
_R_LANE_KEYWORD = _coded("launch-lane-override", ("launch gate (rule 2): bash's `keyword` mode "
            "(`set -k`, `set -o keyword`, a shell run with `-k`) makes every `NAME=value` word "
            "of a command an assignment, which can set a variable of the 7-day package lane "
            "where the gate doesn't look. Don't turn it on, or ask the user."))


def _lane_entry(name: str):
    return _LANE_ENV.get(name.lower().replace("-", "_"))


_DATE_AGO_RE = re.compile(r"(\d{1,6}) ?(days?|weeks?) ago|-(\d{1,6}) ?(days?|weeks?)")
_DATE_BSD_RE = re.compile(r"-v-(\d{1,6})([dw])")


def _lane_value(value: str, ctx: _Ctx, ahead: bool = False) -> str:
    """The value as the lane's tests read it. A whole value that is
    `$(date -d 'N days ago' +%F)` (or `-d '-N days'`, BSD's `-v-Nd`, `+%Y-%m-%d`,
    `-I`, or with `-u` `+%Y-%m-%dT%H:%M:%SZ`) reads as that date in UTC. A
    `date` without `-u` prints the user's own calendar day, which east of UTC
    can be a day ahead (up to UTC+14); with `ahead` it's read at that latest
    zone. That's for a test that reads a bare date in UTC (npm's `before`,
    where `date` and npm use different zones). uv reads a bare date in the
    zone `date` prints it in, which its own end-of-day reading (UTC-12)
    already covers, so uv's tests leave `ahead` off. Any other substitution,
    or one in a command that defines its own `date`, stays unreadable."""
    m = _PLACEHOLDER_RE.fullmatch(value)
    sub = _sub_body(value, ctx) if m else None
    if not sub or sub[0] != "c" or ctx.date_defined:
        return value
    words = _split(sub[1])
    if not words or words[0] != "date":
        return value
    days = fmt = None
    utc = False
    # GNU date takes -d and BSD date (macOS) takes -v; the other one prints
    # nothing, so each counts only where it runs.
    bsd = sys.platform == "darwin" or "bsd" in sys.platform
    i = 1
    while i < len(words):
        w = words[i]
        ago = None
        if w in ("-u", "--utc"):
            utc = True
        elif w in ("-d", "--date") and i + 1 < len(words):
            i += 1
            ago = words[i]
        elif w.startswith("--date="):
            ago = w[len("--date="):]
        elif _DATE_BSD_RE.fullmatch(w) and days is None and bsd:
            b = _DATE_BSD_RE.fullmatch(w)
            days = int(b.group(1)) * (7 if b.group(2) == "w" else 1)
        elif w.startswith("-d") and len(w) > 2:
            ago = w[2:]
        elif w in ("+%F", "+%Y-%m-%d", "-I", "--iso-8601", "--iso-8601=date") and fmt is None:
            fmt = "%Y-%m-%d"
        elif w == "+%Y-%m-%dT%H:%M:%SZ" and fmt is None:
            fmt = w[1:]
        else:
            return value
        if ago is not None:
            a = _DATE_AGO_RE.fullmatch(ago)
            if not a or days is not None or bsd:
                return value
            n, unit = (a.group(1), a.group(2)) if a.group(1) else (a.group(3), a.group(4))
            days = int(n) * (7 if unit[0] == "w" else 1)
        i += 1
    # Without -u, date prints local time with the Z, which isn't UTC.
    if days is None or not fmt or (fmt.endswith("Z") and not utc):
        return value
    try:
        now = _now() + (timedelta(hours=14) if ahead and not utc else timedelta(0))
        return (now - timedelta(days=days)).strftime(fmt)
    except (OverflowError, ValueError):
        return value


def _lane_assign(word: str, ctx: _Ctx) -> str | None:
    """`NAME=value`, `NAME+=value` or `NAME[i]=value` on a lane variable. An
    append, or an element (which makes the variable an array, and bash
    doesn't export arrays), is refused whatever the value."""
    name, _, value = word.partition("=")
    whole = name.rstrip("+").split("[", 1)[0]
    entry = _lane_entry(whole)
    if entry and (entry[1] is None or name != whole
                  or not entry[1](_lane_value(value, ctx, entry[1] is _lane_date))):
        return _r_lane(entry[0])
    return None


def _lane_seen(seen: list, ctx: _Ctx) -> str | None:
    """Check the assignments, unsets and clears _strip_wrappers saw. Every
    clear is refused: what it runs may run a package manager in turn."""
    for kind, word in seen:
        if kind == "clear":
            return _R_LANE_CLEAR
        # (An element's subscript may hold a run-time part: `arr[$i]=x`. The
        # name before it can't, or the gate can't tell which variable it is.)
        name = word.partition("=")[0].split("[", 1)[0]
        if "$" in name or _PLACEHOLDER_RE.search(name):
            return _R_LANE_UNREAD       # `env $n=false`, `env -u $n`: which name?
        if kind == "set":
            reason = _lane_assign(word, ctx) or _prompt_assign(word, ctx)
            if reason:
                return reason
        else:
            entry = _lane_entry(word)
            if entry:
                return _r_lane(entry[0])
    return None


def _npm_lane_key(flag: str) -> str | None:
    if flag in _NPM_LANE:
        return flag
    keys = [k for k in _NPM_LANE if len(flag) >= 2 and k.startswith(flag)]
    if not keys:
        return None
    # npm 11.20.0 took a long option by a prefix only it has (`--ig=false`,
    # `--be`; a probe, 2026-10-28). Read one the strictest way.
    return "min-release-age-exclude" if "min-release-age-exclude" in keys else keys[0]


MAX_EXPANDED_CHARS = 20_000     # the longest word a known variable may grow into
MAX_EXPAND_ROUNDS = 8
_IFS_DEFAULT = " \t\n"
# A mention of IFS that isn't a read (`$IFS`, `${IFS}`, `${IFS:0:1}`): an
# assignment, `read IFS`, `export IFS=:`, `local IFS`.
# (`IFS=` with an empty value can't add a split, so `IFS= read -r line` passes.)
_IFS_SET_RE = re.compile(r"(?<![$\w{])IFS(?!\w)(?!=(?:[\s;&|)]|$))")
# `IFS=value command`: an assignment that only prefixes a command. Bash puts
# it in that command's environment after it has expanded the command's words,
# so it splits no later word. (A prefix of eval, source, command, builtin or
# exec reaches the text they run, and so does one in a text that defines a
# function; those still count as setting IFS. So does one before any of
# bash's special builtins, whatever the mode: in posix mode the assignment
# stays set after it. `.` and `:` don't match the pattern's name, so
# they count too.)
_IFS_VALUE = r"(?:'[^']*'|\"[^\"$`\\]*\"|[^\s;&|()<>\"'`$\\]*)"
_IFS_PREFIX_RE = re.compile(r"IFS=" + _IFS_VALUE + r"(?:[ \t]+[A-Za-z_]\w*=" + _IFS_VALUE
                            + r")*[ \t]+([A-Za-z][A-Za-z0-9_.+-]*)(?=[\s;&|)]|$)")
_SPECIAL_BUILTINS = frozenset({"shift", "set", "export", "readonly", "unset", "eval", ".",
                               "source", "exec", "trap", "return", "break", "continue",
                               "exit", "times", ":"})
_IFS_PREFIX_UNSAFE = frozenset({"command", "builtin"}) | _SPECIAL_BUILTINS
_FUNCTION_RE = re.compile(r"\(\s*\)|(?<![\w-])function\s")
_COMMAND_START_WORDS = frozenset({"do", "then", "else", "elif", "if", "while", "until", "time"})


def _starts_command(command: str, s: int) -> bool:
    """Whether the word at s starts a command: it follows the start of the
    text, a newline or one of `;&|({`, or one of the words a command may
    follow (`while IFS=, read ...`)."""
    lo = max(0, s - 64)         # (a window, so many mentions cost little)
    before = command[lo:s].rstrip(" \t")
    if not before:
        return lo == 0          # blanks all the way back; more than 64 of them: unknown
    if before[-1] in ";&|({\n":
        return True
    word = re.search(r"(?:^|[^\w-])([A-Za-z]+)$", before[-12:])
    return bool(word) and word.group(1) in _COMMAND_START_WORDS


def _sets_ifs(command: str) -> bool:
    """Whether the text sets IFS in a way that reaches later words: any
    mention of IFS that isn't a read (`$IFS`) or an empty assignment, except
    `IFS=value command` as a prefix of a command that runs no shell text."""
    functions = bool(_FUNCTION_RE.search(command))
    for m in _IFS_SET_RE.finditer(command):
        prefix = _IFS_PREFIX_RE.match(command, m.start())
        if (prefix and not functions and prefix.group(1) not in _IFS_PREFIX_UNSAFE
                and _starts_command(command, m.start())):
            continue
        return True
    return False


def _ifs(ctx: _Ctx) -> str:
    """The characters bash splits a word on: white space unless the call sets
    IFS. If it sets IFS some way the gate can't read (anything but a plain
    assignment), the call is refused where the gate needs to split a word."""
    if "IFS" in ctx.vars:
        value = ctx.vars["IFS"]
        if "$" in value or _PLACEHOLDER_RE.search(value):
            raise _Refused(_R_LANE_UNREAD)
        return value
    if ctx.ifs_set:
        raise _Refused(_R_LANE_UNREAD)
    return _IFS_DEFAULT


def _ifs_split(text: str, ctx: _Ctx) -> list[str]:
    """The words bash makes of text that a known value or a substitution's
    output put into a word: split at the characters of IFS exactly as bash
    does (see _split_fields), reading no quotes and no backslashes
    (`--x\\ --y` is two words, and so is `--x' --y`). With `ctx.fine` the split
    is the finer one (white space, also \\r, \\f and \\v, splits even where IFS
    leaves it out); when the two differ the exact split is returned and
    `ctx.reread` is set, so that check() reads the text both ways.
    (shlex is for text that is parsed as shell again, as eval does.)"""
    ifs = _ifs(ctx)
    exact = _split_fields(text, ifs)
    # The finer reading: white space (also \r, \f and \v) splits too, even
    # where IFS leaves it out, and an empty field is dropped.
    table = {ord(c): " " for c in _IFS_DEFAULT + "\r\f\v" + ifs}
    finer = [w for w in text.translate(table).split(" ") if w]
    if ctx.fine:
        return finer
    if finer != exact:
        ctx.reread = True
    return exact


def _split_fields(text: str, ifs: str) -> list[str]:
    """The fields bash makes of text at the characters of ifs: a run of IFS
    white space (space, tab, newline) is one delimiter and is dropped at the
    ends; any other IFS character ends a field on its own, so two together
    make an empty field; with an empty IFS nothing splits."""
    if not ifs:
        return [text] if text else []
    white = {c for c in ifs if c in _IFS_DEFAULT}
    n, i, fields = len(text), 0, []
    while i < n:
        while i < n and text[i] in white:
            i += 1
        if i >= n:
            break
        j = i
        while j < n and text[j] not in ifs:
            j += 1
        fields.append(text[i:j])
        i = j
        if i < n:
            while i < n and text[i] in white:
                i += 1
            if i < n and text[i] in ifs:        # a non-white delimiter
                i += 1
                while i < n and text[i] in white:
                    i += 1
    return fields


def _expand_known(word: str, ctx: _Ctx) -> str:
    """The word with each known variable's value put in (and `$IFS`, which is
    white space unless the call sets it), again for a value that names
    another, up to MAX_EXPAND_ROUNDS rounds. A word that a substitution grew
    past MAX_EXPANDED_CHARS, or that is still changing after the last round,
    is refused: the gate can't read it."""
    def value(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        if name in ctx.vars:
            return ctx.vars[name]
        return _ifs(ctx) if name == "IFS" else m.group(0)

    for _ in range(MAX_EXPAND_ROUNDS):
        new = _VAR_RE.sub(value, word)
        if len(new) > MAX_EXPANDED_CHARS and len(new) > len(word):
            raise _Refused(_R_LANE_UNREAD)
        if new == word:
            return word
        word = new
    if _VAR_RE.sub(value, word) != word:
        raise _Refused(_R_LANE_UNREAD)
    return word


def _lane_args(args: list[str], ctx: _Ctx) -> list[str]:
    """The arguments with a known variable (also inside a word, where its
    value may split it: `npm ci$IFS--no-ignore-scripts`) or a trivial
    substitution expanded, as the gate does for the command word
    (`f=--x; npm ci $f`)."""
    out: list[str] = []
    for a in args:
        if "$" in a:
            expanded = _expand_known(a, ctx)
            if expanded != a:
                _ifs_mix(a, ctx)
                out.extend(_ifs_split(expanded, ctx))
                continue
        if _PLACEHOLDER_RE.fullmatch(a):
            sub = _sub_body(a, ctx)
            words = _static_output(sub[1], ctx) if sub and sub[0] == "c" else None
            if words:
                out.extend(words)
                continue
        out.append(a)
    return out


MAX_READING_WORDS = 5       # words with two readings, up to which every mix is tried


def _arg_readings(a: str, ctx: _Ctx) -> list[list[str]]:
    """The ways bash may make words of one argument: where a known variable
    or a trivial substitution is put in, the words it splits into (as _lane_args
    reads it), and the whole text as one word (where the argument is in
    double quotes: `--title "$t"`). Otherwise one reading, the argument."""
    if "$" in a:
        expanded = _expand_known(a, ctx)
        if expanded != a:
            _ifs_mix(a, ctx)
            split = _ifs_split(expanded, ctx)
            return [split] if split == [expanded] else [split, [expanded]]
    if _PLACEHOLDER_RE.fullmatch(a):
        sub = _sub_body(a, ctx)
        text = _static_text(sub[1], ctx) if sub and sub[0] == "c" else None
        if text is not None:
            split = _ifs_split(text, ctx)
            if split:
                return [split] if split == [text] else [split, [text]]
            return [[a], [text]]
    return [[a]]


_R_IFS_MIX = _coded("launch-hidden-command", ("launch gate (rule 1): with IFS set, bash "
            "splits only the text an unquoted expansion puts in a word, and this word mixes "
            "such an expansion with written text that holds an IFS character, which the gate "
            "can't read that way here; blocked to be safe. Quote the expansion, or leave IFS "
            "at its default."))
_R_READINGS = _coded("launch-lane-override", ("launch gate (rule 2): more than "
            f"{MAX_READING_WORDS} words of this command hold a known value that bash may "
            "split or keep whole, too many for the gate to try every way it reads; blocked "
            "to be safe. Write the values out, or quote them the same way."))


def _ifs_mix(word: str, ctx: _Ctx) -> None:
    """Refuse a word (quotes already taken off) that mixes an expansion with
    written text holding a character of a set IFS: bash splits only
    the expansion's text, and without the word as written the gate can't
    tell which is which."""
    ifs = _ifs(ctx)
    if ifs != _IFS_DEFAULT and any(c in ifs for c in _RUNTIME_PART_RE.sub("", word)):
        raise _Refused(_R_IFS_MIX)


def _raw_chunks(raw: str, ctx: _Ctx) -> tuple[list[tuple[str, bool]], bool] | None:
    """The text of one word as written (quotes kept), as (text, may split)
    pieces: what an unquoted known variable or readable substitution puts in
    may split, anything quoted or written may not. And whether it holds a
    quoted part. None for a form it doesn't read."""
    chunks: list[tuple[str, bool]] = []
    quoted = False
    i, n = 0, len(raw)

    def expansion(k: int, in_double: bool) -> int:
        m = _VAR_RE.match(raw, k)
        if m:
            value = _expand_known(m.group(0), ctx)
            chunks.append((value, value != m.group(0) and not in_double))
            return m.end()
        chunks.append(("$", False))
        return k + 1

    while i < n:
        c = raw[i]
        p = _PLACEHOLDER_RE.match(raw, i)
        if p:
            sub = _sub_body(p.group(0), ctx)
            text = _static_text(sub[1], ctx) if sub and sub[0] == "c" else None
            chunks.append((p.group(0), False) if text is None else (text, True))
            i = p.end()
        elif c == "'":
            j = raw.find("'", i + 1)
            if j < 0:
                return None
            chunks.append((raw[i + 1:j], False))
            quoted, i = True, j + 1
        elif c == "\\":
            chunks.append((raw[i + 1:i + 2], False))
            i += 2
        elif c == "$":
            i = expansion(i, False)
        elif c == '"':
            quoted, i = True, i + 1
            while True:
                if i >= n:
                    return None
                c = raw[i]
                if c == '"':
                    i += 1
                    break
                p = _PLACEHOLDER_RE.match(raw, i)
                if p:
                    sub = _sub_body(p.group(0), ctx)
                    text = _static_text(sub[1], ctx) if sub and sub[0] == "c" else None
                    chunks.append((p.group(0) if text is None else text, False))
                    i = p.end()
                elif c == "\\" and raw[i + 1:i + 2] in ("$", "`", '"', "\\"):
                    chunks.append((raw[i + 1], False))
                    i += 2
                elif c == "$":
                    i = expansion(i, True)
                else:
                    chunks.append((c, False))
                    i += 1
        else:
            chunks.append((c, False))
            i += 1
    return chunks, quoted


def _raw_reading(raw: str, ctx: _Ctx) -> list[str] | None:
    """The words bash makes of one word as written: quoted parts whole, the
    text of unquoted expansions split at IFS, written text never ; as _ifs_split does, the finer reading (white space and \\r, \\f,
    \\v also split) is given with `ctx.fine`, and `ctx.reread` set where the
    two differ. None for a form it doesn't read."""
    parsed = _raw_chunks(raw, ctx)
    if parsed is None:
        return None
    chunks, quoted = parsed
    seq = [(ch, split) for text, split in chunks for ch in text]
    ifs = _ifs(ctx)

    def fields(delims: str, white: str, keep_empty: bool) -> list[str]:
        out, i, n = [], 0, len(seq)
        def is_d(k): return seq[k][1] and seq[k][0] in delims
        def is_w(k): return is_d(k) and seq[k][0] in white
        while i < n:
            while i < n and is_w(i):
                i += 1
            if i >= n:
                break
            j = i
            while j < n and not is_d(j):
                j += 1
            out.append("".join(ch for ch, _ in seq[i:j]))
            i = j
            if i < n:
                while i < n and is_w(i):
                    i += 1
                if i < n and is_d(i):
                    i += 1
                    while i < n and is_w(i):
                        i += 1
        if not keep_empty:
            out = [w for w in out if w]
        if not out and quoted:
            out = [""]
        return out

    exact = fields(ifs, "".join(c for c in ifs if c in _IFS_DEFAULT), True)
    finer_delims = ifs + _IFS_DEFAULT + "\r\f\v"
    finer = fields(finer_delims, finer_delims, False)
    if ctx.fine:
        return finer
    if finer != exact:
        ctx.reread = True
    return exact


def _lane_readings(args: list[str], ctx: _Ctx, raws: list[str] | None = None,
                   strict: bool = False) -> list[list[str]]:
    """The arguments as _lane_args reads them, and as bash reads them where a
    known value sits in double quotes, which keeps it one word. The lane's
    checks refuse if any reading is refused. Where the word as written is
    known (`raws`), it is read the one way bash reads it: quoted parts whole,
    unquoted expansions split. Up to MAX_READING_WORDS words with
    two readings, every mix is tried; past it, all split and all whole, or
    with `strict` (the lane's own checks) a refusal: a reading the lane needs
    isn't computed."""
    if raws is not None and len(raws) != len(args):
        raws = None
    options = []
    for k, a in enumerate(args):
        exact = None
        if raws is not None and ("$" in raws[k] or _PLACEHOLDER_RE.search(raws[k])):
            exact = _raw_reading(raws[k], ctx)
        options.append([exact] if exact is not None else _arg_readings(a, ctx))
    two = [k for k, o in enumerate(options) if len(o) > 1]
    if not two:
        return [[w for o in options for w in o[0]]]
    if len(two) > MAX_READING_WORDS:
        if strict:
            raise _Refused(_R_READINGS)
        return [[w for o in options for w in o[0]], [w for o in options for w in o[-1]]]
    readings = []
    for mask in range(1 << len(two)):
        pick = {k: mask >> i & 1 for i, k in enumerate(two)}
        readings.append([w for k, o in enumerate(options) for w in o[pick.get(k, 0)]])
    return readings


_RUNTIME_PART_RE =re.compile(r"\$(?:\{[^}]{0,256}\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])"
                              r"|__sd[cp]\d+__")
# Options of the lane's tools, for _optionish.
_LANE_OPTIONS = tuple(_NPM_LANE) + ("exclude-newer", "exclude-newer-package",
                                    "no-exclude-newer", "no-binary", "only-binary")
_AGE_PARTS = ("releaseage", "minimalage", "agegate")


def _optionish(text: str) -> bool:
    """Whether text left after a run-time part (dashes already taken off) may
    be the name, or a prefix of the name, of one of the lane's options."""
    text = text.lower().replace("_", "-")
    stripped = text
    while stripped.startswith("no-"):
        stripped = stripped[3:]
    for form in (text, stripped):
        compact = form.replace("-", "")
        if len(compact) < 2:
            continue
        if (any(o.startswith(form) for o in _LANE_OPTIONS) or form.startswith("config.")
                or any(p in compact for p in _AGE_PARTS)
                or compact in ("dangerouslyallowallbuilds", "trust", "allowbuild")):
            return True
    return False


def _lane_unread(args: list[str]) -> str | None:
    """An option whose name is built at run time (`--no-ignore-scripts$u`,
    `$u--no-ignore-scripts`, `$@--ig=false`, `ci$1--no-ignore-scripts`): the
    gate can't tell which option it is, and a run-time part may hold white
    space that splits the word, so what follows it may be a word of its own.
    A word that starts with a dash and holds a run-time part is refused. So
    is one where the text after a run-time part (dashes taken off) could be
    an option's name; `npm i $a-$b` is a package name, since the rest, `-`,
    names no option. Some run-time words aren't seen
    (a known miss)."""
    for a in args:
        if a == "--":
            break
        name = a.partition("=")[0]
        if "$" in name or _PLACEHOLDER_RE.search(name):
            if name.startswith("-") or _LONG_BRACE_RE.search(name):
                return _R_LANE_UNREAD
            if any(_optionish(rest.lstrip("-")) for rest in _RUNTIME_PART_RE.split(name)[1:]):
                return _R_LANE_UNREAD
            if _RUNTIME_PART_RE.match(name) and _optionish(
                    _RUNTIME_PART_RE.sub("", name).lstrip("-")):
                return _R_LANE_UNREAD
    return None


def _defines_date(command: str) -> bool:
    """Whether the call may define its own `date` (see _DATE_FUNC_RE), also
    with quotes or backslashes in the name (`da''te(){ ...; }`) or spelled by
    a `$'...'` escape."""
    return bool(_DATE_FUNC_RE.search(command) or _DATE_FUNC_RE.search(_name_norm(command))
                or ("$'" in command and _ANSI_LETTER_RE.search(command)))


# Subcommands of pnpm, Yarn and Bun whose options are their own, so a prefix
# of a lane option counts there; after any other word (a script or a tool:
# `yarn nodemon --ignore=dist`) only the exact name counts.
_INSTALL_WORDS = frozenset({"install", "i", "add", "ci", "update", "up", "upgrade", "remove",
                            "rm", "uninstall", "rebuild", "rb", "link", "dedupe", "import",
                            "fetch", "patch", "pm"})


def _lane_npm_flags(args: list[str], ctx: _Ctx, tool: str = "npm") -> str | None:
    """npm's lane options; on pnpm, Yarn and Bun also any age setting, whose
    units differ, and their ways to let install scripts run (pnpm's
    `--dangerously-allow-all-builds`, `--allow-build` and `approve-builds`,
    Bun's `--trust` and `pm trust`). npm 11.20.0 read any number of leading
    dashes, a prefix only one option has, and flipped the value for each
    `no-` (a probe, 2026-10-28), so every `no-` is refused. On
    npx, bunx and pnpx a prefix counts only before the tool's name."""
    npm = tool in ("npm", "npx")
    positionals: list[str] = []     # the subcommand first
    every: list[str] = []           # every word that isn't an option
    for i, a in enumerate(args):
        if a == "--":
            break
        if not a.startswith("-") or a == "-":
            every.append(a.lower())
            if not npm and ("approve-builds" in every or every[-2:] == ["pm", "trust"]):
                return _r_lane("ignore-scripts")
            # On pnpm, Yarn and Bun a word right after an option with no `=`
            # may be that option's value (`pnpm --filter foo install
            # --ig=false`), so it isn't taken as the subcommand: fewer
            # positionals read an option the strict way, by prefix. (npx's
            # tool name follows its own boolean `--no`, so it stays.)
            prev = args[i - 1] if i else ""
            if npm or tool not in ("pnpm", "yarn", "bun") or not (
                    prev.startswith("-") and prev != "-" and "=" not in prev):
                positionals.append(a.lower())
            continue
        flag, eq, value = a.lstrip("-").partition("=")
        flag = flag.lower().replace("_", "-")
        if flag.startswith("config."):      # pnpm's --config.<key>
            flag = flag[len("config."):]
        negated = False
        while flag.startswith("no-"):
            flag, negated = flag[3:], True
        compact = flag.replace("-", "")     # pnpm also takes camelCase
        if not npm and compact in ("dangerouslyallowallbuilds", "trust", "allowbuild"):
            return _r_lane("dangerously-allow-all-builds" if compact[0] == "d" else compact)
        if not npm and any(w in compact for w in _AGE_PARTS):
            return _r_lane("minimum-release-age")
        if tool == "npm" or not positionals or (
                tool in ("pnpm", "yarn", "bun") and positionals[0] in _INSTALL_WORDS):
            key = _npm_lane_key(flag)
        else:
            key = flag if flag in _NPM_LANE else None
        if key is None:
            continue
        test = _NPM_LANE[key]
        if negated or test is None:
            return _r_lane(key)
        if not eq:
            following = args[i + 1] if i + 1 < len(args) else None
            if key == "ignore-scripts":
                value = following if following and following.lower() in ("true", "false") else "true"
            elif following is None:
                return _r_lane(key)
            else:
                value = following
        if not test(_lane_value(value, ctx, ahead=True)):
            return _r_lane(key)
    return None


def _lane_npm_config(args: list[str], ctx: _Ctx) -> str | None:
    """`npm config set|delete <key>` (and `npm set`, `npm c`, and the
    prefixes npm takes, `npm confi`) on a lane key; pnpm's and Yarn's too.
    Any age setting other than npm's own is refused, and Yarn's
    `enableScripts` set to anything but `false`."""
    words = []
    for a in args:
        if a == "--":
            break
        if not a.startswith("-"):
            words.append(a)
    for i, w in enumerate(words):
        if (w == "c" or (len(w) >= 3 and "config".startswith(w))) and i + 1 < len(words):
            verb, rest = words[i + 1], words[i + 2:]
        elif w == "set":
            verb, rest = "set", words[i + 1:]
        else:
            continue
        if verb == "edit":
            return _r_lane("config edit")       # opens the config file in an editor
        deleting = verb in ("rm", "unset") or (len(verb) >= 3 and "delete".startswith(verb))
        for k, word in enumerate(rest):
            name, eq, value = word.partition("=")
            key = name.lower().replace("_", "-")
            compact = key.replace("-", "")
            if key not in _NPM_LANE and any(x in compact for x in _AGE_PARTS):
                return _r_lane("minimum-release-age")   # pnpm's, Yarn's, Bun's
            if not eq and k + 1 < len(rest):
                following = rest[k + 1]
            else:
                following = value if eq else None
            if compact == "enablescripts" and (deleting or following != "false"):
                return _r_lane("enableScripts")         # Yarn's
            if key not in _NPM_LANE:
                continue
            if deleting:
                return _r_lane(key)
            if verb == "set":
                if not eq:
                    value = rest[k + 1] if k + 1 < len(rest) else None
                test = _NPM_LANE[key]
                if test is None or value is None or not test(_lane_value(value, ctx, True)):
                    return _r_lane(key)
        break       # one config command per call
    return None


def _lane_uv_flags(args: list[str], ctx: _Ctx) -> str | None:
    for i, a in enumerate(args):
        if a == "--":
            break
        flag, eq, value = a.partition("=")
        if flag in ("--exclude-newer-package", "--no-exclude-newer"):
            return _r_lane(flag[2:])
        if flag != "--exclude-newer":
            continue
        if not eq:
            if i + 1 >= len(args):
                return _r_lane("exclude-newer")
            value = args[i + 1]
        if not _lane_uv(_lane_value(value, ctx)):
            return _r_lane("exclude-newer")
    return _lane_pip_flags(args, ctx)


def _lane_pip_flags(args: list[str], ctx: _Ctx) -> str | None:
    """pip's (and `uv pip`'s) builds from source, which run the package's own
    code: any `--no-binary`, and `--only-binary` with a value but `:all:`.
    pip takes a long option by a prefix only it has."""
    for i, a in enumerate(args):
        if a == "--":
            break
        if not a.startswith("--"):
            continue
        flag, eq, value = a[2:].partition("=")
        if flag.startswith("no-binary") or (len(flag) >= 5 and "no-binary".startswith(flag)):
            return _r_lane("no-binary")
        if len(flag) >= 4 and "only-binary".startswith(flag):
            if not eq:
                value = args[i + 1] if i + 1 < len(args) else ""
            if not _lane_all(_lane_value(value, ctx)):
                return _r_lane("only-binary")
    return None


def _lane_declare(name: str, args: list[str], ctx: _Ctx) -> str | None:
    """export, declare, typeset, readonly, local and unset: a lane name given
    a value, unset or made local, or given any option but -x, -g, -r, -p, -f
    and -F (`declare -i` reads `true` as 0, `-a` makes an array bash doesn't
    export, `export -n` and `+x` un-export it, `-n` makes it a reference)."""
    opts = [a for a in args if a[:1] in "-+" and a not in ("-", "--")]
    if name in ("declare", "typeset", "local") and any(
            o.startswith("-") and set(o[1:]) & set("in") for o in opts):
        # An integer variable reads its value as arithmetic, which assigns
        # (`x=$a$b=0`); a reference follows a name held in its value.
        return _R_LANE_ATTR
    odd =any(o.startswith("+") or set(o[1:]) - set("xgrpfF") for o in opts)
    drops = name in ("unset", "local")
    for a in args:
        if a[:1] in "-+":
            continue
        word, eq, _ = a.partition("=")
        if "$" in word or _PLACEHOLDER_RE.search(word):
            return _R_LANE_UNREAD       # `export $n=false`: which name?
        if name != "unset" and _prompt_assign(a, ctx):
            return _R_PROMPT_VAR
        entry = _lane_entry(word.rstrip("+").split("[", 1)[0])
        if not entry:
            continue
        if odd:
            return _r_lane(entry[0])
        if eq:
            reason = _lane_assign(a, ctx)
            if reason:
                return reason
        elif drops:
            return _r_lane(entry[0])
    return None


def _lane_setters(name: str, args: list[str]) -> str | None:
    """read, mapfile, readarray, getopts and let, and printf -v, naming a
    lane variable: each sets it."""
    targets = []
    if name == "printf":
        for k, a in enumerate(args):
            if a == "-v" and k + 1 < len(args):
                targets.append(args[k + 1])
            elif a.startswith("-v") and len(a) > 2:
                targets.append(a[2:])
    else:
        targets = [a for a in args if not a.startswith("-")]
    for t in targets:
        if name != "let" and ("$" in t or _PLACEHOLDER_RE.search(t)):
            return _R_LANE_UNREAD       # `read $n`: which name?
        m = _IDENT_RE.match(t.strip())
        entry = _lane_entry(m.group(0)) if m else None
        if entry:
            return _r_lane(entry[0])
    return None


# node's options that take their value in the next word, those that take none
# there (a value comes after `=`, or there is none), and those whose value is
# the program's own text. An option in none of them may be either, and is
# read both ways (see _node_scripts).
_NODE_VALUE_OPTS = frozenset({
    "-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions",
    "--input-type", "--title", "--stack-size", "--env-file", "--env-file-if-exists",
    "--watch-path", "--inspect-port", "--debug-port", "--redirect-warnings",
    "--diagnostic-dir", "--report-dir", "--report-directory", "--report-filename",
    "--report-signal", "--heapsnapshot-signal", "--cpu-prof-dir", "--cpu-prof-name",
    "--cpu-prof-interval", "--heap-prof-dir", "--heap-prof-name", "--heap-prof-interval",
    "--icu-data-dir", "--openssl-config", "--tls-cipher-list", "--tls-keylog",
    "--max-http-header-size", "--secure-heap", "--secure-heap-min", "--trace-event-categories",
    "--trace-event-file-pattern", "--unhandled-rejections", "--disable-warning",
    "--experimental-default-type", "--dns-result-order", "--test-reporter",
    "--test-reporter-destination", "--test-name-pattern", "--test-skip-pattern",
    "--test-concurrency", "--test-timeout", "--test-shard", "--experimental-sea-config",
    "--allow-fs-read", "--allow-fs-write", "--localstorage-file", "--snapshot-blob",
    "--build-snapshot-config", "--watch-kill-signal", "--experimental-config-file",
    "--network-family-autoselection-attempt-timeout", "--inspect-publish-uid",
    "--max-old-space-size", "--max-semi-space-size", "--stack-trace-limit",
    "--security-revert", "--v8-pool-size", "--run"})
_NODE_FLAG_OPTS = frozenset({
    "--inspect", "--inspect-brk", "--inspect-wait", "--inspect-brk-node", "--trace-warnings",
    "--trace-deprecation", "--trace-uncaught", "--trace-exit", "--trace-sigint",
    "--throw-deprecation", "--pending-deprecation", "--enable-source-maps",
    "--preserve-symlinks", "--preserve-symlinks-main", "--experimental-vm-modules",
    "--experimental-strip-types", "--experimental-transform-types",
    "--experimental-require-module", "--experimental-detect-module",
    "--experimental-wasm-modules", "--experimental-import-meta-resolve",
    "--experimental-network-inspection", "--experimental-websocket",
    "--experimental-sqlite", "--experimental-test-coverage", "--test-only",
    "--expose-gc", "--expose_gc", "--harmony", "--abort-on-uncaught-exception", "--watch",
    "--watch-preserve-output", "--test", "--check", "-c", "--interactive", "-i", "--permission",
    "--allow-addons", "--allow-child-process", "--allow-wasi", "--allow-worker", "--use-strict",
    "--frozen-intrinsics", "--force-fips", "--enable-fips", "--zero-fill-buffers", "--jitless",
    "--track-heap-objects", "--prof", "--prof-process", "--cpu-prof", "--heap-prof",
    "--report-on-signal", "--report-uncaught-exception", "--report-on-fatalerror",
    "--report-compact", "--insecure-http-parser", "--verify-base-objects", "--node-snapshot",
    "--build-snapshot", "--openssl-legacy-provider", "--openssl-shared-config",
    "--tls-min-v1.0", "--tls-min-v1.1", "--tls-min-v1.2", "--tls-min-v1.3", "--tls-max-v1.2",
    "--tls-max-v1.3", "--help", "-h", "--version", "-v", "--v8-options", "--completion-bash",
    "--deprecation", "--warnings", "--addons", "--global-search-paths"})
_NODE_CODE_OPTS = frozenset({"-e", "--eval", "-p", "--print", "-pe"})


def _node_scripts(args: list[str]) -> list[tuple[str, list[str]]]:
    """(`npm` or `npx`, the words after it) for each way node's own script
    could be npm. Only node's script counts: its first word that isn't an
    option or an option's value (`node scripts/release.js npm --before=...`
    runs release.js, which gets `npm` as an argument of its own). The option
    tables say which options take the next word as a value. An option in
    neither table may take it or not, so both are tried: the word after it is
    read as the script, and as a value with the script after it."""
    found: list[tuple[str, list[str]]] = []
    k, n = 0, len(args)
    maybe_value = False         # the word before was an option that may take this one
    while k < n:
        a = args[k]
        if a.startswith("-") and a != "-":
            maybe_value = False     # another option: it is not a value
            if a in _NODE_CODE_OPTS:
                break               # the program is the next word's text
            if a == "--":
                k += 1              # the script is the next word
                a = args[k] if k < n else ""
            else:
                flag, eq, _ = a.partition("=")
                if eq or flag in _NODE_FLAG_OPTS or flag.startswith("--no-") or (
                        not flag.startswith("--") and len(flag) > 2 and flag[:2] in ("-r", "-C")):
                    k += 1
                elif flag in _NODE_VALUE_OPTS:
                    k += 2
                else:
                    maybe_value = True
                    k += 1
                continue
        if _base(a).lower() in ("npm-cli.js", "npx-cli.js", "npm", "npx"):
            found.append((_base(a).lower()[:3], args[k + 1:]))
        if not maybe_value:
            break                   # the script
        maybe_value = False         # read as the option's value: the script may follow
        k += 1
    return found


def _keyword_mode(name: str, args: list[str]) -> bool:
    """Whether `set`, `shopt` or a shell turns on bash's keyword mode (`-k`,
    `-o keyword`), where a `NAME=value` word anywhere in a command assigns.
    The options are read as far as bash reads them: up to the first word
    that isn't one (a shell's script or `-c` string, `set`'s operands)."""
    if name == "shopt":
        return "keyword" in args and not any(
            a.startswith("-") and "u" in a for a in args) and any(
            a.startswith("-") and not a.startswith("--") and "o" in a for a in args)
    i = 0
    while i < len(args):
        a = args[i]
        if len(a) < 2 or a[0] not in "-+" or a == "--":
            break
        letters = a[1:]
        if a[0] == "-" and not a.startswith("--") and "k" in letters:
            return True
        if a.startswith("--"):
            i += 2 if a in ("--rcfile", "--init-file") else 1
            continue
        if letters[-1] == "o":          # -o name, +o name
            if a[0] == "-" and args[i + 1:i + 2] == ["keyword"]:
                return True
            i += 1
        elif letters[-1] == "O":        # -O shopt-name
            i += 1
        i += 1
    return False


def _lane_command(name: str, args: list[str], ctx: _Ctx,
                  raws: list[str] | None = None) -> str | None:
    """The lane's checks of one command. `raws` (the arguments as written,
    lined up with args, or None) lets a word that mixes quoted and unquoted
    expansions be read as bash reads it."""
    name = name.lower()     # a case-insensitive file system runs `NPM` as npm
    if raws is not None and len(raws) != len(args):
        raws = None
    # (A known variable's value is put in first: `k=-k; set $k`.)
    if (name in ("set", "shopt") or name in SHELLS) and _keyword_mode(
            name, _lane_args(args, ctx)):
        return _R_LANE_KEYWORD
    if name == "corepack" and args:
        tool = _base(args[0]).split("@", 1)[0].lower()   # corepack npm@11.20.0
        if tool in _NPM_FAMILY:
            name, args, raws = tool, args[1:], raws[1:] if raws else None
    elif name in ("npm-cli.js", "npx-cli.js"):
        name = name[:3]                 # npm's own script, run directly
    elif name in ("node", "nodejs"):
        # npm run by node: `node .../npm-cli.js install`, `node /usr/bin/npm`,
        # `node "$(command -v npm)"`. Each way node's script could be npm is
        # checked as npm.
        for reading in _lane_readings(args, ctx, raws, strict=True):
            for tool, rest in _node_scripts(reading):
                reason = _lane_command(tool, rest, ctx)
                if reason:
                    return reason
        return None
    elif name in ("setpriv", "bwrap") and any(
            a in ("--reset-env", "--clearenv") for a in args):
        return _R_LANE_CLEAR
    elif name in ("uv", "poetry", "pdm") and "run" in args:
        # `uv run npm ci ...`: check the first package manager it runs, too
        for k, a in enumerate(args[args.index("run") + 1:], args.index("run") + 1):
            inner = _base(a).lower()
            if (inner in _NPM_FAMILY or inner in _UV_FAMILY or _PIP_RE.fullmatch(inner)
                    or inner in ("node", "nodejs", "corepack") or _PYTHON_RE.fullmatch(inner)):
                reason = _lane_command(inner, args[k + 1:], ctx, raws[k + 1:] if raws else None)
                if reason:
                    return reason
                break
        if name != "uv":
            return None
    elif _PYTHON_RE.fullmatch(name):
        # `python -m pip`, `python -mpip`
        for k, a in enumerate(args):
            if a == "-m" and k + 1 < len(args) and args[k + 1] == "pip":
                name, args, raws = "pip", args[k + 2:], raws[k + 2:] if raws else None
                break
            if a == "-mpip":
                name, args, raws = "pip", args[k + 1:], raws[k + 1:] if raws else None
                break
        else:
            return None
    if name in _DECLARE:
        return _lane_declare(name, args, ctx)
    if name == "let":
        # Judged here, where the parser has taken off the quotes, wrappers,
        # prefixes and assignments and a known command word is resolved. An
        # argument that assigns through a name built at run time sets a
        # variable the gate can't name (`let "$a$b=0"`).
        args = _lane_args(args, ctx)
        for a in args:
            if _LONG_BRACE_RE.search(a) or _DYN_ASSIGN_RE.search(_PLACEHOLDER_RE.sub("$x", a)):
                return _R_LANE_NAME
    if name in _NAME_SETTERS or name == "printf":
        return _lane_setters(name, args)
    pip = bool(_PIP_RE.fullmatch(name))
    if not (name in _NPM_FAMILY or name in _UV_FAMILY or pip):
        return None
    # (Read both ways where a known value in double quotes is one word.)
    for reading in _lane_readings(args, ctx, raws, strict=True):
        reason = _lane_unread(reading)
        if not reason and name in _NPM_FAMILY:
            reason = (_lane_npm_flags(reading, ctx, name)
                      or (_lane_npm_config(reading, ctx) if name in ("npm", "pnpm", "yarn") else None))
        elif not reason and name in _UV_FAMILY:
            reason = _lane_uv_flags(reading, ctx)
        elif not reason:
            reason = _lane_pip_flags(reading, ctx)
        if reason:
            return reason
    return None


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
    if name in _JS_GLOBAL_OPTS:
        # Every word that may be the subcommand, read with the one table
        #: a refusal in any reading stands.
        values = _JS_GLOBAL_OPTS[name][0]
        for k in _js_subcommands(name, args):
            sub, pos = args[k], _positionals(args[k + 1:], values)
            if name == "npm" and sub in ("exec", "x"):
                if any(a in _NO_FETCH_FLAGS for a in args):
                    continue
                return _r_launch(f"npm {sub}")
            if name == "npm" and (sub == "create" or (sub == "init" and pos)):
                return _r_launch(f"npm {sub} {pos[0] if pos else ''}".strip())
            if name in ("pnpm", "yarn") and sub in ("dlx", "create"):
                return _r_launch(f"{name} {sub}")
            if name == "bun" and sub in ("x", "create"):
                return _r_launch(f"bun {sub}")
        return None
    if name == "uv":
        k = _subcommand_at("uv", args)      # one table with `uv run`
        if k is None:
            return None
        pos = [args[k]] + _positionals(args[k + 1:], _GLOBAL_OPTS["uv"][0] | _RUN_VALUE_OPTS)
        if len(pos) >= 2 and pos[0] == "tool" and pos[1] in ("run", "install", "upgrade"):
            return _r_launch(f"uv tool {pos[1]}")
        if pos[0] == "run":
            after = args[k + 1:]
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


_ESCAPE_HEAD = r"\\(?:x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|"
# `echo -e` (and printf's %b) read `\0` and up to 3 more octal digits.
_ESCAPE_RE = re.compile(_ESCAPE_HEAD + r"(0[0-7]{0,3}|[1-7][0-7]{0,2})|(.))", re.S)
# printf's format reads `\ddd` as 1 to 3 octal digits, the 0 among them
# (`\0401` is `\040` and then `1`).
_PRINTF_ESCAPE_RE = re.compile(_ESCAPE_HEAD + r"([0-7]{1,3})|(.))", re.S)
_ESCAPE_CHARS = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n",
                 "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _decode_escapes(text: str, printf_format: bool = False) -> str | None:
    """The text bash's printf (with `printf_format`, its format string) and
    `echo -e` make of a string with backslash escapes (`\\n`, `\\x20`, `\\040`,
    `\\u0020`), or None for one it doesn't read (`\\c`, a NUL, an unknown
    escape, a trailing backslash)."""
    bad = []

    def one(m: re.Match) -> str:
        hexa, u4, u8, octal, char = m.groups()
        digits, base = (hexa or u4 or u8), 16
        if octal is not None:
            digits, base = octal, 8
        if char is not None:
            if char not in _ESCAPE_CHARS:
                bad.append(char)
            return _ESCAPE_CHARS.get(char, "")
        number = int(digits, base)
        if base == 8:
            number &= 0xFF      # a byte: bash prints `\401` as `\001`
        if not 0 < number <= 0x10FFFF:
            bad.append(digits)
            return ""
        return chr(number)

    out = (_PRINTF_ESCAPE_RE if printf_format else _ESCAPE_RE).sub(one, text)
    lone = (len(text) - len(text.rstrip("\\"))) % 2 == 1      # a backslash with nothing after
    return None if bad or lone else out


def _print_argv(argv: list[str]) -> list[str]:
    """The command a printing command really is: leading assignments and
    wrappers (`X=1 printf ...`, `command printf ...`) dropped, but not
    `command -v`, which is a printing command of its own."""
    words = list(argv)
    while words and _ASSIGN_RE.match(words[0]):
        words.pop(0)
    if words and _base(words[0]) == "command" and words[1:2] in (["-v"], ["-V"]):
        return words
    return _strip_wrappers(words)


def _percent_format(argv: list[str]) -> bool:
    """Whether this is a printf whose format holds a `%`, a print the gate
    reads in part under `eval`."""
    words = _print_argv(argv)
    if not words or _base(words[0]) != "printf":
        return False
    args = words[1:]
    if args[:1] == ["--"]:
        args = args[1:]
    elif args and args[0].startswith("-"):
        return False                # -v and the like are not the format case
    return bool(args) and "%" in args[0]


def _printed_text(argv: list[str], ctx: _Ctx) -> str | None:
    """What a trivial command prints, as text: echo, printf without %, which,
    command -v, also after leading assignments and wrappers. None for one the
    gate doesn't read: an escape it doesn't decode (`\\c`, a NUL, an unknown
    one), a `%` format, a printf option other than `--` (`-v`), an echo that
    would not decode its escapes, or any other command. A printf format whose
    `\\0ddd` printf and `echo -e` read differently is read as printf reads it
    (`\\0401` is `\\040` and `1`), and with `ctx.fine` as `echo -e` and %b do
    (`\\0` and 3 digits); `ctx.reread` is set, so that both are checked."""
    argv = _print_argv(argv)
    if not argv:
        return None
    name, args = _base(argv[0]), argv[1:]
    if name == "printf":
        ended = args[:1] == ["--"]
        if ended:
            args = args[1:]         # printf's end of options
        if not args or "%" in args[0] or (args[0].startswith("-") and not ended):
            return None             # -v and the like, or a format it can't read
        # printf decodes escapes (`\n`, `\x20`, `\040`): white space among
        # them splits words, as the shell splits the output.
        exact = _decode_escapes(args[0], printf_format=True)
        other = _decode_escapes(args[0])
        if other != exact:
            ctx.reread = True
            if ctx.fine:
                return other
        return exact
    if name == "echo":
        flags = 0
        while (flags < len(args) and re.fullmatch(r"-[neE]+", args[flags])):
            flags += 1
        escapes = "".join(a[1:] for a in args[:flags]).replace("n", "")[-1:] == "e"
        rest = args[flags:]
        if escapes:
            return _decode_escapes(" ".join(rest))
        if any("\\" in a for a in rest):
            return None     # a backslash may be an escape (xpg_echo); not read
        return " ".join(rest)
    if any("\\" in a for a in args):
        return None     # bash's printf and echo -e decode escapes; shlex doesn't
    if name in ("which", "type") or (name == "command" and args[:1] in (["-v"], ["-V"])):
        names = [a for a in args if not a.startswith("-")]
        return names[0] if names else None
    return None


def _static_text(body: str, ctx: _Ctx) -> str | None:
    """What a trivial substitution prints, as text (see _printed_text), or
    None if its body is anything else."""
    pipelines = _body_commands(body, ctx)
    if not pipelines or len(pipelines) != 1 or len(pipelines[0]) != 1:
        return None
    return _printed_text(pipelines[0][0].argv, ctx)


_R_LIST_UNREAD = _coded("launch-hidden-command", ("launch gate (rule 1): a command "
            "substitution here runs more than one command (a list or a pipeline), and the "
            "gate reads such a body only when it holds nothing but `printf`, `echo`, `true`, "
            "`:` and `head` or `tail` with plain options (`-n N`), with no redirect; so it "
            "can't tell what runs. Write the command out directly."))
MAX_PRINT_LINES = 32    # lines a print piped to head or tail may have
_FILTER_OPT_RE = re.compile(r"-n\+?\d{1,9}|-\d{1,9}|\+?\d{1,9}|-[qv]|--quiet|--silent|--verbose|"
                            r"--lines=\+?\d{1,9}")


_R_LIST_JOINED = _coded("launch-hidden-command", ("launch gate (rule 1): a command "
            "substitution in command position or in eval's words joins commands with `&&`, "
            "`||` or `&`, so which of them run (and in what order) is decided at run time; "
            "the gate reads such a body only with `;` or a line break between commands. "
            "Write the command out directly."))
_LIST_JOINERS = frozenset({"&&", "||", "&"})


def _joined_list(body: str, ctx: _Ctx) -> bool:
    """Whether a substitution's body joins commands with `&&`, `||` or `&`
   , read from the operators _lex makes, so a quoted one doesn't
    count and `>&`, `&>` and `|&` are other operators. A body _lex can't
    split is left to the other readers."""
    try:
        toks = _lex(body, ctx)
    except (_Unparseable, _TooManyWords):
        return False
    return any(typ == "o" and val in _LIST_JOINERS for typ, val in toks)


def _joined_in(word: str, ctx: _Ctx) -> bool:
    """Whether any command substitution in the word is a _joined_list."""
    for m in _PLACEHOLDER_RE.finditer(word):
        sub = _sub_body(m.group(0), ctx)
        if sub and sub[0] == "c" and _joined_list(sub[1], ctx):
            return True
    return False


def _is_list(body: str, ctx: _Ctx) -> bool:
    """Whether a substitution's body is more than one command."""
    pipelines = _body_commands(body, ctx)
    return bool(pipelines) and (len(pipelines) > 1 or len(pipelines[0]) > 1)


def _one_print(cmd: _Cmd, ctx: _Ctx) -> str | None:
    """What one command of a list prints: a printf or echo the gate reads
    (an echo's own newline included), or nothing for `true` and `:`. None
    for any other command, or one with a redirect."""
    if cmd.redirs or cmd.heredocs:
        return None
    argv = _print_argv(cmd.argv)
    if not argv:
        return None if cmd.argv else ""
    name = _base(argv[0])
    if name in ("true", ":"):
        return ""
    if name not in ("printf", "echo"):
        return None
    text = _printed_text(argv, ctx)
    if text is None or name == "printf":
        return text
    k, newline = 1, True
    while k < len(argv) and re.fullmatch(r"-[neE]+", argv[k]):
        newline = newline and "n" not in argv[k]
        k += 1
    return text + "\n" if newline else text


def _filter_ok(cmd: _Cmd) -> bool:
    """`head` or `tail` reading the pipe, with plain options only."""
    argv = _print_argv(cmd.argv)
    if cmd.redirs or cmd.heredocs or not argv or _base(argv[0]) not in ("head", "tail"):
        return False
    args, k = argv[1:], 0
    while k < len(args):
        a = args[k]
        if a == "-n" and k + 1 < len(args) and re.fullmatch(r"\+?\d{1,9}", args[k + 1]):
            k += 2
        elif _FILTER_OPT_RE.fullmatch(a):
            k += 1
        else:
            return False
    return True


def _list_output(body: str, ctx: _Ctx) -> list[str] | None:
    """The texts a substitution whose body is a list or a pipeline may print
   : for a list of prints, `true` and `:`, what they print in turn;
    for a print piped to `head` or `tail`, each run of its lines. None for a
    body that holds anything else, which the gate can't read."""
    pipelines = _body_commands(body, ctx)
    if not pipelines:
        return None
    if len(pipelines) > 1:
        parts = []
        for pipe in pipelines:
            text = _one_print(pipe[0], ctx) if len(pipe) == 1 else None
            if text is None:
                return None
            parts.append(text)
        return ["".join(parts)]
    pipe = pipelines[0]
    text = _one_print(pipe[0], ctx)
    if text is None or not all(_filter_ok(c) for c in pipe[1:]):
        return None
    if len(pipe) == 1:
        return [text]
    lines = text.splitlines(keepends=True)
    if len(lines) > MAX_PRINT_LINES:
        return None
    runs = ["".join(lines[a:b]) for a in range(len(lines)) for b in range(a + 1, len(lines) + 1)]
    return runs + [""]


def _static_output(body: str, ctx: _Ctx) -> list[str] | None:
    """The words the shell makes of what a trivial substitution prints: its
    text split at IFS, as bash splits an unquoted substitution."""
    text = _static_text(body, ctx)
    return None if text is None else _ifs_split(text, ctx)


def _hidden_in_substitutions(word: str, ctx: _Ctx, eval_ok: bool) -> str | None:
    """A reason if a word in command position holds a command substitution
    that hides what runs. Wherever its body holds a printf or echo (after
    assignments and wrappers, in a list, in a pipeline), what it prints is
    read: text the gate can't read is refused (`eval_ok` reads some prints
    only in part under eval, a known gap), and so is a
    name that starts a blocked command (npx, sudo, curl and the like), also
    one that two of them print between them."""
    for m in _PLACEHOLDER_RE.finditer(word):
        sub = _sub_body(m.group(0), ctx)
        if not sub or sub[0] != "c":
            continue
        if _is_list(sub[1], ctx) and _list_output(sub[1], ctx) is None:
            return _R_LIST_UNREAD       # a list or pipeline the gate can't read
        printed: list[str] = []
        for pipe in _body_commands(sub[1], ctx) or []:
            for cmd in pipe:
                for w in cmd.argv:
                    if _base(w) in HIDDEN_NAME_TRIGGERS:
                        return _r_hidden(_base(w))
                inner = _print_argv(cmd.argv)
                if not inner or _base(inner[0]) not in ("printf", "echo"):
                    continue
                text = _printed_text(inner, ctx)
                if text is None:
                    if eval_ok and _percent_format(inner):
                        continue
                    return _R_PRINT_UNREAD
                printed.append(text)
        for text in printed + ["".join(printed)]:
            for w in text.split():
                if _base(w) in HIDDEN_NAME_TRIGGERS:
                    return _r_hidden(_base(w))
    return None


def _printed(word: str, ctx: _Ctx) -> list[str]:
    """The word, or for a whole `$(echo ...)`/`$(printf ...)` the text it
    prints; for a list or pipeline of prints, each text it may print."""
    sub = _sub_body(word, ctx) if _PLACEHOLDER_RE.fullmatch(word) else None
    if sub and sub[0] == "c" and _is_list(sub[1], ctx):
        texts = [t for t in _list_output(sub[1], ctx) or [] if t]
        return texts or [word]
    out = _static_text(sub[1], ctx) if sub and sub[0] == "c" else None
    return [out] if out else [word]


MAX_EVAL_READINGS = 64      # the most ways eval's text is put together and read


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
            argv = _ifs_split(ctx.vars[name], ctx) + argv[1:]
    if argv and _PLACEHOLDER_RE.search(argv[0]):
        kind, body = _sub_body(argv[0], ctx) or ("c", "")
        if _is_download(body, ctx):
            return argv, _R_SUBST_DOWNLOAD
        if _joined_in(argv[0], ctx):
            return argv, _R_LIST_JOINED     # only `;` and line breaks are read
        whole =bool(_PLACEHOLDER_RE.fullmatch(argv[0]))
        out = _static_output(body, ctx) if whole else None
        if out:
            return out + argv[1:], None
        reason = _hidden_in_substitutions(argv[0], ctx, argv[0] in ctx.eval_args)
        if reason:
            return argv, reason
        if whole and kind == "c" and _is_list(body, ctx):
            # A list or a pipeline of prints: each text it may print
            # is checked as the command, as one print's is above; the first
            # goes on as this command's words.
            texts = _list_output(body, ctx) or [""]
            readings = [_ifs_split(t, ctx) + argv[1:] for t in texts]
            for other in readings[1:]:
                found, reason = _command_argv(other, ctx, depth + 1)
                reason = reason or _check_command(_Cmd(), found, ctx, depth + 1)
                if reason:
                    return argv, reason
            return readings[0], None
    return argv, None


def _blocked_command(name: str, args: list[str]) -> str | None:
    """A reason if this command gives root, starts an agent with its
    guardrails off, or fetches and runs a package."""
    # Lower-cased too: a case-insensitive file system (macOS's default) runs
    # `NPX` as npx.
    lname = name.lower()
    if name in PRIVILEGE or lname in PRIVILEGE:
        return _r_priv(name)
    return (_agent_launch(name, args) or _launcher(name, args)
            or (_agent_launch(lname, args) or _launcher(lname, args)
                if lname != name else None))


# Options of `uv run` that take their value in the next word.
_RUN_VALUE_OPTS = frozenset({"--python", "-p", "--directory", "--project", "--env-file",
                             "--extra", "--group", "--package", "--index", "--with",
                             "--with-requirements", "--with-editable", "--config-file",
                             "--cache-dir", "--color"})


# The global options of uv, Poetry and PDM, which come before the
# subcommand: those that take a value in the next word, and those that take
# none. Any other option there is refused: it might take the next
# word as its value, so the gate couldn't tell which word is the subcommand.
_GLOBAL_OPTS = {
    "uv": (frozenset({"--cache-dir", "--directory", "--project", "--python", "-p",
                      "--config-file", "--color", "--python-preference",
                      "--allow-insecure-host", "--trusted-host"}),
           frozenset({"-q", "--quiet", "-v", "--verbose", "-n", "--no-cache", "--native-tls",
                      "--no-native-tls", "--offline", "--no-offline", "--no-progress",
                      "--no-config", "--preview", "--no-preview", "--isolated",
                      "--show-settings", "--managed-python", "--no-managed-python",
                      "--no-python-downloads", "--allow-python-downloads", "-h", "--help",
                      "-V", "--version"})),
    "poetry": (frozenset({"-C", "--directory", "-P", "--project"}),
               frozenset({"-q", "--quiet", "-v", "--verbose", "-n", "--no-interaction",
                          "--ansi", "--no-ansi", "--no-plugins", "--no-cache", "-h", "--help",
                          "-V", "--version"})),
    "pdm": (frozenset({"-c", "--config", "-p", "--project"}),
            frozenset({"-q", "--quiet", "-v", "--verbose", "-n", "--non-interactive", "-I",
                       "--ignore-python", "--no-cache", "-h", "--help", "-V", "--version"})),
}
_QV_RE = re.compile(r"-[qv]{1,6}")


_R_GLOBAL_OPTION = _coded("launch-unparseable", ("launch gate (rule 1): `uv`, `poetry` or "
            "`pdm` has an option before its subcommand that the gate doesn't know, which may "
            "take the next word as its value, so the gate can't tell which word is the "
            "subcommand; blocked to be safe. Put the option after the subcommand."))


def _subcommand_at(tool: str, args: list[str]) -> int | None:
    """The index of uv's, Poetry's or PDM's subcommand: the first word that
    isn't a global option or an option's value (`uv --cache-dir run run x`
    runs `x`). An option the gate doesn't know there is refused."""
    values, flags = _GLOBAL_OPTS[tool]
    i = 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-") or a == "-":
            return i
        opt, eq, _ = a.partition("=")
        if opt in values:
            i += 1 if eq else 2
        elif not eq and (opt in flags or _QV_RE.fullmatch(a)):
            i += 1
        elif not opt.startswith("--") and len(opt) > 2 and opt[:2] in values:
            i += 1          # a value glued to a short option: -p3.12
        else:
            raise _Refused(_R_GLOBAL_OPTION)
    return None


def _command_after(rest: list[str], value_opts: frozenset | set,
                   flags: frozenset | set = frozenset()) -> list[list[str]]:
    """The command (its words) a runner runs from `rest`: from the first word
    that isn't an option, and, after an option that may take a value (one in
    neither table), from the word after that too."""
    found: list[list[str]] = []
    i, may_take = 0, False
    while i < len(rest):
        w = rest[i]
        if w == "--":
            found.append(rest[i + 1:])
            break
        if w.startswith("-") and w != "-":
            may_take = "=" not in w and w not in value_opts and w not in flags
            i += 1 if may_take or "=" in w or w in flags else 2
            continue
        found.append(rest[i:])
        if not may_take:
            break
        may_take = False        # read as the option's value: the command may follow
        i += 1
    return [c for c in found if c]


def _run_commands(args: list[str], tool: str = "uv") -> list[list[str]]:
    """The command (its words) that `uv run`, `poetry run` or `pdm run` may
    run: `run` is the subcommand only as the first word that isn't a global
    option or its value; the command runs from the first word after it that
    isn't an option, and, after an option that may take a value, from the
    word after that too."""
    sub = _subcommand_at(tool, args)
    if sub is None or args[sub] != "run":
        return []
    return _command_after(args[sub + 1:], _RUN_VALUE_OPTS)


# npm's, pnpm's, Yarn's and Bun's options before the subcommand that take a
# value, and their common options that take none; npx's and `npm
# exec`'s own options, with a value and without; and `pnpm exec`'s. An
# option before the subcommand in neither table, with no `=`, is read both
# ways (see _js_subcommands).
_NPM_VALUE_OPTS = frozenset({"--prefix", "-w", "--workspace", "--registry", "--cache",
                             "--userconfig", "--globalconfig", "--loglevel", "--otp",
                             "--omit", "--include", "--tag", "--access", "--scope",
                             "--install-strategy", "--script-shell", "--cpu", "--os",
                             "--libc", "--fetch-retries", "--fetch-timeout"})
_PNPM_VALUE_OPTS = frozenset({"--dir", "-C", "--filter", "-F", "--cwd", "--reporter",
                              "--loglevel", "--registry", "--store-dir", "--modules-dir",
                              "--virtual-store-dir", "--workspace-concurrency",
                              "--network-concurrency", "--child-concurrency",
                              "--resolution-mode", "--test-pattern", "--changed-files-ignore-pattern"})
_JS_FLAG_OPTS = frozenset({"--no-color", "--quiet", "-q", "--silent", "-s",
                           "--verbose", "-v", "--version", "-h", "--help", "--json", "-g",
                           "--global", "-D", "--save-dev", "-P", "--save-prod", "-O",
                           "--save-optional", "-E", "--save-exact", "-S", "--save",
                           "--no-save", "-r", "--recursive", "-y", "--yes", "-f", "--force",
                           "--dry-run", "--no-audit", "--audit", "--no-fund", "--ignore-scripts",
                           "--frozen-lockfile", "--no-frozen-lockfile", "--prefer-offline",
                           "--offline", "--legacy-peer-deps", "--strict-peer-deps",
                           "--no-progress", "--progress", "--ws", "--workspaces",
                           "--include-workspace-root", "--if-present", "--no-optional",
                           "--production", "--prod", "--dev", "--immutable",
                           "--parallel", "--stream", "--bail", "--no-bail", "--shamefully-hoist",
                           "--no-lockfile", "--pure-lockfile", "--non-interactive",
                           "--no-bin-links", "--no-update-notifier", "--update-notifier"})
_JS_GLOBAL_OPTS = {"npm": (_NPM_VALUE_OPTS, _JS_FLAG_OPTS),
                   "pnpm": (_PNPM_VALUE_OPTS, _JS_FLAG_OPTS),
                   "yarn": (_PNPM_VALUE_OPTS, _JS_FLAG_OPTS),
                   "bun": (_PNPM_VALUE_OPTS, _JS_FLAG_OPTS)}


def _js_subcommands(tool: str, args: list[str]) -> list[int]:
    """The indexes where npm's, pnpm's, Yarn's or Bun's subcommand may be
   : the first word that isn't an option or an option's value, read
    with one table (_JS_GLOBAL_OPTS). An option in neither of its tables,
    with no `=`, is read both ways, as a flag and as an option that takes
    the next word, so each reading's subcommand is in the list (a refusal
    in any of them stands)."""
    values, flags = _JS_GLOBAL_OPTS[tool]
    found: list[int] = []
    todo, seen = [0], set()
    while todo:
        i = todo.pop()
        if i in seen or i >= len(args):
            continue
        seen.add(i)
        a = args[i]
        if a == "--":
            if i + 1 < len(args):
                found.append(i + 1)
            continue
        if not a.startswith("-") or a == "-":
            found.append(i)
            continue
        opt, eq, _ = a.partition("=")
        if eq or opt in flags:
            todo.append(i + 1)
        elif opt in values:
            todo.append(i + 2)
        else:
            todo.extend((i + 1, i + 2))
    return sorted(set(found))
_NPX_VALUE_OPTS = frozenset({"-p", "--package", "-c", "--call", "-w", "--workspace",
                             "--prefix", "--userconfig", "--cache", "--registry", "--loglevel"})
_NPX_FLAGS = _NO_FETCH_FLAGS | frozenset({"-y", "--yes", "-q", "--quiet", "--ws",
                                          "--workspaces", "--include-workspace-root"})
_PNPM_EXEC_VALUE_OPTS = frozenset({"--resume-from", "--filter", "-F", "--dir", "-C",
                                   "--workspace-concurrency", "--reporter"})
_PNPM_EXEC_FLAGS = frozenset({"-r", "--recursive", "--parallel", "-c", "--shell-mode",
                              "--bail", "--no-bail", "--report-summary", "-w",
                              "--workspace-root", "--no-reporter-hide-prefix"})


def _call_text(args: list[str]) -> str | None:
    """The shell text of npx's and `npm exec`'s `-c`/`--call`."""
    for k, a in enumerate(args):
        if a == "--":
            break
        if a in ("-c", "--call"):
            return args[k + 1] if k + 1 < len(args) else ""
        if a.startswith("--call="):
            return a[len("--call="):]
    return None


def _npm_explore(args: list[str]) -> list[str]:
    """The command `npm explore <pkg> -- <cmd>` runs in the package's folder."""
    if "--" in args:
        return args[args.index("--") + 1:]
    pos = _positionals(args, _NPM_VALUE_OPTS)
    return pos[1:]


def _js_runner(lname: str, args: list[str]) -> tuple[list[list[str]], list[str]]:
    """(commands, shell texts) that npx, `npm exec`, `npm explore`, `pnpm
    exec`, `yarn exec` and `bun exec` run: `-c`/`--call` and pnpm's
    `--shell-mode` take shell text, and so do `yarn exec`, `bun exec` and
    `npm explore`, whose words are also read as a command."""
    commands: list[list[str]] = []
    texts: list[str] = []
    if lname == "npx":
        text = _call_text(args)
        if text is not None:
            texts.append(text)
        else:
            commands.extend(_command_after(args, _NPX_VALUE_OPTS, _NPX_FLAGS))
        return commands, texts
    if lname not in _JS_GLOBAL_OPTS:
        return commands, texts
    # Each word that may be the subcommand is read as it.
    for k in _js_subcommands(lname, args):
        sub, rest = args[k], args[k + 1:]
        if lname == "npm" and sub in ("exec", "x"):
            text = _call_text(rest)
            if text is not None:
                texts.append(text)
            else:
                commands.extend(_command_after(rest, _NPX_VALUE_OPTS, _NPX_FLAGS))
        elif lname == "npm" and sub == "explore":
            found = _npm_explore(rest)
            if found:
                commands.append(found)
                texts.append(" ".join(found))
        elif lname == "pnpm" and sub == "exec":
            found = _command_after(rest, _PNPM_EXEC_VALUE_OPTS, _PNPM_EXEC_FLAGS)
            commands.extend(found)
            if any(a in ("-c", "--shell-mode") for a in rest):     # (also read when it's the command's own)
                texts.extend(" ".join(c) for c in found)
        elif lname in ("yarn", "bun") and sub == "exec":
            found = _command_after(rest, frozenset())
            commands.extend(found)
            texts.extend(" ".join(c) for c in found)
    return commands, texts


def _seen_through(name: str, args: list[str], ctx: _Ctx,
                  raws: list[str] | None = None) -> list[tuple[str, list[str]]]:
    """The commands (name, arguments) that this one runs: the command after
    `uv`, `poetry` or `pdm run`; node's script when it is npm or npx; npm's
    own script run directly; the tool after `corepack` (a known variable's
    value put in first); the command after npx, `npm exec`, `npm explore`,
    `pnpm exec`, `yarn exec` and `bun exec`."""
    lname = name.lower()
    out: list[tuple[str, list[str]]] = []
    if lname == "corepack" and args:
        words = _lane_args(args[:1], ctx) + args[1:]       # `t=pnpm; corepack $t ...`
        tool = _base(words[0]).split("@", 1)[0].lower() if words else ""   # corepack npm@11.20.0
        if tool in _NPM_FAMILY:
            out.append((tool, words[1:]))
    elif lname in ("npm-cli.js", "npx-cli.js"):
        out.append((lname[:3], args))
    elif lname in ("node", "nodejs"):
        for reading in _lane_readings(args, ctx, raws, strict=True):
            out.extend(_node_scripts(reading))
    elif lname in ("uv", "poetry", "pdm"):
        out.extend((c[0], c[1:]) for c in _run_commands(args, lname))
    else:
        out.extend((c[0], c[1:]) for c in _js_runner(lname, args)[0])
    return out


def _check_through(name: str, args: list[str], ctx: _Ctx, depth: int,
                   raws: list[str] | None = None) -> str | None:
    """Each command _seen_through finds behind this one goes through every
    check a command typed at the top level gets: wrappers, a known
    variable as its name, `-c` shells, a download it pipes, and the allow
    list by its own name only. Shell text a runner runs (npx `-c`,
    `yarn exec`) is checked as a command line."""
    commands = _seen_through(name, args, ctx, raws)
    texts = _js_runner(name.lower(), args)[1]
    if not commands and not texts:
        return None
    if depth >= MAX_DEPTH:
        return _R_DEPTH
    for tool, rest in commands:
        found, reason = _command_argv([tool] + rest, ctx, depth + 1)
        reason = (reason or _check_command(_Cmd(), found, ctx, depth + 1)
                  or _check_shifted(_Cmd(), found, ctx, depth + 1))
        if reason:
            return reason
    for text in texts:
        reason = _check_text(text, ctx, depth + 1)
        if reason:
            return reason
    return None


def _stdin_reader(argv: list[str], ctx: _Ctx, levels: int = 4) -> str | None:
    """The interpreter that reads its program from stdin in this pipeline
    stage: its own command, or one a runner runs (`curl ... | uv run sh`)."""
    name = _base(argv[0])
    if _is_interpreter(name) and _reads_program_from_stdin(name, argv[1:]):
        return name
    if levels:
        for tool, rest in _seen_through(name, argv[1:], ctx):
            found = _strip_wrappers([tool] + rest)
            if found:
                inner = _stdin_reader(found, ctx, levels - 1)
                if inner:
                    return inner
    # The shell text a runner runs (npx and `npm exec` `-c`/`--call`, `npm
    # explore`, `pnpm exec`, `yarn exec`, `bun exec`) inherits the pipe too
    #: each command in it is read as a pipeline stage is.
    for text in _js_runner(name.lower(), argv[1:])[1]:
        inner = _text_stdin_reader(text, name, ctx, levels)
        if inner:
            return inner
    return None


def _text_stdin_reader(text: str, runner: str, ctx: _Ctx, levels: int) -> str | None:
    """The interpreter that reads stdin among the commands of a runner's
    shell text, with _lex, _parse, _strip_wrappers and _stdin_reader;
    the runner's own name where the gate can't read the text, or a command
    word in it holds a `$` or a substitution, or the levels run out."""
    if not levels:
        return runner
    try:
        pipelines = _parse(_lex(text, ctx))
    except (_Unparseable, _TooManyWords, _Refused):
        return runner
    for pipe in pipelines:
        for cmd in pipe:
            found = _strip_wrappers(cmd.argv)
            if not found:
                continue
            head = cmd.argv[:max(0, len(cmd.argv) - len(found))] + found[:1]
            if any("$" in w or _PLACEHOLDER_RE.search(w) for w in head):
                return runner
            inner = _stdin_reader(found, ctx, levels - 1)
            if inner:
                return inner
    return None


_R_CALLBACK_UNREAD = _coded("launch-hidden-command", ("launch gate (rule 1): `mapfile -C` "
            "(or `readarray -C`) runs its callback as a command, and this one is built at run "
            "time (a `$`, a backtick or a substitution), so the gate can't tell what runs; "
            "blocked to be safe. Write the callback out, or drop `-C`."))
_R_PROMPT_VAR = _coded("launch-hidden-command", ("launch gate (rule 1): this sets PS0, PS1, "
            "PS2, PS4 or PROMPT_COMMAND to a value that holds `$(`, a backtick, `$[` or a "
            "substitution, which the shell runs later (PS4 under `set -x`), so the gate "
            "can't tell what runs; blocked to be safe. Use a plain value, such as "
            "`PS4='+ '`."))
_R_PROMPT_UNREAD = _coded("launch-hidden-command", ("launch gate (rule 1): `${x@P}` expands "
            "a value as a prompt, which runs the substitutions in it, and here the value "
            "isn't one the gate knows, or holds a substitution; blocked to be safe. Use "
            "`${x}` or `${x@Q}` instead."))
_PROMPT_VARS = frozenset({"PS0", "PS1", "PS2", "PS4", "PROMPT_COMMAND"})
_RUNS_LATER = ("$(", "`", "$[")
_AT_P_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)@P\}")


def _prompt_assign(word: str, ctx: _Ctx | None = None) -> str | None:
    """A prompt variable given a value that runs a command later,
    also through a known variable's value (`PS4=$x`)."""
    name, eq, value = word.partition("=")
    if not (eq and name.rstrip("+").split("[", 1)[0] in _PROMPT_VARS):
        return None
    if ctx is not None and "$" in value:
        value = _expand_known(value, ctx)
    if any(s in value for s in _RUNS_LATER) or _PLACEHOLDER_RE.search(value):
        return _R_PROMPT_VAR
    return None


def _prompt_setters(name: str, args: list[str]) -> str | None:
    """read, mapfile, readarray, getopts and `printf -v` setting a prompt
    variable to a value the gate can't see."""
    if name == "printf":
        targets = [args[k + 1] for k, a in enumerate(args[:-1]) if a == "-v"]
        targets += [a[2:] for a in args if a.startswith("-v") and len(a) > 2]
    elif name in ("read", "mapfile", "readarray", "getopts"):
        targets = [a for a in args if not a.startswith("-")]
    else:
        return None
    if any(t.split("[", 1)[0] in _PROMPT_VARS for t in targets):
        return _R_PROMPT_VAR
    return None


def _prompt_expansions(cmd: _Cmd, ctx: _Ctx) -> str | None:
    """`${x@P}` in a command's words, redirects or heredocs: refused unless x
    holds a known value with no substitution in it."""
    texts = list(cmd.argv) + [t for _op, t in cmd.redirs] + [h[0] or "" for h in cmd.heredocs]
    for text in texts:
        if "@P" not in text:
            continue
        found = list(_AT_P_RE.finditer(text))
        if text.count("@P") != len(found):
            return _R_PROMPT_UNREAD
        for m in found:
            value = ctx.vars.get(m.group(1))
            if value is None or any(s in value for s in _RUNS_LATER) or _PLACEHOLDER_RE.search(value):
                return _R_PROMPT_UNREAD
    return None


def _mapfile_callback(args: list[str], ctx: _Ctx, depth: int) -> str | None:
    """mapfile's and readarray's `-C callback`, which runs as a command for
    each batch of lines it reads: checked as one where the gate can
    read it, refused where it's built at run time."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--" or not a.startswith("-") or a == "-":
            break
        for j in range(1, len(a)):
            if a[j] in "dnOsuCc":       # the options that take a value
                value = a[j + 1:]
                if not value:
                    i += 1
                    value = args[i] if i < len(args) else ""
                if a[j] == "C":
                    if "$" in value or "`" in value or _PLACEHOLDER_RE.search(value):
                        return _R_CALLBACK_UNREAD
                    reason = _check_text(value, ctx, depth + 1)
                    if reason:
                        return reason
                break
        i += 1
    return None


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

    # The words as written, where argv is still the command's own (quotes
    # kept), so that a word mixing quoted and unquoted expansions is read
    # with each part's own quoting.
    raws = None
    if cmd.raw and len(cmd.rawx) == len(cmd.argv) and len(argv) <= len(cmd.argv) \
            and cmd.argv[len(cmd.argv) - len(argv):] == argv:
        raws = cmd.rawx[len(cmd.rawx) - len(argv) + 1:]

    reason = _lane_command(name, args, ctx, raws)    # never relaxed by launch_gate.allow
    if reason:
        return reason

    # The allow list relaxes this command's own name only; what a runner
    # runs is checked on its own.
    if not _allowed(argv, ctx):
        reason = _blocked_command(name, args)
        if reason:
            return reason
    reason = _check_through(name, args, ctx, depth, raws)
    if reason:
        return reason

    if name in ("mapfile", "readarray"):
        reason = _mapfile_callback(args, ctx, depth)
        if reason:
            return reason
    reason = _prompt_setters(name, args)
    if reason:
        return reason

    if name == "trap":
        # The handler runs later in this shell: check it as a command.
        handler = [a for a in args if a != "--" and not (a.startswith("-") and len(a) == 2)]
        if handler:
            reason = _check_text(handler[0], ctx, depth + 1)
            if reason:
                return reason

    if name == "eval":
        ctx.eval_args.update(a for a in args if _PLACEHOLDER_RE.fullmatch(a))
        for a in args:
            sub = _sub_body(a, ctx)
            if sub and _is_download(sub[1], ctx):
                return _r_pipe("eval")
            if _joined_in(a, ctx):
                return _R_LIST_JOINED
            # What a list or pipeline in eval's words prints is run as shell
            # text: one the gate can't read is refused.
            for m in _PLACEHOLDER_RE.finditer(a):
                sub = _sub_body(m.group(0), ctx)
                if (sub and sub[0] == "c" and _is_list(sub[1], ctx)
                        and _list_output(sub[1], ctx) is None):
                    return _R_LIST_UNREAD
        text = " ".join(args)
        reason = _check_text(text, ctx, depth + 1)
        if reason:
            return reason
        # What eval runs is the text after the shell has put in the
        # variables and what a substitution it can read prints (an `echo` or
        # `printf`), so check that too (`eval "$a$b=0"`).
        # (A list of prints may print several texts: each is read.)
        combos: list[list[str]] = [[]]
        for a in args:
            combos = [c + [p] for c in combos for p in _printed(a, ctx)]
            if len(combos) > MAX_EVAL_READINGS:
                return _R_LIST_UNREAD
        for combo in combos:
            expanded = _expand_known(" ".join(combo), ctx)
            if expanded != text:
                reason = _lane_text(expanded) or _check_text(expanded, ctx, depth + 1)
                if reason:
                    return reason
                if _defines_date(expanded):
                    ctx.date_defined = True
            # A name still built at run time that the text then assigns
            # (`eval "$1=0"` after `set -- npm_config_ignore_scripts`) is an
            # assignment the gate can't read.
            if _DYN_GLUED_RE.search(expanded):
                return _R_LANE_NAME
        return None

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
    seen = [("set", w) for w in argv[:k]]
    argv, reason = _resolve_command_word(argv[k:], ctx, depth)
    if reason:
        return argv, reason
    if len(argv) > 1 and argv[0] in ("for", "select") and _lane_entry(argv[1]):
        return argv, _r_lane(_lane_entry(argv[1])[0])     # the loop sets it
    argv = _strip_wrappers(argv, seen)
    reason = _lane_seen(seen, ctx)      # never relaxed by launch_gate.allow
    if reason:
        return argv, reason
    return _resolve_command_word(argv, ctx, depth)


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
        reason = _prompt_expansions(cmd, ctx)
        if reason:
            return reason
        # In the variant pass a stage may be shortened to words that look like
        # assignments (`$e v=ls` to `v=ls`). Bash decides that when it parses, so
        # only a stage that was all assignments as written sets variables.
        if argv and all(_ASSIGN_RE.match(w) for w in argv) and (not variant or cmd.assigns == len(argv)):
            # The template's lane names are exported, so a bare assignment
            # changes what later commands get.
            reason = _lane_seen([("set", w) for w in argv], ctx)
            if reason:
                return reason
            for w in argv:
                key, value = w.split("=", 1)
                if key.endswith("+") or "[" in key:
                    # An append or an element: a value the gate may not know.
                    ctx.vars.pop(key.rstrip("+").split("[", 1)[0], None)
                else:
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
        name = _stdin_reader(argv, ctx)
        if not name:
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
_FALLBACK_PM = re.compile(r"(?<![\w.-])(npm|pnpm|yarn|bun|uv|pip[0-9.]*|node|nodejs|corepack|"
                          r"npm-cli\.js)(?![\w-])", re.I)
_FALLBACK_DOWNLOAD = re.compile(r"(?<![\w-])(curl|wget|iwr|irm|fetch)(?![\w-])", re.I)
_FALLBACK_INTERP = re.compile(
    r"\s*(?:sudo\s+)?(?:\S*/)?((?:ba|z|da|k|mk|fi|a)?sh|python[0-9.]*|node|perl|ruby|php|iex|pwsh|powershell)\b",
    re.I)


def _fallback(text: str) -> str | None:
    """Unparseable text: deny only if it mentions something we'd block, in
    the text as written or as the shell would join its words (`n''px`)."""
    reason = _fallback_form(text)
    if reason:
        return reason
    norm = _name_norm(text)
    return _fallback_form(norm) if norm != text else None


def _fallback_form(text: str) -> str | None:
    m = _FALLBACK_WORDS.search(text)
    if m:
        return _r_parse(m.group(1))
    m = _FALLBACK_PHRASES.search(text)
    if m:
        return _r_parse(m.group(0))
    # A package manager with any option: bash may still run it (a trailing
    # backslash), and the lane checks can't read its options here.
    m = _FALLBACK_PM.search(text)
    # (`$IFS` is white space unless set, so an option may follow it.)
    if m and re.search(r"(?:^|\s)['\"]?-", re.sub(r"\$\{?IFS\}?", " ", text)):
        return _r_parse(m.group(1))
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
    reason = _lane_text(command)
    if reason:
        return reason
    # Read the text as bash splits it. Where a finer split would read other
    # words (a carriage return, a form feed or a vertical tab, white space
    # that IFS leaves out, an empty field), read it that way too: a refusal
    # in either reading stands.
    ifs_set = _sets_ifs(command)
    date_defined = _defines_date(command)
    for fine in (False, True):
        _BRACE_BUDGET[0] = MAX_BRACE_WORK
        ctx = _Ctx(allow, ssh_hosts)
        ctx.fine = fine
        ctx.date_defined = date_defined
        ctx.ifs_set = ifs_set
        try:
            reason = _check_text(command, ctx, 0)
        except _Refused as exc:
            reason = exc.reason
        except RecursionError:
            reason = _R_DEPTH
        if reason or not ctx.reread:
            return reason
    return None


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
            try:
                reason = _monitor_feed(command)
            except _Refused as exc:
                reason = exc.reason
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
