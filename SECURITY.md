# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open the
repository's **Security** tab and choose **Report a vulnerability**. Don't
open a public issue for a bypass.

A useful report names the gate, the hook input that gets past it (a synthetic
event JSON is ideal), what the gate decided, and your Claude Code version.

## Supported versions

Only the latest release gets fixes.

## Scope

In scope: a hook input that the [README](README.md) says a gate denies but
the gate lets through. For example:

- a main-session or ordinary-subagent call that reaches WebFetch or WebSearch;
- a WebFetch that reaches a local or private address;
- a read of a configured untrusted or quarantine folder by anyone but its
  reader, or a reader reading outside its folders;
- a read of a built-in secret path;
- a non-reader agent that passes as a reader;
- a reader agent that uses a tool outside its own list (the reader-tools
  hook);
- a crash or hang in the reader gate or the reader-tools hook that lets a
  call through instead of blocking it.

Out of scope: what the README lists under
[What this does not do](README.md#what-this-does-not-do). That covers:

- **the launch gate.** It's a tripwire, not a security boundary, and it has
  known gaps, so a way past it is not a vulnerability in what the README
  promises. Still report one privately, as above, never in a public issue.
  The control for downloads is the sandbox's network allowlist;
- Bash reading files (the reader gate doesn't see Bash);
- DNS rebinding;
- the behavior of Claude Code itself, such as how and when it shows
  permission prompts. Report Claude Code issues to Anthropic.
