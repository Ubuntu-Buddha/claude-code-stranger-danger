# Harness portability and roadmap (design draft)

> **Status:** draft, 2026-10-09. Today the plugin targets Claude Code only. This note records the plan for other harnesses and is honest about where each one can and can't enforce the rules.

## Two layers

StrangerDanger is two layers, and only one of them is tied to a harness:

- **The principles** are harness-agnostic. Readers don't act and actors don't read; the 7-day lane; untrusted text is never an instruction; secrets stay put; the reader agents; the [coordinator](COORDINATOR.md). These are the same wherever you run.
- **The enforcement** is harness-specific. The reader gate and launch gate are Claude Code hooks, and the deny rules are Claude Code permissions. They don't drop into another harness unchanged.

The gate logic itself (parsing a command, deciding a path) is plain Python with no Claude Code imports. Any harness that can run a command on a tool call can reuse it. What differs per harness is the wiring: how the harness calls the gate, and whether it can actually stop the tool.

## Where each harness can enforce

Enforcement is only as strong as the harness's choke point — the place a guardrail can sit and say no before a tool runs.

| Harness | Choke point | Strength | What's enforced vs. advisory | Status |
|---|---|---|---|---|
| **Claude Code** | `PreToolUse` hooks (a non-zero exit blocks the call) plus `permissions` allow/deny/ask and per-subagent tool lists | Strong | The gates hard-block. The rules are advisory (the model follows them). | Built |
| **OpenCode** | Plugins run code and can hook tool execution; config sets permissions and agents | Strong, with caveats | A plugin can hard-block and can shell out to the same gate logic. Caveats below. | Roadmap, next |
| **Cursor** | `.cursor/rules` and MCP config | Weak / advisory | Rules are text the model is asked to follow. No user-configurable deterministic gate to block an arbitrary tool call. | Roadmap, later |
| **Codex** | Its own OS sandbox and approval modes | Mixed | The sandbox and approvals are real, but the pluggable-rule surface is different and narrower. | Roadmap, uncertain |

Rows marked [verify] in future edits need checking against each tool's current version before we claim them; harness features change.

## Why Cursor is weak (and stays roadmap)

Cursor's main control surface is `.cursor/rules`: instructions handed to the model. That's the same thing prompt-injection defeats — text the model is *asked* to honor, not a gate that *prevents* the action. There's no user-configurable equivalent of Claude Code's `PreToolUse` hook where we can attach a deterministic deny before a tool runs. So in Cursor, StrangerDanger can ship the principles and the reader pattern, but it can't promise the hard blocks.

That's worth documenting plainly rather than shipping something that looks protective and isn't. Until Cursor exposes a deterministic tool-gating hook, its adapter is "principles + advisory rules, clearly labeled as not enforced." [verify] against Cursor's current extension and hook surface before release.

## Why Codex is a separate adapter

Codex leans on an OS-level sandbox and approval prompts rather than pluggable hooks. Some of that is genuinely strong — a sandbox can beat a hook. But it's a different model: we'd express the rules through Codex's sandbox and approval config, not by porting our hooks. That makes it its own adapter, and its priority is lowest until we've confirmed what its config can and can't express. [verify].

## The stack that matters first: Claude Code inside OpenCode

Some people run Claude Code *inside* OpenCode. This changes where protection has to live:

- The **outer** harness (OpenCode) is where OS-level actions actually happen. Its guardrails are the ones that contain the machine.
- Claude Code's hooks only govern Claude Code's *own* tool calls. They don't see or stop what OpenCode does directly, or what another agent running under OpenCode does.

So for this stack, locking down Claude Code is necessary but not sufficient. The OpenCode adapter isn't a nice-to-have; it's the layer that actually contains the host. That's the reason OpenCode is next, not later.

## Repo shape (planned, not done)

Keep one repo. Don't fork per harness — separate repos drift, and the threat model and tests should stay shared.

```
core/        the rules, threat model, gate logic, reader and coordinator design, tests
adapters/
  claude-code/   hooks.json, settings + sandbox templates, setup/doctor (today's plugin)
  opencode/      a plugin that calls the core gate logic; permission + agent config
  cursor/        principles + advisory rules (no hard blocks)   [roadmap]
  codex/         sandbox + approval config                       [roadmap]
docs/        shared design notes
```

We hold off on this move until the OpenCode adapter actually starts, so the Claude Code hardening isn't churned mid-flight. When we do split, the Claude Code pieces move under `adapters/claude-code/` and the harness-agnostic gate logic moves to `core/`.

## Order of work

1. **Claude Code — rock solid, v0.1 experimental.** Done in v0.1.0: the README rewrite, a doctor blast-radius check, a linear-time regex meta-test for the gates, runs of `docs/VERIFY.md`, squashed history, and the experimental label.
2. **OpenCode adapter.** The core gate logic behind an OpenCode plugin, plus its permission and agent config. Honest about the caveats: OpenCode plugins run code (so the plugin itself must be trusted and pinned), and `opencode.json` lives in-repo (so a stranger's repo can carry its own config — the adapter has to assume the project config, not inherit a stranger's).
3. **Cursor** — principles and advisory rules, labeled as not enforced.
4. **Codex** — once its sandbox and approval config are confirmed.

Each harness ships with a one-line, honest statement of what it enforces and what it only advises.
