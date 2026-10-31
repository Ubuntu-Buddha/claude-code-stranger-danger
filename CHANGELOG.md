# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-01

### Added

- **Instruction-file check** (`hooks/instr_check.py`, a SessionStart hook on
  start, resume, clear, after compaction and in a fork, the last two as Claude Code's docs describe them, not yet checked live). Tells you, and the model, when a file Claude Code
  loads as instructions (`CLAUDE.md`, `AGENTS.md`, `CLAUDE.local.md`, and
  files under `.claude/` rules, agents, commands, output-styles and skills) is
  new or differs from git `HEAD`, in fixed text with no file names from the
  repo and no file text. Git is looked up from a fixed list of places, never
  `PATH`, and runs only after the repo's git config passes an allowlist (a repo
  at format version 0 that has `extensions.worktreeConfig` (as sparse-checkout can
  leave it, not yet checked live)
  passes, as git accepts it; other extensions at version 0 stop git). It
  compares with `HEAD`, which a sandboxed shell can move, so a planted file
  that was also committed passes; see the README, "What this does not do". If
  the hook can't start, its command prints one fixed line.
- **Coordinator skill: models are named.** The skill now tells the coordinator to
  name the model and effort on every Agent call and every session it starts at
  the user's request, where the host allows it, to check a new session's model
  where the host shows it, and to report a wrong or unchecked one rather than
  switch it.
- **Gate misses are reported privately.** SECURITY.md, the report skill and
  the README now send a command the launch gate misses to private
  vulnerability reporting, never to a public issue. The repo needs private
  reporting turned on in its GitHub settings.
- **Approve-to-run for the desktop app's Terminal panel** (`hooks/terminal_gate.py`).
  A step Claude can't do itself, a check you want run outside the sandbox, can
  go to the panel as one line you approve at a permission prompt that shows the
  whole line. The gate allows only check lines, by full path and at most 200
  characters: `sha256sum` or `stat` of a file in a short lane of folders, a
  unit's `is-active` or `is-enabled`, and the `sudo -k true` password check.
  Everything else is refused: installs, unit actions, status checks, `cwd`, a
  `tab_id`, a subagent's call, any entrypoint but the desktop app, and any
  permission mode that wouldn't show you a prompt. It is off while a settings
  file allows a terminal tool, enables another plugin, has a hook on terminal
  tools or a permission-request hook, limits rules to managed ones, a
  server-managed cache exists, more than one key of this plugin is enabled, a
  settings file can't be read, there is no absolute working folder, or the settings template's new ask rule
  `mcp__terminal__run_in_terminal` is missing. Claude may read a line's tab
  once and close it; a `sudo` line's tab is never read. A tripwire for what an
  agent sends, not a boundary around the panel: see `docs/HOW-IT-WORKS.md`
  (Approve-to-run) for what it doesn't cover. Whether a plugin hook's "ask"
  reaches you in the desktop app is `docs/VERIFY.md` row T1.
- **Settings template: terminal tools.** `mcp__terminal__read_terminal` and
  `mcp__terminal__stop_terminal_tab` join the ask list, opening and listing
  tabs are denied, and `Edit` of `.claude/skills` is denied.
- **Doctor: a quarantine folder that isn't dedicated.** The doctor warns
  (`config quarantine_root`) when a quarantine folder in your gate config holds
  your home folder (other agents' file tools are refused there), or the
  project or working folder it runs in (the quarantine reviewer reads
  `.npmrc` and `.yarnrc.yml` there). It doesn't
  notice a folder above your projects when it runs from somewhere else.
- **The 7-day package lane in the settings template.** Its `env` entries set
  `npm_config_min_release_age=7` and `npm_config_ignore_scripts=true` for
  every command Claude Code runs, which npm's docs say it reads ahead of any
  `.npmrc` (an install that waits through them wasn't tried here). The
  doctor checks them, warns when a project's settings set them weaker, and
  warns on an npm older than 11.10.0. The README says what they break and
  gives the uv, pnpm and Bun forms, which the template doesn't set.
- **The launch gate guards the package lane.** It refuses the common
  spellings of a command whose own words turn off, shorten or clear the
  lane, judged by value: npm's `min-release-age`, `before` and
  `ignore-scripts` as options (any number of dashes or `no-`s, or a prefix
  only one option has; on npm run through node, `npm-cli.js`, corepack or
  `uv run` too), through `npm config set`, `delete` or `edit`, or as
  `npm_config_*` variables (assigned or exported with a value it judges,
  passed through `env`, unset, or dropped with `env -i`, `exec -c`,
  `setpriv --reset-env` or `bwrap --clearenv`); uv's `--exclude-newer` or
  `UV_EXCLUDE_NEWER` under 7 days, with a bare date read as the end of
  that day in the latest time zone, as uv reads it in yours; pip's and
  uv's options that turn on builds from source (`--no-binary`, or
  `--only-binary` other than `:all:`, also through `python -m pip`);
  pnpm, Yarn and Bun's own age settings (other units) and their ways to let
  install scripts run (`--dangerously-allow-all-builds`, `--allow-build`,
  `approve-builds`, `--trust`, `enableScripts`); and an option whose name
  is built at run time (a word that holds a variable or substitution is
  refused when it starts with a dash, or when the text after the variable
  could be a lane option's name, since the value may hold white space that
  splits the word: `npm ci$1--no-ignore-scripts`; `npm i $a-$b` passes). A
  known variable's value, `$IFS` included, or the output of an `echo` or
  `printf` substitution it can read, is put into a word before its options
  are read, and split exactly as bash splits it: at the characters of `IFS`
  (a space, tab and newline unless the call sets it; no carriage return,
  form feed or vertical tab, and no white space that `IFS` leaves out), with
  no quotes or backslashes read (`IFS=:; x=ci:--no-ignore-scripts; npm $x`;
  `x="--x' --no-ignore-scripts"; npm ci $x` is two words). Where a finer
  split would read other words, the whole call is read that way too, and a
  refusal in either reading stands. A call that sets `IFS` some way the
  gate can't read is refused where it needs that split; `IFS=, read -r a b
  < f` and other `IFS=value` words that only prefix a command that runs no
  shell text set nothing for later words; one before any of bash's special
  builtins (`shift`, `set`, `export`, `eval`, `.`, `:` and the rest) counts
  as setting `IFS`, since posix mode keeps it set. A raw carriage return is
  part of a word, as in bash, and the call is read with it as a separator
  too. A package manager's or node's options are read as bash reads each
  word as written: quoted parts whole, the text of unquoted expansions split
  at `IFS`, written text never split (`node --title "$t"$u`, `npm
  ci$x--no-ignore-scripts` with `IFS` set). Where the word as written isn't
  known (behind a runner), a known value is read both ways, split and
  whole, for up to five words, and past that the call is refused; with
  `IFS` set there, a word that mixes an expansion with written text holding
  an `IFS` character is refused. A
  chain of variables still changing after 8
  rounds, or a word a substitution grew past 20,000 characters, is refused;
  a long word that no substitution grew is not. A lane variable's name may
  appear only as a plain read (`$NAME`, or a form that only reads it, such
  as `${NAME:-x}`) or an assignment the gate judges: bash has too many
  other ways to set a variable (a loop, `read`, `let`, arithmetic,
  `${NAME:=x}`, a reference, `coproc`), so any other mention is refused,
  harmless ones too. So are the ways to set one by a name built from
  parts: arithmetic (`(( ))`, `$(( ))`, `$[ ]`), `let`, an array subscript,
  a substring's offset (`${x: ...}`) or `[[ ]]` that assigns or counts up
  or down through a `$` expansion written straight before the operator
  (`(( $1=0 ))`, `(( $a$b-- ))`; in `[[ ]]` only a glued `=` or one inside
  a quoted word, since `-eq` reads its operands as arithmetic). The gate
  reads only the text inside the construct itself, not what follows it, so
  `n=$((n+1)); [ $n = 5 ]` passes; a `(( ))`, `$[ ]`, subscript or `let`
  that never closes is read as arithmetic to the end of the text, while a
  `[[` that never closes (`echo [[`, a quoted `"[["`) is text or a syntax
  error that runs nothing, so the search goes on past it for later openers
  (`grep -c '[[' f; [ $n = 0 ]` passes, `echo [[; (( $a$b = 0 ))` is
  refused); `$((` is arithmetic only when the `)` that closes its second
  `(` is followed at once by another `)`, and otherwise a command
  substitution that is checked like any other; a piece of arithmetic it
  can't parse is refused; arithmetic (`$(( ))`, `(( ))`, `$[ ]`) that holds
  a `#` at its start or after a blank, a carriage return, `;`, `&`, `|`,
  `(`, `)`, `<` or `>`, or a line break, or (in `$[ ]`) a quote, is
  refused, since the parser would read such a `#` as a comment and bash's
  arithmetic has none; a `#` after any other character passes (`16#ff`,
  `$#`, `${#x}`, `${x#0}`, `${n##0}`, `${base}#ff`);
  more arithmetic than it can read (300,000 characters) is refused, with a
  reason that says the arithmetic is too long to read. A `$'..'`, a
  substitution or a quoted string inside `[[ ]]` is stepped over as the
  parser reads it, and one the parser refuses is refused. `let`
  is judged as a command, after the quotes, wrappers, prefixes and
  assignments are taken off and a known command word is resolved
  (`X=1 let "$a$b=0"`, `time -p let ...`, `c=let; $c ...`): an argument
  that assigns through a name built at run time is refused. An element
  assignment with a variable subscript (`arr[$i]=x`) passes. The gate also
  refuses `declare`, `typeset` or `local` with `-i` or `-n`, `eval`
  of text that names one once its known variables and the output of an
  `echo` or `printf` substitution it can read are put in (or that assigns
  through a name it can't resolve: `eval "$1=0"`), and bash's keyword mode
  (`set -k`, `set -o keyword`, a shell run with `-k`, `SHELLOPTS`, also
  when the option comes from a known variable), where a `NAME=value` word
  anywhere in a command assigns. On pnpm, Yarn and Bun the gate reads npm's three option names
  the way it does on npm, except that a word after an option with no `=`
  may be that option's value, so `pnpm --filter foo install --ig=false` is
  refused; after a script or tool name only the exact name counts. node
  counts as running npm only when npm is node's own script, not an
  argument of another script. The gate has lists of node's options that
  take their value in the next word (`node --redirect-warnings w.js
  /usr/bin/npm ci` runs npm) and of those that take none (`node --inspect
  ./bin/tool npm ...` runs `./bin/tool`); an option in neither list is read
  both ways. A
  command word or argument printed by `printf` or `echo -e` is read with
  its escapes (`$(printf 'npx\n')`, `\x20`, `\040`, `\u0020`; also
  `printf --`), also after assignments and wrappers (`X=1 printf ...`,
  `command printf ...`). `printf` reads `\ddd` as 1 to 3 octal digits
  (`\0401` is `\040` and then `1`), `echo -e` and `%b` read `\0` and up to
  3 more, and where the two differ the call is read both ways. A
  command-position substitution whose body holds a `printf` or `echo`
  anywhere (after assignments and wrappers, in a list, in a pipeline) is
  refused when what it prints starts a blocked command (`npx`, `sudo`,
  `curl` and the like), and when a `printf` or `echo` in it prints text the
  gate can't read: an escape it doesn't decode (an unknown one, a trailing
  backslash), `\c`, a NUL, a `%` format, any `printf` option but `--`
  (`-v` and the rest), or an `echo` with a backslash and no `-e`. Under
  `eval` the same holds within limits (see the README). A body that is a list or a pipeline, in
  command position or as an `eval` argument, is read only when it holds
  nothing but `printf`, `echo`, `true`, `:` and `head` or `tail` with plain
  options, joined only by `;` or a line break: each text it may print is
  then checked as the command (`$(true; echo npm) exec x` as `npm exec x`),
  and any other such body is refused, also one that joins commands with
  `&&`, `||` or `&` (outside quotes), since bash may skip a print or run it
  in the background. A
  function defined inside a quoted string, for `eval`, or with quotes or
  backslashes in its name (`da''te(){ ...; }`), counts as defining `date`.
  Only the exact word `true` keeps `ignore-scripts` on, since npm didn't
  read `TRUE` as true. `--exclude-newer "7 days"`, a date 9 days ago and
  `"$(date -d '9 days ago' +%F)"` pass for uv, and `--before` with a date
  8 days ago for npm, and `launch_gate.allow` never relaxes it. The gate
  reads `$(date ...)` in UTC; for npm's `--before`, where a bare date is
  midnight UTC, it reads a `date` without `-u` at the latest zone (UTC+14),
  since a user east of UTC can be a calendar day ahead, so 7 days ago is
  refused from about 10:00 UTC. For uv it doesn't, because uv reads the
  date in the zone `date` printed it in, and its end-of-day reading in the
  latest zone (UTC-12) covers that. The refusal for a lane option now gives
  uv's form as the rules do, a date 9 days ago. Like the rest of the gate
  it's a tripwire: a script, a Makefile, a `package.json` script, an
  `.npmrc`, or uv's, pnpm's, Yarn's and Bun's config files, and shell text the
  call defines, get past it. The plugin's rules now give uv's date form as 9 days ago. uv reads a bare
  date as the end of that day in your zone, so a date typed by hand or
  printed by `date -u` can fall short at 8 days for part of the day; a
  local `date` in uv's own zone is fine at 8, but the gate can't know the
  zone, so it reads the date at the latest zone (UTC-12) and refuses 8
  days ago before 12:00 UTC. That 9 is the gate's margin. Rule 1's checks
  see through runners: what `uv`, `poetry` and `pdm run`, node's npm or npx
  script, `npx-cli.js` run directly, corepack, `pnpm exec`, `yarn exec`,
  `bun exec`, `npm explore <pkg> -- <cmd>`, and npx's and `npm exec`'s
  command and `-c`/`--call` text run gets every check a command typed at
  the top level gets (wrappers, a known variable as its name, `-c` shells,
  a download piped into it), except the known gaps below. A download piped into a runner whose shell
  text (`-c`/`--call`, `npm explore`, `pnpm exec`, `yarn exec`, `bun
  exec`) runs a shell or another interpreter that reads stdin is refused as
  a download piped to a shell (some forms get past it; see the known gaps
  below), and so is one whose text the gate can't split or that holds a `$`
  or a substitution in a command word; a text that runs a script file
  passes. uv's, Poetry's and
  PDM's global options that take a value are read, so `run` is the
  subcommand only as the first word that is neither an option nor its value
  (`uv add run sudo` passes), and an option the gate doesn't know before the
  subcommand is refused. The launcher check reads uv's subcommand with that
  same table, so a uv call with a global option missing from the gate's
  table is now refused there too (`uv tool run` behind one is found). npm,
  pnpm, Yarn and Bun have one table of options before the subcommand, those
  that take a value (`--loglevel`, `--otp`, `--omit`, `--reporter` and the
  like) and common ones that take none (`--no-color`, `--silent`, `-g`,
  `-r` and the like), used by the launcher check and by every runner the
  gate sees through; an option in neither table, with no `=`, is read both
  ways, as a flag and as an option with a value, and a refusal in either
  reading stands.
  `launch_gate.allow` relaxes a runner by its own name only, never the
  command it runs. The parse fallback for text it
  can't parse also searches the text as the shell would join its words
  (`n''px`). Beyond what is listed above, the gate does
  not follow names, options or word splits built at run time (arithmetic,
  `eval`, payloads, traps, `IFS` and the like), among them some `eval` forms.
- **The launch gate refuses forms it can't read.** Where reading a form
  exactly would mean modelling more of bash, the gate refuses it with
  `launch-hidden-command` or `launch-unparseable` and a line that says what
  to write instead: arithmetic holding a comment-like `#`, a line break or
  (in `$[ ]`) a quote; a list or pipeline substitution that holds more than
  prints, or joins commands with `&&`, `||` or `&`; a download piped into a
  runner's shell text that the gate can't read; an unknown uv, Poetry or PDM
  option before the subcommand; a word
  that mixes an expansion with written `IFS` text where the word as written
  isn't known; `mapfile -C` or `readarray -C` with a callback built at run
  time (a readable one is checked as a command); a `PS0`, `PS1`, `PS2`,
  `PS4` or `PROMPT_COMMAND` value that holds `$(`, a backtick, `$[` or a
  substitution (also through a known variable, or set by `read`, `mapfile`
  or `printf -v`); and `${x@P}` on a value that isn't known or holds a
  substitution. A few unusual but harmless commands are refused too (a
  `$(( ))` over two lines, a comment inside `(( ))`). Names, options and
  word splits built at run time stay the stated known miss.
- **A reminder to run the doctor after updates.** A session-start hook shows
  you a fixed line when a session starts or resumes after the `claude` on
  your PATH or the plugin changes. It tells Claude nothing, never blocks,
  runs nothing and makes no network call.
- **A canary word at install.** The one-command install fills in a random
  rules canary and prints it, and gives one to a rules copy that still has
  the placeholder.
- **Setup in chat.** `/stranger-danger:setup` now sets up in chat: it checks
  your settings file for anything that looks like a secret before Claude
  reads it, asks whether you use auto mode, changes each file through one
  Write prompt that shows its diff, and guides you through the steps that
  stay yours. The terminal install is still there.
- **A settings guard.** A new gate on Edit, Write, MultiEdit and NotebookEdit
  refuses every change to your settings file, the `CLAUDE.md` that loads the
  rules, the rules folder and the gate config folder, except a Write of the
  text setup works out from your files as they are. It catches other
  spellings of those paths, hard links and other names for their folders.
  It doesn't see the shell or MCP tools that write files, and while the
  plugin is off these files are only asked about.
- **Sandbox write denies for setup's files.** Setup adds your settings file,
  the `CLAUDE.md` that loads the rules and the rules folder to
  `sandbox.filesystem.denyWrite` once they exist, so sandboxed commands
  can't change them, and the doctor warns while one is missing.
- **A canary word nothing shows a session.** A session-start hook fills in
  a rules file's placeholder canary line with a random word and shows you
  fixed text without it; a session sees the word only by loading your
  rules. The doctor's canary step now compares the word a session states
  with the file and prints only whether it matches, so you needn't know
  the word.
- **Sandbox read denies for your gate config's folders.** The one-command
  install adds the untrusted, quarantine and plain secret folders that exist
  to `sandbox.filesystem.denyRead`, so sandboxed commands can't read what
  the reader gate keeps from the file tools. It leaves out folders that
  sandboxed work needs, and the doctor lists the ones still open.
- **A scan for hidden instructions.** Type `/stranger-danger:scan <folder>`
  for a skill, plugin or MCP server folder in your quarantine folder, and a
  hook on your typed prompt counts instruction-style and injection text,
  model-aimed markup, hidden comments in agent instruction files, invisible
  and lookalike characters, controls, download-and-run lines, Discord
  webhooks and paste sites. Claude sees counts only, never the folder's text,
  and can't start a scan itself (unless another prompt source, such as a
  background agent's report, delivers the bare line; VERIFY row S2e checks
  this). The per-file detail goes to a results folder
  beside the scanned one, for the quarantine reviewer. It counts; it doesn't
  judge, and it doesn't look at code behaviour yet. Its core
  (`hooks/trigger_scan.py`) is a port of a trigger
  inventory, for those rules only. For other callers, the walker's `run()`
  (`skills/scan/scan.py`) also takes `results_fd` (an open folder outside
  the quarantine folders it's given) and `results_name`, the results
  folder's name; the hook's scan is unchanged.
- **An OSV check, when you ask (optional).** Type `/stranger-danger:osv` and
  a sandboxed command checks the packages your lockfiles and global installs
  hold, and your Node.js and CPython versions, against OSV and GitHub's
  malware advisories, with severity words and fixed versions. Claude sees
  counts and fixed words, never package names. A session-start line tells
  you about a malware record, a fix out for a high or critical
  vulnerability, or a check that's due (24 hours) or stale (36); Claude
  gets the same line to pass on once, since the desktop app didn't show a
  session-start hook's message when checked. It reads 6 folders below each
  folder you name, and the summary and the doctor count the lockfiles,
  runtime pins, Dockerfiles and virtualenvs it found deeper but didn't
  read. It also scans the worktrees under a named folder's own
  `.claude/worktrees`, which count as held: a stale worktree shows its old
  versions (the README says what to do). Nothing runs in the background.
  Setup's new OSV option adds five hosts and the check's results folder to
  your sandbox settings; the README says what that opens. Node.js's end of
  life isn't checked, since its list is on a host setup doesn't add;
  Node's security releases are, for exact versions. It needs your
  system's bash, curl, jq 1.6+ and python3. Its scan code is the
  OSV scan core (seven files, hash lines pinned by a test); a config with a
  `settings_json` key is refused.

### Known gaps

- **The launch gate has known gaps that are not fixed in v0.2.0.** The
  v0.2.0 review found forms the gate doesn't read, each a way past one of its
  checks, in three kinds (`docs/CLAIMS.md`, "Launch gate", and
  `docs/HOW-IT-WORKS.md`, "Launch gate decisions"): hidden operators (some
  shell syntax that can hide a command), piped launchers (some downloads run
  through an interpreter or a runner's shell text) and unknown options (options,
  aliases and subcommands the gate doesn't know). The exact forms aren't listed here. The gate is a tripwire, not a security boundary;
  a redesign is planned for v0.2.1. These gaps override the statements elsewhere in this
  release about what the gate denies, refuses or checks.

### Fixed

- **A command substitution inside `$(( ))` went unchecked.** The launch gate
  read `$(( ))` as the number 0 and never looked at what ran inside it, so
  `: $(( $(npx -y cowsay) ))`, `echo "$(( $(sudo id) ))"` and a download
  piped into a shell inside `$(( ))` got past rule 1's checks. This hole is
  older than the package lane (v0.1.0 and v0.1.1 have it); the bodies of `$(...)` and
  backticks inside `$(( ))` are now checked like any other substitution,
  also in a quoted string and an unquoted heredoc.
- **A `$((` that bash runs as a command went unchecked.** Bash reads `$((`
  as arithmetic only when the `)` that closes its second `(` is followed at
  once by another `)`; otherwise the whole `$( ... )` is a command
  substitution that runs, and the launch gate read every `$((` as arithmetic,
  so a command written that way got past rule 1's checks. v0.1.0 and v0.1.1
  have this hole too. The gate now reads `$((` by bash's rule, in plain
  text, in a quoted string, in an unquoted heredoc and inside other
  arithmetic, and refuses a piece of arithmetic it can't parse.
- **A raw carriage return split a word for the launch gate, not for bash.**
  The gate read a carriage return as white space between words, so a
  command word or an option's value that holds one was read as two words
  and the command after it could go unchecked. v0.1.0 and v0.1.1 have this
  hole too. A raw carriage return is now part of the word, as in bash, and
  the call is also read with it as a separator.
- **`time -p` hid the command after it.** The gate took the `-p` for the
  command word, so the command after `time -p` went unchecked (rule 1's
  launcher and privilege checks and the lane's). v0.1.0 and v0.1.1 have this
  hole too; the gate now reads the keyword's options (fixed earlier in this
  release's work).
- **The doctor counted a `Read(/path)` deny rule as an absolute path.**
  Claude Code's docs say a single `/` in a permission rule is relative to
  the project (only `//path` is absolute), so such a rule doesn't hide that
  path from sandboxed commands. Its advice for a secret file outside your
  home folder now gives the `//` form.
- **One odd settings file could stop the whole doctor.** A check that
  crashes now shows as a FAIL naming the error's type, and the rest run.
- **The launch gate checked the wrong word after some assignments and
  wrappers.** `NAME+=value` before a command, an `env` assignment whose name
  bash wouldn't take (`env a-b=1`), `env -a name`, `env --split`, and
  `exec -ca name` made it check a word that isn't the command, so the
  command after it went unchecked. So did 32 or more wrappers in a row and
  an `env -S` string that GNU env reads by its own rules (`\_`, `#`, `\c`,
  `${N}`), and, going by BSD env's docs and not tested here, BSD
  `env -P` and, on a case-insensitive file system such as macOS's default,
  `NPX` or `SUDO`. It now reads them as bash and env do, reads
  `busybox <applet>` as the applet, checks a `trap` handler as a command,
  and refuses the `-S` strings and the long wrapper chains, and a package
  manager with options in text it can't parse (a trailing backslash, which
  bash still runs).

### Changed

- **A `.npmrc` or `.yarnrc.yml` in a project is now a secret for every agent (the quarantine reviewer may read them with Read inside quarantine folders),**
  superseding v0.1.1's "a project's `.npmrc` stays readable". A Grep glob
  that names one is refused like the other secret names. Templates such as
  `.env.example` stay readable.
- **The gates take your home folder from your account, not `$HOME`.** A
  project's settings `env` can set `HOME` for hooks; a `$HOME` that resolves
  elsewhere now blocks the gated calls; the scan reports a config problem, and
  the canary fill and update reminder stay silent. A user id with no home
  folder entry blocks the gated calls too.
- **Config entries that could never match are refused:** a wildcard in an
  untrusted or quarantine folder, `~user`, a `.` or `..` segment, a trailing
  `/`, blanks or a `$HOME` prefix in a secret path, and a private host that
  isn't a bare host name.
- **Background-task output is closed:** a `tasks` folder under Claude Code's
  per-user temp folders and what is in it, for every agent. A Grep over the
  temp folder or anything above it is refused whatever the glob; over a
  project folder there, whatever the glob when a session's `tasks` folder
  lies below it, and over a session folder (or a project folder with `tasks`
  directly in it) unless the glob is anchored to a sub-folder such as the
  scratchpad, in both cases only while a `tasks` folder exists below. A Glob is refused when its pattern
  could list the task files.
  `$XDG_CONFIG_HOME/claude` and `~/.config/claude` count as transcript
  folders when they exist.
- **A working or project folder that isn't a usable absolute path** (or is
  nested more than 64 folders deep) turns the readers off. IPv6 site-local
  addresses (`fec0::/10`) are refused for fetches.
- **The sandbox template sets `allowUnsandboxedCommands` to `false`,** so a
  command the sandbox stops can't be run again outside it. A value you've
  set yourself is kept, and the doctor warns while it isn't `false`.
- **Edits to your settings file, the `CLAUDE.md` that loads the rules and
  the rules folder are asked, not denied,** so setup can make them in chat;
  the settings guard refuses every change to them but setup's own. The
  one-command install moves v0.1's deny rules for them to ask; setup in
  chat names the lines for you to delete. The gate config stays denied.
- **The doctor's canary step** checks the word a session states against
  your rules file and prints only whether it matches.

## [0.1.1] - 2026-10-23

Security fixes and hardening. Unit tests pass on Python 3.10; 3.11 to 3.13
weren't run for this release.
[docs/VERIFY.md](docs/VERIFY.md) row M1 was run by hand on Claude Code
2.1.301 (step M1b, the refusal, again on 2.1.309), and row M2 on 2.1.309
([results](docs/verify/RESULTS-2026-10-22-cc2.1.301-2.1.309.md)); the
`run.py` rows weren't rerun for this release.

### Security

- **The launch gate's ssh checks could be got round (fixed).** In v0.1.0,
  text that the gate's own parser read differently from bash could slip a
  second command, or an ssh option that runs a local program, past its
  checks on `ssh`, `scp` and `sftp`. There were four kinds: a line after the
  call that doesn't parse, an arithmetic expansion holding a command
  substitution, a heredoc marker hidden inside another construct, and words
  that bash expands before ssh sees them (brace expansion, parameter
  defaults, an unquoted glob that can pick up a planted file).
  - **Who it affects:** users whose `sandbox.excludedCommands` lets ssh run
    outside the sandbox with its arguments, through an entry such as
    `"ssh *"`. Claude Code's docs say an entry with no wildcard is an exact
    match, so a bare `"ssh"` exempts only `ssh` with no arguments, and these
    calls stayed sandboxed there. That matching wasn't checked on a live run.
  - **What changed:** see "Refused now" below.
- **The launch gate wasn't registered for Monitor (fixed).** Claude Code's
  Monitor tool runs a shell command;
  Claude Code's docs say it uses the same permission rules as Bash, and
  that the sandbox covers Monitor commands as it covers Bash. v0.1.0 ran the launch
  gate for `Bash` only, so a Monitor command got none of its checks. Claude
  Code's sandbox and permission rules still applied. `hooks.json` now
  matches `Bash|Monitor`, and a live run ([VERIFY](docs/VERIFY.md) row M1)
  showed Claude Code runs the hook for a main-session Monitor call on
  2.1.301 (default mode), and its refusal step (M1b) again on 2.1.309; a
  subagent's Monitor call and other modes weren't tested.
  Claude Code's hook docs don't list Monitor as a matcher, so the settings
  template also denies Monitor until row M1 passes on your version.
- **Three shell forms hid a command from the launch gate's checks (fixed).**
  In v0.1.0:
  - a redirect that names its file descriptor with a variable, placed before
    the command, made the gate read the redirect as the command word;
  - a brace expansion let bash build a command, a subcommand or a `-c`
    payload the gate never saw;
  - a word in front of the command that bash drops when it comes out empty
    (an unset variable, `$@`, an empty substitution, an empty brace
    expansion) made the gate read it as the command word.

  Each skipped the gate's checks on that command: launchers, downloads run
  directly, `sudo`, agents with guardrails off, and the ssh checks. Claude
  Code's sandbox and permission rules still applied. The gate now reads the
  redirect as bash does, brace-expands each word as bash does before it
  checks the command, and, when words up to the command word are built at
  run time, also checks the command as bash would run it with them empty:
  every combination for up to 6 such words, each alone and all together
  for 7 to 16. A mix it doesn't try can still get through; that's part of
  the known gap "command names built at run time or held in variables".

### Added

- Monitor commands get all the launch gate's checks. The gate also refuses:
  - a Monitor input field it doesn't know, naming it (a new field could
    change what runs or where);
  - a Monitor WebSocket watch (`ws`);
  - a Monitor command whose text names a downloader or a raw network client
    (`curl`, `wget`, `fetch`, `nc`, `socat`, `telnet` and the like) anywhere,
    or bash's `/dev/tcp` paths, or that builds its command name at run time
    (a variable, a glob, a substitution), or holds a `$'…'` string with a
    letter-building escape anywhere. It reads the words after brace
    expansion and follows shell `-c` payloads and `eval`. It's a tripwire,
    not a boundary: a name built some other way can still get through.

  The last two would stream outside text into an acting agent for as long as
  the watch runs.
- `"Monitor"` in the settings template's `permissions.deny`.
- The one-command install (`apply.py`) adds start-up paths in your home
  folder to `sandbox.filesystem.denyWrite`: the folders `claude`, your PATH
  tools and your shell start from (`~/.local`, `~/.nvm`, `~/.cargo`,
  `~/.bashrc`, `~/.profile` and the like). This narrows a route; it doesn't
  close it. It matters in a session started in your home folder, where
  sandboxed commands could otherwise plant code that your next shell or
  `claude` runs outside the sandbox.
  - The cost, in such sessions only: sandboxed commands can't write there, so
    `pip --user`, `uv tool`, `npm i -g`, `rustup`, `cargo build` and `cargo
    fetch` (the registry cache is in `~/.cargo`) and similar fail. `~/.local`
    also holds tools' data (pnpm, uv), and other tool folders on your PATH
    (`~/.pixi`, `~/.dotnet`, `~/.sdkman` and the like) are denied the same way.
    Keep a path writable with allowWrite (below).
  - Each entry is a whole folder or file directly in your home folder,
    because a deeper entry can be got round by renaming the folder above it.
  - Only paths that exist, and aren't symlinks, are added. Claude Code's
    sandboxing docs describe holding a write-denied file that doesn't exist
    yet with an empty read-only placeholder, and an empty `~/.bash_profile`
    would stop bash reading `~/.profile`. So a start file you don't have, such as
    `~/.zshenv` or `~/.bash_profile`, isn't covered, and an agent could still
    create one. The doctor lists them.
  - Cache, venv and data folders on your PATH (`~/.cache`, `~/.npm`,
    `~/.venv`, `~/.docker` and the like) and relative PATH entries are left
    out, so sandboxed package managers keep working.
  - A path your `sandbox.filesystem.allowWrite` names is left writable, and
    apply.py says so. That's how you keep one: a deny you only delete comes
    back the next time you run apply.py.
- Doctor checks:
  - "Monitor tool" warns when Monitor is neither denied nor asked. It reads
    managed drop-ins, and says when a deny covers only this project.
  - "start paths" lists start-up paths that aren't write-denied, notes what
    a deny can't cover (start files that don't exist, symlinks) and deeper
    denies in start-up folders.
  - A self-test probe checks that the launch gate refuses `npx` through
    Monitor.
- Decision-log codes `launch-ssh-tricky`, `launch-ssh-expand`,
  `launch-monitor-field`, `launch-monitor-ws`, `launch-monitor-feed` and
  `launch-domains`.
- [VERIFY](docs/VERIFY.md) row M1, a hand check that the launch gate runs
  for Monitor, and row M2, a hand check that a call with extra network
  hosts shows you a prompt that nothing approves for you.
- `launch_gate.ask_for_domains` (on by default): a call with extra network
  hosts goes to Claude Code's permission prompt; `false` refuses it. The
  doctor notes the risk, and warns when a Bash or Monitor allow rule with a
  wildcard might approve the prompt for you.
- Decision-log decision `ask`, and code `launch-domains-host` for a host
  name the gate won't show in a prompt.

### Changed: refused or asked now, and what to do instead

- **A call that names `ssh`, `scp` or `sftp` and has more than one line,
  a carriage return, a heredoc or here-string (`<<`), an arithmetic
  expansion (`$((`, `$[`), or doesn't parse.** That includes a heredoc to a
  remote shell (`ssh host bash <<'EOF' …`), a here-string, and a multi-line
  commit message that mentions ssh. Instead, keep the ssh call on one line
  and join remote commands with `;` inside the quoted remote command. For a
  longer remote script, write it to a file with the Write tool, `scp` it
  over and run it with `ssh`. Write long text that names these commands to
  a file with the Write tool, and pass the file (`git commit -F msg.txt`).
- **An ssh-family word that bash would expand:** an unquoted `$`, `{`, `}`,
  `*`, `?` or `[`, or a `$` inside double quotes. So `ssh host "echo $HOME"`
  and an unquoted IPv6 host (`ssh [::1]`) are refused. Instead, put anything
  meant for the remote side in single quotes (`ssh host 'echo $HOME'`,
  `ssh '[::1]' uptime`), and write local values out in full.
- **More ssh options:** `-o XAuthLocation` (it runs a local program), and
  shared connections (`-M`, `-S`, `-o ControlMaster`, `-o ControlPersist`,
  `-o ControlPath`), which leave an ssh process running outside the sandbox
  after the call. Instead, open a new connection for each call.
- **A Bash or Monitor call that asks for extra network hosts**
  (`allowed_domains`, which reaches past your sandbox's network allowlist
  for one command) now goes to Claude Code's permission prompt, naming
  each host. That's a request for a prompt, not a block. On Claude Code
  2.1.309, for Bash, with the sandbox on and in auto mode (VERIFY row M2),
  the gate asked and a prompt appeared each time, even with an allow rule
  matching every command. Where its wording was recorded, it was Claude
  Code's own prompt, showing the command and each host but not the gate's
  warning text; whether Claude Code would prompt for the hosts without the
  gate wasn't tested. Monitor calls, other permission modes and other
  versions weren't tested, and there an allow rule might approve the call;
  another plugin's hook, a PermissionRequest hook or an SDK callback wasn't
  tested either and could approve it without showing you. If you use any of
  those, or haven't run M2 yourself in the permission mode you use, set
  `launch_gate.ask_for_domains` to `false`, and such calls are refused.
  They're refused anyway from a subagent, where nobody can be asked
  (`dontAsk`, `bypassPermissions`, or an event that doesn't say its mode),
  and for a name that isn't a plain host name of two or more labels or a
  public IPv4 address (no wildcards, no local names or addresses, at most
  10). Instead, to trust a host for good, add it to
  `sandbox.network.allowedDomains` yourself; the gate never adds hosts.
- **A Monitor watch whose text names a downloader or network client,**
  including a local health check (`until curl -s localhost:3000; do …`,
  `nc -z localhost 5432`) and `git fetch`; one whose command name comes from
  a variable, glob or substitution (`$HOME/bin/watcher`); and one holding a
  `$'…'` string with a letter-building escape anywhere, even in a pattern.
  Instead, run the check as a Bash call with a time limit
  (`curl --max-time 5 …`), watch a log file, or write the command's path and
  patterns out plainly.
- **A brace expansion too large to check:** more than 1024 words from one
  word, more than 4096 in one call, in a word over 1024 characters, or in a
  word that also holds an empty `{}` (bash reads that pair differently in
  different places; find's own `{}` is fine).
  Instead, use a loop. Ordinary ones (`mkdir -p src/{a,b}`, `{1..100}`) are
  expanded and checked like the words bash makes of them.
- **More than 16 words built at run time in a run at the start of a
  command** (variables, substitutions, globs, counting a wrapper's operands
  such as `env NAME=$value` and the arguments of a command whose name is
  one), since the gate tries them empty. Instead,
  write the command out. A command whose name is built at run time also has
  its next word checked as a command, since bash would run that word if the
  name came out empty.
- **A Monitor watch whose shell `-c` or `eval` payload doesn't parse, or
  makes too large a brace expansion.** Instead, fix the quoting, or run it
  as a Bash call.
- **Monitor's `persistent` field,** as an unknown field: it isn't in the
  tool's input schema as the plugin's author saw it, and a field the gate doesn't
  know fails closed. Instead, run the watch without it.
- The doctor's "settings deny rules" count leaves out the Monitor deny, which
  has its own check.

## [0.1.0] - 2026-10-15

First release, experimental. Tested end to end on Claude Code 2.1.296 and
2.1.295 on Linux ([docs/verify/](docs/verify/)). The install from the GitHub
marketplace isn't tested yet.

### Added

- Three reader agents with narrow tool lists: `web-researcher` (web search
  and fetch only), `document-reader` and `quarantine-reviewer` (Read, Grep
  and Glob only).
- The reader gate, a PreToolUse hook for Read, Grep, Glob, WebFetch and
  WebSearch:
  - web tools for the web reader only, never to local or private hosts;
  - untrusted and quarantine folders for their own reader only;
  - readers confined to their folders;
  - built-in secret paths denied to every agent.
- The launch gate, a PreToolUse hook for Bash that denies fetch-and-run
  launchers, downloads piped into an interpreter, privilege escalation, and
  agent launches with permissions off. It's a tripwire with known gaps, not a
  security boundary. The sandbox's network allowlist is the control.
- `/stranger-danger:doctor`: a read-only setup check plus live probes.
- `/stranger-danger:setup`: prints the install commands with the plugin's
  real folder filled in, so every install step works right after
  `/plugin install`. It writes nothing.
- Templates: settings deny rules, sandbox, gate config, auto-mode rules, and
  the seven rules for `~/.claude/stranger-danger/RULES.md`.
- The coordinator (optional; see `docs/COORDINATOR.md`). One session you
  pick keeps track across your projects and brings you decisions one at a
  time; it never approves anything.
  - `/stranger-danger:coordinator` checks it's in the coordinator's folder,
    then keeps the open-items list and builds a read-only status page: gate
    activity, doctor results and the decisions waiting for you. The page has
    no link, form, button, script or image.
  - Setup step 5 (`install.py`, which you run) writes the folder and a
    display name to the gate config and a recognition paragraph to your
    `CLAUDE.md`. The paragraph tells every session that the coordinator's
    messages are requests, never your OK, and that it counts only in your own
    `CLAUDE.md`.
- `skills/setup/apply.py`: setup steps 1 to 3 in one command. It shows every
  change as a diff, asks before writing and keeps a `.bak`.
- New doctor checks:
  - secret-shaped files in the project that no exact Read deny rule covers,
    listed by name only;
  - wildcard allow rules for `ssh`, `scp`, `sftp`, `mosh`, `rsync`,
    `sshpass` or `autossh`, also behind `env`, `timeout` or `nohup`, and an
    allow rule for every Bash command;
  - the coordinator:
    - its config, and the `CLAUDE.md` paragraph word for word;
    - settings only its project has;
    - a tampered status page;
    - a fake coordinator paragraph in a project's instruction files or
      their imports;
    - a folder that shares its project key;
  - `STRANGER_DANGER_CONFIG` set.
- `launch_gate.ssh_hosts`: the only hosts `ssh` and `scp` may reach.

### Fixed

- On Python 3.10 to 3.12, the reader gate refused a read through a `/proc`
  link it couldn't resolve (such as `/proc/1/task/1/fd/3`) with "internal
  error" instead of its `/proc` reason. It now checks for `/proc` and
  `/dev/fd` paths before resolving them. Such reads were blocked either way.

### Security

Reader gate fixes from the pre-release gap check of 2026-10-14 (fixed
2026-10-15, then checked and fixed again the same day; C and D stay
documented limits):

- A: more secret paths, in the gate and the settings template.
  - Credential files that also turn up inside projects are now secret
    anywhere, not only in your home folder: `*.env`, `.envrc`,
    `.git-credentials`, `.netrc`, `_netrc`, `.pypirc`, `.pgpass`,
    `.htpasswd`, `.vault-token`, `.aws/credentials`, `.docker/config.json`,
    `.kube/config`, `*.tfstate`, `*.tfstate.backup`, `client_secret*.json`,
    `*.ppk`, `AuthKey_*.p8` (Apple API keys), `wallet.dat`,
    `.aptos/config.yaml`, and any `.ssh` folder (so a copied `deploy_key`
    too). A project's `.npmrc` stays readable, since it holds npm's safety
    settings.
  - Grep reaches them less: a Grep glob aimed at one of these names is
    refused; a glob with a folder in it is tested whole, with a `**/` also
    read as no folder at all (`.aws/credentials`, `.aws/**/credentials`,
    `**/.kube/config`, `.ssh/*`, and below other folders, as in
    `deploy/.aws/credentials`); a glob with no folder is also tested
    against these files' own names, since it matches at any depth
    (`credentials`, `cred*`, `auth.json`, `config`); and a Grep rooted at a
    `.aws`, `.docker`, `.kube`, `.aptos`, `keystore` or `containers` folder
    is refused unless its glob is anchored to a sub-folder. Globs that also
    match ordinary names still pass (`*`, `*.json`, `*/config`, `config*`):
    that is limit C. Safety comes first in between, so some globs that
    would match only ordinary files in your project are refused (`*.dat`,
    `*.backup`, `*rc`, `.*`, `*.tf*`, `*.p8`, `config`, `credentials`); the
    README lists them with the workaround.
  - Native browser and mail profiles: Chrome Beta and Unstable, Edge
    (stable, beta, dev), Vivaldi, Opera, Firefox's newer `~/.config/mozilla`,
    LibreWolf and Thunderbird (native, snap, flatpak) on Linux; everything
    under `~/Library/Application Support/Google`, Chromium, Brave, Edge,
    Vivaldi, Opera, Firefox, Thunderbird and Safari (with its cookies) on
    macOS. KWallet's folder joins the keyrings.
  - Desktop apps' session stores, by name only: `Cookies`,
    `Cookies-journal`, `Local Storage`, `Session Storage`, `IndexedDB`,
    `Local State`, `Trust Tokens`, `Network Persistent State`, `Partitions`
    and `Network` (where newer Chromium keeps `Cookies` and `Trust Tokens`)
    for Claude Desktop, Slack and Discord (Linux and macOS),
    plus Claude Desktop's `claude_desktop_config.json` and
    `buddy-tokens.json`. The rest of `~/.config/Claude` stays readable.
  - Wallets: Foundry keystores, geth's macOS keystore, Hardhat's
    configuration variables, Bitcoin Core (Linux and macOS), Electrum, Exodus
    and Atomic (Linux and macOS), Sui, Aptos and NEAR.
  - Cloud and hosting CLIs: OCI, `doctl` (Linux and macOS), `hcloud`,
    `linode-cli`, Fly, Alibaba Cloud, Terraform's login files, Databricks,
    Wrangler, rclone, `s3cmd`, `boto`, and the MySQL client's `~/.my.cnf`.
    All of `~/.kube` is now secret (its cache holds tokens), not only
    `~/.kube/config`.
- H: Claude Code's own state outside `~/.claude/projects` is closed to
  every agent:
  - as secrets: the backups of `~/.claude.json` (beside it and in
    `~/.claude/backups/`), the IDE lock files (`ide/`, which hold an auth
    token) and saved session environments (`session-env/`);
  - as Claude Code's records: the prompt history (`history.jsonl`), the
    copies of edited files (`file-history/`), the debug logs (`debug/`),
    pasted and uploaded text (`paste-cache/`, `uploads/`), shell snapshots
    (`shell-snapshots/`) and to-do lists (`todos/`).

  Under `CLAUDE_CONFIG_DIR`, the same files in that profile are closed too,
  along with its own `.claude.json` and `.credentials.json`. The settings
  template denies Read on these as well, which also hides them from
  sandboxed commands such as `cat`. The exceptions are `shell-snapshots/`
  and `session-env/`: they're closed to the Read tool only, and sandboxed
  Bash can still read them. A user report (anthropics/claude-code issue
  28308) says every Bash command fails when the sandbox can't read the
  shell snapshot, and `session-env` is loaded the same way.
- B: a secret folder that is a symlink, or sits under one, is now also
  matched at its real path, so a Read of the real file or a Grep at the real
  folder's parent is refused (reading through the link already was). A Grep
  at the real parent of a symlinked quarantine, untrusted or transcript
  folder is refused the same way. A symlinked file inside a secret folder
  isn't followed back to where it lives (README, "Paths are judged by
  name").
- E: Glob no longer lists names inside a secret folder (one whose entries a
  pattern covers, `~/vault/*` too), Claude Code's transcripts and records,
  or (for anyone but the document reader) an untrusted folder, whether the
  Glob starts there or walks into one. A pattern segment that names a folder
  secret anywhere (`**/.ssh/*`, `**/secrets/*` for a `**/secrets/*` entry) is
  refused too. The exemptions are Grep's: a project's `memory` folder, and a
  quarantine folder inside an untrusted one. Listing the *names* of secret
  files in an ordinary folder (`**/.env`) still works.

  Some Globs that passed are now refused. `*.md` from your home folder would
  list names in `~/.ssh`: run it from the project folder. With an untrusted
  folder inside a repo, `**/*.py` from the repo's root walks into it: use an
  anchored pattern such as `src/**/*.py` (the refusal suggests one), or
  better, keep untrusted and quarantine folders outside project trees.

Reader gate fixes from review on 2026-10-11:

- Glob patterns that walk into quarantine or `/proc` are refused (they
  could list file names in a quarantine folder):
  - Claude Code's Glob matches a pattern with no `/` at any depth (`*.md`
    from your home folder lists names inside quarantine), and an absolute
    pattern's last part the same way. The gate now reads patterns that way.
  - A segment with a wildcard, a backslash escape (ripgrep reads `\q` as
    `q`) or an extglob opener counts as matching any name
    (`/pr?c/self/root/...`, `\q/*`). A segment with a character class
    counts as matching any number of folders, since a class like `[!x]`
    matches `/`.
  - A pattern with a part starting with `!` or `#` (so `!(` too), or with a
    part that starts or ends with blank space, is refused: ripgrep reads `!`
    as a negation and `#` as a comment, and lists everything.
  - A Glob folder with a wildcard (`*`, `?`, `{}`, `\`, an extglob opener) is
    refused. `[` and `]` are allowed there, because the tool takes the folder
    literally and folders like `[slug]` are common.
  - A Glob pattern over 4,096 characters is refused.
- Grep globs:
  - A Grep glob starting with `!` or `#` no longer counts as narrowing the
    search.
  - Claude Code splits a Grep glob on spaces and on commas (unless it holds
    braces), so `project/**,**/*.txt` also searched quarantine. A glob with
    a space is now refused, and each comma-separated piece is judged on its
    own, for the secret-name check too (`*.py,.env`). A glob with braces
    and a comma outside them (`src/{a,b},**/*.txt`), which could be read
    either way, is refused, and so is a piece with an unclosed `[`.
  - Brace alternatives are expanded and each one is judged on its own. One
    that climbs with `..` or starts with `/` or `~` inside a relative
    pattern is refused, and so is a pattern whose braces can't be expanded.
  - A pattern that names one path exactly is judged at that path too, so a
    symlink into quarantine named that way is refused.
  - Patterns that go through `/proc` (directly, through a symlink anywhere
    on the way, or with a wildcard after `/proc`) and patterns under `/dev`
    are refused.

  A Glob that is now refused, such as `*.md` with your home folder as its
  path when quarantine is under your home folder, lists names inside
  quarantine; run it from the project folder.
- Reads that reach `/proc` or `/dev/fd` through a symlink are refused even
  when `realpath` resolves the link (a link to `/proc/self/root` resolves
  to `/`). The gate follows the chain itself, link by link, up to 40 links,
  in both the path as written and its normalized form (tools normalize
  `/bin/../x` to `/x` before opening), and refuses any path whose links
  can't be followed. Links into `/proc/self` now refused this way include
  `/etc/mtab`, `/proc/mounts` and `/proc/net/*`.
- Each hook in `hooks.json` sets `onFailure: "block"`, so a gate that runs
  past its 15-second timeout blocks the call instead of letting it through.
  Claude Code reads the field from 2.1.295 on, which is now the minimum
  supported version: the doctor fails on an older one, and warns for each
  installed gate that doesn't set the field.
- Under `/proc/<pid>/` (and `task/<tid>/`), only `status`, `stat`, `statm`
  and `limits` can be read. Everything else there is refused: `cmdline`,
  `environ`, `mem`, `maps`, `mountinfo`, `attr/*`, the `ns` links, and so
  on. So are `/proc/<pid>` itself, `/proc/cmdline`, `/proc/keys` and
  `/proc/kcore`.
- Everything under `/dev` is refused except `/dev/null`, `/dev/zero`,
  `/dev/full`, `/dev/random` and `/dev/urandom` (so `/dev/shm/*` too).
  Elsewhere, block and character devices are refused unless their device
  number is one of those five, and so are FIFOs and sockets: a Read on a
  FIFO can hang. A path whose type can't be checked is refused. The
  `/proc` and `/dev` checks ignore case on macOS.

Fixes from the coordinator's first pre-release check (20 findings; see `docs/COORDINATOR.md`,
"Pre-release checks"):

- The status page check lexes strictly. Python's HTML parser reads
  `<!--><script>` as a comment, but a browser doesn't. The check refuses a
  byte-order mark, NUL or non-UTF-8 bytes, and reports counts, never the
  page's text.
- A hook that sees `STRANGER_DANGER_CONFIG` inside a Claude Code session fails
  closed, and the doctor, `--whoami`, the installer and `apply.py` refuse it.
- The coordinator paragraph:
  - names the interactive session only;
  - says rule 6 still needs your OK in the worker's own session;
  - tells workers not to act on an unknown sender;
  - doesn't count when two paragraphs disagree.

  Any edit to it fails the doctor.
- The coordinator's folder can't hold or sit inside your Claude config, the
  gates' config or log folders, or `~/.ssh`. Names are at most four plain
  words.
- The installer:
  - needs a terminal and refuses inside Claude Code;
  - rolls the config back if `CLAUDE.md` can't be written;
  - keeps the line endings of `CLAUDE.md`;
  - writes the notes at mode 600.

  Edits to a `.stranger-danger` notes folder ask you first.
- With `CLAUDE_CONFIG_DIR` set, setup adds the deny rules for that folder's
  own `CLAUDE.md`, settings, hooks and agents, by the path as given and by its
  real path.

Fixes from the second coordinator review:

- The doctor checks the template's ask rules and fails when `HOME` isn't
  your account's home folder.
- `apply.py` refuses inside Claude Code.
- The page build refuses a symlinked notes folder and a redirected config.

`docs/verify/run.py` runs the VERIFY checklist in one command. You run it
yourself, in a terminal; it refuses inside Claude Code. Verified again on
Claude Code 2.1.280 on 2026-10-10: 27 of 27 rows match
(`docs/verify/RESULTS-2026-10-10-cc2.1.280.md`). The run found that the web
reader didn't load WebFetch on its own in a fresh profile; its instructions now
say to load it with ToolSearch.

The settings template asks before the common ways of going public or driving
a browser (B3, B2): GitHub repo changes, releases, gists, issues, PRs, `gh api`,
package publishing, image pushes, and the Claude in Chrome, Playwright,
Puppeteer and Chrome DevTools tools. The rules match a command's start, so
other spellings get past them. The doctor checks the ask rules are in place.

The rules and auto-mode rules now carry the protocol's main points (B7; review
3 found more drift, fixed below):

- an OK covers one action, once, and a standing instruction isn't one;
- Rust crates always need an OK;
- container images take the 7-day rule and a digest;
- browser control needs your ask;
- agents never run `sudo`;
- with no VM, strangers' repos stay off the machine.

Fixes from the third pre-release check of the post-check-2 work (2026-10-10;
details and accepted items in `docs/COORDINATOR.md`, "Pre-release check 3"):

- The doctor counts a broader rule of yours as covering a secret rule only when
  it also stops sandboxed commands (an exact path or `folder/**`), reads `**`
  inside a path segment as a plain `*`, samples `**` at depths 0 to 3, and
  checks a profile's own rules under `CLAUDE_CONFIG_DIR`. It warns on allow
  rules for a whole publishing tool (`Bash(npm *)`), and each warning's
  explanation fits its case.
- `rules/RULES.md` and the auto-mode template restore points that had drifted:
  `gh api` in the fetch list, `~/.claude/CLAUDE.md` and the gate config as
  guardrails, "no values" in the `jq` exception, branch pushes to private
  repos only, your repos' images, your OS's own archive, bot PRs as untrusted
  text, crates "by any route", a new entry for stranger container images, and
  the standing-instruction sentence on every entry you can clear.
- The ask rules add `gh` issue and PR edits and closes, `gh workflow run`,
  `gh secret set`, more image pushes and publishers, and the GitHub MCP
  server. The deny rules add `Edit(~/.claude.json)`, which holds MCP servers,
  and a profile gets the same rule for its own `.claude.json`.
- The web reader may use ToolSearch only for its two web tools, and the launch
  gate refuses Bash from any reader agent.
- The VERIFY runner passes a row only for the expected subagent, fails a row
  where a retry of the same tool by that caller got through, counts "no call" only when the session finished,
  shows only the gates' own deny messages, allows the tool on rows 19, 20 and
  27 so that only a gate can refuse, pins the checklist's commands by sha256,
  and refuses scratch folders that aren't yours or hold Claude config.

Fixes from the fourth pre-release check, of check 3's fixes (2026-10-10):

- A reader-tools hook, run for every tool, lets a reader agent use only its own
  tools (plus the tool background subagents hand back with), so it can't
  write files, use MCP tools, start agents or send messages; the launch gate
  refuses readers Bash too.
- The doctor warns about publish tokens in the environment while sandboxed
  commands run without a prompt (`sandbox.autoAllowBashIfSandboxed`, on by
  default), and its broad-allow check covers `Bash(*)`, wrappers,
  interpreters and subcommand groups such as `Bash(gh pr *)`.
- The VERIFY runner needs the reader to have run for a "no call", counts only
  this plugin's own hooks and the row's rule, and refuses a test profile with
  its own hooks, rules or plugins. Rows 29 and 30 ask a reader to load a
  tool; row 31 gives one Write outright, so only the hook can refuse it, and
  a probe file left behind fails the row.
- More ask rules (`npx --no` and `pnpm -r` publish spellings), setup checks a
  profile's real path, and the docs no longer say an unnamed command always
  prompts.

Fixes from the fifth and sixth pre-release checks (2026-10-10):

- The reader-tools hook takes inputs up to 64 MiB (it refused a main
  session's Write over 1 MiB), has the gates' 5-second alarm, and its message
  says to rename an agent that only shares a reader's name.
- The doctor checks that `python3` starts from the session's folder (if it
  doesn't, every hook fails and every tool is refused), that `hooks.json` runs
  each gate before the tool and blocks on failure, and the reader-tools hook
  for every tool. The publish-token warning counts WebFetch domain rules and
  local and managed settings, and says INFO, not PASS, for a token whose
  host isn't reachable yet.
- Deny rules and the reader gate close more credential files: RubyGems (both
  places), `~/.cargo/credentials`, `~/.config/containers/auth.json`, `~/.vsce`
  and Poetry's `auth.toml`.
- The VERIFY runner accepts either hook's refusal where two apply (rows 8 and
  29), allows Write on row 31 so only the hook can refuse it, names that row's
  agent exactly, and refuses a test profile with its own rules folder.

Fixes from the seventh pre-release check, of check 6's fixes (2026-10-10):

- The doctor checks that each gate's matcher covers the tools it guards (the
  reader gate on Read, Grep, Glob, WebFetch and WebSearch; the launch gate on
  Bash), not only the reader-tools hook's. It probes `python3` from the
  session's folder, and the README now gives the symptom of a `python3` that
  doesn't start and the terminal command to check it, since the doctor can't
  run in such a session.
- The publish-token check reads the sandbox switch and the hosts from every
  settings file, highest precedence first: managed (at each system's path,
  `managed-settings.d` included), the project's local and shared settings, then
  yours. A `WebFetch(domain:*)` rule counts as every host; a `WebFetch` rule
  with no `domain:` part doesn't touch the sandbox's list.
- The Read tool and the reader gate can't open Podman's Linux login file
  (`$XDG_RUNTIME_DIR/containers/auth.json`) or Poetry's `auth.toml` on macOS.
  Sandboxed commands still can unless you add the exact-path rule the README
  gives.

Fixes from the eighth pre-release check, of check 7's fixes (2026-10-10):

- The doctor compares `hooks.json` with the hooks the plugin ships (matcher,
  command and timeout for each gate), so a command that drops the exit code,
  a short timeout or a broken matcher regex fails. Its `python3` check shows
  the version the hooks would start, not the doctor's own.
- The VERIFY runner fails a reader row when the reader used any tool other
  than its own successfully.
- The reader gate names this account's Podman login file exactly, so a Grep
  from `/run`, `/run/user` or `/run/user/<uid>` is refused too.
- The publish-token check also counts token names in a settings file's `env`,
  and its "skipped" line says it doesn't see `--settings`, MDM or Windows
  registry policy.

Fixes from the ninth pre-release check, of check 8's fixes (2026-10-10):

- The `hooks.json` check accepts `onFailure: "block"` on a gate, the
  hardening the doctor suggests on Claude Code 2.1.295 and later.
- A VERIFY probe file left behind always fails its row again. A main-session
  write on row 31 had been credited, which could hide the file check.

Release preparation (step B9, 2026-10-10): the history was squashed into one
commit, and the release is labelled experimental. An independent read-only
reviewer checked the label and swept every file against a list of
what must never be published. Fixed:

- A repo test ran a scanner from a sibling folder if one
  existed, which would run whatever code a folder of that name held; it's
  removed, and the scan runs outside the repo. Two test comments named
  private projects.
- The label and the compatibility notes now say that a pre-release build was
  tested end to end, that the later hook changes and the marketplace install
  weren't part of that run, and that macOS and WSL2 are untested.
- Commit hashes in the verify results are marked as pre-release builds, and
  sentences that went stale after the squash are fixed.

Bug reports (2026-10-10):

- New `/stranger-danger:report` (`doctor.py --report`) prints a summary to
  paste into an issue: plugin, Claude Code and python3 versions, the OS
  name, the plugin's own doctor checks by name and result, a count of the
  setup checks, the log's state and the last 7 days of the decision log
  counted by decision and code. Nothing is sent; the user pastes it.
- A GitHub bug report template asks for it and sends reader-gate and
  reader-tools bypasses to private reporting.
- An independent pre-release check found no path that fails open. Its
  findings, all fixed:
  - Listing every check by name would publish which of a user's
    protections are off, under their GitHub name. The setup checks are now
    only counted.
  - Anything that can write the log could choose the words that reach the
    report (a covert channel, or text aimed at the model). The report now
    shows only the decisions and codes the hooks write (`_log.KNOWN_CODES`,
    kept in sync by a test), and only lines dated within the last 7 days,
    not in the future.
  - The plugin version was free text; it's now a strict version or
    "unknown".
  - A link or pipe in the log's place, or a log that filled up weeks ago,
    read as "nothing logged". The report now states the log's state, and
    the coordinator's page flags a log that isn't a regular file (rule 7).
  - A crash printed a traceback with paths; it now prints one line.
  - The report and the docs disagreed with SECURITY.md about where launch
    gate misses go; SECURITY.md now also covers the reader-tools hook.
- A narrow re-check of those fixes found no path that fails open and no
  attacker-chosen word left in the report. Its findings, all fixed:
  - Some named checks still showed protection state (the config folders).
    Those are counted now, and the docs no longer say the report hides
    which protections are off: it names only the checks of whether the
    gates run, and a FAIL there shows a gate isn't working.
  - The log state missed a log the hooks can't write: a changed owner or
    mode, a hard link (the writer now refuses those too), or a log padded
    to the cap without a `log-full` line. It's now judged by the file's
    owner, mode, links and size, and a forged `log-full` line no longer
    counts. The coordinator's page gives one message per state.
  - The writer now enforces the known codes and decisions itself, so a new
    code missing from the list fails the hook's own tests; the sync test
    scans every hook file and the decisions too.
  - Exact counts made the report a wider channel for anything that can
    write the log. The report now gives rough counts; which rows appear can
    still carry several hundred bits (see the last point).
  - Wording: the coordinator's sandbox caveat, the doctor's exit codes,
    "the log's agent names", and a stricter version pattern.
- A last check of the writer change found no path that fails open and no
  text leak. It corrected two doc sentences (the size of the counts channel,
  and how the page judges a full log), the "not writable" wording, and a
  crash on a log line whose decision isn't a string. Those fixes were too
  small to review again.
  - Recorded, not changed: anything that can write the log chooses which
    decision-and-code rows appear, several hundred bits, enough for a token.
    With the template's deny rules, only a process outside the sandbox or
    a session in the home folder can write the log, and such a process can usually reach the network
    directly; CLAIMS.md states the limit. Blank issues
    stay on, since the issue chooser shows the private security link either
    way; the template's SECURITY.md link assumes the default branch is
    `main` at publish.

README final read before v0.1 (step B8, 2026-10-10): an independent
read-only reviewer found 21 places where the README claimed more than the
plugin does, and a web-researcher checked the outside facts. All are fixed:

- The hooks keep acting agents from opening the web and untrusted folders
  with Claude Code's own read and web tools; a reader's report is still
  untrusted text. Untrusted folders work only once you list them in the gate
  config, which the quick start now says.
- New limits: a hijacked reader can put instructions in its report and send
  its brief to any public site; Bash reads of untrusted folders (with the
  `sandbox.filesystem.denyRead` fix); the sandbox's retry-outside door
  (`allowUnsandboxedCommands`) and `excludedCommands`; a project's settings
  can turn the gates off (`disableAllHooks`, `enabledPlugins`); claude.ai
  connectors; Glob lists names in untrusted folders; DNS failures; the
  reader-tools hook matches by name; `ssh_hosts` and `scp`; the alarm
  doesn't cover Python's start.
- Corrected: a grown reader is treated as an ordinary agent (not refused);
  the doctor's live probes prove the reader gate and launch gate (not all
  three hooks); unlisted hosts are held for a prompt or the classifier (not
  blocked); the install wording (diffs for existing files, `--automode`,
  `.bak`, RULES.md isn't replaced on upgrade); the stranger's-repo advice
  now matches rule 1; the verified-run lines name the method, mode and
  build.
- The settings template denies Edit and Write in `~/.claude/plugins/**`, so
  an agent can't change the installed plugin's own hooks.

Second end-to-end run on Claude Code 2.1.280 (2026-10-10, on a pre-release build):

- 30 of 30 rows match (`docs/verify/RESULTS-2026-10-10-cc2.1.280-run2.md`). In
  row 31 the reader-tools hook refused a reader that was given Write.
- The run showed that only the reader gate logged its denies.

Logging for every hook (2026-10-10):

- The launch gate and the reader-tools hook now log each deny to the same
  decision log as the reader gate, through a shared writer (`hooks/_log.py`),
  and the reader gate now also logs bad input and internal errors. A timeout,
  or a hook that fails before its code runs, still blocks without a line.
  A line holds a reason code (`launch-…` or `reader-tools…`), the tool and
  the claimed agent_type, never command text. The writer opens the log
  without blocking, writes only to a regular file, and runs before the
  hook's alarm is cleared, so a write that stalls in a way a signal can
  interrupt still ends in a block.
- The log stops growing at 20 MB, with one `log-full` line that the
  coordinator's page flags, so refusals in a loop can't fill the disk.
- The shared writer takes only short lowercase codes, so an event's input
  can't reach the code field by mistake, and the hooks' `_deny` arguments
  are keyword-only.
- The reader-tools hook exits at once on its alarm, as the other gates do.
- The doctor's self-test runs its refusal probe with a throwaway home, so it
  doesn't log a fake reader escape. The coordinator's page flags any
  `reader-tools` or `launch-reader-shell` line in the last 5 MB of the log
  at once (rule 7).
- An independent pre-release check of this change found no path that fails
  open; its findings are fixed as listed above.
- A second, narrower review of the fixes again found no path that fails
  open and nothing that puts command text or contents in the log. It found
  seven places where the docs claimed more than the code did. All are fixed:
  - The code check now runs in the shared writer, so the reader gate's own
    lines get it too.
  - The `log-full` line is padded to reach the cap, so a long line at the
    cap can't leave room for more lines after it.
  - The coordinator's page keeps the newest 50,000 lines of the 5 MB it
    reads; it used to keep the oldest, which could drop a recent escape or
    the `log-full` line. The page and the report now read the log only if
    it's a regular file, and read no more than their limit, so a FIFO in
    its place can't stall them.
  - The VERIFY log check counts only lines added after the doctor's
    probes, and says a WebSearch deny has no path or host.
  - The README and docstrings say the log stops at its cap and that a
    timeout isn't logged; the timeout limit names a wait a signal can't
    interrupt; HOW-IT-WORKS names which missing fields pass.
  - The reviewer asked whether `Edit(...)` deny rules also cover the Write
    tool. Claude Code's own bundled settings guide says path rules use
    `Edit(path)` for every file-writing tool (Write, Edit, NotebookEdit).

Fixes from the end-to-end run on Claude Code 2.1.280 and the fourth review:

- The launch gate keeps `ssh`, `scp` and `sftp` to plain remote access. A
  sandbox that lists them in `excludedCommands` runs them outside the
  sandbox, so the gate refuses options that run a local command or load a
  library (`ProxyCommand`, `LocalCommand`, `KnownHostsCommand`, `Match`,
  `Include`, PKCS11 and security-key providers, `-I`, `-F`, `scp -S/-D`),
  port forwarding and tunnels, log and known-hosts file options, `sftp`
  (its batch input runs `!` commands locally), and, at the top level,
  anything run alongside them.
- Two launch-gate parser bugs, both of which failed closed: text shaped like
  the gate's own substitution markers crashed it, and the pipe-to-interpreter
  check was quadratic. Every regex in the gates is now linted and timed on
  hostile input in the test suite.
- Read deny rules reach sandboxed Bash only for exact paths; glob rules such
  as `Read(//**/.env)` don't. The README and setup said otherwise. They now
  tell you to add an exact rule per secret file, and the doctor lists the
  ones missing.
- The settings template denies edits to `~/.local/state/stranger-danger`, so
  a hijacked agent can't erase the gates' decision log.
- Under `CLAUDE_CONFIG_DIR`, setup wrote an import line that loaded the
  default profile's rules. It now names the profile's own copy, and the
  doctor accepts only an import that resolves to the rules in use.
- The setup creates the gate config at mode 600 in a 700 folder, and a
  config problem is written to the decision log with its deny.

Fixes from the third review, before the first release:

- Claude Code's transcript folder (`~/.claude/projects`) is closed to Read
  and Grep for every agent. It holds every agent's tool results, so the main
  session could read a web reader's fetched pages from its transcript or its
  saved output. An agent may still open its own saved output, by the record
  in its own transcript, and a project's memory folder stays readable. The
  settings template denies edits to transcripts and session folders.

- The reader identity check fails closed on any file under a `.claude/agents`
  folder that contains `stranger-danger:`, at any depth up to 8, whatever its
  extension, case, encoding or YAML escapes, through symlinks, and also under
  `$CLAUDE_CONFIG_DIR/agents`. It used to parse frontmatter of `.md` files two
  folders deep, which a BOM, a comment, a folded scalar or a deeper folder
  slipped past.
- The config loader refuses unknown keys at the top level and in both
  sections, and repeated keys. `"reader-gate"` used to be ignored silently.
- Grep globs with brace alternatives (`{.env,.env.local}`, nested) or
  backslash escapes (`\.env`) no longer slip past the secret-name check.
- More built-in secret paths: snap and flatpak browser profiles, Solana and
  Ethereum keystores, fish history, `id_ecdsa`, `id_dsa`, `*.p12`, `*.pfx`,
  `*.jks`, `*.kdbx` and `~/.password-store`. The settings template mirrors
  them, except the key names that already sit under `~/.ssh`.
- The doctor no longer opens `.npmrc` files or walks up the folder tree. It
  asks `npm config get`, with and without `--userconfig /dev/null`.
