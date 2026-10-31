---
description: Set up stranger-danger in chat. Checks your settings file first, asks a question or two, then changes each file with one prompt that shows its diff, and walks you through the steps only you can do. Nothing is written without your approval.
---

# stranger-danger setup

Set up the plugin in chat. Each file changes through one Write prompt that shows the user its diff. The plugin's settings guard hook refuses any change to these files except the one `chat.py` works out, so copy the staged text exactly. Guide the user through every step: say what comes next and why before each prompt or step, in plain words, one step at a time.

The script is `python3 -I "${CLAUDE_PLUGIN_ROOT}/skills/setup/chat.py"` below; run each command exactly as written, from the folder the session started in.

## 1. Check the settings file first

Run:

```bash
python3 -I "${CLAUDE_PLUGIN_ROOT}/skills/setup/chat.py" check
```

You have to read the user's settings file to change it, and whatever you read lands in this session. This check reads it for you and prints only the names of values that look like secrets.

- If it exits 0, go on.
- If it exits 1, show its output exactly and stop. Walk the user through its numbered steps one at a time, waiting for them to say each is done. Those steps happen in the user's own editor. Don't read the settings file, don't offer to move the values yourself, and don't work around the check. When they're done, they start a new session and run `/stranger-danger:setup` again.

## 2. Ask, then show the plan

Ask the user one question, with a recommendation: do they use auto mode? If yes, add `--automode` to every `plan` and `show` command below; it adds the plugin's auto-mode rules. If they aren't sure, the answer is no.

Then ask a second question: do they want the OSV check (`/stranger-danger:osv`), which checks the packages they hold against public advisories when they type it? If yes, add `--osv` to every `plan` and `show` command below. Say plainly what it adds before they answer:

- five hosts to the sandbox's network list (`api.osv.dev`, `api.github.com`, `nodejs.org`, `peps.python.org`, `www.python.org`), which then open to every sandboxed command in every session; `api.github.com` is the widest, since a command with a GitHub token at hand could write to GitHub through it;
- the results folder `~/.cache/stranger-danger/osv` to the sandbox's write list, so any sandboxed command could also write there, and forge a result that silences the check's session line; the plugin's session hook makes the folder, private, when the next session starts;
- each run sends the names and versions of everything it finds, in the folders checked and the user's global installs, to OSV and GitHub;
- Node.js's end of life isn't checked, because its list is on a host setup doesn't add (Node's security releases are checked for exact versions, not for a line-only pin such as `.nvmrc` 20);
- it needs the system's own bash, curl, jq 1.6+ and python3.

If they aren't sure, recommend no for now; they can run setup again later with it.

Then run:

```bash
python3 -I "${CLAUDE_PLUGIN_ROOT}/skills/setup/chat.py" plan
```

Show its output exactly. Tell the user that each listed file is one prompt with its diff, that they can approve or decline each, and that nothing changes until they approve. If it says there's nothing to change, skip to step 4.

## 3. One prompt per file

For each name the plan listed, in this order: `rules`, `claude-md`, `settings` (skip a name the plan didn't list):

1. Run `python3 -I "${CLAUDE_PLUGIN_ROOT}/skills/setup/chat.py" show NAME` (with `--automode` and `--osv` if chosen), with `NAME` the file's name. Run it just before that file's Write, not all at once: each file's text can depend on the ones written before it.
2. Read the staged file it names.
3. If the target file already exists, Read it too (the Write tool needs that). The check in step 1 found nothing that looks like a secret in the settings file.
4. Tell the user in one sentence what this file is and what changes, then Write the staged text, exactly and in full, to the target path. Copy only the file's text, not the Read tool's line numbers.

If the user declines a prompt, don't retry it: go on to the next file, and say at the end which files weren't changed. If the settings guard refuses a Write, run `show` for that file again and try once more. If it refuses again, stop and show the user the guard's message. Never write these files any other way: not with Edit, and never through Bash.

## 4. The user's own steps

Run:

```bash
python3 -I "${CLAUDE_PLUGIN_ROOT}/skills/setup/chat.py" next
```

Show its steps exactly, then guide the user through them one at a time, waiting for each to be done. Explain what each is for if they ask. These steps are the user's by design. Don't edit the rules file or the gate config yourself (the guard refuses it), and don't ask the user for their canary word: it isn't shown, and the doctor checks it.

## In a terminal instead

If the user would rather set up from a terminal, tell them to run `python3 -I "${CLAUDE_PLUGIN_ROOT}/skills/setup/apply.py"` there themselves, with the path filled in, or run `python3 "${CLAUDE_PLUGIN_ROOT}/skills/setup/setup.py"` and show its step-by-step commands exactly. Never run `apply.py` or those commands yourself.

If a script fails, show its error and point the user to the install steps in the plugin's README.
