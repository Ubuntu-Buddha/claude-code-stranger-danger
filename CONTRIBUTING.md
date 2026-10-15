# Contributing

Thanks for helping. Bug reports, new test cases and fixes are all welcome.
Security bypasses go through [SECURITY.md](SECURITY.md), not public issues.

## Run the checks

```bash
python3 -W error -X dev -m unittest -v   # every test, warnings are errors
python3 skills/doctor/doctor.py          # the doctor against your own setup
```

Python 3.10 or newer, standard library only. Python 3.10 stays supported:
upstream ended its support on 2026-10-01, but it is still the system
`python3` on Ubuntu 22.04 LTS.

## Ground rules

- **No dependencies.** The hooks run on every tool call, as `python3 -I`, and
  must work on a stock Python. Please don't add a package.
- **Gates only deny.** A gate returns a deny or no decision. Never "allow"
  (that would skip your permission rules) and never "ask" (a prompt approved in
  passing isn't a review).
- **Fail closed.** Any error, bad input or timeout must exit 2.
- **Every gate change comes with tests**, including disguised variants of the
  input it stops, and a control that must still pass.
- **Fixtures are synthetic.** Use temporary folders, a fake home, reserved
  names (`example.com`, `.invalid`) and documentation addresses. Tests must
  never read real secret files or touch the network.
- **Never weaken a user-scope rule from a project file.** Config comes only
  from `~/.config/stranger-danger/config.json`.
- Keep the README's tables and its "What this does not do" section in step
  with what the code does.
