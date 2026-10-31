"""Test stand-in for curl in the OSV runner's tests: no network.

The tests start it through a small sh wrapper they write, because the core
runs whatever path --curl names. It serves fixed replies, logs each URL to
urls.log and the names (never values) of the caller's CA, curl and proxy
variables to env.log, all in $TMPDIR, and prints the HTTP code for -w. It
exits 7 (can't connect) for a URL it doesn't know, or one listed in
fail.txt. rules.json, when there, gives OSV batch hits:
{"ver": {"eco|name|version": [vulns]}}.
"""
import json
import os
import sys

d = os.environ["TMPDIR"]
a = sys.argv[1:]
out = a[a.index("-o") + 1]
body = a[a.index("--data-binary") + 1].lstrip("@") if "--data-binary" in a else None
url = next(x for x in a if x.startswith("https://"))
with open(os.path.join(d, "urls.log"), "a") as f:
    f.write(url + "\n")
names = sorted(k for k in os.environ if k.upper() in (
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "CURL_HOME", "HTTPS_PROXY", "HTTP_PROXY",
    "ALL_PROXY", "NO_PROXY", "STUB_MARKER"))
with open(os.path.join(d, "env.log"), "a") as f:
    f.write(",".join(names) + "\n")
fail_path = os.path.join(d, "fail.txt")
fails = open(fail_path).read().split() if os.path.exists(fail_path) else []
rules_path = os.path.join(d, "rules.json")
rules = json.load(open(rules_path)) if os.path.exists(rules_path) else {}


def reply(data):
    with open(out, "wb") as f:
        f.write(data if isinstance(data, bytes) else json.dumps(data).encode())
    if "-w" in a:
        sys.stdout.write("200")
    sys.exit(0)


if any(url.startswith(p) for p in fails):
    sys.exit(7)
if url == "https://api.osv.dev/v1/querybatch":
    qs = json.load(open(body))["queries"]
    mode = "ver" if "version" in qs[0] else "any"
    res = []
    for q in qs:
        key = "|".join([q["package"]["ecosystem"], q["package"]["name"]]
                       + ([q["version"]] if mode == "ver" else []))
        hits = rules.get(mode, {}).get(key)
        res.append({"vulns": hits} if hits else {})
    reply({"results": res})
if url == "https://api.osv.dev/v1/query":
    q = json.load(open(body))
    key = "|".join([q["package"]["ecosystem"], q["package"]["name"], q["version"]])
    reply(rules.get("query", {}).get(key, {}))
if url.startswith("https://api.github.com/advisories?"):
    reply([])
if url == "https://nodejs.org/dist/index.json":
    reply([{"version": "v99.1.0", "date": "2026-01-01", "lts": False, "security": True}])
if url == "https://peps.python.org/api/release-cycle.json":
    reply({"3.99": {"status": "bugfix", "end_of_life": "2099-10"}})
if url == "https://www.python.org/api/v2/downloads/release/":
    reply([{"name": "Python 3.99.1", "is_published": True, "pre_release": False}])
sys.exit(7)
