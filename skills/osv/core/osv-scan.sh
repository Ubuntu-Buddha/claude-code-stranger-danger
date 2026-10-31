#!/usr/bin/env bash
# osv-scan.sh: the OSV scan core.
# No model, no host path built in. Linux and macOS: bash 3.2+, curl, jq 1.6+,
# python3 3.9+ (standard library).
#
#   osv-scan.sh --config FILE --out DIR [--curl PATH] [--jq PATH] [--python PATH]
#
# Lists everything the config names as installed or locked (osvd.py
# enumerate), asks OSV's querybatch API for each package at its version and at
# any version, and asks the GitHub Advisory Database for malware advisories
# that name one of our packages (affects=). Each reply is saved unread and
# reduced by jq to advisory ids, dates and indices into our own package list
# (a reply is read only by jq, into fixed fields). No prose, URL or name from
# a reply is ever printed or stored. For packages with a new vulnerability at
# a held version, OSV's /v1/query (our own name and version only) gives a severity
# word, reduced to one of five fixed words, and the fixed version, for the CVE
# notice and the severe-with-fix list.
#
# Writes DIR/daily.json (DIR/daily.prev.json keeps the last one). Exit 0 OK or
# INFO, 1 ALERT (a malware record names something installed or locked at that
# version), 2 ERROR (a source failed, replied off-shape or was cut short, or
# the run itself failed).
set -Eeuo pipefail
umask 077
export LC_ALL=C

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
CONF="" OUT="" CURL=curl JQ=jq PY=python3
while [ $# -gt 0 ]; do
  case $1 in
    --config) CONF=$2 ;; --out) OUT=$2 ;; --curl) CURL=$2 ;; --jq) JQ=$2 ;; --python) PY=$2 ;;
    *) echo "usage: osv-scan.sh --config FILE --out DIR [--curl P] [--jq P] [--python P]" >&2; exit 2 ;;
  esac
  shift 2
done
[ -n "$CONF" ] && [ -n "$OUT" ] || { echo "usage: --config and --out are required" >&2; exit 2; }
UA="osv-scan/1 (package malware check)"
MAXB=$((200 * 1024 * 1024))
OSV=https://api.osv.dev/v1/querybatch
OSVQ=https://api.osv.dev/v1/query

py() { "$PY" -I "$HERE/osvd.py" "$@"; }
# jq never reads ~/.jq (it can redefine builtins): HOME points nowhere.
jqx() { HOME=/nonexistent "$JQ" -n -L "$HERE/jq" "$@" 2>/dev/null; }
cfg() { HOME=/nonexistent "$JQ" -r "$1" "$CONF" 2>/dev/null; }
size_ok() { [ "$(wc -c < "$1")" -le "$MAXB" ]; }
# fetch OUTFILE URL [BODY]: -q first so no ~/.curlrc is read; https only, no
# redirects followed; only a 200 counts. The reply is saved unread.
fetch() {
  local code
  if [ $# -eq 3 ]; then
    code=$("$CURL" -q -sS --proto '=https' --max-time 180 --max-filesize "$MAXB" -A "$UA" -w '%{http_code}' \
      -H 'Content-Type: application/json' --data-binary "@$3" -o "$1" "$2" 2>/dev/null) || return 1
  else
    code=$("$CURL" -q -sS --proto '=https' --max-time 120 --max-filesize "$MAXB" -A "$UA" -w '%{http_code}' \
      -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' -o "$1" "$2" 2>/dev/null) || return 1
  fi
  [ "$code" = 200 ] && size_ok "$1"
}
# fetch_plain OUTFILE URL: a GET to a fixed URL with no API headers.
fetch_plain() {
  local code
  code=$("$CURL" -q -sS --max-time 120 --proto '=https' --max-filesize "$MAXB" -A "$UA" -w '%{http_code}' \
    -o "$1" "$2" 2>/dev/null) || return 1
  [ "$code" = 200 ] || return 1
  size_ok "$1"
}
# OSV is retried (a machine just woken may have no network yet).
fetch_osv() {
  local n=0
  until fetch "$@"; do
    n=$((n+1)); [ "$n" -le "$RETRIES" ] || return 1
    sleep "$WAIT"
  done
}

mkdir -p -- "$OUT"
# Any failure, or a TERM, INT or HUP: a fixed ERROR result, never yesterday's.
fail() {
  trap - ERR TERM INT HUP
  if ! py placeholder "$OUT" >/dev/null 2>&1 && [ -d "$OUT" ] && [ ! -L "$OUT" ]; then
    # no Python: a new file and a rename, so a link at daily.json is replaced, not followed
    local t; t=$(mktemp "$OUT/.daily.json.XXXXXXXX" 2>/dev/null) \
      && printf '{"schema":"sd-osv/1","level":"ERROR","errors":["run"]}\n' > "$t" \
      && mv -f -- "$t" "$OUT/daily.json"
  fi
  exit 2
}
trap fail ERR TERM INT HUP
py start "$OUT"
WD=$(mktemp -d "${TMPDIR:-/tmp}/osv-scan.XXXXXXXX")
trap 'rm -rf -- "$WD"' EXIT

VSIZE=$(cfg '.osv.ver_batch // 200') ASIZE=$(cfg '.osv.any_batch // 50')
FOLLOW=$(cfg '.osv.follow_page_tokens // false')
RETRIES=$(cfg '.osv.retries // 2') WAIT=$(cfg '.osv.retry_wait // 30')
case "$VSIZE$ASIZE$RETRIES$WAIT" in *[!0-9]*|"") fail ;; esac
# GitHub's limits too, before any request: a bad value found only after the
# OSV passes would turn their result (an ALERT, say) into ERROR run.
GHN=$(cfg '.github.chunk_names // 500') GHC=$(cfg '.github.max_calls // 40')
[[ $GHN =~ ^[1-9][0-9]{0,2}$ ]] && [ "$GHN" -le 500 ] && [[ $GHC =~ ^[1-9][0-9]?$ ]] && [ "$GHC" -le 55 ] || fail
# The runtimes' end-of-life sources: true or false, default true.
# jq's // would turn false into the default, so absent is tested with has();
# tojson keeps the string "false" from passing as the boolean.
rtswitch() {
  cfg "if (.runtimes | type) == \"object\" and (.runtimes | has(\"$1\")) then .runtimes.$1 else true end | tojson"
}
NSCHED=$(rtswitch node_schedule) || NSCHED=x
PCYCLE=$(rtswitch python_cycle) || PCYCLE=x
case "$NSCHED $PCYCLE" in "true true"|"true false"|"false true"|"false false") ;; *) fail ;; esac
STATUS=()
setst() { STATUS+=("$1=$2"); }

# 1. What is installed or locked (the config's files only).
py enumerate "$CONF" "$WD/inv.json" >/dev/null
py batches "$WD/inv.json" "$WD" "$VSIZE" "$ASIZE" >/dev/null

# 2. OSV, by version and at any version.
# extract BODY REPLY MODE TAG: hits -> x-TAG.tsv, page tokens -> tok-TAG.tsv
extract() {
  local n tsv="$WD/e.tsv"
  n=$(HOME=/nonexistent "$JQ" '.queries | length' "$1")
  jqx -r --argjson n "$n" --arg mode "$3" -f "$HERE/jq/osv-batch.jq" < "$2" > "$tsv" || return 1
  awk -F'\t' -v OFS='\t' '$1 == "H" && NF == 4 { print $2, $3, $4 }' "$tsv" > "$WD/x-$4.tsv.new"
  awk -F'\t' -v OFS='\t' '$1 == "T" && NF == 3 { print $2, $3 }' "$tsv" > "$WD/tok-$4.tsv"
  # every line was one or the other
  [ "$(wc -l < "$tsv")" -eq $(( $(wc -l < "$WD/x-$4.tsv.new") + $(wc -l < "$WD/tok-$4.tsv") )) ] || return 1
  mv -f -- "$WD/x-$4.tsv.new" "$WD/x-$4.tsv"
}
has_tokens() { # MODE ROUND: any page token left from that round?
  local f
  for f in "$WD"/tok-"$1"-*-r"$2".tsv; do [ -s "$f" ] && return 0; done
  return 1
}
for mode in ver any; do
  st=ok
  for q in "$WD"/q-$mode-[0-9]*.json; do
    [ -e "$q" ] || continue
    b=${q##*/q-$mode-}; b=${b%.json}
    case $b in *[!0-9]*) continue ;; esac
    if ! fetch_osv "$WD/r-$mode-$b.json" "$OSV" "$q"; then st=unreachable; break; fi
    if ! extract "$q" "$WD/r-$mode-$b.json" "$mode" "$mode-$b-r0"; then st=malformed; break; fi
    mv -f -- "$WD/x-$mode-$b-r0.tsv" "$WD/x-$mode-$b.tsv"
  done
  # Page tokens: following one sends OSV's own token back to OSV, so it
  # is opt-in (osv.follow_page_tokens); until the config
  # turns it on, a paged reply is an ERROR ("paged"), never a quiet miss.
  r=1
  while [ "$st" = ok ] && has_tokens "$mode" $((r-1)); do
    if [ "$FOLLOW" != true ]; then st=paged; break; fi
    if [ "$r" -gt 5 ]; then st=truncated; break; fi
    py pages "$WD/inv.json" "$WD" "$mode" "$r" >/dev/null || { st=malformed; break; }
    for q in "$WD"/q-$mode-*-r$r.json; do
      [ -e "$q" ] || continue
      b=${q##*/q-$mode-}; b=${b%-r$r.json}
      if ! fetch_osv "$WD/r-$mode-$b-r$r.json" "$OSV" "$q"; then st=unreachable; break; fi
      if ! extract "$q" "$WD/r-$mode-$b-r$r.json" "$mode" "$mode-$b-r$r"; then st=malformed; break; fi
    done
    r=$((r+1))
  done
  # Hits already validated from replies that parsed are kept: an ALERT
  # outranks the ERROR a later failure adds.
  setst "osv_$mode" "$st"
done

# 3. GitHub malware advisories naming one of our packages (affects=, in chunks
# of names). Unauthenticated: 60 calls an hour. A full page means some were not
# seen: "partial", an ERROR. At most github.max_calls calls a run; an
# ecosystem that lost a chunk to that cap is "capped", also an ERROR.
py ghchunks "$WD/inv.json" "$WD" "$GHN" "$GHC" >/dev/null
# worst ST NEW: a status never gets better within one ecosystem
worst() {
  local r=(skipped ok unreachable capped partial malformed) i a=0 b=0
  for i in 0 1 2 3 4 5; do [ "${r[$i]}" = "$1" ] && a=$i; [ "${r[$i]}" = "$2" ] && b=$i; done
  [ "$b" -gt "$a" ] && echo "$2" || echo "$1"
}
for ge in npm pip rust go; do
  st=skipped
  while IFS=$'\t' read -r e c url; do
    [ "$e" = "$ge" ] || continue
    [ "$st" = skipped ] && st=ok
    if ! fetch "$WD/gh-$ge-$c.json" "$url"; then st=$(worst "$st" unreachable); break; fi
    if ! jqx -r --arg eco "$ge" --slurpfile names "$WD/ghn-$ge-$c.json" -f "$HERE/jq/gh-malware.jq" \
         < "$WD/gh-$ge-$c.json" > "$WD/gh-$ge-$c.tsv"; then
      rm -f -- "$WD/gh-$ge-$c.tsv"; st=malformed; break
    fi
    cnt=$(jqx 'include "common"; one | length' < "$WD/gh-$ge-$c.json") || cnt=x
    case $cnt in ""|*[!0-9]*) st=malformed; break ;; esac
    [ "$cnt" -lt 100 ] || st=$(worst "$st" partial)
  done < "$WD/ghurls.tsv"
  grep -qx -- "$ge" "$WD/gh-capped" && st=$(worst "$st" capped)
  setst "gh_$ge" "$st"
done

# 3b. Runtimes (Node.js, CPython): their own release data, from fixed URLs.
# Nothing of ours is sent (a plain GET). jq keeps versions, a security yes/no,
# end dates and a status word. Each runtime has two sources, fetched only
# when such a runtime is held: its release list (rt_node, rt_python) and its
# end-of-life data (rt_node_eol, rt_python_eol). The config can skip an
# end-of-life source (runtimes.node_schedule, runtimes.python_cycle false),
# for a host whose sandbox can't reach that host; then end of life is
# not_checked, never "no". rt-<kind>.tsv holds a source's rows, prefixed
# with its kind, only when that source finished.
rtfetch() { # SOURCE KIND URL: one source into rt-KIND.tsv
  local st=ok
  if ! fetch_plain "$WD/rf-$2.json" "$3"; then st=unreachable
  elif ! jqx -r --arg kind "$2" -f "$HERE/jq/runtimes.jq" < "$WD/rf-$2.json" > "$WD/rr.tsv"; then st=malformed
  else
    awk -F'\t' -v OFS='\t' -v k="$2" '{ print k, $0 }' "$WD/rr.tsv" > "$WD/rt-$2.tsv.new"
    mv -f -- "$WD/rt-$2.tsv.new" "$WD/rt-$2.tsv"
  fi
  setst "$1" "$st"
}
HELD_RT=$(HOME=/nonexistent "$JQ" -r '[.runtimes[]?.rt] | unique | join(" ")' "$WD/inv.json" 2>/dev/null) || HELD_RT=bad
if [ "$HELD_RT" = bad ]; then
  setst rt_node malformed; setst rt_node_eol malformed; setst rt_python malformed; setst rt_python_eol malformed
else
  case " $HELD_RT " in *" node "*)
    rtfetch rt_node node-index https://nodejs.org/dist/index.json
    if [ "$NSCHED" = true ]; then
      rtfetch rt_node_eol node-sched https://raw.githubusercontent.com/nodejs/Release/main/schedule.json
    else setst rt_node_eol skipped; fi ;;
    *) setst rt_node skipped; setst rt_node_eol skipped ;;
  esac
  case " $HELD_RT " in *" python "*)
    rtfetch rt_python py-release https://www.python.org/api/v2/downloads/release/
    if [ "$PCYCLE" = true ]; then
      rtfetch rt_python_eol py-cycle https://peps.python.org/api/release-cycle.json
    else setst rt_python_eol skipped; fi ;;
    *) setst rt_python skipped; setst rt_python_eol skipped ;;
  esac
fi

# 3c. Severity and fix of vulnerabilities at held versions, last, so a
# failure here can't stop the malware passes above. querybatch gives ids
# only, and asking for a record by an id from a reply would send untrusted
# text out. So OSV's /v1/query gets only our own ecosystem, name and
# version (osvd.py sevq: packages with a new hit first, then the backlog never
# asked, then answers older than 7 days), and jq keeps the severity word, ids,
# aliases and the fixed version above ours. Up to osv.severity_max packages
# and 10 minutes a run. Capped (by either) is INFO; unreachable or paged is
# INFO once after a good run, an ERROR two runs running (osvd.py join); those
# issues count as unasked. Off-shape, a bad setting or a helper failure is an
# ERROR. None of these stops the run.
SMAX=$(cfg '.osv.severity_max // 150') || SMAX=x
st=skipped pg=no cap=no
SDEAD=$((SECONDS + 600))
case "$SMAX" in
  ""|*[!0-9]*) st=malformed ;;
  *)
    if ! py sevq "$WD/inv.json" "$WD" "$OUT" "$SMAX" >/dev/null 2>&1; then
      st=malformed
    else
      # in sevq's order (new hits first), by number: a glob would sort sq-10 before sq-2
      k=0
      while [ -e "$WD/sq-$k.json" ]; do
        q=$WD/sq-$k.json
        [ "$SECONDS" -lt "$SDEAD" ] || { cap=yes; break; }
        st=ok
        if ! fetch "$WD/sr-$k.json" "$OSVQ" "$q"; then st=unreachable; break; fi
        if ! jqx -r --slurpfile q "$q" -f "$HERE/jq/osv-sev.jq" < "$WD/sr-$k.json" > "$WD/se.tsv"; then st=malformed; break; fi
        awk -F'\t' -v OFS='\t' '$1 == "V" && NF == 6 { print $2, $3, $4, $5, $6 }' "$WD/se.tsv" > "$WD/sv-$k.tsv.new"
        np=$(grep -cx P "$WD/se.tsv") || true
        # every line was one or the other
        [ "$(wc -l < "$WD/se.tsv")" -eq $(( $(wc -l < "$WD/sv-$k.tsv.new") + np )) ] || { st=malformed; break; }
        mv -f -- "$WD/sv-$k.tsv.new" "$WD/sv-$k.tsv"
        [ "$np" -eq 0 ] || pg=yes
        k=$((k + 1))
      done
      if [ "$st" = ok ] || [ "$st" = skipped ]; then
        [ "$(cat "$WD/sq-capped")" = no ] || cap=yes
        if [ "$pg" = yes ]; then st=paged; elif [ "$cap" = yes ]; then st=capped; fi
      fi
    fi ;;
esac
setst osv_sev "$st"

# 4. Join, write daily.json.
printf '%s\n' "${STATUS[@]}" > "$WD/status"
rc=0
py join "$WD/inv.json" "$WD" "$OUT" || rc=$?
case $rc in 0|1|2) ;; *) fail ;; esac
trap - ERR TERM INT HUP
exit "$rc"
