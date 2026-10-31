# Input (jq -n): one OSV POST /v1/query reply. Args: $q (slurped: the body
# we sent, holding only our own ecosystem, name and version).
# Output lines: "V<TAB>id<TAB>severity<TAB>aliases<TAB>fix<TAB>fixed" per
# record, and "P" when the reply carries a page token (never followed or
# printed).
# - severity: critical, high, medium, low or unknown: GitHub's word in
#   database_specific.severity, a word in an affected entry's
#   ecosystem_specific or database_specific, or an "Ubuntu" severity[] entry's
#   word, the worst one found; any other word, a CVSS vector or nothing is
#   unknown.
# - aliases: up to 20 ids of our shapes, comma-joined, or "-".
# - fix: "fix" when a SEMVER or ECOSYSTEM range of the affected entry for our
#   own package has a "fixed" event that sorts after our version (fixed: the
#   lowest such, a plain version shape); "none" when those ranges parse and
#   none does; "unknown" otherwise (fixed: "-"). Names in the reply are only
#   compared with ours, never printed.
# Anything off-shape stops with an error.
include "common";
def sevword: if isstr then ascii_upcase
  | if . == "CRITICAL" then "critical" elif . == "HIGH" then "high"
    elif . == "MODERATE" or . == "MEDIUM" then "medium" elif . == "LOW" then "low" else "unknown" end
  else "unknown" end;
def rank: if . == "critical" then 4 elif . == "high" then 3 elif . == "medium" then 2 elif . == "low" then 1 else 0 end;
# a fixed version reaches daily.json and the journal: digits and dots, an
# optional "v", at most one pre-release tag from a fixed list (osvd.py FIXED_RE)
def verre: "\\Av?[0-9]{1,9}(\\.[0-9]{1,9}){0,5}(-(alpha|beta|rc|pre|preview|next|canary|dev)(\\.?[0-9]{1,9})?)?\\z";
($q[0].package.ecosystem) as $eco | ($q[0].package.name) as $name | ($q[0].version | vkey) as $hk
| def ours: (.package | obj) as $p
    | $p.ecosystem == $eco and ($p.name | isstr)
      and (if $eco == "PyPI" then ($p.name | pep503) == ($name | pep503) else $p.name == $name end);
one
| if type == "object" and ((has("vulns") | not) or (.vulns | type) == "array")
     and all((.vulns // [])[]; type == "object")
  then
    ( (.vulns // [])[]
      | (if (.id | okid) then .id elif (.id | isstr) and (.id | startswith("MAL-")) then "MAL-other" else "other" end) as $id
      | ([ (.database_specific | obj | .severity | sevword),
           ( (.severity | arr)[] | obj | select(.type == "Ubuntu") | .score | sevword ),
           ( (.affected | arr)[] | obj
             | (.ecosystem_specific | obj | .severity | sevword), (.database_specific | obj | .severity | sevword) ) ]
         | map(select(. != "unknown")) | if length == 0 then "unknown" else max_by(rank) end) as $sev
      | ([ (.aliases | arr)[] | select(okid) ] | unique | .[0:20] | if length == 0 then "-" else join(",") end) as $al
      | ([ (.affected | arr)[] | obj | select(ours) | (.ranges | arr)[] | obj
           | select(.type == "SEMVER" or .type == "ECOSYSTEM") | (.events | arr)[] | obj | select(has("fixed")) | .fixed ]) as $fx
      | ([ (.affected | arr)[] | obj | select(ours) | (.ranges | arr)[] | obj
           | select(.type == "SEMVER" or .type == "ECOSYSTEM") ] | length) as $nr
      | ([ $fx[] | select(isstr and test(verre)) | select(vkey as $k | $k != null and $hk != null and $k > $hk) ]
         | min_by(vkey)) as $fixed
      | (if $fixed != null then ["fix", $fixed]
         elif $nr > 0 and $hk != null and all($fx[]; isstr and test(verre) and vkey != null) then ["none", "-"]
         else ["unknown", "-"] end) as $f
      | ["V", $id, $sev, $al, $f[0], $f[1]] | @tsv ),
    ( if (.next_page_token | isstr and length > 0) then "P" else empty end )
  else error("malformed") end
