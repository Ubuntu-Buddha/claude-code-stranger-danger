# Shared shapes. Every value printed from a reply matches one of these, or is
# replaced by a fixed word. Prose, URLs and names from replies are never
# printed; names are only compared with your own. Regexes are anchored
# with \A and \z: in jq 1.6, $ also matches before a final newline (^ matches
# only at the start; jq 1.7+ not checked).
def idre: "\\A(MAL-[0-9]{4}-[0-9]{1,8}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|CVE-[0-9]{4}-[0-9]{4,8}|PYSEC-[0-9]{4}-[0-9]{1,8}|RUSTSEC-[0-9]{4}-[0-9]{4}|GO-[0-9]{4}-[0-9]{4,8})\\z";
def datere: "\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?(Z|[+]00:00)\\z";
def tokre: "\\A[A-Za-z0-9+/=_-]{1,1024}\\z";
def isstr: type == "string";
def okid: if isstr then test(idre) else false end;
def okdate: if isstr then test(datere) else false end;
# one shape for dates everywhere: ...Z
def date_or_dash: if okdate then sub("[+]00:00\\z"; "Z") else "-" end;
def yn: if . then "yes" else "no" end;
def count: if type == "number" and . >= 0 and . == floor and . < 1e13 then tostring else "-" end;
def arr: if type == "array" then . else [] end;
def obj: if type == "object" then . else {} end;
# Run with jq -n: the reply must be exactly one JSON document (empty is malformed).
def one: [inputs] | if length == 1 then .[0] else error("malformed") end;
def pep503: ascii_downcase | gsub("[-_.]+"; "-");
# A sortable key for a version: six numeric parts, then 1 for a release and 0
# for a pre-release (so 1.2.0-rc.1 < 1.2.0), then the pre-release identifiers
# (jq sorts numbers before strings, as SemVer does). null when the core has a
# part that isn't a number (an epoch, .post, .dev): not comparable here.
# Same order as osvd.py vkey.
def vkey: if (isstr | not) or ltrimstr("v") == "" or startswith("+") or startswith("v+") then null else
  ltrimstr("v") | split("+")[0] | (index("-")) as $i
  | (if $i == null then . else .[0:$i] end) as $core
  | (if $i == null then [] else .[$i + 1:] | split(".") | map(if test("\\A[0-9]{1,9}\\z") then tonumber else . end) end) as $pre
  | ($core | split(".")) as $p
  | if ($p | length) == 0 or ($p | length) > 6 or any($p[]; test("\\A[0-9]{1,9}\\z") | not) then null
    elif $i != null and ($pre | length) == 0 or any($pre[]; . == "") then null
    else ($p | map(tonumber) + [0, 0, 0, 0, 0, 0])[0:6] + [ (if $i == null then 1 else 0 end) ] + $pre end end;
# Is version $v inside this comparator range (">= 1.0.0, < 1.2.3", "= 1.0.1",
# "< 2", "*")? true or false; null when any part doesn't parse.
def inrange($v):
  if test("\\A *\\*? *\\z") or test("\\A *>= *0(\\.0){0,2} *\\z") then true   # every version
  else [ split(",")[] | (capture("\\A *(?<op>>=|<=|>|<|=) *(?<ver>[0-9A-Za-z.+_~-]{1,80}) *\\z") // null) ] as $c
    | ($v | vkey) as $k
    | if ($c | length) == 0 or any($c[]; . == null) or $k == null or any($c[]; .ver | vkey == null) then null
      else all($c[]; (.ver | vkey) as $r
            | if .op == ">=" then $k >= $r elif .op == "<=" then $k <= $r elif .op == ">" then $k > $r
              elif .op == "<" then $k < $r else $k == $r end)
      end
  end;
