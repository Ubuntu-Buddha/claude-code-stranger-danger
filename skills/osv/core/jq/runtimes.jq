# Input (jq -n): one runtime release file, fetched from a fixed URL (nothing
# of ours is sent). Arg: $kind. Output lines, fixed shapes only (codenames,
# notes and URLs are never printed):
#   node-index   https://nodejs.org/dist/index.json:
#                "R<TAB>major.minor.patch<TAB>yes|no" (security release or not)
#   node-sched   https://raw.githubusercontent.com/nodejs/Release/main/schedule.json:
#                "L<TAB>major<TAB>end date (YYYY-MM-DD)"
#   py-cycle     https://peps.python.org/api/release-cycle.json:
#                "L<TAB>3.N<TAB>status word<TAB>end of life (YYYY-MM-DD, YYYY-MM or -)"
#   py-release   https://www.python.org/api/v2/downloads/release/:
#                "R<TAB>3.N.P" (published, not a pre-release)
# Entries of other shapes are skipped; a file of the wrong kind, or one with
# no usable entry, stops with an error.
include "common";
def dayre: "\\A[0-9]{4}-[0-9]{2}-[0-9]{2}\\z";
def rows:
  if $kind == "node-index" then
    if type == "array" and all(.[]; type == "object") then
      .[] | select(.version | isstr and test("\\Av[0-9]{1,3}\\.[0-9]{1,4}\\.[0-9]{1,4}\\z"))
      | ["R", (.version | ltrimstr("v")), (if .security == true then "yes" else "no" end)]
    else error("malformed") end
  elif $kind == "node-sched" then
    if type == "object" then
      to_entries[] | select((.key | test("\\Av[1-9][0-9]{0,2}\\z")) and (.value | type) == "object"
                            and (.value.end | isstr and test(dayre)))
      | ["L", (.key | ltrimstr("v")), .value.end]
    else error("malformed") end
  elif $kind == "py-cycle" then
    if type == "object" then
      to_entries[] | select((.key | test("\\A3\\.[0-9]{1,2}\\z")) and (.value | type) == "object")
      | ["L", .key,
         (.value.status | if isstr and test("\\A(feature|prerelease|bugfix|security|end-of-life)\\z") then . else "other" end),
         (.value.end_of_life | if isstr and test("\\A[0-9]{4}-[0-9]{2}(-[0-9]{2})?\\z") then . else "-" end)]
    else error("malformed") end
  elif $kind == "py-release" then
    if type == "array" and all(.[]; type == "object") then
      .[] | select(.is_published == true and .pre_release == false
                   and (.name | isstr and test("\\APython 3\\.[0-9]{1,2}\\.[0-9]{1,3}\\z")))
      | ["R", (.name | ltrimstr("Python "))]
    else error("malformed") end
  else error("malformed") end;
one | [rows] | if length == 0 then error("malformed") else .[] | @tsv end
