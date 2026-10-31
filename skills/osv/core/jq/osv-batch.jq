# Input (jq -n): one OSV /v1/querybatch reply. Args: $n (queries sent), $mode (ver|any).
# Output lines: "H<TAB>i<TAB>id<TAB>modified" and "T<TAB>i<TAB>page token".
# Anything off-shape stops with an error (the caller drops jq's stderr).
include "common";
one
| if type == "object" and (.results | type) == "array" and (.results | length) == $n
     and all(.results[]; type == "object"
         and ((has("vulns") | not) or (.vulns | type) == "array")
         and ((has("next_page_token") | not) or (.next_page_token | if isstr then test(tokre) else false end)))
  then
    .results | to_entries[] | .key as $i | .value as $r
    | ( ($r.vulns // [])[]
        | if type == "object" and (.id | okid) then
            select($mode == "ver" or (.id | startswith("MAL-")))
            | ["H", $i, .id, (.modified | date_or_dash)]
          elif type == "object" and (.id | isstr) and (.id | startswith("MAL-")) then
            # a malware id of a shape we don't know is still malware
            ["H", $i, "MAL-other", (.modified | date_or_dash)]
          elif $mode == "ver" then ["H", $i, "other", "-"]
          else empty end ),
      ( if $r | has("next_page_token") then ["T", $i, $r.next_page_token] else empty end )
    | @tsv
  else error("malformed") end
