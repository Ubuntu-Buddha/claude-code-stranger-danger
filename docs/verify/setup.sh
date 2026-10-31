#!/usr/bin/env bash
# Turnkey setup for docs/VERIFY.md. Creates a harmless scratch layout and a
# matching gate config so you can verify an install end to end. Everything it
# writes is inert test text.
#
#   bash docs/verify/setup.sh              # uses /tmp/sd-verify
#   bash docs/verify/setup.sh /path/you/pick
#
# Use a base OUTSIDE your home directory. A base under ~ makes Claude Code load
# your real ~/.claude/CLAUDE.md as an ancestor config even in a fresh profile,
# so the test session isn't clean.
#
# Clean up afterwards with:  rm -rf /tmp/sd-verify   (or the path you chose).
# This never touches an existing gate config; if you have one, it prints the
# paths to merge instead.
set -euo pipefail

base="${1:-/tmp/sd-verify}"
case "$base" in
  "$HOME" | "$HOME"/*)
    echo "warning: $base is under your home directory. Claude Code will load your" >&2
    echo "  real ~/.claude/CLAUDE.md as an ancestor config, so the test session" >&2
    echo "  won't be clean. Prefer a base outside \$HOME." >&2
    ;;
esac

# /tmp is shared: refuse a base that someone else created or pointed elsewhere,
# so the files below can't be redirected through a planted symlink.
if [ -L "$base" ] || { [ -e "$base" ] && [ ! -O "$base" ]; }; then
  echo "error: $base is a symlink or isn't yours; remove it or pick another base." >&2
  exit 1
fi
mkdir -p "$base"
chmod 700 "$base"
mkdir -p "$base/untrusted" "$base/quarantine" "$base/project"
printf 'a harmless test document\n' > "$base/untrusted/doc.txt"
printf 'a harmless test file\n'     > "$base/quarantine/file.txt"
printf 'my own notes\n'             > "$base/project/notes.txt"
# Rows 32 and 32b: a symlink into quarantine, to check that Glob doesn't walk
# through it. If qlink is a real folder, ln would put the link inside it.
if [ -e "$base/project/qlink" ] && [ ! -L "$base/project/qlink" ]; then
  echo "error: $base/project/qlink exists and isn't a symlink; remove it and rerun." >&2
  exit 1
fi
ln -sfn "$base/quarantine" "$base/project/qlink"

# The gate config must be readable only by you. If it's group- or world-
# writable, or owned by someone else, both gates fail closed and block
# everything they cover. So: folder 700, file 600.
cfg_dir="$HOME/.config/stranger-danger"
cfg="$cfg_dir/config.json"
mkdir -p "$cfg_dir"
chmod 700 "$cfg_dir"
if [ -e "$cfg" ]; then
  echo "note: $cfg already exists; left unchanged."
  echo "      merge these folders into its reader_gate section, then run: chmod 600 '$cfg'"
  echo "        untrusted_paths:  $base/untrusted"
  echo "        quarantine_paths: $base/quarantine"
else
  ( umask 077
    cat > "$cfg" <<JSON
{
  "reader_gate": {
    "untrusted_paths": ["$base/untrusted"],
    "quarantine_paths": ["$base/quarantine"]
  }
}
JSON
  )
  chmod 600 "$cfg"
  echo "wrote gate config (mode 600): $cfg"
fi

echo "created: $base/{untrusted,quarantine,project} and $base/project/qlink"
echo
echo "next:"
echo "  1. install the plugin from this checkout and restart Claude Code"
echo "  2. run /stranger-danger:setup then /stranger-danger:doctor"
echo "  3. open a fresh session in $base/project and work through"
echo "     docs/VERIFY.md, recording into a copy of docs/verify/RESULTS.template.md"
