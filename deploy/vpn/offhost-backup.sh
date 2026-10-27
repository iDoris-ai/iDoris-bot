#!/usr/bin/env bash
# Take one new backup and encrypt that snapshot for an off-host disk.
#
# Cron must call this script. Archiving a directory that already exists
# reuses yesterday's snapshot and hides a failed ctl.sh backup.
#
#   umask 077
#   AGE_RECIPIENT=age1... OFFHOST_DIR=/mnt/offhost bash deploy/vpn/offhost-backup.sh
#
# The stamp file idoris-vpn-backup.created is the bundle's created_utc.
# Monitor that, not the archive mtime. It is written only after tar and age
# both succeed.
set -euo pipefail
umask 077

here="$(cd "$(dirname "$0")" && pwd)"

[[ -n "${AGE_RECIPIENT:-}" ]] || { echo "offhost: AGE_RECIPIENT is required" >&2; exit 1; }
[[ -n "${OFFHOST_DIR:-}" ]] || { echo "offhost: OFFHOST_DIR is required" >&2; exit 1; }
[[ -d "$OFFHOST_DIR" && ! -L "$OFFHOST_DIR" ]] || { echo "offhost: OFFHOST_DIR must be a real directory" >&2; exit 1; }

out="$(bash "$here/ctl.sh" backup)"
dest="$(printf '%s\n' "$out" | sed -n 's/^backup_dir=//p' | tail -n 1)"
[[ -n "$dest" && -d "$dest" && ! -L "$dest" ]] || { echo "offhost: backup did not report a directory" >&2; exit 1; }

created="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["created_utc"])' "$dest/manifest.json")"
[[ "$created" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
  echo "offhost: bad created_utc" >&2
  exit 1
}

partial="$OFFHOST_DIR/idoris-vpn-${created}.tar.age.partial"
final="$OFFHOST_DIR/idoris-vpn-${created}.tar.age"
stamp="$OFFHOST_DIR/idoris-vpn-backup.created"
rm -f "$partial"
trap 'rm -f "$partial"' EXIT
tar -C "$(dirname "$dest")" -cf - "$(basename "$dest")" | age -r "$AGE_RECIPIENT" -o "$partial"
mv "$partial" "$final"
chmod 600 "$final"
printf '%s\n' "$created" > "$stamp"
chmod 600 "$stamp"
trap - EXIT
echo "offhost: $final"
echo "offhost: created_utc $created"
