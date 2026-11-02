#!/usr/bin/env bash
# The cron line must run ctl.sh backup, archive that new snapshot, and
# record manifest created_utc. A failed backup or age leaves the stamp put.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/idoris-offhost.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

cp "$root/offhost-backup.sh" "$tmp/offhost-backup.sh"
chmod 700 "$tmp/offhost-backup.sh"

cat > "$tmp/ctl.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${FAIL_BACKUP:-}" == 1 ]]; then
  echo "ctl: backup forced to fail" >&2
  exit 1
fi
nfile="${CTL_COUNT:?}"
n=0
if [[ -f "$nfile" ]]; then
  n="$(cat "$nfile")"
fi
n=$((n + 1))
printf '%s\n' "$n" > "$nfile"
created="$(python3 -c 'import datetime,sys
n=int(sys.argv[1])
base=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc)
print((base+datetime.timedelta(seconds=n)).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$n")"
dest="${BACKUP_ROOT:?}/snap-$n"
mkdir -p "$dest"
chmod 700 "$dest"
printf '{"created_utc":"%s"}\n' "$created" > "$dest/manifest.json"
chmod 600 "$dest/manifest.json"
printf 'backup_dir=%s\n' "$dest"
echo "backup written to $dest"
EOF
chmod 700 "$tmp/ctl.sh"

mkdir -p "$tmp/bin"
cat > "$tmp/bin/age" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="${2:-}"; shift 2 ;;
    -r) shift 2 ;;
    *) shift ;;
  esac
done
if [[ "${FAIL_AGE:-}" == 1 ]]; then
  echo "age: forced to fail" >&2
  exit 1
fi
[[ -n "$out" ]] || { echo "age: -o is required" >&2; exit 1; }
cat > "$out"
EOF
chmod 700 "$tmp/bin/age"

export PATH="$tmp/bin:$PATH"
export BACKUP_ROOT="$tmp/snaps"
export CTL_COUNT="$tmp/count"
mkdir -p "$BACKUP_ROOT" "$tmp/off"
chmod 700 "$BACKUP_ROOT" "$tmp/off"
printf '%s\n' '2000-01-01T00:00:00Z' > "$tmp/off/idoris-vpn-backup.created"
chmod 600 "$tmp/off/idoris-vpn-backup.created"
old_stamp="$(cat "$tmp/off/idoris-vpn-backup.created")"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../ops-lib.sh
source "$root/ops-lib.sh"
line="$(offhost_cron_line "$tmp/offhost-backup.sh" "$tmp/off")"
prefix='15 3 * * * '
cmd="${line#"$prefix"}"
[[ "$cmd" != "$line" ]] || { echo "cron prefix was not present: $line" >&2; exit 1; }
[[ "$cmd" == *"offhost-backup.sh"* ]] || { echo "cron does not call offhost-backup.sh" >&2; exit 1; }
[[ "$cmd" != *"tar "* ]] || { echo "cron still archives by hand" >&2; exit 1; }

echo "offhost: run the generated command"
bash -c "$cmd"
bash -c "$cmd"
archives="$(find "$tmp/off" -name 'idoris-vpn-*.tar.age' | wc -l | tr -d ' ')"
[[ "$archives" == 2 ]] || { echo "expected 2 archives, got $archives" >&2; exit 1; }
snaps="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
[[ "$snaps" == 2 ]] || { echo "expected 2 snapshots, got $snaps" >&2; exit 1; }
second="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["created_utc"])' "$BACKUP_ROOT/snap-2/manifest.json")"
[[ "$(cat "$tmp/off/idoris-vpn-backup.created")" == "$second" ]] || {
  echo "stamp is not the second created_utc" >&2
  exit 1
}
[[ -f "$tmp/off/idoris-vpn-${second}.tar.age" ]] || { echo "missing archive for $second" >&2; exit 1; }

echo "offhost: age failure does not move the stamp"
before="$(cat "$tmp/off/idoris-vpn-backup.created")"
set +e
FAIL_AGE=1 bash -c "$cmd" >/dev/null 2>"$tmp/age.err"
age_ec=$?
set -e
[[ "$age_ec" -ne 0 ]] || { echo "age failure was ignored" >&2; exit 1; }
[[ "$(cat "$tmp/off/idoris-vpn-backup.created")" == "$before" ]] || { echo "stamp moved after age failure" >&2; exit 1; }
[[ ! -e "$tmp/off/idoris-vpn-${second}.tar.age.partial" ]] || { echo "partial archive left behind" >&2; exit 1; }

echo "offhost: backup failure does not move the stamp"
set +e
FAIL_BACKUP=1 bash "$tmp/offhost-backup.sh" >/dev/null 2>"$tmp/bak.err"
bak_ec=$?
set -e
unset FAIL_BACKUP
[[ "$bak_ec" -ne 0 ]] || { echo "backup failure was ignored" >&2; exit 1; }
[[ "$(cat "$tmp/off/idoris-vpn-backup.created")" == "$before" ]] || { echo "stamp moved after backup failure" >&2; exit 1; }
[[ "$(cat "$tmp/off/idoris-vpn-backup.created")" != "$old_stamp" ]] || { echo "stamp never advanced" >&2; exit 1; }
grep -q 'offhost_cron_line' "$root/ctl.sh" || { echo "ctl.sh does not call offhost_cron_line" >&2; exit 1; }
echo "offhost backup ok"
