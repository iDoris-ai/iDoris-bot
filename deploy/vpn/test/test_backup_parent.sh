#!/usr/bin/env bash
# ctl.sh backup with no path creates $here/backups mode 0700.
# A symlink or a loose parent is refused and left unchanged.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/idoris-bakparent.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

cp "$root/ctl.sh" "$root/ops-lib.sh" "$tmp/"
mkdir -p "$tmp/enroll" "$tmp/headplane" "$tmp/headscale" "$tmp/bin"
printf '%s\n' '{"tenants":[]}' > "$tmp/enroll/config.json"
printf '%s' 'placeholder' > "$tmp/enroll/headscale.apikey"
printf '%s' '0123456789abcdef0123456789abcdef' > "$tmp/headplane/cookie_secret"
printf '%s\n' '{}' > "$tmp/headscale/managed.json"
printf '%s\n' 'server_url: https://flags.example.test' > "$tmp/headscale/config.yaml"
printf '%s\n' '{}' > "$tmp/headscale/policy.hujson"
printf '%s\n' 'server:' > "$tmp/headplane/config.yaml"
printf '%s\n' 'name: idoris-vpn' > "$tmp/compose.yaml"
cat > "$tmp/.env" <<'EOF'
COMPOSE_PROJECT_NAME=idoris-vpn-r2d-bakparent
ENROLL_UID=65532
ENROLL_GID=65532
HEADSCALE_PORT=18080
HEADPLANE_PORT=13000
ENROLL_PORT=18787
DERP_STUN_PORT=13478
HEADPLANE_BIND=127.0.0.1
EOF
chmod 600 "$tmp/.env" "$tmp/enroll/config.json" "$tmp/enroll/headscale.apikey" \
  "$tmp/headplane/cookie_secret" "$tmp/headscale/managed.json"

cat > "$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *" ls "* || "$*" == ls* ]]; then
  printf '[]\n'
fi
exit 0
EOF
chmod 700 "$tmp/bin/docker"
export PATH="$tmp/bin:$PATH"

mode_of() {
  python3 -c 'import os,sys; print("%o" % (os.stat(sys.argv[1]).st_mode & 0o777))' "$1"
}

echo "backup-parent: default destination"
set +e
out="$(bash "$tmp/ctl.sh" backup 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || { echo "backup without a headscale container succeeded" >&2; exit 1; }
grep -q 'no Headplane container' <<<"$out" || { echo "unexpected failure: $out" >&2; exit 1; }
[[ "$(mode_of "$tmp/backups")" == "700" ]] || { echo "parent mode $(mode_of "$tmp/backups")" >&2; exit 1; }
[[ ! -L "$tmp/backups" ]] || { echo "parent is a symlink" >&2; exit 1; }
child="$(find "$tmp/backups" -mindepth 1 -maxdepth 1 -type d ! -type l)"
[[ -n "$child" ]] || { echo "no backup directory was created" >&2; exit 1; }
[[ "$(mode_of "$child")" == "700" ]] || { echo "child mode $(mode_of "$child")" >&2; exit 1; }

echo "backup-parent: symlink parent is refused"
rm -rf "$tmp/backups"
mkdir -p "$tmp/link-target"
ln -s "$tmp/link-target" "$tmp/backups"
set +e
out="$(bash "$tmp/ctl.sh" backup 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || { echo "symlink parent was accepted" >&2; exit 1; }
grep -q 'symlink' <<<"$out" || { echo "symlink was not named: $out" >&2; exit 1; }
[[ -z "$(ls -A "$tmp/link-target")" ]] || { echo "wrote through the symlink parent" >&2; exit 1; }

echo "backup-parent: loose parent is not chmodded"
rm "$tmp/backups"
python3 -c 'import os,sys; os.mkdir(sys.argv[1], 0o755); os.chmod(sys.argv[1], 0o755)' "$tmp/backups"
[[ "$(mode_of "$tmp/backups")" == "755" ]] || { echo "could not create a 0755 parent" >&2; exit 1; }
set +e
out="$(bash "$tmp/ctl.sh" backup 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || { echo "0755 parent was accepted" >&2; exit 1; }
grep -q 'not private' <<<"$out" || { echo "loose parent was not refused: $out" >&2; exit 1; }
[[ "$(mode_of "$tmp/backups")" == "755" ]] || { echo "loose parent was chmodded" >&2; exit 1; }

echo "backup-parent: a missing custom parent is not created"
set +e
out="$(bash "$tmp/ctl.sh" backup "$tmp/no-such/child" 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || { echo "missing custom parent was created" >&2; exit 1; }
[[ ! -e "$tmp/no-such" ]] || { echo "created $tmp/no-such" >&2; exit 1; }
echo "backup parent ok"
