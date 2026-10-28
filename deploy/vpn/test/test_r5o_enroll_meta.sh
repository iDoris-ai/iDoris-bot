#!/usr/bin/env bash
# Rollback restores enroll directory and config.json.lock metadata.
# The check runs on the container's own filesystem: Docker Desktop does not
# preserve ownership of a macOS bind mount.
set -euo pipefail
umask 077

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
root="$repo/deploy/vpn"
alpine="alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63"
rand="$(python3 -c 'import random; print(random.randint(100000, 999999))')"
name="idoris-vpn-r5o-meta-${rand}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/r5o-enroll-meta.XXXXXX")"

die() { echo "r5o-enroll-meta: $*" >&2; exit 1; }

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

case "$(uname -m)" in
  arm64|aarch64) goarch=arm64 ;;
  x86_64) goarch=amd64 ;;
  *) die "unsupported machine $(uname -m)" ;;
esac

echo "test: build linux enroll and roll back ownership inside the container"
(
  cd "$repo/vpn"
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -o "$tmp/idoris-vpn-enroll" ./cmd/idoris-vpn-enroll
)
chmod 755 "$tmp/idoris-vpn-enroll"

cat > "$tmp/inner.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
umask 077
die() { echo "r5o-enroll-meta: $*" >&2; exit 1; }
here=/work
# shellcheck disable=SC1091
source /opt/ops-lib.sh
mkdir -p /work/enroll
chmod 755 /work
cat > /work/enroll/config.json <<'JSON'
{
  "control_url": "https://vpn.example.org",
  "tenants": [
    {
      "name": "acme",
      "headscale_user_id": "1",
      "token_hashes": []
    }
  ]
}
JSON
: > /work/enroll/config.json.lock
chown 65532:65532 /work/enroll /work/enroll/config.json /work/enroll/config.json.lock
chmod 750 /work/enroll
chmod 640 /work/enroll/config.json /work/enroll/config.json.lock

snap="$(mktemp -d /tmp/snap.XXXXXX)"
_snapshot_host_files "$snap"
grep -q '^d enroll 65532 65532 750$' "$snap/META" || die "directory metadata was not snapshotted: $(cat "$snap/META")"
grep -q '^f enroll/config.json.lock 65532 65532 640$' "$snap/META" || die "lock metadata was not snapshotted: $(cat "$snap/META")"

chown_enroll_runtime 65531 65531
_restore_host="$snap"
_restore_vol=""
_restore_snap=""
_restore_current=""
_restore_dest=""
_restore_prev_mode="published"
_restore_rollback

python3 - <<'PY'
import os, sys
want = {
    "/work/enroll": (65532, 65532, 0o750),
    "/work/enroll/config.json": (65532, 65532, 0o640),
    "/work/enroll/config.json.lock": (65532, 65532, 0o640),
}
for path, (uid, gid, mode) in want.items():
    st = os.stat(path)
    got = (st.st_uid, st.st_gid, st.st_mode & 0o777)
    if got != (uid, gid, mode):
        sys.exit("%s is %s, want %s" % (path, got, (uid, gid, mode)))
PY

run_as() {
  python3 - "$@" <<'PY'
import os, sys
os.setgid(65532)
os.setuid(65532)
os.execv(sys.argv[1], sys.argv[1:])
PY
}
run_as /usr/local/bin/idoris-vpn-enroll list-credentials --config /work/enroll/config.json --entry acme >/tmp/list.out
code=/tmp/invite-code
run_as /usr/local/bin/idoris-vpn-enroll invite --config /work/enroll/config.json --entry acme --label lab --enroll-url https://enroll.example.org >"$code"
test -s "$code"
rm -f "$code"
echo "ownership ok"
EOF
chmod 755 "$tmp/inner.sh"

docker run --name "$name" --user 0 \
  -v "$root/ops-lib.sh:/opt/ops-lib.sh:ro" \
  -v "$tmp/idoris-vpn-enroll:/usr/local/bin/idoris-vpn-enroll:ro" \
  -v "$tmp/inner.sh:/inner.sh:ro" \
  "$alpine" \
  sh -c 'apk add --no-cache bash python3 >/dev/null && bash /inner.sh'

echo "test_r5o_enroll_meta: ok"
