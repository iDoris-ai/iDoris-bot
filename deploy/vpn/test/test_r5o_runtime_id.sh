#!/usr/bin/env bash
# Runtime identity selection with a shim id/chown. This Mac is not a root
# Linux Docker host, so the root branch is exercised by putting fake
# id and chown binaries first on PATH.
set -euo pipefail
umask 077

origin="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/r5o-runtime.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

die() { echo "r5o-runtime: $*" >&2; exit 1; }

mkdir -p "$tmp/bin"
cat > "$tmp/bin/id" <<'EOF'
#!/bin/sh
case "$1" in
  -u) printf '%s\n' "${R5O_FAKE_UID:?}" ;;
  -g) printf '%s\n' "${R5O_FAKE_GID:?}" ;;
  *) echo "unexpected id $*" >&2; exit 1 ;;
esac
EOF
cat > "$tmp/bin/chown" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${R5O_CHOWN_LOG:?}"
EOF
chmod 755 "$tmp/bin/id" "$tmp/bin/chown"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../ops-lib.sh
source "$origin/ops-lib.sh"
export PATH="$tmp/bin:$PATH"
export R5O_CHOWN_LOG="$tmp/chown.log"

mode_of() {
  python3 -c 'import os, sys; print(format(os.stat(sys.argv[1]).st_mode & 0o777, "o"))' "$1"
}

read_ids() {
  local prefix="$1" out err
  out="$tmp/ids.out"
  err="$tmp/ids.err"
  : > "$out"
  : > "$err"
  select_enroll_runtime "$prefix" >"$out" 2>"$err"
  IDS="$(cat "$out")"
  ERR="$(cat "$err")"
}

export R5O_FAKE_UID=0 R5O_FAKE_GID=0
read_ids bootstrap
[[ "$IDS" == "65532 65532" ]] || die "root ids: $IDS"
[[ "$ERR" == "bootstrap: refusing to run enroll as root; using uid 65532 (the image USER)" ]] || die "root notice: $ERR"

export R5O_FAKE_UID=501 R5O_FAKE_GID=20
read_ids probe
[[ "$IDS" == "501 20" ]] || die "operator ids: $IDS"
[[ -z "$ERR" ]] || die "operator notice should be empty: $ERR"

: > "$R5O_CHOWN_LOG"
printf 'fixture\n' > "$tmp/fixture"
export R5O_FAKE_UID=0 R5O_FAKE_GID=0
got="$(listing_fixture_owner "$tmp/fixture" 65532)"
[[ "$got" == "65534:65534" ]] || die "fixture owner for 65532: $got"
grep -q '65534:65534' "$R5O_CHOWN_LOG" || die "root did not chown the fixture: $(cat "$R5O_CHOWN_LOG")"
grep -q -F "$tmp $tmp/fixture" "$R5O_CHOWN_LOG" || die "root did not chown the fixture directory: $(cat "$R5O_CHOWN_LOG")"

: > "$R5O_CHOWN_LOG"
got="$(listing_fixture_owner "$tmp/fixture" 65534)"
[[ "$got" == "65531:65531" ]] || die "fixture owner for 65534: $got"
grep -q '65531:65531' "$R5O_CHOWN_LOG" || die "root did not chown the nobody fixture: $(cat "$R5O_CHOWN_LOG")"
grep -q -F "$tmp $tmp/fixture" "$R5O_CHOWN_LOG" || die "root did not chown the nobody fixture directory: $(cat "$R5O_CHOWN_LOG")"

export R5O_FAKE_UID=501 R5O_FAKE_GID=20
: > "$R5O_CHOWN_LOG"
want="$(python3 - "$tmp/fixture" <<'PY'
import os, sys
st = os.stat(sys.argv[1])
print("%d:%d" % (st.st_uid, st.st_gid))
PY
)"
got="$(listing_fixture_owner "$tmp/fixture" 65532)"
[[ "$got" == "$want" ]] || die "non-root fixture owner $got, stat $want"
[[ ! -s "$R5O_CHOWN_LOG" ]] || die "non-root chowned the fixture: $(cat "$R5O_CHOWN_LOG")"

mkdir -p "$tmp/tree/enroll"
printf 'cfg\n' > "$tmp/tree/enroll/config.json"
chmod 755 "$tmp/tree/enroll"
chmod 644 "$tmp/tree/enroll/config.json"
printf 'cookie\n' > "$tmp/tree/cookie_secret"
chmod 644 "$tmp/tree/cookie_secret"
: > "$R5O_CHOWN_LOG"
provision_enroll_tree 501 20 "$tmp/tree/enroll"
[[ ! -s "$R5O_CHOWN_LOG" ]] || die "non-root provision chowned: $(cat "$R5O_CHOWN_LOG")"
[[ "$(mode_of "$tmp/tree/enroll/config.json")" == "644" ]] || die "non-root provision chmod the config"

export R5O_FAKE_UID=0 R5O_FAKE_GID=0
: > "$R5O_CHOWN_LOG"
provision_enroll_tree 65532 65532 "$tmp/tree/enroll"
grep -q '65532:65532' "$R5O_CHOWN_LOG" || die "root provision did not chown: $(cat "$R5O_CHOWN_LOG")"
[[ "$(mode_of "$tmp/tree/enroll")" == "700" ]] || die "enroll dir mode $(mode_of "$tmp/tree/enroll")"
[[ "$(mode_of "$tmp/tree/enroll/config.json")" == "600" ]] || die "config mode $(mode_of "$tmp/tree/enroll/config.json")"
[[ "$(mode_of "$tmp/tree/cookie_secret")" == "644" ]] || die "cookie_secret mode changed"

echo "test_r5o_runtime_id: ok"
