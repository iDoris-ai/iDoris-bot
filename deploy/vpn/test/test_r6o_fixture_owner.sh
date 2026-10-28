#!/usr/bin/env bash
# A root-created 0700 fixture directory must be traversable by the uid
# listing_fixture_owner selects. Docker Desktop keeps this ownership when
# the directory is created as root on a named volume, not on a macOS bind
# mount. The reader is the same shape as restore-drill.sh: the fixture
# directory is mounted at /work and the process runs as --user uid:gid.
set -euo pipefail
umask 077

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
origin="$repo/deploy/vpn"
alpine="alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63"
rand="$(python3 -c 'import random; print(random.randint(100000, 999999))')"
vol="r6o-fixture-${rand}"
work="$(mktemp -d "${TMPDIR:-/tmp}/r6o-fixture.XXXXXX")"
payload='fixture-bytes'

die() { echo "r6o-fixture: $*" >&2; exit 1; }

cleanup() {
  docker volume rm -f "$vol" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

command -v docker >/dev/null || die "docker not found"

read_as() {
  local uidgid="$1" out="$2" err="$3"
  set +e
  docker run --rm --user "$uidgid" --network none -v "${vol}:/work:ro" "$alpine" \
    cat /work/config.json >"$out" 2>"$err"
  local rc=$?
  set -e
  printf '%s\n' "$rc"
}

echo "test: volume=${vol}; root-owned 0700 fixture is not readable by uid 65534"
docker volume create "$vol" >/dev/null
docker run --rm --user 0 --network none -v "${vol}:/fixture" "$alpine" \
  sh -c 'chmod 700 /fixture && printf "%s\n" "$1" > /fixture/config.json && chmod 600 /fixture/config.json && chown 0:0 /fixture /fixture/config.json' \
  sh "$payload"
before="$(read_as 65534:65534 "$work/before.out" "$work/before.err")"
[[ "$before" -ne 0 ]] || die "reader traversed the root-owned directory before the helper: $(cat "$work/before.out")"
grep -q -i 'permission denied' "$work/before.err" || die "expected permission denied, got: $(cat "$work/before.err")"

echo "test: listing_fixture_owner lets uid 65534 read the fixture"
docker run --rm -i --user 0 \
  -v "${vol}:/fixture" \
  -v "${origin}/ops-lib.sh:/ops-lib.sh:ro" \
  "$alpine" \
  sh -c 'apk add --no-cache bash >/dev/null && bash -s' <<'EOF'
set -euo pipefail
die() { echo "helper: $*" >&2; exit 1; }
here=/tmp/unused
# shellcheck disable=SC1091
source /ops-lib.sh
listing_fixture_owner /fixture/config.json 65532 > /fixture/owner.txt
EOF
owner="$(docker run --rm --user 0 --network none -v "${vol}:/fixture:ro" "$alpine" cat /fixture/owner.txt)"
[[ "$owner" == "65534:65534" ]] || die "helper owner is ${owner}"
after="$(read_as 65534:65534 "$work/after.out" "$work/after.err")"
[[ "$after" -eq 0 ]] || die "selected uid could not read the fixture: $(cat "$work/after.err")"
got="$(tr -d '\r' < "$work/after.out")"
[[ "$got" == "$payload" ]] || die "reader saw ${got}"
stat_out="$(docker run --rm --user 0 --network none -v "${vol}:/fixture:ro" "$alpine" \
  stat -c '%u:%g %a %n' /fixture /fixture/config.json)"
grep -q '^65534:65534 700 /fixture$' <<<"$stat_out" || die "directory owner: ${stat_out}"
grep -q '^65534:65534 600 /fixture/config.json$' <<<"$stat_out" || die "file owner: ${stat_out}"

echo "test_r6o_fixture_owner: ok"
