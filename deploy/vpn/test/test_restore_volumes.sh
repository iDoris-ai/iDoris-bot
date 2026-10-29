#!/usr/bin/env bash
# Retained volumes are data even when no container exists.
# A volume marked for another directory is a collision.
# Rollback recreates from the saved config and keeps snapshots when it fails.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/idoris-restore-vol.XXXXXX")"
proj="idoris-vpn-r4o-rvol-$(python3 -c 'import random; print(random.randint(100000, 999999))')"
vol="${proj}_headscale-data"
alpine="alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63"

cleanup() {
  docker volume rm -f "$vol" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

mkdir -p "$tmp/vpn/headscale" "$tmp/bin"
printf 'services: {}\n' > "$tmp/vpn/compose.yaml"
printf 'COMPOSE_PROJECT_NAME=%s\n' "$proj" > "$tmp/vpn/.env"
chmod 600 "$tmp/vpn/.env"

# shellcheck disable=SC2034
here="$tmp/vpn"
die() { echo "restore-vol: $*" >&2; exit 1; }
# shellcheck disable=SC1091
source "$root/ops-lib.sh"

echo "test: failed rollback keeps the snapshots; phase 0 still deletes"
keep_host="$(mktemp -d "$tmp/keep-host.XXXXXX")"
keep_vol="$(mktemp -d "$tmp/keep-vol.XXXXXX")"
keep_snap="$(mktemp "$tmp/keep-snap.XXXXXX")"
printf 'x\n' > "$keep_host/marker"
(
  # _restore_on_exit calls this override.
  # shellcheck disable=SC2329
  _restore_rollback() { return 1; }
  _restore_ok=0
  _restore_phase=2
  _restore_host="$keep_host"
  _restore_vol="$keep_vol"
  _restore_snap="$keep_snap"
  set +e
  ( _restore_on_exit )
  set -e
  [[ -d "$keep_host" && -f "$keep_host/marker" ]] || die "incomplete rollback deleted the host snapshot"
  [[ -d "$keep_vol" ]] || die "incomplete rollback deleted the volume snapshot"
  [[ -f "$keep_snap" ]] || die "incomplete rollback deleted the service snapshot"
)
phase_host="$(mktemp -d "$tmp/phase-host.XXXXXX")"
(
  _restore_ok=0
  _restore_phase=0
  _restore_host="$phase_host"
  _restore_vol=""
  _restore_snap=""
  set +e
  ( _restore_on_exit )
  set -e
  [[ ! -d "$phase_host" ]] || die "phase 0 kept a snapshot"
)

echo "test: rollback force-recreates the saved services and does not down -v"
rb="$tmp/rb"
mkdir -p "$rb/vol/headscale" "$rb/host" "$rb/bin"
printf 'original-bytes\n' > "$rb/vol/headscale/db.sqlite"
printf '1\n' > "$rb/vol/HAD"
printf '%s\n' "$vol" > "$rb/vol/volumes.before"
: > "$rb/vol/containers.before"
: > "$rb/vol/networks.before"
printf 'headscale\n' > "$rb/snap"
export DOCKER_LOG="$rb/docker.log"
: > "$DOCKER_LOG"
cat > "$rb/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'CMD'
  printf ' %q' "$@"
  printf '\n'
} >> "${DOCKER_LOG:?}"
if [[ "$1" == "compose" && "$*" == *" config "* ]]; then
  printf '%s\n' '{"services":{"headscale":{"image":"headscale/headscale:v0.29.6"},"enroll":{},"headplane":{"ports":[{"target":3000,"published":"3000","host_ip":"127.0.0.1"}]}}}'
  exit 0
fi
if [[ "$1" == "image" && "$2" == "inspect" ]]; then
  printf '%s\n' 'nonroot'
  exit 0
fi
if [[ "$1" == "volume" && "$2" == "ls" ]]; then
  exit 0
fi
if [[ "$1" == "volume" && "$2" == "inspect" ]]; then
  exit 0
fi
if [[ "$1" == "ps" || "$1" == "network" ]]; then
  exit 0
fi
exit 0
EOF
chmod 755 "$rb/bin/docker"
(
  export PATH="$rb/bin:$PATH"
  export COMPOSE_PROJECT_LOCK="$proj"
  _restore_current="$proj"
  _restore_dest="$proj"
  _restore_prev_mode="published"
  _restore_host="$rb/host"
  _restore_vol="$rb/vol"
  _restore_snap="$rb/snap"
  _restore_rollback
)
if grep -q 'down -v' "$DOCKER_LOG"; then
  echo "rollback deleted the project with down -v" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
fi
grep -q 'up -d --force-recreate --wait --wait-timeout 180 headscale' "$DOCKER_LOG" || {
  echo "rollback did not recreate headscale from the saved config" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
}
if grep -E 'CMD compose .* start headscale' "$DOCKER_LOG"; then
  echo "rollback used compose start" >&2
  exit 1
fi

echo "test: a volume from another directory is refused"
docker volume create --label "com.docker.compose.project=${proj}" --label "com.docker.compose.volume=headscale-data" "$vol" >/dev/null
docker run --rm --network none -v "${vol}:/data" -e MARK="/tmp/r4o-other-deploy" "$alpine" \
  sh -c 'printf %s "$MARK" > /data/.idoris-deploy-dir; printf original-bytes > /data/db.sqlite'
set +e
out="$(reject_project_named "$proj" 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || die "foreign volume was accepted"
grep -q 'has volume' <<<"$out" || die "collision error missing: $out"

echo "test: the same directory and an unlabeled volume are not a collision"
docker run --rm --network none -v "${vol}:/data" -e MARK="$here" "$alpine" \
  sh -c 'printf %s "$MARK" > /data/.idoris-deploy-dir'
reject_project_named "$proj"
docker volume rm -f "$vol" >/dev/null
docker volume create "$vol" >/dev/null
reject_project_named "$proj"

echo "test: snapshot and rollback preserve volume bytes with no container"
docker run --rm --network none -v "${vol}:/data" "$alpine" \
  sh -c 'printf original-bytes > /data/db.sqlite; printf noise > /data/noise_private.key'
snap="$(mktemp -d "$tmp/snap.XXXXXX")"
COMPOSE_PROJECT_LOCK="$proj"
_snapshot_volumes "$snap" published
[[ "$(cat "$snap/HAD")" == "1" ]] || die "retained volume was recorded as absent (HAD=$(cat "$snap/HAD"))"
grep -qx "$vol" "$snap/volumes.before" || die "volume name was not recorded"
grep -q 'original-bytes' "$snap/headscale/db.sqlite" || die "snapshot did not copy the database"
docker run --rm --network none -v "${vol}:/data" "$alpine" sh -c 'printf mutated > /data/db.sqlite'
_restore_copy_volume_alpine "$snap" || die "alpine restore failed"
got="$(docker run --rm --network none -v "${vol}:/data:ro" "$alpine" sh -c 'cat /data/db.sqlite')"
[[ "$got" == "original-bytes" ]] || die "rollback left mutated bytes: $got"

echo "test_restore_volumes: ok"
