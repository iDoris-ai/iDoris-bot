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
# Checksum read. The snapshot file in this test is original-bytes plus a newline.
if [[ "$1" == "run" && "$*" == *"tar -C /data -cf"* ]]; then
  payload="$(mktemp -d)"
  printf 'original-bytes\n' > "$payload/db.sqlite"
  tar -C "$payload" -cf - db.sqlite
  rm -rf "$payload"
  exit 0
fi
exit 0
EOF
chmod 755 "$rb/bin/docker"
(
  # shellcheck disable=SC2030
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

# The volume above has no deploy-directory marker. Restore from another
# directory must refuse it, proceed only with the adopt flag, and refuse
# an unreadable marker even with that flag.
echo "test: markerless volume, restore from another directory"
other="$tmp/other"
bundle="$tmp/bundle"
mkdir -p "$other" \
  "$bundle/headscale" "$bundle/state/enroll" "$bundle/state/headscale" "$bundle/state/headplane"
cp "$root/bundle.py" "$other/bundle.py"
printf 'services: {}\n' > "$other/compose.yaml"
op_uid="$(id -u)"
op_gid="$(id -g)"
printf 'COMPOSE_PROJECT_NAME=%s\nENROLL_UID=%s\nENROLL_GID=%s\n' "$proj" "$op_uid" "$op_gid" > "$other/.env"
chmod 600 "$other/.env"
printf '{}\n' > "$bundle/manifest.json"
printf 'bundle-db\n' > "$bundle/headscale/db.sqlite"
printf 'bundle-noise\n' > "$bundle/headscale/noise_private.key"
printf '{}\n' > "$bundle/state/enroll/config.json"
printf 'key\n' > "$bundle/state/enroll/headscale.apikey"
printf '0123456789abcdef0123456789abcdef\n' > "$bundle/state/headplane/cookie_secret"
printf 'COMPOSE_PROJECT_NAME=%s\nENROLL_UID=%s\nENROLL_GID=%s\n' "$proj" "$op_uid" "$op_gid" > "$bundle/state/dotenv"
printf '{}\n' > "$bundle/state/headscale/managed.json"
printf 'server_url: https://vpn.example.org\n' > "$bundle/state/headscale/config.yaml"
printf '{}\n' > "$bundle/state/headscale/policy.hujson"
printf 'server:\n  base_url: "http://127.0.0.1:3000"\n  cookie_secure: false\n' > "$bundle/state/headplane/config.yaml"
printf 'services: {}\n' > "$bundle/state/compose.yaml"
here="$other"
unset COMPOSE_PROJECT_LOCK
set +e
out="$(restore_deployment "$bundle" 0 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || die "markerless restore was accepted: $out"
grep -q 'no deploy-directory marker' <<<"$out" || die "markerless refusal missing: $out"
grep -q -- '--adopt-existing-volumes' <<<"$out" || die "flag not named: $out"
grep -q "$vol" <<<"$out" || die "volume not named: $out"
got="$(docker run --rm --network none -v "${vol}:/data:ro" "$alpine" sh -c 'cat /data/db.sqlite')"
[[ "$got" == "original-bytes" ]] || die "refused restore changed the database: $got"

echo "test: --adopt-existing-volumes proceeds and names the volumes"
set +e
out="$(restore_deployment "$bundle" 1 2>&1)"
ec=$?
set -e
grep -q 'will overwrite' <<<"$out" || die "adopt did not list volumes: $out"
grep -q "$vol" <<<"$out" || die "adopt did not name $vol: $out"
if grep -q 'no deploy-directory marker' <<<"$out"; then
  die "adopt still refused markerless volumes: $out"
fi
# The bundle uid matches this operator, so host install continues into
# container creation. The empty compose file then fails. That is past the gate.
grep -q 'creating stopped containers' <<<"$out" || die "adopt did not proceed into restore: $out"
got="$(docker run --rm --network none -v "${vol}:/data:ro" "$alpine" sh -c 'cat /data/db.sqlite')"
[[ "$got" == "original-bytes" ]] || die "adopt's failed install changed the database: $got"

echo "test: an unreadable marker is refused, with or without the flag"
docker run --rm --network none -v "${vol}:/data" "$alpine" \
  sh -c 'rm -rf /data/.idoris-deploy-dir && mkdir /data/.idoris-deploy-dir'
set +e
out="$(restore_deployment "$bundle" 0 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || die "unreadable marker was accepted: $out"
grep -q 'unreadable marker' <<<"$out" || die "unreadable refusal missing: $out"
if grep -q 'no deploy-directory marker' <<<"$out"; then
  die "unreadable marker was treated as absent: $out"
fi
set +e
out="$(restore_deployment "$bundle" 1 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || die "adopt accepted an unreadable marker: $out"
grep -q 'unreadable marker' <<<"$out" || die "adopt unreadable refusal missing: $out"
if grep -q 'will overwrite' <<<"$out"; then
  die "adopt printed overwrite for an unreadable marker: $out"
fi
got="$(docker run --rm --network none -v "${vol}:/data:ro" "$alpine" sh -c 'cat /data/db.sqlite')"
[[ "$got" == "original-bytes" ]] || die "unreadable-marker restore changed the database: $got"

# A swallowed docker cp plus a later success must not delete the snapshots.
# The shim plants the snapshot bytes on the way out, so a checksum that ran
# after the failed copy would match. Alpine's extract then fails. Rollback
# is incomplete only when the failed copy itself returns 1.
echo "test: a failed copy keeps snapshots even when the checksum would match"
r5o_rb="$tmp/r5o-rb"
mkdir -p "$r5o_rb/bin" "$r5o_rb/vol/headscale" "$r5o_rb/host"
printf 'original-bytes\n' > "$r5o_rb/vol/headscale/db.sqlite"
printf 'noise\n' > "$r5o_rb/vol/headscale/noise_private.key"
printf '1\n' > "$r5o_rb/vol/HAD"
: > "$r5o_rb/vol/volumes.before"
: > "$r5o_rb/vol/containers.before"
: > "$r5o_rb/vol/networks.before"
printf 'marker\n' > "$r5o_rb/host/marker"
printf 'headscale\n' > "$r5o_rb/snap"
cat > "$r5o_rb/bin/docker" <<'EOF'
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
if [[ "$1" == "compose" && "$*" == *" ps -aq headscale"* ]]; then
  printf '%s\n' 'cidhs'
  exit 0
fi
if [[ "$1" == "image" && "$2" == "inspect" ]]; then
  printf '%s\n' '65532:65532'
  exit 0
fi
if [[ "$1" == "inspect" ]]; then
  if [[ "$*" == *".Config.Image"* ]]; then
    printf '%s\n' 'headscale/headscale:v0.29.6'
    exit 0
  fi
  printf '%s %s\n' "/var/lib/headscale" "${R5O_HS_VOL:-hsvol}"
  exit 0
fi
if [[ "$1" == "cp" ]]; then
  src="${2:-}"
  dest="${3:-}"
  if [[ "$dest" == *:* && "$src" == *noise_private.key && "${R5O_FAIL_NOISE:-}" == "1" ]]; then
    exit 1
  fi
  if [[ "$src" == *:* && "$src" == */db.sqlite ]]; then
    cp "${R5O_DB_FILE:?}" "$dest"
    exit 0
  fi
  exit 0
fi
if [[ "$1" == "run" && "$*" == *"tar -C /data -xf"* && "${R5O_FAIL_ALPINE:-}" == "1" ]]; then
  exit 1
fi
if [[ "$1" == "run" && "$*" == *"tar -C /data -cf"* ]]; then
  payload="$(mktemp -d)"
  cp "${R5O_DB_FILE:?}" "$payload/db.sqlite"
  tar -C "$payload" -cf - db.sqlite
  rm -rf "$payload"
  exit 0
fi
exit 0
EOF
chmod 755 "$r5o_rb/bin/docker"
r5o_rollback_out() {
  local log="$1" dbfile="$2" fail_noise="$3" fail_alpine="$4"
  set +e
  # shellcheck disable=SC2031
  out="$(
    {
      export PATH="${r5o_rb}/bin:${PATH}"
      export DOCKER_LOG="$log"
      export COMPOSE_PROJECT_LOCK="$proj"
      export R5O_HS_VOL="${proj}_headscale-data"
      export R5O_DB_FILE="$dbfile"
      export R5O_FAIL_NOISE="$fail_noise"
      export R5O_FAIL_ALPINE="$fail_alpine"
      _restore_current="$proj"
      _restore_dest="$proj"
      _restore_prev_mode="published"
      _restore_host="$r5o_rb/host"
      _restore_vol="$r5o_rb/vol"
      _restore_snap="$r5o_rb/snap"
      _restore_ok=0
      _restore_phase=2
      _restore_on_exit
    } 2>&1
  )"
  set -e
  printf '%s\n' "$out"
}
: > "$r5o_rb/fail.log"
fail_out="$(r5o_rollback_out "$r5o_rb/fail.log" "$r5o_rb/vol/headscale/db.sqlite" 1 1)"
grep -q 'rollback incomplete' <<<"$fail_out" || die "failed copy reported success: $fail_out"
if grep -q 'rollback complete' <<<"$fail_out"; then
  die "failed copy still said rollback complete: $fail_out"
fi
grep -q 'noise_private.key' "$r5o_rb/fail.log" || die "noise copy was not attempted"
grep -q 'tar -C /data -xf' "$r5o_rb/fail.log" || die "alpine fallback did not run: $(cat "$r5o_rb/fail.log")"
[[ -f "$r5o_rb/host/marker" ]] || die "failed copy deleted the host snapshot"
[[ -d "$r5o_rb/vol" && -f "$r5o_rb/vol/headscale/db.sqlite" ]] || die "failed copy deleted the volume snapshot"
[[ -f "$r5o_rb/snap" ]] || die "failed copy deleted the service snapshot"

echo "test: matching commands with different database bytes stay incomplete"
printf 'nope\n' > "$r5o_rb/planted"
: > "$r5o_rb/sum.log"
sum_out="$(r5o_rollback_out "$r5o_rb/sum.log" "$r5o_rb/planted" 0 0)"
grep -q 'does not match snapshot' <<<"$sum_out" || die "checksum mismatch was ignored: $sum_out"
grep -q 'rollback incomplete' <<<"$sum_out" || die "checksum mismatch reported success: $sum_out"
if grep -q 'rollback complete' <<<"$sum_out"; then
  die "checksum mismatch still said rollback complete: $sum_out"
fi
[[ -f "$r5o_rb/host/marker" ]] || die "checksum mismatch deleted the host snapshot"
[[ -d "$r5o_rb/vol" && -f "$r5o_rb/vol/headscale/db.sqlite" ]] || die "checksum mismatch deleted the volume snapshot"
[[ -f "$r5o_rb/snap" ]] || die "checksum mismatch deleted the service snapshot"

echo "test_restore_volumes: ok"
