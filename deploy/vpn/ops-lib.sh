#!/usr/bin/env bash
# Helpers shared by bootstrap.sh and ctl.sh.
# The caller defines die() and sets `here` to the deploy/vpn directory.
# shellcheck shell=bash
# shellcheck disable=SC2154

admin_mode_file() {
  printf '%s/.admin-mode' "$here"
}

read_admin_mode() {
  local f mode
  f="$(admin_mode_file)"
  mode=""
  if [[ -f "$f" ]]; then
    mode="$(sed -n 's/^mode=//p' "$f" | head -n1 | tr -d '[:space:]')"
  fi
  case "$mode" in
    published|tailnet-admin) printf '%s' "$mode" ;;
    "") printf '%s' "published" ;;
    *) die "admin mode file $f has unknown mode '$mode'" ;;
  esac
}

write_admin_mode() {
  local mode="$1" tmp
  case "$mode" in
    published|tailnet-admin) ;;
    *) die "unknown admin mode '$mode'" ;;
  esac
  tmp="$(mktemp "$here/.admin-mode.XXXXXX")"
  printf 'mode=%s\n' "$mode" > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$(admin_mode_file)"
}

# Profile services are invisible to `docker compose ps` unless the profile is enabled.
_compose_ps_id() {
  local svc="$1"
  if [[ "$svc" == "vpn-sidecar" || "$svc" == "headplane-tailnet" ]]; then
    docker compose --profile tailnet-admin ps -aq "$svc" 2>/dev/null || true
  else
    docker compose ps -aq "$svc" 2>/dev/null || true
  fi
}

service_running() {
  local svc="$1" id
  if [[ "$svc" == "vpn-sidecar" || "$svc" == "headplane-tailnet" ]]; then
    id="$(docker compose --profile tailnet-admin ps --status running -q "$svc" 2>/dev/null || true)"
  else
    id="$(docker compose ps --status running -q "$svc" 2>/dev/null || true)"
  fi
  [[ -n "$id" ]]
}

# Stop whichever Headplane process is actually running. Never starts one.
stop_headplane_writers() {
  if service_running headplane; then
    docker compose stop headplane
  fi
  if service_running headplane-tailnet; then
    docker compose --profile tailnet-admin stop headplane-tailnet
  fi
}

# One writer. The mode file wins over a container that should not be up.
enforce_headplane_exclusion() {
  local mode="$1"
  if [[ "$mode" == "tailnet-admin" ]]; then
    if service_running headplane || [[ -n "$(_compose_ps_id headplane)" ]]; then
      docker compose stop headplane >/dev/null 2>&1 || true
    fi
  else
    if service_running vpn-sidecar || service_running headplane-tailnet \
      || [[ -n "$(_compose_ps_id headplane-tailnet)" ]]; then
      docker compose --profile tailnet-admin stop vpn-sidecar headplane-tailnet >/dev/null 2>&1 || true
    fi
  fi
}

# Start headscale+enroll and exactly one Headplane, matching the mode file.
# Tailnet mode starts the profile only when VPN_SERVER_ENROLL_TOKEN is set.
start_stack_for_mode() {
  local mode="$1"
  enforce_headplane_exclusion "$mode"
  if [[ "$mode" == "tailnet-admin" ]]; then
    docker compose up -d --wait --wait-timeout 180 headscale enroll
    if [[ -n "${VPN_SERVER_ENROLL_TOKEN:-}" ]]; then
      docker compose --profile tailnet-admin up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet
      echo "tailnet-admin profile is up. Published Headplane is stopped."
    else
      echo "admin mode is tailnet-admin. Published Headplane stays stopped."
      echo "export VPN_SERVER_ENROLL_TOKEN (the vpn-server enrollment token) and run: bash $here/ctl.sh up"
    fi
  else
    docker compose --profile tailnet-admin stop vpn-sidecar headplane-tailnet >/dev/null 2>&1 || true
    docker compose up -d --wait --wait-timeout 180
  fi
}

# Write one service name per line for every service that is running now.
snapshot_running() {
  local dest="$1" svc
  : > "$dest"
  for svc in headscale enroll headplane vpn-sidecar headplane-tailnet; do
    if service_running "$svc"; then
      printf '%s\n' "$svc" >> "$dest"
    fi
  done
}

snapshot_has() {
  local dest="$1" svc="$2"
  grep -qx "$svc" "$dest"
}

# Bring back the services in the snapshot, minus any Headplane that is not
# the selected mode. A snapshot that caught both writers restarts only one.
restore_running_services() {
  local snap="$1" mode="$2" svc
  local -a plain=() profile=()
  enforce_headplane_exclusion "$mode"
  while IFS= read -r svc; do
    [[ -n "$svc" ]] || continue
    case "$svc" in
      headplane)
        [[ "$mode" == "published" ]] && plain+=("$svc")
        ;;
      vpn-sidecar|headplane-tailnet)
        [[ "$mode" == "tailnet-admin" ]] && profile+=("$svc")
        ;;
      *)
        plain+=("$svc")
        ;;
    esac
  done < "$snap"
  if [[ ${#plain[@]} -gt 0 ]]; then
    docker compose start "${plain[@]}" >/dev/null
  fi
  if [[ ${#profile[@]} -gt 0 ]]; then
    docker compose --profile tailnet-admin start "${profile[@]}" >/dev/null
  fi
}

# Refuse a destination we did not create as mode 0700, a symlink destination
# or parent, and any symlink inside an existing directory. Ancestors such as
# /var (a symlink on macOS) are not the destination; refusing those would
# make every backup path illegal. A failed check returns before chmod, so a
# caller that disables set -e (an if-test) cannot turn a 0755 directory into
# 0700 and then accept it.
prepare_backup_dest() {
  local dest="$1" ec
  python3 - "$dest" <<'PY'
import os, sys
dest = os.path.abspath(sys.argv[1])
parent = os.path.dirname(dest)
if os.path.islink(parent):
    sys.exit("symlink in backup path: %s" % parent)
if not os.path.isdir(parent):
    sys.exit("backup parent is missing or a symlink: %s" % parent)
if os.path.lexists(dest):
    if os.path.islink(dest) or not os.path.isdir(dest):
        sys.exit("backup destination must be a real directory, not a file or symlink")
    mode = os.stat(dest).st_mode & 0o777
    if mode & 0o077:
        sys.exit("existing destination mode %o is not private (want 0700); refusing to chmod it" % mode)
    for dirpath, dirnames, filenames in os.walk(dest, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                sys.exit("symlink inside backup destination: %s" % path)
    if any(os.scandir(dest)):
        sys.exit("backup destination is not empty: %s" % dest)
PY
  ec=$?
  if [[ "$ec" -ne 0 ]]; then
    return "$ec"
  fi
  mkdir -p "$dest"
  chmod 700 "$dest"
  python3 - "$dest" <<'PY'
import os, sys
mode = os.stat(sys.argv[1]).st_mode & 0o777
if mode & 0o077:
    sys.exit("backup directory mode %o is not 0700 after mkdir" % mode)
if os.path.islink(sys.argv[1]):
    sys.exit("backup destination became a symlink")
PY
  ec=$?
  if [[ "$ec" -ne 0 ]]; then
    return "$ec"
  fi
}

require_regular() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "need a regular file for backup: $path"
}

copy_private() {
  local src="$1" dest="$2"
  require_regular "$src"
  mkdir -p "$(dirname "$dest")"
  chmod 700 "$(dirname "$dest")"
  cp -P "$src" "$dest"
  chmod 600 "$dest"
}

seal_tree() {
  local dest="$1"
  find "$dest" -type d -exec chmod 700 {} +
  find "$dest" -type f -exec chmod 600 {} +
}

restore_private() {
  local src="$1" dest="$2" parent
  [[ -f "$src" && ! -L "$src" ]] || die "backup is missing $src"
  if [[ -L "$dest" ]]; then
    die "refusing to restore through symlink $dest"
  fi
  parent="$(dirname "$dest")"
  if [[ -L "$parent" ]]; then
    die "refusing to restore through symlink $parent"
  fi
  python3 - "$here" "$dest" <<'PY'
import os, sys
root, dest = sys.argv[1:]
root = os.path.realpath(root)
parent = os.path.realpath(os.path.dirname(dest))
if parent != root and not parent.startswith(root + os.sep):
    sys.exit("restore path escapes %s: %s" % (root, dest))
PY
  mkdir -p "$parent"
  cp -P "$src" "$dest"
  chmod 600 "$dest"
}

# Named volume mounted at a container path. Bind mounts have an empty Name.
volume_name_for() {
  local cid="$1" dest="$2"
  docker inspect -f '{{range .Mounts}}{{println .Destination .Name}}{{end}}' "$cid" \
    | awk -v d="$dest" '$1 == d && $2 != "" { print $2; exit }'
}

# Image Config.User, as uid:gid. An empty user is root. "nonroot" is distroless 65532.
image_owner() {
  local cid="$1" spec
  spec="$(docker image inspect "$(docker inspect -f '{{.Config.Image}}' "$cid")" --format '{{.Config.User}}' 2>/dev/null || true)"
  python3 -c 'import sys
u = sys.argv[1].strip()
if u == "":
    print("0:0")
    raise SystemExit
if u == "nonroot":
    print("65532:65532")
    raise SystemExit
if ":" not in u:
    u = u + ":" + u
a, b = u.split(":", 1)
if a == "nonroot" or not a.isdigit():
    a = "65532"
if b == "nonroot" or not b.isdigit():
    b = "65532"
print("%s:%s" % (a, b))' "$spec"
}

# alpine has no login shell in the headscale image, so volume fixes run here.
# Multi-arch index digest. Keep the tag so the version stays readable.
ALPINE_VOLUME_IMAGE="${ALPINE_VOLUME_IMAGE:-alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63}"

wipe_headscale_wal() {
  local cid="$1" vol
  vol="$(volume_name_for "$cid" /var/lib/headscale)"
  [[ -n "$vol" ]] || die "could not find the headscale data volume"
  docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
    rm -f /data/db.sqlite-wal /data/db.sqlite-shm
}

# docker cp writes root-owned files. Headscale's image is non-root and will
# refuse to open them. Chown the volume to the image user while it is stopped.
chown_volume_to_image() {
  local cid="$1" dest="$2" vol owner
  vol="$(volume_name_for "$cid" "$dest")"
  [[ -n "$vol" ]] || die "no named volume mounted at $dest"
  owner="$(image_owner "$cid")"
  [[ "$owner" =~ ^[0-9]+:[0-9]+$ ]] || die "refusing odd image user $owner"
  docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
    chown -R "$owner" /data
}
