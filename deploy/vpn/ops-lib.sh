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

# Profile services are invisible to `compose ps` unless the profile is enabled.
_compose_ps_id() {
  local svc="$1"
  if [[ "$svc" == "vpn-sidecar" || "$svc" == "headplane-tailnet" ]]; then
    compose --profile tailnet-admin ps -aq "$svc" 2>/dev/null || true
  else
    compose ps -aq "$svc" 2>/dev/null || true
  fi
}

service_running() {
  local svc="$1" id
  if [[ "$svc" == "vpn-sidecar" || "$svc" == "headplane-tailnet" ]]; then
    id="$(compose --profile tailnet-admin ps --status running -q "$svc" 2>/dev/null || true)"
  else
    id="$(compose ps --status running -q "$svc" 2>/dev/null || true)"
  fi
  [[ -n "$id" ]]
}

# Stop whichever Headplane process is actually running. Never starts one.
stop_headplane_writers() {
  if service_running headplane; then
    compose stop headplane
  fi
  if service_running headplane-tailnet; then
    compose --profile tailnet-admin stop headplane-tailnet
  fi
}

# One writer. The mode file wins over a container that should not be up.
enforce_headplane_exclusion() {
  local mode="$1"
  if [[ "$mode" == "tailnet-admin" ]]; then
    if service_running headplane || [[ -n "$(_compose_ps_id headplane)" ]]; then
      compose stop headplane >/dev/null 2>&1 || true
    fi
  else
    if service_running vpn-sidecar || service_running headplane-tailnet \
      || [[ -n "$(_compose_ps_id headplane-tailnet)" ]]; then
      compose --profile tailnet-admin stop vpn-sidecar headplane-tailnet >/dev/null 2>&1 || true
    fi
  fi
}

# Start headscale+enroll and exactly one Headplane, matching the mode file.
# Tailnet mode starts the profile when there is a token or the sidecar
# volume already holds tailscaled.state.
start_stack_for_mode() {
  local mode="$1"
  enforce_headplane_exclusion "$mode"
  assert_compose_bindings "$mode"
  if [[ "$mode" == "tailnet-admin" ]]; then
    compose up -d --wait --wait-timeout 180 headscale enroll
    if [[ -n "${VPN_SERVER_ENROLL_TOKEN:-}" ]] || sidecar_has_identity; then
      compose --profile tailnet-admin up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet
      verify_published_bindings "$mode"
      echo "tailnet-admin profile is up. Published Headplane is stopped."
    else
      echo "admin mode is tailnet-admin. Published Headplane stays stopped."
      echo "export VPN_SERVER_ENROLL_TOKEN (the vpn-server enrollment token) and run: bash $here/ctl.sh up"
    fi
  else
    compose --profile tailnet-admin stop vpn-sidecar headplane-tailnet >/dev/null 2>&1 || true
    compose up -d --wait --wait-timeout 180 headscale enroll headplane
    verify_published_bindings "$mode"
  fi
  mark_deploy_dir
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
    compose start "${plain[@]}" >/dev/null
  fi
  if [[ ${#profile[@]} -gt 0 ]]; then
    compose --profile tailnet-admin start "${profile[@]}" >/dev/null
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
  ensure_managed_backup_parent "$dest" || return $?
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

# docker outside `compose`. An inherited COMPOSE_PROFILES must not select a
# profile on a later compose command, and it must not reach this process either.
_docker_host() {
  env -u COMPOSE_PROFILES -u COMPOSE_FILE -u COMPOSE_PATH_SEPARATOR docker "$@"
}

# Compose volume for this project, by label or by the conventional name.
# Empty output means the volume does not exist. A down stack keeps the volume.
_project_volume_name() {
  local short="$1" project labeled name
  project="${COMPOSE_PROJECT_LOCK:-}"
  if [[ -z "$project" ]]; then
    project="$(current_project_name)"
  fi
  labeled="$(_docker_host volume ls -q --filter "label=com.docker.compose.project=${project}" --filter "label=com.docker.compose.volume=${short}" 2>/dev/null | head -n1 || true)"
  if [[ -n "$labeled" ]]; then
    printf '%s' "$labeled"
    return 0
  fi
  name="${project}_${short}"
  if _docker_host volume inspect "$name" >/dev/null 2>&1; then
    printf '%s' "$name"
    return 0
  fi
  return 1
}

# The sidecar already has a node key when tailscaled.state is non-empty.
# ctl.sh up must not demand a new enrollment token in that case.
sidecar_has_identity() {
  local vol
  vol="$(_project_volume_name vpn-sidecar-state 2>/dev/null || true)"
  [[ -n "$vol" ]] || return 1
  _docker_host run --rm --network none -v "${vol}:/state:ro" "$ALPINE_VOLUME_IMAGE" \
    sh -c 'test -s /state/tailscaled.state'
}

# Compose 5.1 keeps the project label on a volume and drops the container
# (and its working_dir label) on `down`. The marker is the directory that
# created the volume. It is not a secret.
mark_deploy_dir() {
  local vol dir
  vol="$(_project_volume_name headscale-data 2>/dev/null || true)"
  [[ -n "$vol" ]] || return 0
  dir="$(cd "$here" && pwd -P)"
  # $1 is the container shell's argument, not this shell's.
  # shellcheck disable=SC2016
  _docker_host run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
    sh -c 'umask 022; printf %s "$1" > /data/.idoris-deploy-dir' _ "$dir"
}

# Read /data/.idoris-deploy-dir. Exit 0 and print the marker when the file
# was read. Exit 2 when the file is absent. Exit 1 when the read failed
# (docker error, symlink, or not a regular file). Callers must not turn
# exit 1 into an empty marker.
_volume_deploy_dir() {
  local vol="$1" out rc
  set +e
  out="$(_docker_host run --rm --network none -v "${vol}:/data:ro" "$ALPINE_VOLUME_IMAGE" \
    sh -c 'if [ ! -e /data/.idoris-deploy-dir ]; then exit 2; fi
           if [ -L /data/.idoris-deploy-dir ] || [ ! -f /data/.idoris-deploy-dir ]; then exit 1; fi
           cat /data/.idoris-deploy-dir' 2>/dev/null)"
  rc=$?
  set -e
  if [[ "$rc" -eq 2 ]]; then
    return 2
  fi
  if [[ "$rc" -ne 0 ]]; then
    return 1
  fi
  printf '%s' "$out"
  return 0
}

_safe_volume_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]]
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

# Return 1 on failure. Rollback calls this from `if !`, where set -e is off,
# and a die() there would skip the "rollback incomplete" message.
wipe_headscale_wal() {
  local cid="$1" vol
  vol="$(volume_name_for "$cid" /var/lib/headscale)"
  [[ -n "$vol" ]] || return 1
  docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
    rm -f /data/db.sqlite-wal /data/db.sqlite-shm || return 1
}

# docker cp writes root-owned files. Headscale's image is non-root and will
# refuse to open them. Chown the volume to the image user while it is stopped.
# Return 1 on failure (see wipe_headscale_wal).
chown_volume_to_image() {
  local cid="$1" dest="$2" vol owner
  vol="$(volume_name_for "$cid" "$dest")"
  [[ -n "$vol" ]] || return 1
  owner="$(image_owner "$cid")"
  [[ "$owner" =~ ^[0-9]+:[0-9]+$ ]] || return 1
  docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
    chown -R "$owner" /data || return 1
}

# Create stopped containers for this mode when the host has none.
# `up --no-start` does not start the other Headplane.
ensure_mode_containers() {
  local mode="$1"
  if [[ -z "$(_compose_ps_id headscale)" ]]; then
    echo "creating stopped containers for admin mode ${mode}..."
    if [[ "$mode" == "tailnet-admin" ]]; then
      compose up -d --no-start headscale enroll
      compose --profile tailnet-admin up -d --no-start vpn-sidecar headplane-tailnet
    else
      compose up -d --no-start headscale enroll headplane
    fi
  fi
  if [[ "$mode" == "tailnet-admin" ]]; then
    if [[ -z "$(_compose_ps_id headplane-tailnet)" ]]; then
      compose --profile tailnet-admin up -d --no-start vpn-sidecar headplane-tailnet
    fi
  elif [[ -z "$(_compose_ps_id headplane)" ]]; then
    compose up -d --no-start headplane
  fi
  if [[ -z "$(_compose_ps_id enroll)" ]]; then
    compose up -d --no-start enroll
  fi
}

# Manifest lists image tags, ids and digests only. The compose config JSON
# also contains env values; it is written to a 0600 temp file and deleted.
write_backup_manifest() {
  local dest="$1" mode="$2" version="$3" tmp ec project
  project="${COMPOSE_PROJECT_LOCK:-}"
  if [[ -z "$project" ]]; then
    project="$(current_project_name)"
  fi
  tmp="$(mktemp "$here/.running.XXXXXX")"
  chmod 600 "$tmp"
  ec=0
  compose --profile tailnet-admin config --format json > "$tmp" || ec=$?
  if [[ "$ec" -eq 0 ]]; then
    python3 - "$dest/manifest.json" "$mode" "$version" "$tmp" "$here" "$project" <<'PY' || ec=$?
import json, os, subprocess, sys
out_path, mode, version, cfg_path, here, project = sys.argv[1:]
cfg = json.load(open(cfg_path))
wanted = {
    "state/dotenv": os.path.join(here, ".env"),
    "state/enroll/config.json": os.path.join(here, "enroll", "config.json"),
    "state/enroll/headscale.apikey": os.path.join(here, "enroll", "headscale.apikey"),
    "state/headplane/cookie_secret": os.path.join(here, "headplane", "cookie_secret"),
    "state/headscale/managed.json": os.path.join(here, "headscale", "managed.json"),
    "state/headscale/config.yaml": os.path.join(here, "headscale", "config.yaml"),
    "state/headscale/policy.hujson": os.path.join(here, "headscale", "policy.hujson"),
    "state/headplane/config.yaml": os.path.join(here, "headplane", "config.yaml"),
    "state/compose.yaml": os.path.join(here, "compose.yaml"),
}
file_modes = {}
for rel, src in wanted.items():
    file_modes[rel] = format(os.stat(src).st_mode & 0o777, "o")
images = []
for name in sorted(cfg.get("services", {})):
    image = cfg["services"][name].get("image") or ""
    env = os.environ.copy()
    env["COMPOSE_PROJECT_NAME"] = project
    base = ["docker", "compose", "-p", project, "--project-directory", here]
    ps = subprocess.run(base + ["ps", "-aq", name], capture_output=True, text=True, env=env)
    cid = ""
    if ps.stdout.strip():
        cid = ps.stdout.strip().splitlines()[-1]
    if not cid and name in ("vpn-sidecar", "headplane-tailnet"):
        ps = subprocess.run(
            base + ["--profile", "tailnet-admin", "ps", "-aq", name],
            capture_output=True, text=True, env=env)
        if ps.stdout.strip():
            cid = ps.stdout.strip().splitlines()[-1]
    image_id = ""
    digests = []
    if cid:
        ins = subprocess.run(
            ["docker", "inspect", "-f", "{{.Image}}", cid],
            capture_output=True, text=True)
        image_id = ins.stdout.strip()
        if image_id:
            dig = subprocess.run(
                ["docker", "image", "inspect", "-f", "{{json .RepoDigests}}", image_id],
                capture_output=True, text=True)
            if dig.returncode == 0 and dig.stdout.strip() and dig.stdout.strip() != "null":
                digests = json.loads(dig.stdout)
    images.append({
        "service": name,
        "image": image,
        "image_id": image_id,
        "repo_digests": digests,
    })
doc = {
    "created_utc": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "admin_mode": mode,
    "compose_project": cfg.get("name") or os.environ.get("COMPOSE_PROJECT_NAME", ""),
    "headscale_version": version.strip(),
    "file_modes": file_modes,
    "images": images,
}
blob = json.dumps(doc, indent=2) + "\n"
# The manifest is built from image metadata only. Refuse to persist a secret
# if one ever leaks into an image name or version string.
for needle in ("idv1_", "hskey-", "ENROLL_TOKEN"):
    if needle in blob:
        sys.exit("manifest would contain %s; refusing to write it" % needle)
with open(out_path, "w") as fh:
    fh.write(blob)
os.chmod(out_path, 0o600)
PY
  fi
  rm -f "$tmp"
  [[ "$ec" -eq 0 ]] || die "could not write backup manifest"
}

# Non-secret files go back to the mode they had on the host (never a
# group/other-writable mode). Secrets stay 0600.
apply_restored_mode() {
  local manifest="$1" rel="$2" dest="$3"
  python3 - "$manifest" "$rel" "$dest" <<'PY'
import json, os, sys
manifest, rel, dest = sys.argv[1:]
secrets = {
    "state/dotenv",
    "state/enroll/config.json",
    "state/enroll/headscale.apikey",
    "state/headplane/cookie_secret",
    "state/headscale/managed.json",
}
mode = 0o600
if rel not in secrets:
    try:
        raw = json.load(open(manifest)).get("file_modes", {}).get(rel, "600")
        mode = int(raw, 8)
    except (OSError, ValueError, json.JSONDecodeError):
        mode = 0o600
    if mode & 0o022 or mode == 0:
        mode = 0o600
os.chmod(dest, mode)
PY
}

# Container id of the Headplane that owns the data volume for this mode.
headplane_writer_id() {
  local mode="$1" id
  if [[ "$mode" == "tailnet-admin" ]]; then
    id="$(_compose_ps_id headplane-tailnet)"
    [[ -n "$id" ]] || id="$(_compose_ps_id headplane)"
  else
    id="$(_compose_ps_id headplane)"
    [[ -n "$id" ]] || id="$(_compose_ps_id headplane-tailnet)"
  fi
  [[ -n "$id" ]] || die "no Headplane container to copy; start the stack once before backup or restore"
  printf '%s' "$id"
}

# 0600 .env update. Key is a shell identifier; the value is one line.
write_env_var() {
  local key="$1" value="$2" tmp
  [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]] || die "bad env key '$key'"
  [[ "$value" != *$'\n'* ]] || die "env value for $key must be one line"
  tmp="$(mktemp "$here/.env.XXXXXX")"
  { grep -v "^${key}=" "$here/.env" 2>/dev/null || true; printf '%s=%s\n' "$key" "$value"; } > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$here/.env"
}

# Shell export wins, then .env, then the compose.yaml default.
current_project_name() {
  local from_env
  if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
    printf '%s' "$COMPOSE_PROJECT_NAME"
    return
  fi
  from_env=""
  if [[ -f "$here/.env" ]]; then
    from_env="$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$here/.env" | head -n1 | tr -d "\"'" | tr -d '[:space:]')"
  fi
  if [[ -n "$from_env" ]]; then
    printf '%s' "$from_env"
    return
  fi
  printf '%s' "idoris-vpn"
}

# "office" -> idoris-vpn-office. A name that already starts with idoris-vpn is kept.
sanitize_instance_name() {
  local name
  name="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$name" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] || die "--instance must be a short lowercase label (got '$1')"
  case "$name" in
    idoris-vpn|idoris-vpn-*) ;;
    *) name="idoris-vpn-${name}" ;;
  esac
  printf '%s' "$name"
}

# Same project name from another directory shares volumes and container names.
reject_project_collision() {
  reject_project_named "$(current_project_name)"
}

reject_project_named() {
  local want="$1" mine json err
  [[ "$want" =~ ^[a-z0-9][a-z0-9_-]{0,50}$ ]] || die "compose project name '$want' is not a safe label"
  mine="$(cd "$here" && pwd)/compose.yaml"
  if ! json="$(docker compose ls --all --format json 2>/dev/null)"; then
    if ! json="$(docker compose ls --format json)"; then
      die "could not list compose projects"
    fi
  fi
  if ! err="$(python3 -c '
import json, os, sys
want, mine, raw = sys.argv[1], sys.argv[2], sys.argv[3]
raw = raw.strip()
if not raw or raw == "null":
    raise SystemExit(0)
try:
    data = json.loads(raw)
except ValueError:
    data = [json.loads(line) for line in raw.splitlines() if line.strip()]
if isinstance(data, dict):
    data = [data]
mine = os.path.realpath(mine)
for item in data:
    if (item.get("Name") or "") != want:
        continue
    files = item.get("ConfigFiles") or ""
    paths = []
    for part in files.split(","):
        part = part.strip()
        if not part:
            continue
        if not os.path.isabs(part):
            part = os.path.join(os.getcwd(), part)
        paths.append(os.path.realpath(part))
    if mine not in paths:
        sys.stderr.write(
            "compose project %s is already used by %s; pass --instance NAME or set COMPOSE_PROJECT_NAME\n"
            % (want, files or "another directory"))
        raise SystemExit(1)
' "$want" "$mine" "$json" 2>&1)"; then
    die "${err:-compose project ${want} collides with another directory}"
  fi
  reject_project_volumes "$want"
}

# Volumes survive `compose down`. A working_dir label, when the volume has
# one, or a readable deploy-dir marker must be this directory. No label and
# no marker is not proof of another directory (`up` may adopt that volume).
# A marker that cannot be read is a refusal, not an empty marker.
# Restore uses require_restore_volume_ownership, which demands positive
# evidence before it overwrites anything.
reject_project_volumes() {
  local want="$1" ours names name short labels marker marker_rc err collision=""
  ours="$(cd "$here" && pwd -P)"
  names="$(mktemp "$here/.running.XXXXXX")"
  chmod 600 "$names"
  if ! docker volume ls -q --filter "label=com.docker.compose.project=${want}" > "$names"; then
    rm -f "$names"
    die "could not list volumes for ${want}"
  fi
  for short in headscale-data headscale-run headplane-data vpn-sidecar-state; do
    name="${want}_${short}"
    if _safe_volume_name "$name" && docker volume inspect "$name" >/dev/null 2>&1; then
      printf '%s\n' "$name" >> "$names"
    fi
  done
  sort -u -o "$names" "$names"
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    _safe_volume_name "$name" || continue
    labels="$(docker volume inspect -f '{{json .Labels}}' "$name" 2>/dev/null || true)"
    if ! err="$(python3 -c '
import json, os, sys
ours, raw, name, want = sys.argv[1:]
ours = os.path.realpath(ours)
text = (raw or "").strip()
if text in ("", "null"):
    raise SystemExit(0)
try:
    labels = json.loads(text)
except ValueError:
    raise SystemExit(0)
if not isinstance(labels, dict):
    raise SystemExit(0)

def foreign(path):
    sys.stderr.write(
        "compose project %s has volume %s from %s; pass --instance NAME or set COMPOSE_PROJECT_NAME\n"
        % (want, name, path))
    raise SystemExit(1)

wd = labels.get("com.docker.compose.project.working_dir") or ""
cf = labels.get("com.docker.compose.project.config_files") or ""
if isinstance(wd, str) and wd:
    try:
        same = os.path.realpath(wd) == ours
    except OSError:
        same = False
    if not same:
        foreign(wd)
if isinstance(cf, str) and cf:
    ours_file = os.path.realpath(os.path.join(ours, "compose.yaml"))
    matched = False
    for part in cf.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if os.path.realpath(part) == ours_file:
                matched = True
                break
        except OSError:
            continue
    if not matched:
        foreign(cf)
' "$ours" "$labels" "$name" "$want" 2>&1)"; then
      collision="${err:-compose project ${want} has volume ${name} from another directory}"
      break
    fi
    if [[ "$name" == *_headscale-data || "$labels" == *'"com.docker.compose.volume":"headscale-data"'* || "$labels" == *'"com.docker.compose.volume": "headscale-data"'* ]]; then
      set +e
      marker="$(_volume_deploy_dir "$name")"
      marker_rc=$?
      set -e
      marker="${marker//$'\r'/}"
      marker="${marker//$'\n'/}"
      if [[ "$marker_rc" -eq 1 ]]; then
        collision="could not read the deploy-directory marker on ${name}; refusing to treat an unreadable marker as empty"
        break
      fi
      if [[ "$marker_rc" -eq 0 && -n "$marker" ]]; then
        if ! err="$(python3 -c '
import os, sys
ours, marker, name, want = sys.argv[1:]
if os.path.realpath(marker) == os.path.realpath(ours):
    raise SystemExit(0)
sys.stderr.write(
    "compose project %s has volume %s from %s; pass --instance NAME or set COMPOSE_PROJECT_NAME\n"
    % (want, name, marker))
raise SystemExit(1)
' "$ours" "$marker" "$name" "$want" 2>&1)"; then
          collision="${err:-compose project ${want} has volume ${name} from another directory}"
          break
        fi
      fi
    fi
  done < "$names"
  rm -f "$names"
  [[ -z "$collision" ]] || die "$collision"
}

# Names of this project's data volumes, one per line. Empty when none exist.
_project_data_volume_names() {
  local project="$1" short name listed
  listed="$(mktemp "$here/.running.XXXXXX")"
  for short in headscale-data headscale-run headplane-data vpn-sidecar-state; do
    name="${project}_${short}"
    if _safe_volume_name "$name" && _docker_host volume inspect "$name" >/dev/null 2>&1; then
      printf '%s\n' "$name" >> "$listed"
    fi
  done
  if ! _docker_host volume ls -q --filter "label=com.docker.compose.project=${project}" >> "$listed"; then
    rm -f "$listed"
    return 1
  fi
  sort -u -o "$listed" "$listed"
  # Drop blanks. volume ls prints nothing when the project has no labeled volumes.
  grep -v '^$' "$listed" || true
  rm -f "$listed"
}

# Restore overwrites existing volumes only with positive ownership evidence:
# the headscale-data marker is this checkout, or there are no volumes, or
# the operator passed --adopt-existing-volumes. A foreign marker stays a
# refusal. An unreadable marker stays a refusal and is never an empty one.
# adopt is 1 or 0. The adopt path prints the volumes and does not prompt.
require_restore_volume_ownership() {
  local project="$1" adopt="$2" ours data name marker marker_rc listed vols
  ours="$(cd "$here" && pwd -P)"
  vols="$(mktemp "$here/.running.XXXXXX")"
  if ! _project_data_volume_names "$project" > "$vols"; then
    rm -f "$vols"
    die "could not list volumes for ${project}"
  fi
  if [[ ! -s "$vols" ]]; then
    rm -f "$vols"
    return 0
  fi
  data=""
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if [[ "$name" == *_headscale-data ]]; then
      data="$name"
    fi
  done < "$vols"
  if [[ -z "$data" ]]; then
    data="$(_docker_host volume ls -q --filter "label=com.docker.compose.project=${project}" --filter "label=com.docker.compose.volume=headscale-data" 2>/dev/null | head -n1 || true)"
  fi
  if [[ -n "$data" ]]; then
    set +e
    marker="$(_volume_deploy_dir "$data")"
    marker_rc=$?
    set -e
    marker="${marker//$'\r'/}"
    marker="${marker//$'\n'/}"
    if [[ "$marker_rc" -eq 1 ]]; then
      rm -f "$vols"
      die "could not read the deploy-directory marker on ${data}; refusing to treat an unreadable marker as empty"
    fi
    if [[ "$marker_rc" -eq 0 && -n "$marker" ]]; then
      if python3 -c '
import os, sys
ours, marker = sys.argv[1:]
raise SystemExit(0 if os.path.realpath(marker) == os.path.realpath(ours) else 1)
' "$ours" "$marker"; then
        rm -f "$vols"
        return 0
      fi
      rm -f "$vols"
      die "compose project ${project} has volume ${data} from ${marker}; pass --instance NAME or set COMPOSE_PROJECT_NAME"
    fi
  fi
  listed="$(tr '\n' ' ' < "$vols" | sed 's/ *$//')"
  rm -f "$vols"
  if [[ "$adopt" != "1" ]]; then
    die "refusing to overwrite existing volumes with no deploy-directory marker: ${listed}. Pass --adopt-existing-volumes to overwrite them"
  fi
  echo "restore: --adopt-existing-volumes will overwrite: ${listed}" >&2
}

# One knob for Headplane's origin and cookie. tunnel, lan and proxy publish
# the headplane service. tailnet does not: the profile serves it on the
# tailnet address only. Rewrites base_url and cookie_secure in place.
apply_headplane_access() {
  local mode="$1" port bind base secure host_url server_host admin_host allow
  case "$mode" in
    tunnel|lan|tailnet|proxy) ;;
    *) die "HEADPLANE_ACCESS must be tunnel, lan, tailnet or proxy (got '$mode')" ;;
  esac
  port="${HEADPLANE_PORT:-}"
  if [[ -z "$port" && -f "$here/.env" ]]; then
    port="$(sed -n 's/^HEADPLANE_PORT=//p' "$here/.env" | head -n1 | tr -d '[:space:]')"
  fi
  port="${port:-3000}"
  [[ "$port" =~ ^[0-9]+$ ]] || die "HEADPLANE_PORT must be numeric"
  bind="${HEADPLANE_BIND:-}"
  if [[ -z "$bind" && -f "$here/.env" ]]; then
    bind="$(sed -n 's/^HEADPLANE_BIND=//p' "$here/.env" | head -n1 | tr -d "\"'" | tr -d '[:space:]')"
  fi
  bind="${bind:-127.0.0.1}"
  case "$mode" in
    tunnel)
      bind="127.0.0.1"
      base="http://127.0.0.1:${port}"
      secure=false
      ;;
    lan)
      [[ "$bind" != "127.0.0.1" ]] || die "HEADPLANE_ACCESS=lan needs HEADPLANE_BIND set to a LAN address (not 127.0.0.1)"
      host_url="${HEADPLANE_LAN_HOST:-}"
      if [[ -z "$host_url" && -f "$here/.env" ]]; then
        host_url="$(sed -n 's/^HEADPLANE_LAN_HOST=//p' "$here/.env" | head -n1 | tr -d "\"'" | tr -d '[:space:]')"
      fi
      host_url="${host_url:-$bind}"
      base="http://${host_url}:${port}"
      secure=false
      echo "WARNING: Headplane will speak plain HTTP on ${bind}." >&2
      echo "WARNING: the session cookie is not marked Secure. Anyone on that LAN can steal it." >&2
      echo "WARNING: prefer HEADPLANE_ACCESS=tunnel (SSH) or tailnet." >&2
      ;;
    tailnet)
      bind="127.0.0.1"
      base="http://vpn-server.idoris.internal:3000"
      secure=false
      ;;
    proxy)
      base="${HEADPLANE_BASE_URL:-}"
      if [[ -z "$base" && -f "$here/.env" ]]; then
        base="$(sed -n 's/^HEADPLANE_BASE_URL=//p' "$here/.env" | head -n1 | tr -d "\"'" | tr -d '[:space:]')"
      fi
      [[ "$base" == https://* ]] || die "HEADPLANE_ACCESS=proxy needs HEADPLANE_BASE_URL=https://admin.example.org (a different host from server_url)"
      server_host="$(sed -n 's/^server_url:[[:space:]]*//p' "$here/headscale/config.yaml" | sed 's/[[:space:]]*#.*$//' | tr -d "\"'" | head -n1)"
      admin_host="$(python3 -c 'import sys; from urllib.parse import urlparse; print(urlparse(sys.argv[1]).hostname or "")' "$base")"
      server_host="$(python3 -c 'import sys; from urllib.parse import urlparse; print(urlparse(sys.argv[1]).hostname or "")' "$server_host")"
      allow="${HEADPLANE_ALLOW_PUBLIC_ADMIN:-}"
      if [[ -z "$allow" && -f "$here/.env" ]]; then
        allow="$(sed -n 's/^HEADPLANE_ALLOW_PUBLIC_ADMIN=//p' "$here/.env" | head -n1 | tr -d '[:space:]')"
      fi
      if [[ -n "$admin_host" && "$admin_host" == "$server_host" && "$allow" != "1" ]]; then
        die "HEADPLANE_BASE_URL uses the public VPN hostname ($server_host). /admin stays off that name unless HEADPLANE_ALLOW_PUBLIC_ADMIN=1"
      fi
      if [[ "$allow" == "1" ]]; then
        echo "WARNING: HEADPLANE_ALLOW_PUBLIC_ADMIN=1 puts /admin on the public VPN hostname." >&2
        echo "WARNING: the default is a separate admin hostname that is not published as server_url." >&2
      fi
      bind="127.0.0.1"
      secure=true
      ;;
  esac
  python3 - "$here/headplane/config.yaml" "$base" "$secure" <<'PY'
import sys
path, base, secure = sys.argv[1:]
lines = open(path).read().splitlines(keepends=True)
saw_base = saw_cookie = False
out = []
for line in lines:
    stripped = line.lstrip()
    if stripped.startswith("base_url:"):
        out.append('  base_url: "%s"\n' % base)
        saw_base = True
        continue
    if stripped.startswith("cookie_secure:"):
        out.append("  cookie_secure: %s\n" % secure)
        saw_cookie = True
        continue
    out.append(line)
if not saw_base or not saw_cookie:
    sys.exit("headplane config is missing base_url or cookie_secure")
open(path, "w").writelines(out)
PY
  write_env_var HEADPLANE_ACCESS "$mode"
  write_env_var HEADPLANE_BIND "$bind"
  write_env_var HEADPLANE_PORT "$port"
  if [[ "$mode" == "lan" ]]; then
    write_env_var HEADPLANE_LAN_HOST "$host_url"
  fi
  if [[ "$mode" == "proxy" ]]; then
    write_env_var HEADPLANE_BASE_URL "$base"
  fi
  if [[ "$mode" == "tailnet" ]]; then
    write_admin_mode tailnet-admin
  else
    write_admin_mode published
  fi
  echo "Headplane access: $mode base_url=$base cookie_secure=$secure bind=$bind"
}

# Persist the project name, then refuse a name some other directory already uses.
assign_instance() {
  local requested="${1:-}" existing name
  existing=""
  if [[ -f "$here/.env" ]]; then
    existing="$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$here/.env" | head -n1 | tr -d "\"'" | tr -d '[:space:]')"
  fi
  if [[ -n "$requested" ]]; then
    name="$(sanitize_instance_name "$requested")"
    if [[ -n "$existing" && "$existing" != "$name" ]]; then
      die "COMPOSE_PROJECT_NAME is already $existing; refusing to switch to $name"
    fi
  elif [[ -n "$existing" ]]; then
    name="$existing"
  elif [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
    name="$(sanitize_instance_name "$COMPOSE_PROJECT_NAME")"
  else
    name="idoris-vpn"
  fi
  if [[ -n "${COMPOSE_PROJECT_NAME:-}" && "$COMPOSE_PROJECT_NAME" != "$name" ]]; then
    die "COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME does not match this instance ($name)"
  fi
  write_env_var COMPOSE_PROJECT_NAME "$name"
  export COMPOSE_PROJECT_NAME="$name"
  reject_project_collision
}

# Shell exports beat .env for the keys listed below: every compose invocation
# re-applies those keys from this directory's .env (or unsets them) so a stale
# HEADPLANE_BIND cannot publish a port the mode file just turned off.
# COMPOSE_PROFILES, COMPOSE_FILE and COMPOSE_PATH_SEPARATOR are always
# removed. A profile has to be requested with --profile, or an inherited
# COMPOSE_PROFILES=tailnet-admin starts the second Headplane. COMPOSE_PROJECT_NAME
# is set to this deployment. VPN_SERVER_ENROLL_TOKEN is a process credential
# and is left alone.
_COMPOSE_FILE_KEYS="HEADPLANE_BIND HEADPLANE_PORT HEADSCALE_PORT ENROLL_PORT DERP_STUN_PORT ENROLL_UID ENROLL_GID HEADPLANE_ACCESS HEADPLANE_LAN_HOST HEADPLANE_BASE_URL HEADPLANE_ALLOW_PUBLIC_ADMIN ENROLL_PUBLIC_URL ENROLL_IMAGE IDORIS_VPN_VERSION VPN_SERVER_LOGIN_SERVER"

dotenv_value() {
  local key="$1" line
  [[ -f "$here/.env" && ! -L "$here/.env" ]] || return 1
  line="$(grep -E "^${key}=" "$here/.env" 2>/dev/null | head -n1 || true)"
  [[ -n "$line" ]] || return 1
  line="${line#"${key}="}"
  if [[ ${#line} -ge 2 && ( "$line" == \"*\" || "$line" == \'*\' ) ]]; then
    line="${line:1:${#line}-2}"
  fi
  printf '%s' "$line"
}

compose() {
  local project key val
  if [[ -n "${COMPOSE_PROJECT_LOCK:-}" ]]; then
    project="$COMPOSE_PROJECT_LOCK"
  else
    project="$(current_project_name)"
  fi
  [[ "$project" =~ ^[a-z0-9][a-z0-9_-]{0,50}$ ]] || die "compose project name '$project' is not a safe label"
  local -a unset_args=() set_args=()
  set_args+=("COMPOSE_PROJECT_NAME=${project}")
  # Always. These are not deployment settings, and a shell export must not
  # select a second compose file or turn the tailnet-admin profile on.
  unset_args+=("-u" "COMPOSE_PROFILES" "-u" "COMPOSE_FILE" "-u" "COMPOSE_PATH_SEPARATOR")
  for key in $_COMPOSE_FILE_KEYS; do
    if val="$(dotenv_value "$key")"; then
      set_args+=("${key}=${val}")
    else
      unset_args+=("-u" "$key")
    fi
  done
  if [[ ${#unset_args[@]} -gt 0 ]]; then
    env "${unset_args[@]}" "${set_args[@]}" docker compose -p "$project" --project-directory "$here" "$@"
  else
    env "${set_args[@]}" docker compose -p "$project" --project-directory "$here" "$@"
  fi
}

# Create only $here/backups. A missing parent anywhere else is still refused,
# and a pre-existing loose or symlinked directory is not chmodded into acceptance.
ensure_managed_backup_parent() {
  python3 - "$1" "$here" <<'PY'
import os, sys
dest, here = sys.argv[1:]
parent = os.path.dirname(os.path.abspath(dest))
managed = os.path.join(os.path.abspath(here), "backups")
if parent != managed:
    raise SystemExit(0)
if os.path.islink(managed):
    sys.exit("symlink in backup path: %s" % managed)
if os.path.lexists(managed):
    if not os.path.isdir(managed):
        sys.exit("backup parent is missing or a symlink: %s" % managed)
    mode = os.stat(managed).st_mode & 0o777
    if mode & 0o077:
        sys.exit("backup parent mode %o is not private (want 0700); refusing to chmod it" % mode)
else:
    os.mkdir(managed, 0o700)
mode = os.stat(managed).st_mode & 0o777
if mode & 0o077 or os.path.islink(managed):
    sys.exit("backup parent mode %o is not 0700 after mkdir" % mode)
PY
}

# --headplane-access tailnet and --tailnet-admin are one decision. Call this
# before policy or enrollment entries are rendered.
normalize_admin_choice() {
  local flag="$1" access="$2" from_env
  case "$access" in
    ""|tunnel|lan|tailnet|proxy) ;;
    *) die "--headplane-access must be tunnel, lan, tailnet or proxy" ;;
  esac
  if [[ "$access" == "tailnet" ]]; then
    flag=1
  fi
  if [[ "$flag" == "1" && -n "$access" && "$access" != "tailnet" ]]; then
    die "--tailnet-admin cannot be combined with --headplane-access $access"
  fi
  if [[ "$flag" == "1" && -z "$access" ]]; then
    access="tailnet"
  fi
  if [[ -z "$access" && -f "$here/.env" && ! -L "$here/.env" ]]; then
    if from_env="$(dotenv_value HEADPLANE_ACCESS)"; then
      access="$from_env"
    fi
  fi
  case "$access" in
    ""|tunnel|lan|tailnet|proxy) ;;
    *) die "HEADPLANE_ACCESS in .env must be tunnel, lan, tailnet or proxy" ;;
  esac
  if [[ "$access" == "tailnet" ]]; then
    flag=1
  fi
  if [[ -z "$access" ]]; then
    access="tunnel"
  fi
  # Callers (bootstrap.sh) read these after the function returns.
  # shellcheck disable=SC2034
  tailnet_admin="$flag"
  # shellcheck disable=SC2034
  headplane_access="$access"
}

# select_enroll_runtime prints "uid gid" on stdout. A non-root operator keeps
# their own ids. Root is rewritten to the image USER 65532. prefix is the
# program name on the stderr notice.
select_enroll_runtime() {
  local prefix="${1:-enroll}" uid gid
  uid="$(id -u)"
  gid="$(id -g)"
  if [[ "$uid" == 0 ]]; then
    echo "${prefix}: refusing to run enroll as root; using uid 65532 (the image USER)" >&2
    uid=65532
    gid=65532
  fi
  printf '%s %s\n' "$uid" "$gid"
}

# listing_fixture_owner prints uid:gid for a read-only credential fixture.
# The owner stays different from the enrollment runtime uid. Root chowns the
# file and its parent directory. umask 077 leaves that directory 0700, and
# the selected uid has to be able to traverse it. Anyone else prints the
# owner the file already has.
listing_fixture_owner() {
  local path="$1" runtime_uid="$2" owner parent
  if [[ "$runtime_uid" == 65534 ]]; then
    owner=65531
  else
    owner=65534
  fi
  if [[ "$(id -u)" == 0 ]]; then
    parent="$(dirname "$path")"
    chown "${owner}:${owner}" "$parent" "$path"
    printf '%s:%s\n' "$owner" "$owner"
    return 0
  fi
  python3 - "$path" <<'PY'
import os, sys
st = os.stat(sys.argv[1])
print("%d:%d" % (st.st_uid, st.st_gid))
PY
}

# provision_enroll_tree gives the enrollment directory to the runtime ids.
# Root sets directories to 0700 and files to 0600. A non-root caller already
# owns the files and returns without changing them. Pass the enroll directory
# only: headplane/cookie_secret belongs to the Headplane image user.
provision_enroll_tree() {
  local uid="$1" gid="$2" tree="$3"
  [[ "$(id -u)" == 0 ]] || return 0
  [[ "$uid" =~ ^[1-9][0-9]{0,9}$ && "$gid" =~ ^[1-9][0-9]{0,9}$ ]] || die "ENROLL_UID and ENROLL_GID must be non-zero numeric ids"
  chown -R "${uid}:${gid}" "$tree"
  find "$tree" -type d -exec chmod 700 {} +
  find "$tree" -type f -exec chmod 600 {} +
}

# Same ownership bootstrap uses, but the uid comes from the deployment's
# ENROLL_UID/GID. Root may chown. Anyone else can only chmod when the ids
# already match; a different id has to be repaired by root.
chown_enroll_runtime() {
  local uid="$1" gid="$2" myuid
  [[ "$uid" =~ ^[1-9][0-9]{0,9}$ && "$gid" =~ ^[1-9][0-9]{0,9}$ ]] || die "ENROLL_UID and ENROLL_GID must be non-zero numeric ids"
  myuid="$(id -u)"
  if [[ "$myuid" != "0" && ( "$myuid" != "$uid" || "$(id -g)" != "$gid" ) ]]; then
    die "enrollment files must be owned by ${uid}:${gid}; re-run restore as root"
  fi
  python3 - "$here/enroll" "$uid" "$gid" "$myuid" <<'PY'
import os, sys
root, uid_s, gid_s, myuid_s = sys.argv[1:]
uid, gid, myuid = int(uid_s), int(gid_s), int(myuid_s)
if os.path.islink(root) or not os.path.isdir(root):
    sys.exit("enroll directory is missing or a symlink")

def apply(path, mode):
    if os.path.islink(path):
        sys.exit("symlink in enroll tree: %s" % path)
    if myuid == 0:
        os.chown(path, uid, gid)
    os.chmod(path, mode)

apply(root, 0o700)
for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
    for name in dirnames:
        path = os.path.join(dirpath, name)
        if not os.path.isdir(path) or os.path.islink(path):
            sys.exit("special file in enroll tree: %s" % path)
        apply(path, 0o700)
    for name in filenames:
        path = os.path.join(dirpath, name)
        if not os.path.isfile(path) or os.path.islink(path):
            sys.exit("special file in enroll tree: %s" % path)
        apply(path, 0o600)
PY
}

offhost_cron_line() {
  local script="$1" outdir="$2"
  printf '15 3 * * * umask 077; AGE_RECIPIENT=%q OFFHOST_DIR=%q bash %q\n' \
    "AGE_RECIPIENT" "$outdir" "$script"
}

copy_sidecar_state() {
  local dest="$1" sid vol rc
  sid="$(_compose_ps_id vpn-sidecar)"
  if [[ -z "$sid" ]]; then
    echo "backup: no vpn-sidecar container; sidecar state omitted" >&2
    return 0
  fi
  vol="$(volume_name_for "$sid" /var/lib/tailscale)"
  if [[ -z "$vol" ]]; then
    echo "backup: sidecar has no state volume; omitted" >&2
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  chmod 700 "$(dirname "$dest")"
  set +e
  docker run --rm --user 0 --network none -v "${vol}:/data:ro" "$ALPINE_VOLUME_IMAGE" \
    sh -c 'cd /data && find . -type f ! -name "*.sock" > /tmp/list && if grep -q "tailscaled.state" /tmp/list; then tar -cf - -T /tmp/list; exit 0; fi; exit 42' > "$dest"
  rc=$?
  set -e
  if [[ "$rc" -eq 42 ]]; then
    rm -f "$dest"
    echo "backup: sidecar volume has no tailscaled.state; omitted" >&2
    return 0
  fi
  if [[ "$rc" -ne 0 || ! -s "$dest" ]]; then
    rm -f "$dest"
    die "backup: could not read sidecar state"
  fi
  chmod 600 "$dest"
}

extract_sidecar_tar() {
  local tarpath="$1" sid vol
  sid="$(_compose_ps_id vpn-sidecar)"
  [[ -n "$sid" ]] || return 1
  vol="$(volume_name_for "$sid" /var/lib/tailscale)"
  [[ -n "$vol" ]] || return 1
  docker run --rm --user 0 --network none -v "${vol}:/data" -i "$ALPINE_VOLUME_IMAGE" \
    tar -xf - -C /data < "$tarpath" || return 1
  chown_volume_to_image "$sid" /var/lib/tailscale || return 1
}

assert_compose_bindings() {
  local mode="$1" tmp bind port
  bind="$(dotenv_value HEADPLANE_BIND || true)"
  port="$(dotenv_value HEADPLANE_PORT || true)"
  bind="${bind:-127.0.0.1}"
  port="${port:-3000}"
  tmp="$(mktemp "$here/.running.XXXXXX")"
  chmod 600 "$tmp"
  if [[ "$mode" == "tailnet-admin" ]]; then
    compose --profile tailnet-admin config --format json > "$tmp"
  else
    compose config --format json > "$tmp"
  fi
  local rc=0
  set +e
  python3 - "$tmp" "$mode" "$bind" "$port" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
mode, bind, port = sys.argv[2:]
services = cfg.get("services") or {}

def ports(name):
    return (services.get(name) or {}).get("ports") or []

def text(value):
    return "" if value is None else str(value)

if mode == "tailnet-admin":
    for name in ("headplane-tailnet", "vpn-sidecar"):
        if ports(name):
            sys.exit("%s must not publish a host port" % name)
else:
    found = False
    for item in ports("headplane"):
        if text(item.get("target")) == "3000" and text(item.get("published")) == port and text(item.get("host_ip")) == bind:
            found = True
    if not found:
        sys.exit("rendered headplane port is not %s:%s -> 3000" % (bind, port))
PY
  rc=$?
  set -e
  rm -f "$tmp"
  [[ "$rc" -eq 0 ]] || die "compose config does not match the selected Headplane binding"
}

verify_published_bindings() {
  local mode="$1" bind port out id spec
  if [[ "$mode" == "tailnet-admin" ]]; then
    if service_running headplane; then
      die "published Headplane is running in tailnet-admin mode"
    fi
    if service_running headplane-tailnet; then
      out="$(compose --profile tailnet-admin port headplane-tailnet 3000 2>/dev/null || true)"
      [[ -z "${out//[[:space:]]/}" ]] || die "headplane-tailnet published a host port ($out)"
    fi
    if service_running vpn-sidecar; then
      out="$(compose --profile tailnet-admin port vpn-sidecar 41641 2>/dev/null || true)"
      [[ -z "${out//[[:space:]]/}" ]] || die "vpn-sidecar published a host port ($out)"
    fi
    return 0
  fi
  if service_running headplane-tailnet; then
    die "headplane-tailnet is running in published mode"
  fi
  if ! service_running headplane; then
    return 0
  fi
  bind="$(dotenv_value HEADPLANE_BIND || true)"
  port="$(dotenv_value HEADPLANE_PORT || true)"
  bind="${bind:-127.0.0.1}"
  port="${port:-3000}"
  out="$(compose port headplane 3000 | tr -d '\r' | head -n1)"
  [[ "$out" == "${bind}:${port}" ]] || die "headplane is published on ${out}, want ${bind}:${port}"
  id="$(_compose_ps_id headplane)"
  spec="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$id")"
  python3 -c '
import json, sys
bind, port, raw = sys.argv[1:]
data = json.loads(raw)
entries = data.get("3000/tcp") or []
if not entries:
    sys.exit("headplane has no 3000/tcp binding")
host = entries[0].get("HostIp") or ""
host_port = entries[0].get("HostPort") or ""
if host != bind or host_port != port:
    sys.exit("headplane binding %s:%s, want %s:%s" % (host, host_port, bind, port))
' "$bind" "$port" "$spec"
}

stop_db_writers() {
  local svc rc
  for svc in headplane-tailnet vpn-sidecar headplane headscale enroll; do
    if service_running "$svc" || [[ -n "$(_compose_ps_id "$svc")" ]]; then
      set +e
      if [[ "$svc" == "vpn-sidecar" || "$svc" == "headplane-tailnet" ]]; then
        compose --profile tailnet-admin stop "$svc"
      else
        compose stop "$svc"
      fi
      rc=$?
      set -e
      if [[ "$rc" -ne 0 ]]; then
        echo "restore: stop $svc failed" >&2
        return 1
      fi
      if service_running "$svc"; then
        echo "restore: $svc is still running after stop" >&2
        return 1
      fi
    fi
  done
  return 0
}

_restore_cleanup_temp() {
  if [[ -n "${_restore_snap:-}" ]]; then
    rm -f "$_restore_snap"
  fi
  if [[ -n "${_restore_host:-}" ]]; then
    rm -rf "$_restore_host"
  fi
  if [[ -n "${_restore_vol:-}" ]]; then
    rm -rf "$_restore_vol"
  fi
  _restore_snap=""
  _restore_host=""
  _restore_vol=""
}

_restore_on_exit() {
  local rc=$?
  trap - EXIT
  if [[ "${_restore_ok:-0}" == "1" || "${_restore_phase:-0}" == "0" ]]; then
    _restore_cleanup_temp
    unset COMPOSE_PROJECT_LOCK
    exit "$rc"
  fi
  echo "restore: rolling back after failure" >&2
  if _restore_rollback; then
    echo "restore: rollback complete" >&2
    _restore_cleanup_temp
  else
    echo "restore: rollback incomplete; keeping snapshots" >&2
    echo "restore: host=${_restore_host:-} vol=${_restore_vol:-} snap=${_restore_snap:-}" >&2
  fi
  unset COMPOSE_PROJECT_LOCK
  exit "$rc"
}

_restore_rollback() {
  local rc=0
  if [[ -n "${_restore_host:-}" && -d "${_restore_host}" ]]; then
    python3 - "$here" "$_restore_host" <<'PY' || return 1
import os, shutil, sys
here, snap = sys.argv[1:]
meta = os.path.join(snap, "META")
if os.path.isfile(meta):
    for line in open(meta):
        line = line.rstrip("\n")
        if not line:
            continue
        kind, rel, uid, gid, mode = line.split(" ", 4)
        dest = os.path.join(here, rel)
        parent = os.path.dirname(dest)
        if (parent and os.path.islink(parent)) or os.path.islink(dest):
            sys.exit("refusing to roll back through symlink %s" % dest)
        if kind == "d":
            if os.path.lexists(dest) and not os.path.isdir(dest):
                sys.exit("refusing to roll back directory onto %s" % dest)
            os.makedirs(dest, exist_ok=True)
            os.chmod(dest, int(mode, 8))
            if os.geteuid() == 0:
                os.chown(dest, int(uid), int(gid))
            continue
        if kind != "f":
            sys.exit("snapshot META kind %s" % kind)
        src = os.path.join(snap, "files", rel)
        os.makedirs(parent, exist_ok=True)
        shutil.copy2(src, dest)
        os.chmod(dest, int(mode, 8))
        if os.geteuid() == 0:
            os.chown(dest, int(uid), int(gid))
missing = os.path.join(snap, "MISSING")
if os.path.isfile(missing):
    for rel in open(missing):
        rel = rel.strip()
        if not rel:
            continue
        dest = os.path.join(here, rel)
        if os.path.lexists(dest) and not os.path.islink(dest):
            os.remove(dest)
PY
  fi
  if [[ -n "${_restore_vol:-}" && -f "${_restore_vol}/HAD" ]]; then
    COMPOSE_PROJECT_LOCK="${_restore_dest}"
    stop_db_writers || rc=1
    _restore_drop_created "$_restore_vol" || rc=1
    if [[ "$(cat "${_restore_vol}/HAD")" == "1" ]]; then
      if ! _restore_copy_volume_back "$_restore_vol" "${_restore_prev_mode}"; then
        _restore_copy_volume_alpine "$_restore_vol" || rc=1
      fi
      # Sidecar state lives in a named volume. Dropping the containers this
      # restore created must not leave the bundle's identity behind.
      _restore_sidecar_volume "$_restore_vol" || rc=1
    fi
  fi
  COMPOSE_PROJECT_LOCK="${_restore_current}"
  if [[ -n "${_restore_snap:-}" && -f "${_restore_snap}" ]]; then
    _recreate_original_services "$_restore_snap" "${_restore_prev_mode}" || rc=1
  fi
  return "$rc"
}

# The saved database is back only when its bytes match the snapshot.
# A later successful command must not hide a failed copy. This runs under
# `if !`, so set -e does not apply: every read failure returns 1.
_restore_verify_database() {
  local dest="$1" cid vol dir tmp rc
  dir="$(mktemp -d "$here/.running.XXXXXX")" || return 1
  tmp="$dir/db.sqlite"
  cid="$(_compose_ps_id headscale)"
  if [[ -n "$cid" ]]; then
    set +e
    docker cp "$cid:/var/lib/headscale/db.sqlite" "$tmp"
    rc=$?
    set -e
  else
    vol="$(_project_volume_name headscale-data 2>/dev/null || true)"
    if [[ -z "$vol" ]]; then
      rm -rf "$dir"
      return 1
    fi
    set +e
    _copy_volume_file_out "$vol" db.sqlite "$tmp"
    rc=$?
    set -e
  fi
  if [[ -s "$dest/headscale/db.sqlite" ]]; then
    if [[ "$rc" -ne 0 || ! -s "$tmp" ]]; then
      echo "restore: rollback could not read the restored database" >&2
      rm -rf "$dir"
      return 1
    fi
    python3 - "$dest/headscale/db.sqlite" "$tmp" <<'PY' || { rm -rf "$dir"; return 1; }
import hashlib, sys
def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
snap, got = digest(sys.argv[1]), digest(sys.argv[2])
if snap != got:
    sys.stderr.write(
        "restore: restored database checksum %s does not match snapshot %s\n" % (got, snap)
    )
    raise SystemExit(1)
PY
    rm -rf "$dir"
    return 0
  fi
  if [[ "$rc" -eq 0 && -s "$tmp" ]]; then
    echo "restore: rollback left a database the snapshot did not have" >&2
    rm -rf "$dir"
    return 1
  fi
  if [[ "$rc" -eq 1 ]]; then
    echo "restore: rollback could not read the restored database" >&2
    rm -rf "$dir"
    return 1
  fi
  rm -rf "$dir"
  return 0
}

_restore_copy_volume_back() {
  local dest="$1" mode="$2" hsid hpid
  hsid="$(_compose_ps_id headscale)"
  [[ -n "$hsid" ]] || return 1
  compose stop headscale enroll >/dev/null 2>&1 || true
  if [[ "$mode" == "tailnet-admin" ]]; then
    compose --profile tailnet-admin stop vpn-sidecar headplane-tailnet >/dev/null 2>&1 || true
  else
    compose stop headplane >/dev/null 2>&1 || true
  fi
  docker cp "$dest/headscale/db.sqlite" "$hsid:/var/lib/headscale/db.sqlite" || return 1
  docker cp "$dest/headscale/noise_private.key" "$hsid:/var/lib/headscale/noise_private.key" || return 1
  if [[ -f "$dest/headscale/derp_server_private.key" ]]; then
    docker cp "$dest/headscale/derp_server_private.key" "$hsid:/var/lib/headscale/derp_server_private.key" || return 1
  fi
  if [[ -f "$dest/headscale/db.sqlite-wal" ]]; then
    docker cp "$dest/headscale/db.sqlite-wal" "$hsid:/var/lib/headscale/db.sqlite-wal" || return 1
  else
    wipe_headscale_wal "$hsid" || return 1
  fi
  if [[ -f "$dest/headscale/db.sqlite-shm" ]]; then
    docker cp "$dest/headscale/db.sqlite-shm" "$hsid:/var/lib/headscale/db.sqlite-shm" || return 1
  fi
  chown_volume_to_image "$hsid" /var/lib/headscale || return 1
  if [[ "$mode" == "tailnet-admin" ]]; then
    hpid="$(_compose_ps_id headplane-tailnet)"
  else
    hpid="$(_compose_ps_id headplane)"
  fi
  if [[ -n "$hpid" && -d "$dest/headplane" ]]; then
    docker cp "$dest/headplane/." "$hpid:/var/lib/headplane/" || return 1
    chown_volume_to_image "$hpid" /var/lib/headplane || return 1
  fi
  _restore_verify_database "$dest" || return 1
}

_snapshot_host_files() {
  local dest="$1"
  python3 - "$here" "$dest" <<'PY'
import os, shutil, sys
here, dest = sys.argv[1:]
rels = [
    "enroll/config.json",
    "enroll/config.json.lock",
    "enroll/headscale.apikey",
    "enroll/minted-tokens.txt",
    "headplane/cookie_secret",
    ".env",
    "headscale/managed.json",
    "headscale/config.yaml",
    "headscale/policy.hujson",
    "headplane/config.yaml",
    ".admin-mode",
]
meta = []
missing = []
enroll_dir = os.path.join(here, "enroll")
if os.path.islink(enroll_dir):
    sys.exit("refusing to snapshot symlink enroll")
if os.path.isdir(enroll_dir):
    st = os.stat(enroll_dir)
    meta.append("d enroll %d %d %o" % (st.st_uid, st.st_gid, st.st_mode & 0o777))
for rel in rels:
    src = os.path.join(here, rel)
    if os.path.islink(src):
        sys.exit("refusing to snapshot symlink %s" % src)
    if os.path.isfile(src):
        target = os.path.join(dest, "files", rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(src, target)
        st = os.stat(src)
        meta.append("f %s %d %d %o" % (rel, st.st_uid, st.st_gid, st.st_mode & 0o777))
    else:
        missing.append(rel)
open(os.path.join(dest, "META"), "w").write("\n".join(meta) + ("\n" if meta else ""))
open(os.path.join(dest, "MISSING"), "w").write("\n".join(missing) + ("\n" if missing else ""))
os.chmod(os.path.join(dest, "META"), 0o600)
os.chmod(os.path.join(dest, "MISSING"), 0o600)
PY
}

_record_project_resources() {
  local dest="$1" project short name
  project="${COMPOSE_PROJECT_LOCK:-}"
  if [[ -z "$project" ]]; then
    project="$(current_project_name)"
  fi
  : > "$dest/containers.before"
  : > "$dest/volumes.before"
  : > "$dest/networks.before"
  docker ps -aq --filter "label=com.docker.compose.project=${project}" > "$dest/containers.before" \
    || return 1
  docker volume ls -q --filter "label=com.docker.compose.project=${project}" > "$dest/volumes.before" \
    || return 1
  for short in headscale-data headscale-run headplane-data vpn-sidecar-state; do
    name="${project}_${short}"
    if _safe_volume_name "$name" && docker volume inspect "$name" >/dev/null 2>&1; then
      printf '%s\n' "$name" >> "$dest/volumes.before"
    fi
  done
  sort -u -o "$dest/volumes.before" "$dest/volumes.before"
  docker network ls -q --filter "label=com.docker.compose.project=${project}" > "$dest/networks.before" \
    || return 1
}

# Delete only containers, volumes and networks that this restore created.
# A name in the before list is pre-existing data and stays.
_restore_drop_created() {
  local before="$1" project tmp name id
  if [[ ! -f "$before/containers.before" || ! -f "$before/volumes.before" || ! -f "$before/networks.before" ]]; then
    echo "restore: resource snapshot is incomplete; not deleting anything" >&2
    return 0
  fi
  project="${COMPOSE_PROJECT_LOCK:-}"
  if [[ -z "$project" ]]; then
    project="$(current_project_name)"
  fi
  tmp="$(mktemp "$here/.running.XXXXXX")"
  if ! docker ps -aq --filter "label=com.docker.compose.project=${project}" > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    if ! grep -qx "$id" "$before/containers.before"; then
      docker rm -f "$id" >/dev/null 2>&1 || true
    fi
  done < "$tmp"
  if ! docker volume ls -q --filter "label=com.docker.compose.project=${project}" > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  for short in headscale-data headscale-run headplane-data vpn-sidecar-state; do
    name="${project}_${short}"
    if _safe_volume_name "$name" && docker volume inspect "$name" >/dev/null 2>&1; then
      printf '%s\n' "$name" >> "$tmp"
    fi
  done
  sort -u -o "$tmp" "$tmp"
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    _safe_volume_name "$name" || continue
    if ! grep -qx "$name" "$before/volumes.before"; then
      docker volume rm "$name" >/dev/null 2>&1 || true
    fi
  done < "$tmp"
  if ! docker network ls -q --filter "label=com.docker.compose.project=${project}" > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    if ! grep -qx "$id" "$before/networks.before"; then
      docker network rm "$id" >/dev/null 2>&1 || true
    fi
  done < "$tmp"
  rm -f "$tmp"
}

# Copy one file out of a named volume. Exit 2 when the file is absent.
# stdout is a tar, so this does not bind-mount the host temp directory.
_copy_volume_file_out() {
  local vol="$1" src="$2" dest="$3" rc archive
  archive="$(mktemp "$here/.running.XXXXXX")"
  set +e
  docker run --rm --network none -e SRC="$src" -v "${vol}:/data:ro" "$ALPINE_VOLUME_IMAGE" \
    sh -c 'if [ ! -f "/data/$SRC" ]; then exit 2; fi; tar -C /data -cf - "$SRC"' > "$archive"
  rc=$?
  set -e
  if [[ "$rc" -eq 2 ]]; then
    rm -f "$archive" "$dest"
    return 2
  fi
  if [[ "$rc" -ne 0 || ! -s "$archive" ]]; then
    rm -f "$archive"
    return 1
  fi
  mkdir -p "$(dirname "$dest")"
  tar -C "$(dirname "$dest")" -xf "$archive"
  rm -f "$archive"
  [[ -f "$dest" ]] || return 1
  return 0
}

_archive_volume_to_dir() {
  local vol="$1" dest="$2" archive rc
  mkdir -p "$dest"
  archive="$(mktemp "$here/.running.XXXXXX")"
  set +e
  docker run --rm --network none -v "${vol}:/data:ro" "$ALPINE_VOLUME_IMAGE" \
    tar -C /data --exclude '*.sock' -cf - . > "$archive"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 || ! -s "$archive" ]]; then
    rm -f "$archive"
    return 1
  fi
  tar -C "$dest" -xf "$archive"
  rm -f "$archive"
}

_format_image_user() {
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
print("%s:%s" % (a, b))' "$1"
}

_image_user_from_compose() {
  local svc="$1" image spec
  image="$(compose config --format json 2>/dev/null | python3 -c '
import json, sys
svc = sys.argv[1]
try:
    cfg = json.load(sys.stdin)
except ValueError:
    raise SystemExit(1)
print(((cfg.get("services") or {}).get(svc) or {}).get("image") or "")
' "$svc" 2>/dev/null || true)"
  [[ -n "$image" ]] || return 1
  spec="$(docker image inspect "$image" --format '{{.Config.User}}' 2>/dev/null || true)"
  _format_image_user "$spec"
}

# Put snapshotted bytes back when no container is left to docker-cp into.
_restore_copy_volume_alpine() {
  local dest="$1" vol owner archive hp
  local -a files=()
  vol="$(_project_volume_name headscale-data 2>/dev/null || true)"
  [[ -n "$vol" ]] || return 1
  if [[ ! -s "$dest/headscale/db.sqlite" ]]; then
    # The retained volume had no database. A failed restore may have added one.
    docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
      rm -f /data/db.sqlite /data/db.sqlite-wal /data/db.sqlite-shm || return 1
    _restore_verify_database "$dest" || return 1
    return 0
  fi
  files=(db.sqlite)
  [[ -s "$dest/headscale/noise_private.key" ]] && files+=(noise_private.key)
  [[ -s "$dest/headscale/derp_server_private.key" ]] && files+=(derp_server_private.key)
  [[ -s "$dest/headscale/db.sqlite-wal" ]] && files+=(db.sqlite-wal)
  [[ -s "$dest/headscale/db.sqlite-shm" ]] && files+=(db.sqlite-shm)
  archive="$(mktemp "$here/.running.XXXXXX")" || return 1
  tar -C "$dest/headscale" -cf "$archive" "${files[@]}" || { rm -f "$archive"; return 1; }
  docker run --rm -i --user 0 --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
    tar -C /data -xf - < "$archive" || { rm -f "$archive"; return 1; }
  rm -f "$archive"
  if [[ ! -s "$dest/headscale/db.sqlite-wal" ]]; then
    docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
      rm -f /data/db.sqlite-wal /data/db.sqlite-shm || return 1
  fi
  owner="$(_image_user_from_compose headscale 2>/dev/null || true)"
  owner="${owner:-65532:65532}"
  [[ "$owner" =~ ^[0-9]+:[0-9]+$ ]] || owner="65532:65532"
  docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
    chown -R "$owner" /data || return 1
  if [[ -d "$dest/headplane" ]] && [[ -n "$(ls -A "$dest/headplane" 2>/dev/null || true)" ]]; then
    hp="$(_project_volume_name headplane-data 2>/dev/null || true)"
    if [[ -n "$hp" ]]; then
      archive="$(mktemp "$here/.running.XXXXXX")" || return 1
      tar -C "$dest/headplane" -cf "$archive" . || { rm -f "$archive"; return 1; }
      docker run --rm -i --user 0 --network none -v "${hp}:/data" "$ALPINE_VOLUME_IMAGE" \
        tar -C /data -xf - < "$archive" || { rm -f "$archive"; return 1; }
      rm -f "$archive"
    fi
  fi
  _restore_verify_database "$dest" || return 1
  return 0
}

# Restore sidecar identity into the retained named volume. The vpn-sidecar
# container is not required. Runs under rollback, so set -e is off.
_restore_sidecar_volume() {
  local dest="$1" vol owner dir rc
  vol="$(_project_volume_name vpn-sidecar-state 2>/dev/null || true)"
  if [[ -s "$dest/sidecar-state.tar" ]]; then
    [[ -n "$vol" ]] || return 1
    docker run --rm -i --user 0 --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
      sh -c 'find /data -type f ! -name "*.sock" -exec rm -f {} + || true; tar -C /data -xf -' \
      < "$dest/sidecar-state.tar" || return 1
    owner="$(_image_user_from_compose vpn-sidecar 2>/dev/null || true)"
    owner="${owner:-0:0}"
    [[ "$owner" =~ ^[0-9]+:[0-9]+$ ]] || owner="0:0"
    docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
      chown -R "$owner" /data || return 1
    dir="$(mktemp -d "$here/.running.XXXXXX")" || return 1
    python3 - "$dest/sidecar-state.tar" "$dir/expected" <<'PY' || { rm -rf "$dir"; return 1; }
import sys, tarfile
tar_path, dest = sys.argv[1:]
with tarfile.open(tar_path, "r:*") as tf:
    wanted = None
    for member in tf.getmembers():
        name = member.name.replace("\\", "/").lstrip("./")
        if name == "tailscaled.state" or name.endswith("/tailscaled.state"):
            if member.isfile():
                wanted = member
                break
    if wanted is None:
        sys.stderr.write("restore: sidecar snapshot has no tailscaled.state\n")
        raise SystemExit(1)
    fh = tf.extractfile(wanted)
    if fh is None:
        raise SystemExit(1)
    open(dest, "wb").write(fh.read())
PY
    set +e
    _copy_volume_file_out "$vol" tailscaled.state "$dir/tailscaled.state"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 || ! -s "$dir/tailscaled.state" ]]; then
      echo "restore: rollback could not read sidecar state" >&2
      rm -rf "$dir"
      return 1
    fi
    python3 - "$dir/expected" "$dir/tailscaled.state" <<'PY' || { rm -rf "$dir"; return 1; }
import hashlib, sys
def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
snap, got = digest(sys.argv[1]), digest(sys.argv[2])
if snap != got:
    sys.stderr.write(
        "restore: restored sidecar checksum %s does not match snapshot %s\n" % (got, snap)
    )
    raise SystemExit(1)
PY
    rm -rf "$dir"
    return 0
  fi
  # sidecar-absent is written only after the volume or tailscaled.state was
  # verified missing. A snapshot that never looked must not delete the
  # identity that down left behind, and must not report a finished rollback.
  if [[ -s "$dest/sidecar-absent" ]]; then
    if [[ -n "$vol" ]]; then
      docker run --rm --network none -v "${vol}:/data" "$ALPINE_VOLUME_IMAGE" \
        rm -f /data/tailscaled.state || return 1
    fi
    return 0
  fi
  echo "restore: sidecar state was not captured; leaving the volume untouched" >&2
  return 1
}

_recreate_original_services() {
  local snap="$1" mode="$2" svc
  local -a plain=() profile=()
  [[ -f "$snap" ]] || return 0
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
    compose up -d --force-recreate --wait --wait-timeout 180 "${plain[@]}" || return 1
  fi
  if [[ ${#profile[@]} -gt 0 ]]; then
    compose --profile tailnet-admin up -d --force-recreate --wait --wait-timeout 180 "${profile[@]}" || return 1
  fi
  verify_published_bindings "$mode" || return 1
  if snapshot_has "$snap" headscale; then
    compose exec -T headscale headscale health || return 1
  fi
}

_restored_enroll_check() {
  local _
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if compose exec -T enroll idoris-vpn-enroll check --config /etc/idoris/enroll.json >/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "restore: enroll config check failed" >&2
  return 1
}

# Snapshot vpn-sidecar-state from the named volume. The vpn-sidecar container
# is not required: down removes it and leaves the volume. sidecar-state.tar
# means the identity was captured. sidecar-absent means the volume or
# tailscaled.state was verified missing. A read failure writes neither and
# returns 1, so a later rollback cannot treat "not captured" as absence.
_snapshot_sidecar_state() {
  local dest="$1" sid rc
  rm -f "$dest/sidecar-state.tar" "$dest/sidecar-absent"
  sid="$(_project_volume_name vpn-sidecar-state 2>/dev/null || true)"
  if [[ -z "$sid" ]]; then
    printf 'volume\n' > "$dest/sidecar-absent" || return 1
    chmod 600 "$dest/sidecar-absent" || return 1
    return 0
  fi
  set +e
  docker run --rm --network none -v "${sid}:/data:ro" "$ALPINE_VOLUME_IMAGE" \
    sh -c 'cd /data && find . -type f ! -name "*.sock" > /tmp/list && if grep -q "tailscaled.state" /tmp/list; then tar -cf - -T /tmp/list; exit 0; fi; exit 42' \
    > "$dest/sidecar-state.tar"
  rc=$?
  set -e
  if [[ "$rc" -eq 42 ]]; then
    rm -f "$dest/sidecar-state.tar"
    printf 'file\n' > "$dest/sidecar-absent" || return 1
    chmod 600 "$dest/sidecar-absent" || return 1
    return 0
  fi
  if [[ "$rc" -ne 0 || ! -s "$dest/sidecar-state.tar" ]]; then
    rm -f "$dest/sidecar-state.tar" "$dest/sidecar-absent"
    echo "restore: could not snapshot sidecar state" >&2
    return 1
  fi
  chmod 600 "$dest/sidecar-state.tar" || return 1
  return 0
}

_snapshot_volumes() {
  local dest="$1" mode="$2" hsid hpid vol rc hp
  mkdir -p "$dest/headscale" "$dest/headplane"
  chmod 700 "$dest" "$dest/headscale" "$dest/headplane"
  _record_project_resources "$dest" || return 1
  hsid="$(_compose_ps_id headscale)"
  if [[ -z "$hsid" ]]; then
    vol="$(_project_volume_name headscale-data 2>/dev/null || true)"
    if [[ -z "$vol" ]]; then
      printf '0\n' > "$dest/HAD"
      return 0
    fi
    printf '1\n' > "$dest/HAD"
    set +e
    _copy_volume_file_out "$vol" db.sqlite "$dest/headscale/db.sqlite"
    rc=$?
    set -e
    if [[ "$rc" -eq 1 ]]; then
      echo "restore: volume snapshot could not copy the database" >&2
      return 1
    fi
    if [[ -s "$dest/headscale/db.sqlite" ]]; then
      _copy_volume_file_out "$vol" noise_private.key "$dest/headscale/noise_private.key" || rc=1
      if [[ "$rc" -eq 1 || ! -s "$dest/headscale/noise_private.key" ]]; then
        echo "restore: volume snapshot is missing the database" >&2
        return 1
      fi
    fi
    _copy_volume_file_out "$vol" derp_server_private.key "$dest/headscale/derp_server_private.key" \
      || rm -f "$dest/headscale/derp_server_private.key"
    _copy_volume_file_out "$vol" db.sqlite-wal "$dest/headscale/db.sqlite-wal" \
      || rm -f "$dest/headscale/db.sqlite-wal"
    _copy_volume_file_out "$vol" db.sqlite-shm "$dest/headscale/db.sqlite-shm" \
      || rm -f "$dest/headscale/db.sqlite-shm"
    hp="$(_project_volume_name headplane-data 2>/dev/null || true)"
    if [[ -n "$hp" ]]; then
      _archive_volume_to_dir "$hp" "$dest/headplane" || return 1
    fi
    _snapshot_sidecar_state "$dest" || return 1
    return 0
  fi
  printf '1\n' > "$dest/HAD"
  docker cp "$hsid:/var/lib/headscale/db.sqlite" "$dest/headscale/db.sqlite"
  docker cp "$hsid:/var/lib/headscale/noise_private.key" "$dest/headscale/noise_private.key"
  docker cp "$hsid:/var/lib/headscale/derp_server_private.key" "$dest/headscale/derp_server_private.key" 2>/dev/null \
    || rm -f "$dest/headscale/derp_server_private.key"
  docker cp "$hsid:/var/lib/headscale/db.sqlite-wal" "$dest/headscale/db.sqlite-wal" 2>/dev/null \
    || rm -f "$dest/headscale/db.sqlite-wal"
  docker cp "$hsid:/var/lib/headscale/db.sqlite-shm" "$dest/headscale/db.sqlite-shm" 2>/dev/null \
    || rm -f "$dest/headscale/db.sqlite-shm"
  if [[ ! -s "$dest/headscale/db.sqlite" || ! -s "$dest/headscale/noise_private.key" ]]; then
    echo "restore: volume snapshot is missing the database" >&2
    return 1
  fi
  if [[ "$mode" == "tailnet-admin" ]]; then
    hpid="$(_compose_ps_id headplane-tailnet)"
  else
    hpid="$(_compose_ps_id headplane)"
  fi
  if [[ -n "$hpid" ]]; then
    docker cp "$hpid:/var/lib/headplane/." "$dest/headplane/"
  fi
  _snapshot_sidecar_state "$dest" || return 1
  return 0
}

_install_bundle_host() {
  local bundle="$1" info="$2" rel mode uid gid
  local -a rels=(
    "state/enroll/config.json|enroll/config.json"
    "state/enroll/headscale.apikey|enroll/headscale.apikey"
    "state/headplane/cookie_secret|headplane/cookie_secret"
    "state/headscale/managed.json|headscale/managed.json"
    "state/headscale/config.yaml|headscale/config.yaml"
    "state/headscale/policy.hujson|headscale/policy.hujson"
    "state/headplane/config.yaml|headplane/config.yaml"
  )
  for rel in "${rels[@]}"; do
    restore_private "$bundle/${rel%%|*}" "$here/${rel#*|}"
    apply_restored_mode "$bundle/manifest.json" "${rel%%|*}" "$here/${rel#*|}"
  done
  python3 -c '
import json, os, sys
info = json.loads(sys.argv[1])
lines = ["%s=%s\n" % (key, info["dotenv"][key]) for key in sorted(info["dotenv"])]
open(sys.argv[2], "w").writelines(lines)
os.chmod(sys.argv[2], 0o600)
' "$info" "$here/.env"
  apply_restored_mode "$bundle/manifest.json" "state/dotenv" "$here/.env"
  mode="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("admin_mode") or "")' "$info")"
  if [[ -n "$mode" ]]; then
    write_admin_mode "$mode"
  fi
  if ! cmp -s "$bundle/state/compose.yaml" "$here/compose.yaml"; then
    echo "restore: bundle compose.yaml differs from this checkout; keeping the checkout file" >&2
  fi
  uid="$(dotenv_value ENROLL_UID || true)"
  gid="$(dotenv_value ENROLL_GID || true)"
  chown_enroll_runtime "${uid:-65532}" "${gid:-65532}"
}

_install_bundle_volumes() {
  local bundle="$1" mode="$2" hsid hpid
  ensure_mode_containers "$mode"
  hsid="$(_compose_ps_id headscale)"
  [[ -n "$hsid" ]] || die "headscale container is missing after create"
  if [[ ! -f "$bundle/headscale/db.sqlite-wal" ]]; then
    wipe_headscale_wal "$hsid" || die "could not wipe the headscale database journal"
  fi
  docker cp "$bundle/headscale/db.sqlite" "$hsid:/var/lib/headscale/db.sqlite"
  docker cp "$bundle/headscale/noise_private.key" "$hsid:/var/lib/headscale/noise_private.key"
  if [[ -f "$bundle/headscale/derp_server_private.key" ]]; then
    docker cp "$bundle/headscale/derp_server_private.key" "$hsid:/var/lib/headscale/derp_server_private.key"
  else
    echo "restore: backup has no DERP key (embedded DERP was off); leaving it unset" >&2
  fi
  if [[ -f "$bundle/headscale/db.sqlite-wal" ]]; then
    docker cp "$bundle/headscale/db.sqlite-wal" "$hsid:/var/lib/headscale/db.sqlite-wal"
  fi
  if [[ -f "$bundle/headscale/db.sqlite-shm" ]]; then
    docker cp "$bundle/headscale/db.sqlite-shm" "$hsid:/var/lib/headscale/db.sqlite-shm"
  fi
  chown_volume_to_image "$hsid" /var/lib/headscale || die "could not chown the headscale volume"
  hpid="$(headplane_writer_id "$mode")"
  if [[ -d "$bundle/headplane" ]]; then
    docker cp "$bundle/headplane/." "$hpid:/var/lib/headplane/"
    chown_volume_to_image "$hpid" /var/lib/headplane || die "could not chown the headplane volume"
  fi
  if [[ "$mode" == "tailnet-admin" && -f "$bundle/sidecar/state.tar" ]]; then
    extract_sidecar_tar "$bundle/sidecar/state.tar" || die "could not restore sidecar state"
  fi
}

_start_restored_stack() {
  local mode="$1" bundle="$2"
  enforce_headplane_exclusion "$mode"
  assert_compose_bindings "$mode"
  if [[ "$mode" == "tailnet-admin" ]]; then
    compose up -d --force-recreate --wait --wait-timeout 180 headscale enroll
    if [[ -f "$bundle/sidecar/state.tar" || -n "${VPN_SERVER_ENROLL_TOKEN:-}" ]]; then
      compose --profile tailnet-admin up -d --force-recreate --wait --wait-timeout 180 vpn-sidecar headplane-tailnet
    else
      echo "restore: no sidecar state and no VPN_SERVER_ENROLL_TOKEN; headscale and enroll are up" >&2
      echo "restore: recover the admin node with:" >&2
      echo "  bash $here/ctl.sh token new --entry vpn-server --label recovery --enroll-url https://enroll.example.org" >&2
      echo "  export VPN_SERVER_ENROLL_TOKEN from that command, then: bash $here/ctl.sh up --tailnet-admin" >&2
    fi
  else
    compose up -d --force-recreate --wait --wait-timeout 180 headscale enroll headplane
  fi
  verify_published_bindings "$mode"
  _restored_enroll_check
}

restore_deployment() {
  local bundle="$1" adopt="${2:-0}" info bundle_project ignored
  [[ -d "$bundle" && ! -L "$bundle" ]] || die "backup directory is missing"
  info="$(python3 "$here/bundle.py" tree "$bundle")"
  bundle_project="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("dotenv", {}).get("COMPOSE_PROJECT_NAME", ""))' "$info")"
  ignored="$(python3 -c 'import json,sys; print("\n".join(json.loads(sys.argv[1]).get("ignored") or []))' "$info")"
  if [[ -n "$ignored" ]]; then
    echo "restore: ignoring obsolete state/enroll/token-labels.json" >&2
  fi
  _restore_ok=0
  _restore_phase=0
  _restore_prev_mode="$(read_admin_mode)"
  _restore_current="$(current_project_name)"
  if [[ -n "$bundle_project" ]]; then
    _restore_dest="$bundle_project"
  else
    _restore_dest="$_restore_current"
  fi
  if [[ -n "${COMPOSE_PROJECT_NAME:-}" && "$COMPOSE_PROJECT_NAME" != "$_restore_dest" ]]; then
    die "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME} does not match the bundle project ${_restore_dest}"
  fi
  reject_project_named "$_restore_current"
  if [[ "$_restore_dest" != "$_restore_current" ]]; then
    reject_project_named "$_restore_dest"
  fi
  # Before any snapshot or stop. Markerless volumes are not overwritten
  # unless the operator named them with --adopt-existing-volumes.
  require_restore_volume_ownership "$_restore_dest" "$adopt"
  _restore_host="$(mktemp -d "${TMPDIR:-/tmp}/idoris-vpn.XXXXXX")"
  _restore_vol="$(mktemp -d "${TMPDIR:-/tmp}/idoris-vpn.XXXXXX")"
  _restore_snap="$(mktemp "${TMPDIR:-/tmp}/idoris-vpn.XXXXXX")"
  chmod 700 "$_restore_host" "$_restore_vol"
  chmod 600 "$_restore_snap"
  trap _restore_on_exit EXIT
  _snapshot_host_files "$_restore_host"
  COMPOSE_PROJECT_LOCK="$_restore_current"
  snapshot_running "$_restore_snap"
  _restore_phase=1
  if ! stop_db_writers; then
    restore_running_services "$_restore_snap" "$_restore_prev_mode" || true
    _restore_phase=0
    die "refusing to restore; a database writer did not stop"
  fi
  COMPOSE_PROJECT_LOCK="$_restore_dest"
  if ! _snapshot_volumes "$_restore_vol" "$_restore_prev_mode"; then
    COMPOSE_PROJECT_LOCK="$_restore_current"
    restore_running_services "$_restore_snap" "$_restore_prev_mode" || true
    _restore_phase=0
    die "refusing to restore; could not snapshot the live volumes"
  fi
  _restore_phase=2
  _install_bundle_host "$bundle" "$info"
  _install_bundle_volumes "$bundle" "$(read_admin_mode)"
  _start_restored_stack "$(read_admin_mode)" "$bundle"
  mark_deploy_dir
  _restore_ok=1
  trap - EXIT
  _restore_cleanup_temp
  unset COMPOSE_PROJECT_LOCK
  echo "restored from $bundle (admin mode $(read_admin_mode); the other Headplane stays stopped)"
}
