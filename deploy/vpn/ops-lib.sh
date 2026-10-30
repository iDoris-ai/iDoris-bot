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
# Tailnet mode starts the profile only when VPN_SERVER_ENROLL_TOKEN is set.
start_stack_for_mode() {
  local mode="$1"
  enforce_headplane_exclusion "$mode"
  assert_compose_bindings "$mode"
  if [[ "$mode" == "tailnet-admin" ]]; then
    compose up -d --wait --wait-timeout 180 headscale enroll
    if [[ -n "${VPN_SERVER_ENROLL_TOKEN:-}" ]]; then
      compose --profile tailnet-admin up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet
      verify_published_bindings "$mode"
      echo "tailnet-admin profile is up. Published Headplane is stopped."
    else
      echo "admin mode is tailnet-admin. Published Headplane stays stopped."
      echo "export VPN_SERVER_ENROLL_TOKEN (the vpn-server enrollment token) and run: bash $here/ctl.sh up"
    fi
  else
    compose --profile tailnet-admin stop vpn-sidecar headplane-tailnet >/dev/null 2>&1 || true
    compose up -d --wait --wait-timeout 180
    verify_published_bindings "$mode"
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
