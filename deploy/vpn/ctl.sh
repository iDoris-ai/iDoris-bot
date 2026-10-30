#!/usr/bin/env bash
# Operate the iDoris VPN stack from a shell on the server.
# Resolves the compose directory from this file, so the working directory
# does not matter. Secrets are printed only by `apikeys create`, whose
# purpose is to mint one.
#
#   bash deploy/vpn/ctl.sh help
set -euo pipefail
# Before any directory or secret is created. A caller umask of 022 must not
# apply to the backup tree, even when a later chmod is skipped by set -e.
umask 077

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

die() { echo "ctl: $*" >&2; exit 1; }
# shellcheck source-path=SCRIPTDIR
# shellcheck source=ops-lib.sh
source "$here/ops-lib.sh"

hs() { docker compose exec -T headscale headscale "$@"; }

# Copy one file out of a container. A missing path is skipped: Headscale does
# not create derp_server_private.key while embedded DERP is disabled. docker cp
# of a missing path can also leave a zero-byte file; that file is removed.
copy_container_file_if_present() {
  local src="$1" dest="$2" err
  err="$(mktemp "$here/.running.XXXXXX")"
  if docker cp "$src" "$dest" 2>"$err"; then
    rm -f "$err"
    if [[ -f "$dest" && ! -s "$dest" ]]; then
      rm -f "$dest"
      echo "backup: $src was empty; omitted" >&2
    fi
    return 0
  fi
  if grep -Eq 'Could not find the file|No such file or directory' "$err"; then
    rm -f "$dest" "$err"
    echo "backup: $src is absent; omitted" >&2
    return 0
  fi
  cat "$err" >&2
  rm -f "$dest" "$err"
  return 1
}

# Redact pre-auth keys and full API keys. A listed API-key prefix is short
# (headscale shows a prefix, not the secret); a full key is much longer.
redact() {
  python3 -c '
import re, sys
text = sys.stdin.read()
def hide(m):
    token = m.group(0)
    if token.startswith("hskey-auth-") or len(token) > 48:
        return "[redacted]"
    return token
sys.stdout.write(re.sub(r"hskey-[A-Za-z0-9_.:+/=-]+", hide, text))
'
}

usage() {
  cat <<'EOF'
Usage: bash deploy/vpn/ctl.sh <command> [args]

  status                         compose ps and headscale health
  health                         headscale health
  users list
  nodes list
  nodes expire --identifier ID [--expiry RFC3339] [--disable]
  nodes delete --identifier ID --force
  preauthkeys list               keys redacted; use the id to expire
  preauthkeys expire --id ID
  routes list [--identifier ID]
  routes approve --identifier ID --routes CIDR[,CIDR...]
  routes clear --identifier ID   remove every approved route on that node
  policy check
  policy reload                  check, then SIGHUP headscale
  apikeys list                   prefixes only
  apikeys create [--expiration 90d]
                                 prints the new key (this is the one command
                                 that shows a secret). Use it to log into Headplane.
  apikeys expire --prefix PFX | --id ID
  token new --entry NAME --label LABEL [--enroll-url URL]
                                 add one enrollment token. The label is stored
                                 beside the config (the enroll CLI has no
                                 --label). Plaintext is appended to
                                 enroll/minted-tokens.txt before reload.
  token revoke --entry NAME (--label LABEL | --hash-prefix HEX)
                                 remove that one hash, then SIGHUP enroll.
                                 Refuses to remove the last hash.
  offboard --entry NAME --hash-prefix HEX [--node-id N]
                                 revoke that credential first. Only if revoke
                                 succeeds, expire and delete the node.
  logs [service] [--tail N]      service: headscale, headplane, enroll,
                                 vpn-sidecar, headplane-tailnet
  backup [DIR]                   stop the running Headplane writer and headscale,
                                 copy sqlite, keys, Headplane data, and the
                                 host state needed to rebuild the machine.
                                 Starts the same services again. Does not
                                 start the other Headplane.
  restore DIR --force            restore that bundle, including onto a host
                                 whose containers are gone. Starts the saved
                                 admin mode only.
  up [--published|--tailnet-admin] [--instance NAME]
      [--headplane-access tunnel|lan|tailnet|proxy]
                                 start the saved admin mode. With no access
                                 flag, reapplies HEADPLANE_ACCESS from .env
                                 (default tunnel). A saved tailnet access is
                                 kept only when the mode is tailnet-admin.
                                 The knob sets base_url, cookie_secure and
                                 which Headplane runs. --instance records the
                                 compose project name.
  down                           docker compose down (keeps volumes and the mode)
  upgrade                        print the upgrade procedure
  break-glass                    print the SSH checklist for when Headscale is down

The compose project is COMPOSE_PROJECT_NAME in .env (default idoris-vpn).
bootstrap.sh --instance NAME sets it. A name already used by another
directory is refused. HEADPLANE_BIND defaults to 127.0.0.1; see
docs/14-VPN-OPERATIONS.md.
EOF
}

require_id() {
  local id="${1:-}"
  [[ "$id" =~ ^[0-9]+$ ]] || die "identifier must be a decimal node or key id"
  printf '%s' "$id"
}

enroll_run_user() {
  local uid gid
  uid="${ENROLL_UID:-}"
  gid="${ENROLL_GID:-}"
  if [[ -z "$uid" && -f "$here/.env" ]]; then
    uid="$(sed -n 's/^ENROLL_UID=//p' "$here/.env" | head -n1 | tr -d '[:space:]')"
    gid="$(sed -n 's/^ENROLL_GID=//p' "$here/.env" | head -n1 | tr -d '[:space:]')"
  fi
  uid="${uid:-65532}"
  gid="${gid:-65532}"
  [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || die "ENROLL_UID/ENROLL_GID must be numeric"
  printf '%s:%s' "$uid" "$gid"
}

# Writable mount of enroll/: invite writes a temp file next to config.json.
# The image rootfs is read-only; this directory is not.
enroll_cli() {
  docker compose run --rm --no-deps -T \
    --user "$(enroll_run_user)" \
    --entrypoint idoris-vpn-enroll \
    -v "$here/enroll:/work" \
    enroll "$@"
}

reload_enroll() {
  if service_running enroll; then
    docker compose kill -s HUP enroll >/dev/null
    echo "sent SIGHUP to enroll so it reloads config.json"
  else
    echo "enroll is not running; the next start reads config.json"
  fi
}

require_label() {
  [[ "${1:-}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || die "label must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
}

require_hash_prefix() {
  [[ "${1:-}" =~ ^[0-9a-fA-F]{4,64}$ ]] || die "hash prefix must be 4 to 64 hex digits"
}

# Sidecar: the enroll config rejects unknown fields, and invite/revoke have
# no --label. Hash -> label lives here until the Go CLI grows one.
label_file() { printf '%s/enroll/token-labels.json' "$here"; }

record_token_label() {
  python3 - "$(label_file)" "$1" "$2" "$3" <<'PY'
import json, os, sys, tempfile
path, entry, digest, label = sys.argv[1:]
doc = {"version": 1, "entries": {}}
if os.path.isfile(path) and not os.path.islink(path):
    doc = json.load(open(path))
entries = doc.setdefault("entries", {})
bucket = entries.setdefault(entry, {})
for have, existing in bucket.items():
    if existing == label and have != digest:
        sys.exit("label %s is already used by another token on %s" % (label, entry))
bucket[digest] = label
fd, tmp = tempfile.mkstemp(prefix=".labels.", dir=os.path.dirname(path) or ".")
os.close(fd)
try:
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.rename(tmp, path)
except Exception:
    os.unlink(tmp)
    raise
os.chmod(path, 0o600)
PY
}

forget_token_hash() {
  python3 - "$(label_file)" "$1" "$2" <<'PY'
import json, os, sys, tempfile
path, entry, digest = sys.argv[1:]
if not os.path.isfile(path) or os.path.islink(path):
    raise SystemExit(0)
doc = json.load(open(path))
bucket = doc.get("entries", {}).get(entry, {})
bucket.pop(digest, None)
fd, tmp = tempfile.mkstemp(prefix=".labels.", dir=os.path.dirname(path) or ".")
os.close(fd)
try:
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.rename(tmp, path)
except Exception:
    os.unlink(tmp)
    raise
os.chmod(path, 0o600)
PY
}

hash_for_label() {
  python3 - "$(label_file)" "$1" "$2" <<'PY'
import json, os, sys
path, entry, label = sys.argv[1:]
if not os.path.isfile(path):
    sys.exit("no label file; revoke with --hash-prefix")
doc = json.load(open(path))
bucket = doc.get("entries", {}).get(entry, {})
hits = [h for h, lab in bucket.items() if lab == label]
if len(hits) != 1:
    sys.exit("label %s on %s matched %d tokens" % (label, entry, len(hits)))
sys.stdout.write(hits[0])
PY
}

parse_identifier() {
  local id=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --identifier|-i)
        [[ $# -ge 2 ]] || die "$1 needs a value"
        id="$2"
        shift 2
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
  require_id "$id" >/dev/null
  printf '%s' "$id"
}

cmd="${1:-help}"
shift || true

# `up --instance` has to record the project name before the collision check,
# otherwise a taken default (idoris-vpn) rejects the new name as well.
early_instance=""
if [[ "$cmd" == "up" ]]; then
  prev=""
  for arg in "$@"; do
    if [[ "$prev" == "--instance" ]]; then
      early_instance="$arg"
    fi
    prev="$arg"
  done
fi
case "$cmd" in
  help|-h|--help|upgrade|break-glass) ;;
  *)
    if [[ -n "$early_instance" ]]; then
      assign_instance "$early_instance"
    else
      reject_project_collision
    fi
    ;;
esac

case "$cmd" in
  help|-h|--help)
    usage
    ;;
  status)
    docker compose ps
    hs health
    ;;
  health)
    hs health
    ;;
  users)
    [[ "${1:-}" == "list" ]] || die "usage: ctl.sh users list"
    hs users list
    ;;
  nodes)
    sub="${1:-list}"
    shift || true
    case "$sub" in
      list)
        hs nodes list
        ;;
      expire)
        id="" expiry="" disable=0
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --identifier|-i) id="${2:-}"; shift 2 ;;
            --expiry|-e) expiry="${2:-}"; shift 2 ;;
            --disable|-d) disable=1; shift ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        id="$(require_id "$id")"
        args=(nodes expire --identifier "$id")
        if (( disable )); then
          args+=(--disable)
        elif [[ -n "$expiry" ]]; then
          [[ "$expiry" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z$ ]] || die "--expiry must be RFC3339 UTC (2006-01-02T15:04:05Z)"
          args+=(--expiry "$expiry")
        fi
        hs "${args[@]}"
        ;;
      delete)
        id="" force=0
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --identifier|-i) id="${2:-}"; shift 2 ;;
            --force) force=1; shift ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        id="$(require_id "$id")"
        (( force )) || die "refusing to delete node $id without --force"
        hs --force nodes delete --identifier "$id"
        ;;
      *)
        die "usage: ctl.sh nodes list|expire|delete"
        ;;
    esac
    ;;
  preauthkeys)
    sub="${1:-list}"
    shift || true
    case "$sub" in
      list)
        hs preauthkeys list | redact
        ;;
      expire)
        id=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --id|-i) id="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        id="$(require_id "$id")"
        hs preauthkeys expire --id "$id"
        ;;
      *)
        die "usage: ctl.sh preauthkeys list|expire --id ID"
        ;;
    esac
    ;;
  routes)
    sub="${1:-list}"
    shift || true
    case "$sub" in
      list)
        id=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --identifier|-i) id="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        if [[ -n "$id" ]]; then
          id="$(require_id "$id")"
          hs nodes list-routes --identifier "$id"
        else
          hs nodes list-routes
        fi
        ;;
      approve|clear)
        id="" routes=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --identifier|-i) id="${2:-}"; shift 2 ;;
            --routes|-r) routes="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        id="$(require_id "$id")"
        if [[ "$sub" == "clear" ]]; then
          hs nodes approve-routes --identifier "$id" --routes ""
        else
          [[ "$routes" =~ ^[0-9a-fA-F.:/,]+$ ]] || die "--routes must be a comma-separated list of CIDRs"
          hs nodes approve-routes --identifier "$id" --routes "$routes"
        fi
        ;;
      *)
        die "usage: ctl.sh routes list|approve|clear"
        ;;
    esac
    ;;
  policy)
    sub="${1:-check}"
    case "$sub" in
      check)
        hs policy check -f /etc/headscale/policy.hujson
        ;;
      reload)
        hs policy check -f /etc/headscale/policy.hujson
        docker compose kill -s HUP headscale >/dev/null
        echo "policy reloaded (SIGHUP)"
        ;;
      *)
        die "usage: ctl.sh policy check|reload"
        ;;
    esac
    ;;
  apikeys)
    sub="${1:-list}"
    shift || true
    case "$sub" in
      list)
        hs apikeys list | redact
        ;;
      create)
        expiration="90d"
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --expiration|-e) expiration="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        [[ "$expiration" =~ ^[0-9]+[smhd]$ ]] || die "--expiration must look like 90d, 24h, 30m"
        echo "Headplane login key (shown once; this is not the enrollment service key):" >&2
        hs apikeys create --expiration "$expiration"
        ;;
      expire)
        id="" prefix=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --id|-i) id="${2:-}"; shift 2 ;;
            --prefix|-p) prefix="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        if [[ -n "$id" ]]; then
          id="$(require_id "$id")"
          hs apikeys expire --id "$id"
        elif [[ -n "$prefix" ]]; then
          [[ "$prefix" =~ ^[A-Za-z0-9_-]+$ ]] || die "unexpected prefix"
          hs apikeys expire --prefix "$prefix"
        else
          die "usage: ctl.sh apikeys expire --prefix PFX | --id ID"
        fi
        ;;
      *)
        die "usage: ctl.sh apikeys list|create|expire"
        ;;
    esac
    ;;
  logs)
    service=""
    tailn=100
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --tail) tailn="${2:-}"; shift 2 ;;
        headscale|headplane|enroll|vpn-sidecar|headplane-tailnet)
          service="$1"
          shift
          ;;
        *) die "unknown argument: $1" ;;
      esac
    done
    [[ "$tailn" =~ ^[0-9]+$ ]] || die "--tail needs an integer"
    if [[ -n "$service" ]]; then
      docker compose logs --tail "$tailn" "$service" | redact
    else
      docker compose logs --tail "$tailn" | redact
    fi
    ;;
  backup)
    dest="${1:-$here/backups/$(date -u +%Y%m%dT%H%M%SZ)}"
    [[ "$dest" != --* ]] || die "usage: ctl.sh backup [DIR]"
    mode="$(read_admin_mode)"
    # Fail before stopping the stack when the host state is incomplete.
    require_regular "$here/enroll/config.json"
    require_regular "$here/enroll/headscale.apikey"
    require_regular "$here/headplane/cookie_secret"
    require_regular "$here/.env"
    require_regular "$here/headscale/managed.json"
    require_regular "$here/headscale/config.yaml"
    require_regular "$here/headscale/policy.hujson"
    require_regular "$here/headplane/config.yaml"
    require_regular "$here/compose.yaml"
    prepare_backup_dest "$dest"
    hs_version="not-running"
    if service_running headscale; then
      hs_version="$(docker compose exec -T headscale headscale version 2>/dev/null | tr -d '\r' || echo unknown)"
    fi
    snap="$(mktemp "$here/.running.XXXXXX")"
    snapshot_running "$snap"
    mkdir -p "$dest/headscale" "$dest/headplane" "$dest/state"
    echo "stopping the running Headplane writer and headscale (mode=$mode)..."
    if snapshot_has "$snap" headscale; then
      docker compose stop headscale
    fi
    stop_headplane_writers
    cleanup_backup() {
      restore_running_services "$snap" "$mode" || true
      rm -f "$snap"
    }
    trap cleanup_backup EXIT
    hsid="$(docker compose ps -aq headscale)"
    hpid="$(headplane_writer_id "$mode")"
    [[ -n "$hsid" ]] || die "headscale container is missing; start the stack first"
    docker cp "$hsid:/var/lib/headscale/db.sqlite" "$dest/headscale/db.sqlite"
    docker cp "$hsid:/var/lib/headscale/noise_private.key" "$dest/headscale/noise_private.key"
    # Present only while derp.server.enabled is true.
    copy_container_file_if_present \
      "$hsid:/var/lib/headscale/derp_server_private.key" \
      "$dest/headscale/derp_server_private.key"
    docker cp "$hsid:/var/lib/headscale/db.sqlite-wal" "$dest/headscale/db.sqlite-wal" 2>/dev/null || true
    docker cp "$hsid:/var/lib/headscale/db.sqlite-shm" "$dest/headscale/db.sqlite-shm" 2>/dev/null || true
    # docker cp of a missing path can leave a zero-byte file. Drop those.
    for extra in db.sqlite-wal db.sqlite-shm; do
      if [[ -f "$dest/headscale/$extra" && ! -s "$dest/headscale/$extra" ]]; then
        rm -f "$dest/headscale/$extra"
      fi
    done
    docker cp "$hpid:/var/lib/headplane/." "$dest/headplane/"
    copy_private "$here/enroll/config.json" "$dest/state/enroll/config.json"
    copy_private "$here/enroll/headscale.apikey" "$dest/state/enroll/headscale.apikey"
    copy_private "$here/headplane/cookie_secret" "$dest/state/headplane/cookie_secret"
    copy_private "$here/.env" "$dest/state/dotenv"
    copy_private "$here/headscale/managed.json" "$dest/state/headscale/managed.json"
    copy_private "$here/headscale/config.yaml" "$dest/state/headscale/config.yaml"
    copy_private "$here/headscale/policy.hujson" "$dest/state/headscale/policy.hujson"
    copy_private "$here/headplane/config.yaml" "$dest/state/headplane/config.yaml"
    copy_private "$here/compose.yaml" "$dest/state/compose.yaml"
    if [[ -f "$(admin_mode_file)" ]]; then
      copy_private "$(admin_mode_file)" "$dest/admin-mode"
    fi
    write_backup_manifest "$dest" "$mode" "$hs_version"
    seal_tree "$dest"
    trap - EXIT
    restore_running_services "$snap" "$mode"
    rm -f "$snap"
    echo "backup written to $dest (admin mode $mode; the other Headplane was not started)"
    cat <<EOF

Restore (overwrites the live database and the host state files):
  bash $here/ctl.sh restore $dest --force
The other Headplane stays stopped. Do not restore a backup onto a newer
Headscale minor than the one that wrote it.

Off-host copy (encrypt before the archive leaves this machine; this repo
does not ship a key). cron, every day at 03:15 UTC:
  15 3 * * * umask 077; tar -C $(dirname "$dest") -cf - $(basename "$dest") | age -r AGE_RECIPIENT -o /mnt/offhost/idoris-vpn-\$(date -u +\\%Y\\%m\\%d).tar.age
A systemd timer that runs the same command is equivalent. Keep the age
identity off this host.
EOF
    ;;
  restore)
    dest="${1:-}"
    force=0
    [[ -n "$dest" ]] || die "usage: ctl.sh restore DIR --force"
    shift || true
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --force) force=1; shift ;;
        *) die "unknown argument: $1" ;;
      esac
    done
    (( force )) || die "refusing to overwrite the live deployment without --force"
    for rel in \
      manifest.json \
      headscale/db.sqlite \
      headscale/noise_private.key \
      state/enroll/config.json \
      state/enroll/headscale.apikey \
      state/headplane/cookie_secret \
      state/dotenv \
      state/headscale/managed.json \
      state/headscale/config.yaml \
      state/headscale/policy.hujson \
      state/headplane/config.yaml \
      state/compose.yaml
    do
      [[ -f "$dest/$rel" && ! -L "$dest/$rel" ]] || die "backup is missing $rel"
    done
    mode="$(read_admin_mode)"
    if [[ -f "$dest/admin-mode" ]]; then
      saved="$(sed -n 's/^mode=//p' "$dest/admin-mode" | head -n1 | tr -d '[:space:]')"
      case "$saved" in
        published|tailnet-admin) mode="$saved" ;;
        *) die "backup admin-mode is '$saved'" ;;
      esac
    fi
    # Host files first: compose refuses to create missing secret bind sources.
    restore_private "$dest/state/enroll/config.json" "$here/enroll/config.json"
    restore_private "$dest/state/enroll/headscale.apikey" "$here/enroll/headscale.apikey"
    restore_private "$dest/state/headplane/cookie_secret" "$here/headplane/cookie_secret"
    restore_private "$dest/state/dotenv" "$here/.env"
    restore_private "$dest/state/headscale/managed.json" "$here/headscale/managed.json"
    restore_private "$dest/state/headscale/config.yaml" "$here/headscale/config.yaml"
    restore_private "$dest/state/headscale/policy.hujson" "$here/headscale/policy.hujson"
    restore_private "$dest/state/headplane/config.yaml" "$here/headplane/config.yaml"
    restore_private "$dest/state/compose.yaml" "$here/compose.yaml"
    apply_restored_mode "$dest/manifest.json" "state/dotenv" "$here/.env"
    apply_restored_mode "$dest/manifest.json" "state/enroll/config.json" "$here/enroll/config.json"
    apply_restored_mode "$dest/manifest.json" "state/enroll/headscale.apikey" "$here/enroll/headscale.apikey"
    apply_restored_mode "$dest/manifest.json" "state/headplane/cookie_secret" "$here/headplane/cookie_secret"
    apply_restored_mode "$dest/manifest.json" "state/headscale/managed.json" "$here/headscale/managed.json"
    apply_restored_mode "$dest/manifest.json" "state/headscale/config.yaml" "$here/headscale/config.yaml"
    apply_restored_mode "$dest/manifest.json" "state/headscale/policy.hujson" "$here/headscale/policy.hujson"
    apply_restored_mode "$dest/manifest.json" "state/headplane/config.yaml" "$here/headplane/config.yaml"
    apply_restored_mode "$dest/manifest.json" "state/compose.yaml" "$here/compose.yaml"
    write_admin_mode "$mode"
    snap="$(mktemp "$here/.running.XXXXXX")"
    snapshot_running "$snap"
    if snapshot_has "$snap" headscale || [[ -n "$(_compose_ps_id headscale)" ]]; then
      docker compose stop headscale >/dev/null 2>&1 || true
    fi
    stop_headplane_writers
    if snapshot_has "$snap" enroll || [[ -n "$(_compose_ps_id enroll)" ]]; then
      docker compose stop enroll >/dev/null 2>&1 || true
    fi
    ensure_mode_containers "$mode"
    docker compose stop headscale enroll >/dev/null 2>&1 || true
    stop_headplane_writers
    hsid="$(_compose_ps_id headscale)"
    hpid="$(headplane_writer_id "$mode")"
    [[ -n "$hsid" ]] || die "headscale container is missing after create"
    # A newer WAL would replay over the restored database. Remove it when
    # this backup has none, before the database file is copied in.
    if [[ ! -f "$dest/headscale/db.sqlite-wal" ]]; then
      wipe_headscale_wal "$hsid"
    fi
    docker cp "$dest/headscale/db.sqlite" "$hsid:/var/lib/headscale/db.sqlite"
    docker cp "$dest/headscale/noise_private.key" "$hsid:/var/lib/headscale/noise_private.key"
    docker cp "$dest/headscale/derp_server_private.key" "$hsid:/var/lib/headscale/derp_server_private.key"
    if [[ -f "$dest/headscale/db.sqlite-wal" ]]; then
      docker cp "$dest/headscale/db.sqlite-wal" "$hsid:/var/lib/headscale/db.sqlite-wal"
    fi
    if [[ -f "$dest/headscale/db.sqlite-shm" ]]; then
      docker cp "$dest/headscale/db.sqlite-shm" "$hsid:/var/lib/headscale/db.sqlite-shm"
    fi
    if [[ -d "$dest/headplane" ]]; then
      docker cp "$dest/headplane/." "$hpid:/var/lib/headplane/"
    fi
    docker compose start headscale headplane enroll >/dev/null
    echo "restored from $dest and started the stack"
    ;;
  up)
    if [[ "${1:-}" == "--tailnet-admin" ]]; then
      [[ -n "${VPN_SERVER_ENROLL_TOKEN:-}" ]] || die "export VPN_SERVER_ENROLL_TOKEN (the vpn-server enrollment token) first"
      # One writer of the Headplane sqlite. The published UI and the tailnet UI do not run together.
      docker compose stop headplane >/dev/null 2>&1 || true
      docker compose --profile tailnet-admin up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet headscale enroll
      echo "tailnet-admin profile is up. Headplane listens on the vpn-server tailnet address port 3000."
      echo "The published Headplane container is stopped. 'ctl.sh up' (without the flag) brings it back and stops the profile."
    else
      docker compose --profile tailnet-admin stop vpn-sidecar headplane-tailnet >/dev/null 2>&1 || true
      docker compose up -d --wait --wait-timeout 180
    fi
    ;;
  down)
    docker compose --profile tailnet-admin down
    ;;
  upgrade)
    cat <<'EOF'
Upgrade notes (Headscale refuses to skip a minor version, and refuses to
downgrade across minors):

  1. Read the Headscale release notes for the version you are leaving and the
     one you are entering. Do not jump more than one minor.
  2. bash deploy/vpn/ctl.sh backup
  3. Change the image tags in deploy/vpn/compose.yaml (headscale, headplane).
     Leave idoris-vpn-enroll on this repo's Dockerfile.
  4. docker compose pull
  5. docker compose up -d
  6. bash deploy/vpn/ctl.sh health
  7. bash deploy/vpn/ctl.sh policy check
  8. From a member: idoris-vpnd status, then reach the Local AI host.

This command does not pull or recreate anything. Roll back by restoring the
backup onto the previous image tags; do not restore an older sqlite into a
newer minor that has already migrated it.
EOF
    ;;
  break-glass)
    cat <<'EOF'
Headscale is down and the tailnet will not come up. Use the server host SSH,
not Tailscale SSH (that path needs Headscale).

  - SSH is key-only. Keep a local admin key that is not stored only on a
    tailnet node.
  - Host firewall, public interface: 443/tcp (Headscale via the TLS proxy),
    3478/udp (embedded DERP STUN), 22/tcp (this SSH). Nothing else.
  - Do not publish Headplane (3000) or enroll (8787) on a public address.
    The compose default binds both to 127.0.0.1. Reach Headplane through an
    SSH tunnel: ssh -L 3000:127.0.0.1:3000 user@server
    then open http://127.0.0.1:3000/admin
  - Put the TLS proxy's rate limit in front of Headscale and the enroll host.
  - While Headscale is down: nodes already up keep their last WireGuard
    sessions until the map expires, but new enrollments and re-logins fail.
    Fix the process with docker compose (from deploy/vpn), or restore a
    backup with ctl.sh restore. The noise and DERP private keys must come
    back with the sqlite file or every node must re-enroll.
EOF
    ;;
  *)
    usage >&2
    die "unknown command: $cmd"
    ;;
esac
