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

hs() { compose exec -T headscale headscale "$@"; }

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
                                 [--hostname-hint H]
                                 pass --label to idoris-vpn-enroll invite.
                                 Plaintext is appended to enroll/minted-tokens.txt
                                 before any later check. Prints the token, the
                                 join code, and the 12-character hash prefix.
  token list --entry NAME        label, hash prefix, created_at. No tokens
                                 and no full hashes. An unlabeled credential
                                 is listed as "-".
  token revoke --entry NAME (--label LABEL | --hash-prefix HEX)
                                 [--allow-empty]
                                 exactly one selector, passed to the enroll
                                 CLI. Then restart enroll. Refuses to remove
                                 the last credential unless --allow-empty.
  offboard --entry NAME (--label LABEL | --hash-prefix HEX)
                                 [--node-id N] [--allow-empty]
                                 revoke that credential first. Only if revoke
                                 succeeds, expire and delete the node.
                                 --node-id is optional. Revoking the last
                                 credential needs --allow-empty; without it
                                 the node is not expired or deleted.
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

# ENROLL_DIR is an absolute directory for tests. Unset means ./enroll.
enroll_dir() {
  local dir
  if [[ -n "${ENROLL_DIR:-}" ]]; then
    dir="$ENROLL_DIR"
    [[ "$dir" == /* ]] || die "ENROLL_DIR must be an absolute path"
    [[ -d "$dir" && ! -L "$dir" ]] || die "ENROLL_DIR must be a real directory"
  else
    dir="$here/enroll"
  fi
  printf '%s' "$dir"
}

# Writable mount of the enroll directory: invite writes a temp file next to
# config.json. The image rootfs is read-only; this directory is not.
enroll_cli() {
  compose run --rm --no-deps -T \
    --user "$(enroll_run_user)" \
    --entrypoint idoris-vpn-enroll \
    -v "$(enroll_dir):/work" \
    enroll "$@"
}

reload_enroll() {
  if service_running enroll; then
    # invite and revoke replace config.json by rename. A file bind keeps the
    # old inode, so SIGHUP does not see the new file. Restart re-binds the
    # path. bootstrap.sh does the same after it renames this file.
    compose restart enroll >/dev/null
    echo "restarted enroll so it reloads config.json"
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

require_one_selector() {
  local label="$1" prefix="$2" usage="$3"
  if [[ -n "$label" && -n "$prefix" ]]; then
    die "$usage"
  fi
  if [[ -z "$label" && -z "$prefix" ]]; then
    die "$usage"
  fi
  if [[ -n "$label" ]]; then
    require_label "$label"
  else
    require_hash_prefix "$prefix"
  fi
}

# Print the CLI success line (revoked, entry, label-or-dash, 12-hex prefix).
# Return 2 when the CLI refuses to remove the last credential, 1 on any
# other failure. This function does not expire or delete a node.
revoke_one() {
  local entry="$1" label="$2" prefix="$3" allow_empty="${4:-0}"
  local revoked line got_cmd got_entry got_label got_prefix extra
  local want shown
  local -a args
  args=(revoke --config /work/config.json --entry "$entry")
  if [[ -n "$label" ]]; then
    args+=(--label "$label")
  else
    args+=(--hash-prefix "$prefix")
  fi
  if [[ "$allow_empty" == "1" ]]; then
    args+=(--allow-empty)
  fi
  if ! revoked="$(enroll_cli "${args[@]}" 2>&1)"; then
    printf '%s\n' "$revoked" >&2
    if [[ "$revoked" == *"refusing to remove the last token hash"* ]]; then
      return 2
    fi
    return 1
  fi
  line="$(printf '%s\n' "$revoked" | tr -d '\r' | sed -n '/^revoked[[:space:]]/p' | head -n1)"
  if [[ -z "$line" ]]; then
    echo "ctl: revoke did not print a revoked line" >&2
    return 1
  fi
  extra=""
  IFS=' ' read -r got_cmd got_entry got_label got_prefix extra <<< "$line"
  if [[ "$got_cmd" != "revoked" || "$got_entry" != "$entry" || -z "$got_label" || -n "${extra:-}" ]]; then
    echo "ctl: revoke line does not have 4 fields: $line" >&2
    return 1
  fi
  if [[ ! "$got_prefix" =~ ^[0-9a-fA-F]{12}$ ]]; then
    echo "ctl: revoke line prefix is not 12 hex digits" >&2
    return 1
  fi
  if [[ -n "$label" && "$got_label" != "$label" ]]; then
    echo "ctl: revoke line label is '$got_label', expected '$label'" >&2
    return 1
  fi
  if [[ -z "$label" ]]; then
    want="$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]')"
    shown="$(printf '%s' "$got_prefix" | tr '[:upper:]' '[:lower:]')"
    if [[ "${#want}" -le 12 ]]; then
      [[ "$shown" == "$want"* ]] || { echo "ctl: revoke line prefix does not match" >&2; return 1; }
    else
      [[ "$want" == "$shown"* ]] || { echo "ctl: revoke line prefix does not match" >&2; return 1; }
    fi
  fi
  printf '%s\n' "$line"
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
    compose ps
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
        compose kill -s HUP headscale >/dev/null
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
      compose logs --tail "$tailn" "$service" | redact
    else
      compose logs --tail "$tailn" | redact
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
      hs_version="$(compose exec -T headscale headscale version 2>/dev/null | tr -d '\r' || echo unknown)"
    fi
    snap="$(mktemp "$here/.running.XXXXXX")"
    snapshot_running "$snap"
    mkdir -p "$dest/headscale" "$dest/headplane" "$dest/state"
    cleanup_backup() {
      restore_running_services "$snap" "$mode" || true
      rm -f "$snap"
    }
    trap cleanup_backup EXIT
    echo "stopping the running Headplane writer, sidecar and headscale (mode=$mode)..."
    if snapshot_has "$snap" headplane-tailnet; then
      compose --profile tailnet-admin stop headplane-tailnet
    fi
    if [[ -n "$(_compose_ps_id vpn-sidecar)" ]]; then
      compose --profile tailnet-admin stop vpn-sidecar
    fi
    if snapshot_has "$snap" headscale; then
      compose stop headscale
    fi
    stop_headplane_writers
    hsid="$(compose ps -aq headscale)"
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
    copy_sidecar_state "$dest/sidecar/state.tar"
    if [[ -f "$(admin_mode_file)" ]]; then
      copy_private "$(admin_mode_file)" "$dest/admin-mode"
    fi
    write_backup_manifest "$dest" "$mode" "$hs_version"
    seal_tree "$dest"
    trap - EXIT
    restore_running_services "$snap" "$mode"
    rm -f "$snap"
    printf 'backup_dir=%s\n' "$dest"
    echo "backup written to $dest (admin mode $mode; the other Headplane was not started)"
    cat <<EOF

Restore (overwrites the live database and the host state files):
  bash $here/ctl.sh restore $dest --force
The other Headplane stays stopped. Do not restore a backup onto a newer
Headscale minor than the one that wrote it.
The checkout compose.yaml is not replaced. sidecar/state.tar, when present,
is the admin node's private key: mode 0700 on the directory, encrypt it
before it leaves the machine.

Off-host copy. Each run takes a new snapshot, then archives that snapshot.
Monitor idoris-vpn-backup.created (the bundle created_utc), not the archive mtime.
Keep the age identity off this host.

$(offhost_cron_line "$here/offhost-backup.sh" "/mnt/offhost")
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
    restore_deployment "$dest"
    ;;
  up)
    mode="$(read_admin_mode)"
    instance=""
    access=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --tailnet-admin)
          mode="tailnet-admin"
          shift
          ;;
        --published)
          mode="published"
          shift
          ;;
        --instance)
          [[ $# -ge 2 ]] || die "--instance needs a value"
          instance="$2"
          shift 2
          ;;
        --headplane-access)
          [[ $# -ge 2 ]] || die "--headplane-access needs a value"
          access="$2"
          shift 2
          ;;
        *)
          die "unknown argument: $1"
          ;;
      esac
    done
    if [[ -n "$instance" ]]; then
      assign_instance "$instance"
    fi
    if [[ "$mode" == "tailnet-admin" && -n "$access" && "$access" != "tailnet" ]]; then
      die "--tailnet-admin cannot be combined with --headplane-access $access"
    fi
    if [[ "$mode" == "tailnet-admin" ]]; then
      access="${access:-tailnet}"
    elif [[ -z "$access" && -f "$here/.env" ]]; then
      access="$(sed -n 's/^HEADPLANE_ACCESS=//p' "$here/.env" | head -n1 | tr -d '[:space:]')"
      if [[ "$access" == "tailnet" ]]; then
        access="tunnel"
      fi
    fi
    apply_headplane_access "${access:-tunnel}"
    mode="$(read_admin_mode)"
    if [[ "$mode" == "tailnet-admin" && -z "${VPN_SERVER_ENROLL_TOKEN:-}" ]]; then
      die "export VPN_SERVER_ENROLL_TOKEN (the vpn-server enrollment token) first"
    fi
    write_admin_mode "$mode"
    start_stack_for_mode "$mode"
    ;;
  down)
    compose --profile tailnet-admin down
    ;;
  upgrade)
    cat <<'EOF'
Upgrade notes (Headscale refuses to skip a minor version, and refuses to
downgrade across minors):

  1. Read the Headscale release notes for the version you are leaving and the
     one you are entering. Do not jump more than one minor.
  2. bash deploy/vpn/ctl.sh backup
  3. Change the image tags in deploy/vpn/compose.yaml (headscale, headplane).
     Leave idoris-vpn-enroll on this repo's Dockerfile. Keep the digest pin.
  4. docker compose pull
  5. bash deploy/vpn/ctl.sh up
     This restarts the saved admin mode (.admin-mode). It does not start the
     published Headplane when the mode is tailnet-admin, and it does not
     start the tailnet profile when the mode is published.
  6. bash deploy/vpn/ctl.sh health
  7. bash deploy/vpn/ctl.sh policy check
  8. From a member: idoris-vpnd status, then reach the Local AI host.

Do not run plain 'docker compose up -d' on a tailnet-admin host: that starts
the published Headplane beside the tailnet one. This command does not pull
or recreate anything. Roll back by restoring the backup onto the previous
image tags; do not restore an older sqlite into a newer minor that has
already migrated it.
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
  token)
    sub="${1:-}"
    shift || true
    case "$sub" in
      new)
        entry="" label="" url="" hint=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --entry) entry="${2:-}"; shift 2 ;;
            --label) label="${2:-}"; shift 2 ;;
            --enroll-url) url="${2:-}"; shift 2 ;;
            --hostname-hint) hint="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        [[ -n "$entry" && -n "$label" ]] || die "usage: ctl.sh token new --entry NAME --label LABEL [--enroll-url URL]"
        require_label "$label"
        [[ -f "$(enroll_dir)/config.json" && ! -L "$(enroll_dir)/config.json" ]] || die "enroll/config.json is missing"
        if [[ -z "$url" && -f "$here/.env" ]]; then
          url="$(sed -n 's/^ENROLL_PUBLIC_URL=//p' "$here/.env" | head -n1 | tr -d "\"'" | tr -d '[:space:]')"
        fi
        [[ -n "$url" ]] || die "pass --enroll-url or set ENROLL_PUBLIC_URL in .env"
        [[ "$url" == http://* || "$url" == https://* ]] || die "enroll URL must start with http:// or https://"
        args=(invite --config /work/config.json --entry "$entry" --enroll-url "$url" --label "$label")
        if [[ "$url" == http://* ]]; then
          args+=(--allow-insecure)
        fi
        if [[ -n "$hint" ]]; then
          args+=(--hostname-hint "$hint")
        fi
        # stdout is the join code. stderr stays on the terminal so a refused
        # label is visible. A failed invite has nothing to persist.
        if ! raw="$(enroll_cli "${args[@]}")"; then
          die "invite failed"
        fi
        # Persist before decode or list-credentials. Either of those can fail
        # after the credential is already on disk.
        minted="$(enroll_dir)/minted-tokens.txt"
        printf '# minted %s\n%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$raw" >> "$minted"
        chmod 600 "$minted"
        code="$(printf '%s\n' "$raw" | tr -d '\r' | grep -oE 'idoris-join-v1\.[A-Za-z0-9_-]+\.[0-9a-fA-F]+' | head -n1 || true)"
        [[ -n "$code" ]] || die "invite output had no join code; the raw output is in $minted"
        if ! token="$(python3 -c '
import base64, json, sys
code = sys.argv[1].strip()
parts = code.split(".")
if len(parts) != 3 or parts[0] != "idoris-join-v1":
    sys.exit("invite did not print a join code")
raw = base64.urlsafe_b64decode(parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4))
sys.stdout.write(json.loads(raw)["token"])
' "$code")"; then
          die "invite output had no token; the raw output is in $minted"
        fi
        prefix="$(python3 -c 'import hashlib,sys; sys.stdout.write(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:12])' "$token")"
        if ! listed="$(enroll_cli list-credentials --config /work/config.json --entry "$entry")"; then
          die "list-credentials failed; the raw invite output is in $minted"
        fi
        if ! printf '%s\n' "$listed" | python3 -c '
import sys
label, prefix = sys.argv[1], sys.argv[2].lower()
found = 0
for line in sys.stdin:
    parts = line.rstrip("\n").split("\t")
    if len(parts) != 3 or parts[0] != label:
        continue
    found += 1
    if parts[1].lower() != prefix:
        sys.exit("label %s is listed with prefix %s, expected %s" % (label, parts[1], prefix))
if found != 1:
    sys.exit("label %s was listed %d times after invite" % (label, found))
' "$label" "$prefix"; then
          die "credential $label was not listed; the raw invite output is in $minted"
        fi
        reload_enroll
        echo "entry:  $entry"
        echo "label:  $label"
        echo "hash:   $prefix"
        echo "token:  $token"
        echo "join:   $code"
        ;;
      list)
        entry=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --entry) entry="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        [[ -n "$entry" ]] || die "usage: ctl.sh token list --entry NAME"
        [[ -f "$(enroll_dir)/config.json" && ! -L "$(enroll_dir)/config.json" ]] || die "enroll/config.json is missing"
        enroll_cli list-credentials --config /work/config.json --entry "$entry"
        ;;
      revoke)
        entry="" label="" prefix="" allow_empty=0
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --entry) entry="${2:-}"; shift 2 ;;
            --label) label="${2:-}"; shift 2 ;;
            --hash-prefix) prefix="${2:-}"; shift 2 ;;
            --allow-empty) allow_empty=1; shift ;;
            *) die "unknown argument: $1" ;;
          esac
        done
        [[ -n "$entry" ]] || die "usage: ctl.sh token revoke --entry NAME (--label LABEL | --hash-prefix HEX) [--allow-empty]; exactly one of --label or --hash-prefix"
        require_one_selector "$label" "$prefix" "usage: ctl.sh token revoke --entry NAME (--label LABEL | --hash-prefix HEX) [--allow-empty]; exactly one of --label or --hash-prefix"
        echo "revoking $entry ${label:-${prefix:0:8}}..."
        set +e
        line="$(revoke_one "$entry" "$label" "$prefix" "$allow_empty")"
        rc=$?
        set -e
        if [[ "$rc" -eq 2 ]]; then
          die "refusing to remove the last token for $entry; pass --allow-empty to revoke the last credential"
        fi
        if [[ "$rc" -ne 0 ]]; then
          die "revoke failed; the node was not changed"
        fi
        printf '%s\n' "$line"
        reload_enroll
        ;;
      *)
        die "usage: ctl.sh token new|list|revoke"
        ;;
    esac
    ;;
  offboard)
    entry="" label="" prefix="" node="" allow_empty=0
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --entry) entry="${2:-}"; shift 2 ;;
        --label) label="${2:-}"; shift 2 ;;
        --hash-prefix) prefix="${2:-}"; shift 2 ;;
        --node-id) node="${2:-}"; shift 2 ;;
        --allow-empty) allow_empty=1; shift ;;
        *) die "unknown argument: $1" ;;
      esac
    done
    [[ -n "$entry" ]] || die "usage: ctl.sh offboard --entry NAME (--label LABEL | --hash-prefix HEX) [--node-id N] [--allow-empty]; exactly one of --label or --hash-prefix"
    require_one_selector "$label" "$prefix" "usage: ctl.sh offboard --entry NAME (--label LABEL | --hash-prefix HEX) [--node-id N] [--allow-empty]; exactly one of --label or --hash-prefix"
    if [[ -n "$node" ]]; then
      node="$(require_id "$node")"
    fi
    if [[ -n "$label" ]]; then
      echo "step 1: revoke $entry label $label (stop here if this fails)"
    else
      echo "step 1: revoke $entry hash prefix ${prefix:0:8} (stop here if this fails)"
    fi
    set +e
    line="$(revoke_one "$entry" "$label" "$prefix" "$allow_empty")"
    rc=$?
    set -e
    if [[ "$rc" -eq 2 ]]; then
      die "refusing to remove the last token for $entry; pass --allow-empty to revoke the last credential. The node was not expired or deleted"
    fi
    if [[ "$rc" -ne 0 ]]; then
      die "revoke failed; the node was not expired or deleted"
    fi
    printf '%s\n' "$line"
    echo "step 2: reload enroll"
    reload_enroll
    if [[ -n "$node" ]]; then
      echo "step 3: expire node $node"
      hs nodes expire --identifier "$node"
      echo "step 4: delete node $node"
      hs --force nodes delete --identifier "$node"
    else
      echo "step 3: no --node-id, so no node was expired or deleted"
    fi
    echo "offboarded entry $entry"
    ;;
  *)
    usage >&2
    die "unknown command: $cmd"
    ;;
esac
