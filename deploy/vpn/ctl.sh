#!/usr/bin/env bash
# Operate the iDoris VPN stack from a shell on the server.
# Resolves the compose directory from this file, so the working directory
# does not matter. Secrets are printed only by `apikeys create`, whose
# purpose is to mint one.
#
#   bash deploy/vpn/ctl.sh help
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

die() { echo "ctl: $*" >&2; exit 1; }

hs() { docker compose exec -T headscale headscale "$@"; }

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
  logs [service] [--tail N]      service: headscale, headplane, enroll,
                                 vpn-sidecar, headplane-tailnet
  backup [DIR]                   stop headscale, copy sqlite + keys + headplane
                                 data, start again. Prints restore notes.
  restore DIR --force            stop, copy a backup back, start
  up [--tailnet-admin]           start the stack. --tailnet-admin stops the
                                 published Headplane and starts the profile
                                 that publishes it only on the tailnet.
  down                           docker compose down (keeps volumes)
  upgrade                        print the upgrade procedure
  break-glass                    print the SSH checklist for when Headscale is down

The compose project is the one in this directory (or COMPOSE_PROJECT_NAME /
.env). HEADPLANE_BIND defaults to 127.0.0.1; see docs/14-VPN-OPERATIONS.md.
EOF
}

require_id() {
  local id="${1:-}"
  [[ "$id" =~ ^[0-9]+$ ]] || die "identifier must be a decimal node or key id"
  printf '%s' "$id"
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
    mkdir -p "$dest/headscale" "$dest/headplane"
    echo "stopping headscale and headplane for a consistent sqlite copy..."
    docker compose stop headscale headplane
    cleanup_backup() {
      docker compose start headscale headplane >/dev/null 2>&1 || true
    }
    trap cleanup_backup EXIT
    hsid="$(docker compose ps -aq headscale)"
    hpid="$(docker compose ps -aq headplane)"
    [[ -n "$hsid" && -n "$hpid" ]] || die "headscale or headplane container is missing; start the stack first"
    docker cp "$hsid:/var/lib/headscale/db.sqlite" "$dest/headscale/db.sqlite"
    docker cp "$hsid:/var/lib/headscale/noise_private.key" "$dest/headscale/noise_private.key"
    docker cp "$hsid:/var/lib/headscale/derp_server_private.key" "$dest/headscale/derp_server_private.key"
    docker cp "$hsid:/var/lib/headscale/db.sqlite-wal" "$dest/headscale/db.sqlite-wal" 2>/dev/null || true
    docker cp "$hsid:/var/lib/headscale/db.sqlite-shm" "$dest/headscale/db.sqlite-shm" 2>/dev/null || true
    docker cp "$hpid:/var/lib/headplane/." "$dest/headplane/"
    trap - EXIT
    docker compose start headscale headplane >/dev/null
    chmod 700 "$dest" "$dest/headscale" "$dest/headplane"
    echo "backup written to $dest"
    cat <<EOF

Restore (overwrites the live database; the stack is stopped during the copy):
  bash $here/ctl.sh restore $dest --force
The backup includes db.sqlite, db.sqlite-wal, db.sqlite-shm (when present),
noise_private.key, derp_server_private.key, and the Headplane data directory.
policy.hujson and the compose files are not in the volume; keep them with git.
Do not restore a backup onto a newer Headscale minor than the one that wrote it.
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
    [[ -f "$dest/headscale/db.sqlite" ]] || die "no db.sqlite in $dest/headscale"
    [[ -f "$dest/headscale/noise_private.key" ]] || die "no noise_private.key in $dest"
    [[ -f "$dest/headscale/derp_server_private.key" ]] || die "no derp_server_private.key in $dest"
    (( force )) || die "refusing to overwrite the live database without --force"
    docker compose stop headscale headplane enroll
    hsid="$(docker compose ps -aq headscale)"
    hpid="$(docker compose ps -aq headplane)"
    [[ -n "$hsid" && -n "$hpid" ]] || die "containers are missing; 'docker compose up' once before restoring into them"
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
