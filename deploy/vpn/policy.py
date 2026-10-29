#!/usr/bin/env python3
"""Render the idoris-managed regions of deploy/vpn/headscale/policy.hujson.

Operators run this through bootstrap.sh. It rewrites only the marked regions.
Rules outside the markers are kept, so a hand-written exception survives the
next init or add-tenant. Content inside the markers is regenerated and is not
a place to hand-edit.

State (org names, LAN CIDRs, admin users) lives in headscale/managed.json,
which is gitignored. If that file is missing it is reconstructed from the
markers so a re-run does not wipe existing organisations.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

from enroll_lock import LeaveUnchanged, locked_update

DEFAULT_ORG = "office"
DEFAULT_ADMIN = "admin"
NAME_RE = re.compile(r"^[a-z]([a-z0-9-]*[a-z0-9])?$")
MARKER_RE = re.compile(
    r"// BEGIN idoris-managed (?P<name>[a-zA-Z0-9_-]+)\n(?P<body>.*?)// END idoris-managed (?P=name)\n",
    re.DOTALL,
)
REGIONS = ("admins", "tagOwners", "acls", "ssh", "routes")

# Ports a member may open on their own Local AI host (tagged node).
LOCAL_AI_PORTS = (
    (8740, "iDoris data plane"),
    (8742, "Agent24 daemon"),
    (443, "HTTPS"),
)
# Ports a member may open on the office LAN through the subnet router.
# 11434 is Ollama's default listen port, for a LAN box that does not run Tailscale.
LAN_PORTS = LOCAL_AI_PORTS + ((11434, "Ollama on the LAN host"),)


def die(message: str) -> None:
    print(f"policy: {message}", file=sys.stderr)
    raise SystemExit(1)


def valid_name(name: str, what: str) -> str:
    if not NAME_RE.match(name or ""):
        die(f"invalid {what} '{name}' (lowercase letters, digits, '-'; must start with a letter)")
    if name == "vpn-server" or name.endswith("-local-ai") or name.endswith("-gateway"):
        die(f"{what} '{name}' is reserved (vpn-server, or a name ending in -local-ai / -gateway)")
    return name


# Tailscale CGNAT and the Headscale IPv6 prefix. A LAN grant that overlaps
# either of these is a grant onto other nodes, not onto an office LAN.
TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")
TAILNET_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")
RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
ULA_V6 = ipaddress.ip_network("fc00::/7")
_FORBIDDEN_V4 = (
    ("unspecified", ipaddress.ip_network("0.0.0.0/8")),
    ("loopback", ipaddress.ip_network("127.0.0.0/8")),
    ("link-local", ipaddress.ip_network("169.254.0.0/16")),
    ("multicast", ipaddress.ip_network("224.0.0.0/4")),
    ("reserved", ipaddress.ip_network("240.0.0.0/4")),
)
_FORBIDDEN_V6 = (
    ("unspecified", ipaddress.ip_network("::/128")),
    ("loopback", ipaddress.ip_network("::1/128")),
    ("link-local", ipaddress.ip_network("fe80::/10")),
    ("multicast", ipaddress.ip_network("ff00::/8")),
)


def warn(message: str) -> None:
    print(f"policy: warning: {message}", file=sys.stderr)


def _parse_network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if not isinstance(text, str) or any(ch.isspace() for ch in text):
        die(f"invalid LAN CIDR {text!r}: whitespace is not allowed")
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        die(f"invalid LAN CIDR '{text}': {exc}")
    return net


def _is_rfc1918_or_ula(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if net.version == 4:
        return any(net.subnet_of(block) for block in RFC1918)
    return bool(net.subnet_of(ULA_V6))


def _classify(net: ipaddress.IPv4Network | ipaddress.IPv6Network, *, allow_public: bool, already_public: bool) -> str:
    """Return 'private' or 'public'. Exits on anything that must not be a LAN grant."""
    if net.prefixlen == 0:
        die(
            f"LAN CIDR {net} is an exit-node route (/0) and overlaps the tailnet; "
            "this deployment does not auto-approve it"
        )
    if net.version == 4 and net.overlaps(TAILNET_V4):
        die(f"LAN CIDR {net} overlaps the tailnet range {TAILNET_V4}")
    if net.version == 6 and net.overlaps(TAILNET_V6):
        die(f"LAN CIDR {net} overlaps the tailnet range {TAILNET_V6}")
    if net.version == 6:
        for addr in (net.network_address, net.broadcast_address):
            if getattr(addr, "ipv4_mapped", None) is not None:
                die(f"LAN CIDR {net} is an IPv4-mapped IPv6 prefix")
    forbidden = _FORBIDDEN_V4 if net.version == 4 else _FORBIDDEN_V6
    for label, block in forbidden:
        if net.overlaps(block):
            die(f"LAN CIDR {net} overlaps {label} range {block}")
    if _is_rfc1918_or_ula(net):
        return "private"
    if allow_public or already_public:
        warn(
            f"PUBLIC CIDR {net} is not RFC1918 and not IPv6 ULA (fc00::/7). "
            "It will be placed in this organisation's ACL and autoApprovers. "
            "Do this only when that prefix is really the office LAN."
        )
        return "public"
    die(
        f"LAN CIDR {net} is not private address space "
        "(IPv4 RFC1918, or IPv6 ULA fc00::/7). "
        "169.254.0.0/16 and 100.64.0.0/10 are rejected. "
        "Pass --allow-public-cidr to acknowledge a public prefix."
    )


def parse_cidr(text: str, *, allow_public: bool = False) -> str:
    """Normalise a CLI prefix. Policy (private, overlap, tailnet) is applied in validate_state.

    allow_public is accepted so callers can pass the flag through; the decision
    itself happens when the whole state is re-validated.
    """
    del allow_public
    return str(_parse_network(text))


def _normalise_org_lists(org: dict) -> None:
    org.setdefault("lan_cidrs", [])
    org.setdefault("public_cidrs", [])
    org.setdefault("ai_callback_ports", [])
    if not isinstance(org["lan_cidrs"], list) or not isinstance(org["public_cidrs"], list):
        die(f"organisation '{org.get('name', '?')}' has a non-list CIDR field")


def validate_state(state: dict, *, allow_public: bool, requested: list[str]) -> None:
    """Re-check every persisted prefix, not only the ones passed on this command line."""
    requested_set = set(requested)
    seen: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
    for org in state["orgs"]:
        name = org["name"]
        _normalise_org_lists(org)
        acked = set(org["public_cidrs"])
        normalised: list[str] = []
        public_now: list[str] = []
        for cidr in org["lan_cidrs"]:
            net = _parse_network(str(cidr))
            text = str(net)
            kind = _classify(
                net,
                allow_public=allow_public and text in requested_set,
                already_public=text in acked,
            )
            for prev_org, prev_net, prev_text in seen:
                if not net.overlaps(prev_net):
                    continue
                if prev_org != name:
                    die(
                        f"LAN CIDR {text} ({name}) overlaps {prev_text} ({prev_org}). "
                        "Prefixes owned by different organisations must not overlap or nest. "
                        "Use a distinct prefix, or a separate deploy/vpn stack."
                    )
                if prev_text != text:
                    warn(
                        f"organisation '{name}' has overlapping prefixes {prev_text} and {text}. "
                        "The wider grant includes the narrower one."
                    )
            seen.append((name, net, text))
            if text not in normalised:
                normalised.append(text)
            if kind == "public" and text not in public_now:
                public_now.append(text)
        org["lan_cidrs"] = normalised
        org["public_cidrs"] = public_now


def marker_bodies(text: str) -> dict[str, str]:
    found = {m.group("name"): m.group("body") for m in MARKER_RE.finditer(text)}
    missing = [name for name in REGIONS if name not in found]
    if missing:
        die("policy file is missing marker regions: " + ", ".join(missing))
    return found


def replace_region(text: str, name: str, body: str) -> str:
    if body and not body.endswith("\n"):
        body += "\n"
    pattern = re.compile(
        rf"// BEGIN idoris-managed {name}\n.*?// END idoris-managed {name}\n",
        re.DOTALL,
    )
    replacement = f"// BEGIN idoris-managed {name}\n{body}// END idoris-managed {name}\n"
    new, n = pattern.subn(replacement, text, count=1)
    if n != 1:
        die(f"could not replace marker region '{name}'")
    return new


def empty_state() -> dict:
    return {"version": 1, "admins": [], "orgs": [], "tailnet_admin": False}


def reconstruct(policy_text: str) -> dict:
    """Recover state from a previously rendered policy. Best-effort."""
    bodies = marker_bodies(policy_text)
    state = empty_state()
    for match in re.finditer(r'"([a-z0-9-]+)@"', bodies["admins"]):
        if match.group(1) not in state["admins"]:
            state["admins"].append(match.group(1))
    orgs: dict[str, dict] = {}
    for match in re.finditer(r'"tag:([a-z0-9-]+)-local-ai"', bodies["tagOwners"]):
        name = match.group(1)
        orgs.setdefault(name, {"name": name, "lan_cidrs": []})
    for match in re.finditer(
        r'"(\d+\.\d+\.\d+\.\d+/\d+)":\s*\["tag:([a-z0-9-]+)-gateway"\]',
        bodies["routes"],
    ):
        cidr, name = match.group(1), match.group(2)
        org = orgs.setdefault(name, {"name": name, "lan_cidrs": []})
        if cidr not in org["lan_cidrs"]:
            org["lan_cidrs"].append(cidr)
    state["orgs"] = list(orgs.values())
    return state


def load_state(path: Path, policy_text: str) -> tuple[dict, bool]:
    if not path.exists():
        return reconstruct(policy_text), False
    try:
        state = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        die(f"cannot parse {path}: {exc}")
    if not isinstance(state, dict) or state.get("version") != 1:
        die(f"{path} is not a version-1 state file; refusing to overwrite the policy")
    state.setdefault("admins", [])
    state.setdefault("orgs", [])
    state.setdefault("tailnet_admin", False)
    return state, True


def org_by_name(state: dict, name: str) -> dict | None:
    for org in state["orgs"]:
        if org["name"] == name:
            return org
    return None


def merge_cidrs(state: dict, org_name: str, cidrs: list[str]) -> None:
    """Append prefixes. Overlap is rejected later by validate_state, which uses network math."""
    org = org_by_name(state, org_name)
    if org is None:
        die(f"internal: org '{org_name}' missing while merging CIDRs")
    _normalise_org_lists(org)
    for cidr in cidrs:
        if cidr not in org["lan_cidrs"]:
            org["lan_cidrs"].append(cidr)


def apply_command(state: dict, args: argparse.Namespace, fresh_file: bool, policy_text: str) -> None:
    if args.command == "init":
        # First run on the stock template: the marker lists the placeholder
        # admin@ and there is no organisation yet. Honour --admin exactly so
        # `init --admin ops` does not also keep the placeholder.
        seeded = reconstruct(policy_text) if fresh_file else None
        placeholder_only = (
            fresh_file
            and not state["orgs"]
            and state["admins"] in ([], ["admin"])
            and (seeded is None or seeded["admins"] in ([], ["admin"]))
        )
        if placeholder_only:
            state["admins"] = [args.admin]
        elif args.admin not in state["admins"]:
            state["admins"].append(args.admin)
        if not state["orgs"]:
            state["orgs"].append({"name": args.org or DEFAULT_ORG, "lan_cidrs": []})
        elif args.org:
            if org_by_name(state, args.org) is None:
                known = ", ".join(o["name"] for o in state["orgs"])
                die(
                    f"this stack is already initialised ({known}). "
                    f"To add '{args.org}', run: bootstrap.sh add-tenant {args.org}"
                )
        target = args.org or state["orgs"][0]["name"]
        merge_cidrs(state, target, args.lan_cidr)
    elif args.command == "add-tenant":
        if not state["orgs"]:
            die("no organisation yet; run bootstrap.sh init first")
        if not args.org:
            die("add-tenant requires an organisation name")
        if org_by_name(state, args.org) is None:
            if args.org in state["admins"]:
                die(f"'{args.org}' is an admin user, not a tenant name")
            state["orgs"].append({"name": args.org, "lan_cidrs": []})
        target = args.org
        merge_cidrs(state, target, args.lan_cidr)
    else:
        die(f"unknown command '{args.command}'")
    if args.tailnet_admin:
        state["tailnet_admin"] = True
    for admin in state["admins"]:
        valid_name(admin, "admin user")
    for org in state["orgs"]:
        valid_name(org["name"], "organisation")
        if org["name"] in state["admins"]:
            die(f"organisation '{org['name']}' collides with an admin user")
        _normalise_org_lists(org)
    validate_state(state, allow_public=bool(args.allow_public_cidr), requested=list(args.lan_cidr))
    if getattr(args, "ai_callback_ports", None) is not None:
        chosen = org_by_name(state, target)
        if chosen is None:
            die(f"internal: org '{target}' missing while recording callback ports")
        chosen["ai_callback_ports"] = parse_callback_ports(args.ai_callback_ports)
    validate_callback_ports(state)


def parse_callback_ports(text: str) -> list[int]:
    """Parse '22,8080'. 'none' clears the list. Order is normalised by sorting."""
    raw = text.strip().lower()
    if raw in {"", "none", "-"}:
        return []
    found: list[int] = []
    for part in text.split(","):
        item = part.strip()
        if not item.isdigit():
            die(f"invalid callback port '{part}' (want 1-65535, comma-separated, or 'none')")
        port = int(item)
        if port < 1 or port > 65535:
            die(f"callback port {port} is outside 1-65535")
        if port not in found:
            found.append(port)
    return sorted(found)


def validate_callback_ports(state: dict) -> None:
    for org in state["orgs"]:
        raw = org.get("ai_callback_ports", [])
        if raw is None:
            raw = []
        if not isinstance(raw, list):
            die(f"organisation '{org['name']}' ai_callback_ports must be a list of ports")
        cleaned: list[int] = []
        for port in raw:
            if isinstance(port, bool) or not isinstance(port, int):
                die(
                    f"organisation '{org['name']}' ai_callback_ports has {port!r}; "
                    "expected an integer 1-65535"
                )
            if port < 1 or port > 65535:
                die(f"organisation '{org['name']}' callback port {port} is outside 1-65535")
            if port not in cleaned:
                cleaned.append(port)
        org["ai_callback_ports"] = sorted(cleaned)


def _callback_block(org_name: str, ports: list[int]) -> str:
    lines = [f'        "{org_name}@:{port}", // opt-in AI callback' for port in ports]
    return "\n".join(lines)


def _ports(prefix: str, ports: tuple[tuple[int, str], ...]) -> str:
    lines = []
    for port, comment in ports:
        lines.append(f'        "{prefix}:{port}", // {comment}')
    return "\n".join(lines)


def _acl(src: str, dst_block: str) -> str:
    return (
        "    {\n"
        '      "action": "accept",\n'
        f'      "src": ["{src}"],\n'
        '      "dst": [\n'
        f"{dst_block}\n"
        "      ]\n"
        "    },\n"
    )


def render(state: dict) -> dict[str, str]:
    admins = "".join(f'      "{name}@",\n' for name in state["admins"])
    tags = []
    acls = []
    ssh = []
    routes = []
    for org in state["orgs"]:
        name = org["name"]
        tags.append(f'    "tag:{name}-local-ai": ["group:admins"],')
        acls.append(f"    // organisation {name}\n")
        acls.append(_acl(f"{name}@", _ports(f"tag:{name}-local-ai", LOCAL_AI_PORTS)))
        # Tailscale ACLs are stateful: a member-initiated connection does not
        # need a reverse grant for the reply. A callback is opt-in, per port.
        callback = _callback_block(name, org.get("ai_callback_ports") or [])
        if callback:
            acls.append(_acl(f"tag:{name}-local-ai", callback))
        acls.append(_acl("group:admins", f'        "tag:{name}-local-ai:22", // Tailscale SSH'))
        ssh.append(
            "    {\n"
            '      "action": "check",\n'
            '      "src": ["group:admins"],\n'
            f'      "dst": ["tag:{name}-local-ai"],\n'
            '      "users": ["autogroup:nonroot"]\n'
            "    },\n"
        )
        if org["lan_cidrs"]:
            tags.append(f'    "tag:{name}-gateway": ["group:admins"],')
            dst = []
            for cidr in org["lan_cidrs"]:
                dst.append(_ports(cidr, LAN_PORTS))
            acls.append(_acl(f"{name}@", "\n".join(dst)))
            # No gateway -> member grant. Subnet SNAT means replies already
            # come from the gateway node, and a stateful ACL allows them.
            # Do not put the LAN prefix in src: that would let any host on
            # the LAN open a connection to a member.
            for cidr in org["lan_cidrs"]:
                routes.append(f'      "{cidr}": ["tag:{name}-gateway"],')
    forbidden = ("autogroup:member", "autogroup:tagged", "autogroup:internet", "autogroup:danger-all")
    rendered = {
        "admins": admins,
        "tagOwners": ("\n".join(tags) + "\n") if tags else "",
        "acls": "".join(acls),
        "ssh": "".join(ssh),
        "routes": ("\n".join(routes) + "\n") if routes else "",
    }
    blob = "\n".join(rendered.values())
    for word in forbidden:
        if word in blob:
            die(f"refusing to write {word}; it is instance-wide and breaks tenant isolation")
    if re.search(r'"(?:\*|autogroup:(?!nonroot))', blob):
        die("refusing to write an autogroup wildcard")
    if "@:*" in rendered["acls"]:
        die("refusing to write a reverse grant onto every member port")
    return rendered


def write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    tmp.replace(path)


def reconcile_gateway_lan_cidrs(cfg: dict, state: dict) -> bool:
    """Set each existing {org}-gateway entry's lan_cidrs from managed state.

    Does not create tenants and does not touch token_hashes. An empty list
    removes the key so discover omits it.
    """
    wanted: dict[str, list[str]] = {}
    for org in state.get("orgs") or []:
        if not isinstance(org, dict) or not isinstance(org.get("name"), str):
            die("state org is missing a name")
        cidrs = org.get("lan_cidrs") or []
        if not isinstance(cidrs, list):
            die("organisation '%s' lan_cidrs must be a list" % org["name"])
        wanted[org["name"]] = [str(item) for item in cidrs]
    tenants = cfg.get("tenants")
    if not isinstance(tenants, list):
        die("enroll config has no tenants list")
    changed = False
    for tenant in tenants:
        if not isinstance(tenant, dict):
            continue
        name = tenant.get("name") or ""
        if not isinstance(name, str) or not name.endswith("-gateway"):
            continue
        org_name = name[: -len("-gateway")]
        if org_name not in wanted:
            continue
        before = json.dumps(tenant.get("token_hashes"), sort_keys=True)
        cidrs = wanted[org_name]
        if cidrs:
            if tenant.get("lan_cidrs") != cidrs:
                tenant["lan_cidrs"] = list(cidrs)
                changed = True
        elif "lan_cidrs" in tenant:
            tenant.pop("lan_cidrs")
            changed = True
        after = json.dumps(tenant.get("token_hashes"), sort_keys=True)
        if after != before:
            die("internal: reconcile changed token hashes for %s" % name)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description="Render idoris-managed Headscale policy regions.")
    parser.add_argument("command", choices=("init", "add-tenant", "reconcile-enroll"))
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--runtime-uid", type=int, default=None)
    parser.add_argument("--runtime-gid", type=int, default=None)
    parser.add_argument("--org", default="")
    parser.add_argument("--admin", default=DEFAULT_ADMIN)
    parser.add_argument("--lan-cidr", action="append", default=[], dest="lan_cidr")
    parser.add_argument(
        "--allow-public-cidr",
        action="store_true",
        help="acknowledge a prefix that is not RFC1918 / IPv6 ULA (prints a warning)",
    )
    parser.add_argument(
        "--ai-callback-ports",
        default=None,
        help="comma-separated ports the Local AI host may open towards its members (or 'none')",
    )
    parser.add_argument("--tailnet-admin", action="store_true")
    args = parser.parse_args()
    if args.command == "reconcile-enroll":
        if args.config is None:
            die("reconcile-enroll needs --state and --config")
        try:
            state = json.loads(args.state.read_text())
        except json.JSONDecodeError as exc:
            die("cannot parse %s: %s" % (args.state, exc))
        if not isinstance(state, dict):
            die("state is not an object")
        state.setdefault("admins", [])
        state.setdefault("orgs", [])
        validate_state(state, allow_public=False, requested=[])
        changed = {"value": False}

        def mutate(cfg):
            if not isinstance(cfg, dict):
                die("enroll config is not an object")
            changed["value"] = reconcile_gateway_lan_cidrs(cfg, state)
            if not changed["value"]:
                return LeaveUnchanged()
            return cfg

        try:
            locked_update(
                args.config,
                mutate,
                runtime_uid=args.runtime_uid,
                runtime_gid=args.runtime_gid,
            )
        except json.JSONDecodeError as exc:
            die("cannot parse %s: %s" % (args.config, exc))
        except (OSError, ValueError, TypeError) as exc:
            die("%s" % exc)
        json.dump({"changed": changed["value"]}, sys.stdout)
        sys.stdout.write("\n")
        return
    if args.policy is None:
        die("--policy is required")
    if args.command == "init":
        valid_name(args.admin, "admin user")
    if args.org:
        valid_name(args.org, "organisation")
    args.lan_cidr = [parse_cidr(c, allow_public=args.allow_public_cidr) for c in args.lan_cidr]

    policy_path = args.policy
    text = policy_path.read_text()
    state, existed = load_state(args.state, text)
    apply_command(state, args, fresh_file=not existed, policy_text=text)
    regions = render(state)
    new_text = text
    for name, body in regions.items():
        new_text = replace_region(new_text, name, body)
    changed = new_text != text
    if changed:
        # Keep the inode. deploy/vpn bind-mounts this file into Headscale;
        # rename(2) detaches that mount and the next policy check cannot
        # open the path.
        with policy_path.open("r+", encoding="utf-8") as fh:
            fh.seek(0)
            fh.write(new_text)
            fh.truncate()
    write_state(args.state, state)
    summary = {
        "admins": state["admins"],
        "orgs": state["orgs"],
        "tailnet_admin": bool(state["tailnet_admin"]),
        "policy_changed": changed,
    }
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
