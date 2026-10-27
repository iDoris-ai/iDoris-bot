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


def parse_cidr(text: str) -> str:
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        die(f"invalid LAN CIDR '{text}': {exc}")
    if not isinstance(net, ipaddress.IPv4Network):
        die(f"LAN CIDR '{text}' must be IPv4")
    if net.prefixlen == 0:
        die(f"LAN CIDR '{text}' is an exit-node route; this deployment does not auto-approve it")
    return str(net)


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
    org = org_by_name(state, org_name)
    if org is None:
        die(f"internal: org '{org_name}' missing while merging CIDRs")
    owned = {c: o["name"] for o in state["orgs"] for c in o["lan_cidrs"]}
    for cidr in cidrs:
        owner = owned.get(cidr)
        if owner is not None and owner != org_name:
            die(
                f"LAN CIDR {cidr} is already auto-approved for '{owner}'. "
                "Two organisations cannot share a prefix on one Headscale; "
                "use a distinct prefix or a separate deploy/vpn stack."
            )
        if cidr not in org["lan_cidrs"]:
            org["lan_cidrs"].append(cidr)
            owned[cidr] = org_name


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
        merge_cidrs(state, args.org, args.lan_cidr)
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
        acls.append(_acl(f"tag:{name}-local-ai", f'        "{name}@:*", // replies and callbacks'))
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
            # The gateway host (not the whole LAN) may reach its members.
            # LAN devices are not a source: with Tailscale's default subnet
            # SNAT, replies already come from the gateway node's own address.
            acls.append(_acl(f"tag:{name}-gateway", f'        "{name}@:*", // gateway host to its members'))
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
    return rendered


def write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    tmp.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Render idoris-managed Headscale policy regions.")
    parser.add_argument("command", choices=("init", "add-tenant"))
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--org", default="")
    parser.add_argument("--admin", default=DEFAULT_ADMIN)
    parser.add_argument("--lan-cidr", action="append", default=[], dest="lan_cidr")
    parser.add_argument("--tailnet-admin", action="store_true")
    args = parser.parse_args()
    if args.command == "init":
        valid_name(args.admin, "admin user")
    if args.org:
        valid_name(args.org, "organisation")
    args.lan_cidr = [parse_cidr(c) for c in args.lan_cidr]

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
