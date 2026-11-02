#!/usr/bin/env python3
"""Adversarial checks for deploy/vpn/policy.py CIDR ownership.

Run from the repo root:
  python3 -m unittest discover -s deploy/vpn/test -v
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PY = ROOT / "policy.py"
TEMPLATE = ROOT / "headscale" / "policy.hujson"


def run(policy: Path, state: Path, *args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(POLICY_PY), *args, "--policy", str(policy), "--state", str(state)]
    return subprocess.run(cmd, capture_output=True, text=True)


class CidrValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.policy = self.dir / "policy.hujson"
        self.state = self.dir / "managed.json"
        shutil.copy(TEMPLATE, self.policy)

    def _init(self, *args: str) -> subprocess.CompletedProcess[str]:
        return run(self.policy, self.state, "init", "--admin", "admin", *args)

    def _add(self, org: str, *args: str) -> subprocess.CompletedProcess[str]:
        return run(self.policy, self.state, "add-tenant", "--org", org, *args)

    def _state(self) -> dict:
        return json.loads(self.state.read_text())

    def _org(self, name: str) -> dict:
        for org in self._state()["orgs"]:
            if org["name"] == name:
                return org
        self.fail(f"org {name} missing in {self._state()}")

    def test_cross_org_containment_rejected(self) -> None:
        first = self._init("--org", "acme", "--lan-cidr", "192.168.0.0/16")
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self._add("globex", "--lan-cidr", "192.168.50.0/24")
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("overlaps", second.stderr)
        self.assertNotIn("globex", self.policy.read_text())
        self.assertEqual(self._org("acme")["lan_cidrs"], ["192.168.0.0/16"])

    def test_host_inside_prefix_rejected(self) -> None:
        first = self._init("--org", "acme", "--lan-cidr", "192.168.1.0/24")
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self._add("globex", "--lan-cidr", "192.168.1.9/32")
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("overlaps", second.stderr)

    def test_same_org_overlap_warns_and_keeps_both(self) -> None:
        result = self._init(
            "--org", "acme",
            "--lan-cidr", "192.168.0.0/16",
            "--lan-cidr", "192.168.50.0/24",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("warning:", result.stderr)
        self.assertIn("overlapping", result.stderr)
        self.assertEqual(
            self._org("acme")["lan_cidrs"],
            ["192.168.0.0/16", "192.168.50.0/24"],
        )

    def test_tailnet_ipv4_rejected_even_with_public_flag(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "100.64.0.0/10", "--allow-public-cidr")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("100.64.0.0/10", result.stderr)
        self.assertFalse(self.state.exists())

    def test_tailnet_subprefix_rejected(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "100.64.1.0/24", "--allow-public-cidr")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tailnet", result.stderr)

    def test_default_route_rejected(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "0.0.0.0/0", "--allow-public-cidr")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/0", result.stderr)

    def test_loopback_rejected(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "127.0.0.0/8", "--allow-public-cidr")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loopback", result.stderr)

    def test_link_local_rejected_even_with_public_flag(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "169.254.0.0/16", "--allow-public-cidr")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("link-local", result.stderr)

    def test_multicast_rejected(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "224.0.0.0/4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("multicast", result.stderr)

    def test_ipv6_tailnet_rejected(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "fd7a:115c:a1e0::/48")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tailnet", result.stderr)

    def test_ipv6_ula_accepted(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "fd12:3456:789a::/48")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._org("acme")["lan_cidrs"], ["fd12:3456:789a::/48"])
        self.assertIn("fd12:3456:789a::/48", self.policy.read_text())

    def test_ipv6_link_local_and_loopback_rejected(self) -> None:
        link = self._init("--org", "acme", "--lan-cidr", "fe80::/10", "--allow-public-cidr")
        self.assertNotEqual(link.returncode, 0)
        self.assertIn("link-local", link.stderr)
        loop = self._init("--org", "acme", "--lan-cidr", "::1/128", "--allow-public-cidr")
        self.assertNotEqual(loop.returncode, 0)
        self.assertIn("loopback", loop.stderr)

    def test_host_bits_rejected(self) -> None:
        result = self._init("--org", "acme", "--lan-cidr", "192.168.1.1/24")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host bits", result.stderr)

    def test_whitespace_rejected(self) -> None:
        for dirty in (" 192.168.1.0/24", "192.168.1.0/24 ", "192.168.1.0/24\n", "192.168.1.0 /24"):
            result = self._init("--org", "acme", "--lan-cidr", dirty)
            self.assertNotEqual(result.returncode, 0, dirty)
            self.assertIn("whitespace", result.stderr)
            self.assertFalse(self.state.exists(), dirty)

    def test_public_prefix_needs_flag_then_persists(self) -> None:
        denied = self._init("--org", "acme", "--lan-cidr", "8.8.8.0/24")
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("not private", denied.stderr)
        self.assertFalse(self.state.exists())
        allowed = self._init("--org", "acme", "--lan-cidr", "8.8.8.0/24", "--allow-public-cidr")
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertIn("PUBLIC CIDR", allowed.stderr)
        self.assertEqual(self._org("acme")["public_cidrs"], ["8.8.8.0/24"])
        again = self._init("--org", "acme")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("PUBLIC CIDR", again.stderr)
        self.assertEqual(self._org("acme")["lan_cidrs"], ["8.8.8.0/24"])

    def test_persisted_overlap_rejected_on_every_run(self) -> None:
        self.state.write_text(json.dumps({
            "version": 1,
            "admins": ["admin"],
            "orgs": [
                {"name": "acme", "lan_cidrs": ["192.168.0.0/16"]},
                {"name": "globex", "lan_cidrs": ["192.168.50.0/24"]},
            ],
            "tailnet_admin": False,
        }))
        before = self.policy.read_text()
        result = self._init("--org", "acme")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("overlaps", result.stderr)
        self.assertEqual(self.policy.read_text(), before)

    def test_persisted_tailnet_prefix_rejected(self) -> None:
        self.state.write_text(json.dumps({
            "version": 1,
            "admins": ["admin"],
            "orgs": [{"name": "acme", "lan_cidrs": ["100.64.0.0/10"]}],
            "tailnet_admin": False,
        }))
        result = self._init("--org", "acme")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tailnet", result.stderr)

    def test_rfc1918_still_accepted(self) -> None:
        result = self._init(
            "--org", "acme",
            "--lan-cidr", "10.1.0.0/16",
            "--lan-cidr", "172.16.8.0/24",
            "--lan-cidr", "192.168.10.0/24",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._org("acme")["lan_cidrs"],
            ["10.1.0.0/16", "172.16.8.0/24", "192.168.10.0/24"],
        )


class CallbackPortTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.policy = self.dir / "policy.hujson"
        self.state = self.dir / "managed.json"
        shutil.copy(TEMPLATE, self.policy)

    def _init(self, *args: str) -> subprocess.CompletedProcess[str]:
        return run(self.policy, self.state, "init", "--admin", "admin", "--org", "acme", *args)

    def test_default_has_no_reverse_grant(self) -> None:
        result = self._init("--lan-cidr", "192.168.5.0/24")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.policy.read_text()
        self.assertNotIn("@:*", text)
        self.assertIn("tag:acme-local-ai:8740", text)
        acls = text.split("// BEGIN idoris-managed acls")[1].split("// END idoris-managed acls")[0]
        self.assertIn('"src": ["acme@"]', acls)
        self.assertNotIn('"src": ["tag:acme-local-ai"]', acls)
        self.assertNotIn('"src": ["tag:acme-gateway"]', acls)

    def test_callback_ports_are_narrow_and_persisted(self) -> None:
        result = self._init("--ai-callback-ports", "8080,22,22")
        self.assertEqual(result.returncode, 0, result.stderr)
        org = json.loads(self.state.read_text())["orgs"][0]
        self.assertEqual(org["ai_callback_ports"], [22, 8080])
        acls = self.policy.read_text().split("// BEGIN idoris-managed acls")[1].split("// END idoris-managed acls")[0]
        self.assertIn('"src": ["tag:acme-local-ai"]', acls)
        self.assertIn('"acme@:22"', acls)
        self.assertIn('"acme@:8080"', acls)
        self.assertNotIn("@:*", acls)
        self.assertNotIn('"src": ["tag:acme-gateway"]', acls)
        again = self._init()
        self.assertEqual(again.returncode, 0, again.stderr)
        org = json.loads(self.state.read_text())["orgs"][0]
        self.assertEqual(org["ai_callback_ports"], [22, 8080])

    def test_callback_ports_cleared_and_rejected(self) -> None:
        self.assertEqual(self._init("--ai-callback-ports", "22").returncode, 0)
        cleared = self._init("--ai-callback-ports", "none")
        self.assertEqual(cleared.returncode, 0, cleared.stderr)
        org = json.loads(self.state.read_text())["orgs"][0]
        self.assertEqual(org["ai_callback_ports"], [])
        self.assertNotIn('"src": ["tag:acme-local-ai"]', self.policy.read_text())
        bad = self._init("--ai-callback-ports", "0,8080")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("outside", bad.stderr)
        junk = self._init("--ai-callback-ports", "ssh")
        self.assertNotEqual(junk.returncode, 0)

    def test_persisted_bad_port_rejected(self) -> None:
        self.state.write_text(json.dumps({
            "version": 1,
            "admins": ["admin"],
            "orgs": [{"name": "acme", "lan_cidrs": [], "ai_callback_ports": [70000]}],
            "tailnet_admin": False,
        }))
        before = self.policy.read_text()
        result = self._init()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("70000", result.stderr)
        self.assertEqual(self.policy.read_text(), before)


class GatewayLanCidrTest(unittest.TestCase):
    def test_reconcile_sets_prefixes_without_touching_hashes(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        state = directory / "managed.json"
        config = directory / "config.json"
        digest = "a" * 64
        state.write_text(json.dumps({
            "version": 1,
            "admins": ["admin"],
            "orgs": [{
                "name": "office",
                "lan_cidrs": ["192.168.1.0/24", "10.8.0.0/24"],
                "public_cidrs": [],
            }],
            "tailnet_admin": False,
        }))
        config.write_text(json.dumps({
            "tenants": [{
                "name": "office-gateway",
                "token_hashes": [{"hash": digest, "label": "bootstrap-office-gateway"}],
                "role": "gateway",
            }, {
                "name": "office",
                "token_hashes": [{"hash": "b" * 64}],
            }],
        }))
        result = subprocess.run(
            [sys.executable, str(POLICY_PY), "reconcile-enroll",
             "--state", str(state), "--config", str(config)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        cfg = json.loads(config.read_text())
        gateway = cfg["tenants"][0]
        self.assertEqual(gateway["lan_cidrs"], ["192.168.1.0/24", "10.8.0.0/24"])
        self.assertEqual(gateway["token_hashes"][0]["hash"], digest)
        self.assertNotIn("lan_cidrs", cfg["tenants"][1])
        lock = Path(str(config) + ".lock")
        self.assertTrue(lock.is_file())
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
        written = config.read_bytes()
        again = subprocess.run(
            [sys.executable, str(POLICY_PY), "reconcile-enroll",
             "--state", str(state), "--config", str(config)],
            capture_output=True, text=True,
        )
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertFalse(json.loads(again.stdout)["changed"])
        self.assertEqual(config.read_bytes(), written)


if __name__ == "__main__":
    unittest.main()
