# ADR-0005 · Private access layer: unmodified Tailscale clients, self-hosted Headscale, Go glue daemon

- **Status:** Agreed direction; first implementation in `vpn/` with unit and Docker integration tests, not yet validated against a production Headscale
- **Date:** 2026-10-27

## Context

Organisation members must reach their own Local AI host (Agent24 / iDoris) from any network without exposing it on the public internet. Tailscale's client is ubiquitous, free, and well maintained on every platform we care about, but its control plane is a SaaS operated by Tailscale Inc. Headscale is the mature (v0.29.x, BSD-3) open-source implementation of that control plane, feature-complete for our needs (pre-auth keys, ACL policy, MagicDNS, embedded DERP relay, OIDC, REST/gRPC API). Members should not have to configure anything; a background process should make the machine join the right network and keep it there.

## Decision

1. **Clients stay official.** Members install the stock Tailscale client. We do not fork, patch or redistribute it. On macOS/Linux a small daemon drives it through LocalAPI, exactly as the `tailscale login` CLI does. Mobile clients use Headscale's built-in onboarding pages or OIDC.
2. **Control plane is unmodified Headscale.** We run the upstream container with our configuration and ACL policy, plus Headplane (MIT) as admin UI. No fork of either; if we need a behaviour change we contribute upstream.
3. **Our code is glue only.** Two small Go programs: `idoris-vpn-enroll` (operator side, the only holder of a Headscale API key, issues single-use 10-minute pre-auth keys against per-tenant tokens) and `idoris-vpnd` (client side, reconciles tailscaled onto our control URL, re-enrolls on expiry, exposes a local status API, installs itself as launchd/systemd service).
4. **One Headscale user plus one dedicated tag per tenant organisation, with per-tenant ACL rules.** A tenant's members are the personal nodes of user `<tenant>@`. Its Local AI host is tagged `tag:<tenant>-local-ai`. The policy grants `<tenant>@` access to that tag on the iDoris/Agent24 ports only. It grants no member-to-member and no cross-tenant access. Headscale users are *not* a network isolation boundary: `autogroup:member` and tags are instance-wide, and v0.29.6 has no `autogroup:admin`. Instance-wide wildcards are therefore forbidden in the template. A local test showed that such a wildcard let one tenant's members reach another tenant's Local AI. Organisations that need stronger isolation get their own `deploy/vpn` instance.
5. **Go for this component.** The rest of the Bridge is planned in Rust, but the entire Tailscale/Headscale ecosystem is Go: `tailscale.com/client/local` is the supported LocalAPI client and the only way to mirror `tailscale login` semantics (profile switching, `Start` with auth key) without re-implementing the LocalAPI protocol. The module lives in its own `vpn/` directory with its own `go.mod`; it exposes nothing to the Rust crates except the local HTTP status API.
6. **Takeover is explicit.** If a machine is already logged into another tailnet the daemon switches to ours by default (Tailscale allows one active profile), records the previous profile id, and can be told not to with `--no-takeover`.

## Consequences

- Zero client maintenance burden; we inherit Tailscale's NAT traversal, key rotation, platform support and security updates.
- Tenant isolation on a shared instance is only as good as the policy file. Adding a tenant means adding its rule block, and a wrong rule can leak across tenants. Production Headscale must be reachable at https on port 443, because the Tailscale client forces TLS on 443 for re-dials.
- Headscale is single-instance by design; acceptable for small/medium organisations, requires a documented backup/upgrade routine (sqlite, noise key, DERP key).
- The Headscale API key is a crown jewel and is confined to the enrollment service container; clients only ever see single-use short-lived keys and a hashed tenant token.
- Simultaneous membership in a personal/corporate tailnet and the iDoris tailnet on the same machine is not possible with the system client. If that becomes a requirement, the fallback is an in-process `tsnet` node inside the Bridge Connector (user-space, no system routing). This is deferred.
- Licensing: Headscale and Tailscale are BSD-3-Clause, Headplane MIT, all compatible with this repository's Apache-2.0; transitive dependencies of `tailscale.com` need a license scan before release. GPL-3.0 UIs (headscale-admin) may be deployed but not vendored.

See [12-VPN-HEADSCALE.md](../12-VPN-HEADSCALE.md), [deploy/vpn](../../deploy/vpn), [vpn/](../../vpn).
