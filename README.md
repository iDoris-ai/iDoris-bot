# iDoris Bridge

**All bots for you. Your agents stay yours.**

iDoris Bridge is a proposed **open-source, local-first communications bridge** linking centrally hosted social/messaging networks (LINE, Telegram, WhatsApp and future channels) to agents running under [Agent24](https://github.com/iDoris-ai/Agent24), [iDoris](https://github.com/iDoris-ai/iDoris), or another standards-compatible Agent host.

It is **not** another Agent framework, inference service, or AI SaaS. A public Relay supplies reliable webhook reception and delivery; the customer's Connector and Agent remain under the customer's control. The Relay can be operated by the project or self-hosted.

> **Project status: design/planning for the SNS bridge; first code for the VPN access layer.** The current three-stage P1–P3 roadmap (LINE first, three steps) is a proposal, not an implemented product. The earlier G0–G5 plan is archived for traceability. The `vpn/` daemon and enrollment service are implemented with unit and integration tests but not yet validated in production.

## Documentation / 规划文档

Start with the [documentation index (中文)](docs/README.md). It covers product scope, platform onboarding and pricing, technical architecture, protocol contracts, threat model, deployment, open-source business model, **three-stage roadmap and the LINE personal → shop → community sequence**, acceptance gates, open decisions and official references.

The [open-source reuse audit](docs/11-OSS-REUSE-AUDIT.md) documents 10 reviewed upstream repositories, exact pinned commits and license boundaries. Recreate shallow research clones locally using [scripts/sync-vendors.sh](scripts/sync-vendors.sh). Third-party source code is intentionally excluded from this repository's Git history.

## Private access layer (VPN)

Besides bridging public SNS, members of an organisation need to reach their own Local AI directly. The `vpn/` module provides that without exposing anything to the internet: members install the **official, unmodified Tailscale client**; a background daemon (`idoris-vpnd`) logs it into the **iDoris-operated Headscale** control server (upstream, unmodified) and keeps it enrolled; an operator-side service (`idoris-vpn-enroll`) hands out single-use short-lived keys so the Headscale API key never leaves the server. See [docs/12-VPN-HEADSCALE.md](docs/12-VPN-HEADSCALE.md), [ADR-0005](docs/adr/0005-vpn-tailscale-client-headscale-control.md) and [deploy/vpn](deploy/vpn).

~~~sh
cd vpn && make test && make lint     # unit tests + lint
make integration                      # real Headscale + real tailscaled in Docker
~~~

## Architectural boundary

~~~text
LINE / Telegram / WhatsApp
          ⇅
Public SNS Relay (webhook, verification, delivery, queues)
          ⇅ outbound-initiated authenticated connection
Customer-owned Connector daemon
          ⇅
Agent24 or other Agent host ⇄ iDoris model-management core
          ⇅
Customer memory / knowledge / tools / local or approved remote models
~~~

The public Relay must never receive iDoris admin credentials, arbitrary access to local resources, or authority to execute Agent tools.

## License

This repository currently uses [Apache License 2.0](LICENSE). A different future licensing strategy would require an explicit decision and appropriate copyright/licensing review.
