# iDoris Bridge

**All bots for you. Your agents stay yours.**

iDoris Bridge is a proposed **open-source, local-first communications bridge** linking centrally hosted social/messaging networks (LINE, Telegram, WhatsApp and future channels) to agents running under [Agent24](https://github.com/iDoris-ai/Agent24), [iDoris](https://github.com/iDoris-ai/iDoris), or another standards-compatible Agent host.

It is **not** another Agent framework, inference service, or AI SaaS. A public Relay supplies reliable webhook reception and delivery; the customer's Connector and Agent remain under the customer's control. The Relay can be operated by the project or self-hosted.

> **Project status: design/planning only.** The G0–G5 milestones are proposals and do not indicate implemented features.

## Documentation / 规划文档

Start with the [documentation index (中文)](docs/README.md). It covers product scope, platform onboarding and pricing, technical architecture, protocol contracts, threat model, deployment, open-source business model, milestones, acceptance gates, open decisions and official references.

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
