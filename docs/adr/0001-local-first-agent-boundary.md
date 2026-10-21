# ADR-0001 · Local-first Agent, transport-only Bridge

- **Status:** Accepted product direction; implementation pending P1-F0
- **Date:** 2026-10-21

## Context

Customer Agent24/iDoris deployments already own model governance, local/remote model selection, knowledge, memory, tools, workflows and approvals. SNS platforms are centralized and commonly require a stable public HTTP webhook service. Rebuilding a second Agent or inference SaaS would duplicate responsibilities and move private execution to the wrong trust domain.

## Decision

Provide a **Relay** (public webhook verification, queued delivery, device pairing, tenant binding, metering) and **Connector** (local outbound connection, existing Agent Host adapter, SNS outbound sender). The customer's Agent remains the execution authority; Relay is low-trust message transport, not a tool executor or arbitrary network tunnel. Support official hosted Relay and self-hosted Relay using the same open protocol. Default Agent24; external AgentAdapter is supported.

## Consequences

- Pros: local privacy and model control, reusable channels, no new Agent Loop, stronger trust from account and data portability.
- Trade-offs: local Agent may be offline; no instant answer guarantee; central webhook still handles transient plaintext and minimal secrets; cross-channel policy complexity belongs in ChannelAdapters.
- Mandatory guard: Relay must never possess iDoris Admin or Agent24 privileged credentials, nor accept arbitrary execution commands.

## Alternatives rejected

1. Single all-customers iDoris Bot: good demo but wrong merchant identity and ownership.
2. Fully cloud-hosted Agent SaaS: outside project scope.
3. Require inbound ports on customer machines: operationally unsafe and impractical for small merchants.

See [architecture](../03-SYSTEM-ARCHITECTURE.md), [security](../05-SECURITY-PRIVACY.md).
