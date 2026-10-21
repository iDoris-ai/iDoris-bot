# ADR-0003 · At-least-once delivery, idempotent work, cost-controlled outbound

- **Status:** Proposed default; G0 protocol/security review required
- **Date:** 2026-10-21

## Context

SNS platforms can retry and reorder webhooks; local agents may disconnect for hours. LINE reply tokens are single-use/time-limited while WhatsApp and LINE have fee-bearing outbound methods. An unreliable network cannot promise true exactly-once business execution, and trying again after an uncertain external send can duplicate customer messages.

## Decision

Durably acknowledge accepted webhook events, use scoped provider event IDs, deliver at least once with resume cursor/lease fencing, and deduplicate business side effects independently at Agent/tool level. Track lifecycle and provider send receipts, including an explicit **ambiguous** state for unknown results. Enforce per-Bot outbound capabilities and tenant-approved budgets. A paid Push/Template/Broadcast fallback is **disabled by default** and must not be activated merely because a Reply Token expired.

## Consequences

Network transport is at least once; all mutations must be idempotent and auditable. Offline messages may expire rather than be delivered late; UI must distinguish “received by Relay” from “answered by Agent”. Budget errors are visible and never bypassed via remote model fallback or invisible outgoing charges.

See [protocol](../04-PROTOCOL-CONTRACTS.md), [operations](../06-DEPLOYMENT-OPERATIONS.md).
