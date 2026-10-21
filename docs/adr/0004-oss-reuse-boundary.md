# ADR-0004 · Upstream OSS reuse without importing another Agent runtime

- **Status:** Agreed project direction; candidate libraries require per-dependency review
- **Date:** 2026-10-21

## Context

Numerous well-starred channel bridges and chat products already implement LINE, Telegram, multi-channel identity mapping, retries, contact inboxes and webhook security. iDoris Bridge is a Rust transport component for Agent24/iDoris and compatible Agents—not another Agent framework or a reproduction of a cloud CRM. Blindly copying large projects risks duplicate Agent logic, outdated WhatsApp protocols, dependencies and incompatible licenses.

## Decision

1. **Prefer directly reusing official provider protocol contracts and mature native Rust libraries:** LINE line-openapi (Apache-2.0) for schema/code generation, Telegram Teloxide (MIT) for Bot API. Confirm generated-code and transitive-licensing terms, versions and security separately.
2. **Borrow tested design patterns only** from OpenClaw (MIT, LINE validation and event spool), Matterbridge (Apache-2.0, gateways), Chatwoot community code (MIT, Inbox and handoff), LINE MCP Server (Apache-2.0, approved message tools).
3. **Study but do not transplant** mautrix/telegram or mautrix/whatsapp (AGPL-3.0); do not copy Chatwoot enterprise/ proprietary code or promote unofficial WhatsApp Web bridges as Meta Business Cloud API.
4. Keep all research clones pinned in git-ignored vendors/; commit upstream manifest and reproducible sync script, not wholesale upstream source. Provenance, notices, SDK versions and license audit are release gates.
5. Implement SNS Relay/Connector, event scope/ACK/cost/permission layer as small Rust components. Do not import OpenClaw's Agent Loop or Chatwoot's CRM core.

## Consequences

- Faster LINE and Telegram implementation with published provider contracts; lower maintenance cost.
- Rust code for new trust-boundary logic is still needed. “Compatible license” is not a declaration of production safety or permission to bypass SNS platform policies.
- Security review explicitly covers retries, ambiguous send, Webhook signature before durable enqueue, privacy/account ownership, and paid Push approval.

See [comparative audit](../11-OSS-REUSE-AUDIT.md), [vendor manifest](../../vendors/references.lock.tsv), [current roadmap](../08-ROADMAP-ACCEPTANCE.md).
