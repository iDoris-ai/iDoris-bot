# ADR-0002 · Customer-owned SNS accounts and scoped credentials

- **Status:** Accepted product direction; detailed credential design pending G0
- **Date:** 2026-10-21

## Context

Small businesses need their own official storefront identity, customer relationships and the ability to change AI vendors. LINE OA and Telegram Bot ownership cannot depend on permanent possession by iDoris. LINE Module OAuth is a qualified/region-limited integration option, not the public default onboarding API.

## Decision

Each organization owns its SNS Official Account/Bot/Business Number. Use LINE OA Messaging API manual-assisted binding (mode B) first; prepare an optional qualifying Module Channel OAuth mode C without promising availability in Thailand. Use BotFather first for Telegram, with user-owned Managed Bot workflow as an optional improvement. Explicit owner approval and ability to revoke are mandatory.

Incoming Webhook verification secrets may need to reside in a restricted Relay Secrets Store. Outbound Bot Access Tokens should by default stay in the customer's OS credential store and be used by Connector, with Relay sending only as a separately authorized exception. No personal LINE/Telegram login passwords or OTP harvesting.

## Consequences

Billing with LINE/Meta remains the account owner's responsibility under their plan; OAuth vs manual setup does not waive platform charges. A compromised Relay has less power to send unsolicited customer messages but still processes inbound webhook plaintext. Device/tenant/channel scoping and rotation are required.

See [onboarding](../02-CHANNEL-ONBOARDING.md) and [costs](../07-COST-OPEN-SOURCE.md).
