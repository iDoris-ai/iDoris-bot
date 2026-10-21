# 10 · 官方来源、市场案例与研究核对

**检索核对日：2026-10-21（Asia/Bangkok）。** 本项目的供应商价格、技术政策和准入限制可能后续变化，开发落地/公开报价时须重查链接。优先提供官方出处，第三方信息单独标注。

## LINE 开发与业务

| 主题 | 来源 | 关键事实 |
|---|---|---|
| Messaging API 开发入门 | [官方 Getting Started](https://developers.line.biz/en/docs/messaging-api/getting-started/) | OA 先创建，再于 OA Manager 启用 Messaging API；Provider 不可随意更换 |
| Messaging API 总览 | [官方 Overview](https://developers.line.biz/en/docs/messaging-api/overview/) | HTTPS Webhook 与发送 API 的基本结构 |
| Webhook、重投、unsend | [官方 Receiving Messages](https://developers.line.biz/en/docs/messaging-api/receiving-messages/) | 原始请求验签、webhookEventId 去重、重投可能乱序 |
| 签名验证 | [官方 Verify Webhook Signature](https://developers.line.biz/en/docs/messaging-api/verify-webhook-signature/) | 在消息解析前核对原始 body HMAC |
| Reply 一分钟期限 | [官方 API Reference](https://developers.line.biz/en/reference/messaging-api/#send-reply-message) | replyToken 一次使用；收到 webhook 后一分钟内使用，超时不保证 |
| 消息费计算 | [官方 Pricing](https://developers.line.biz/en/docs/messaging-api/pricing/) | Reply 不计数；Push/Multi/Broadcast/Narrowcast 计数 |
| 2026 Message Count 解释 | [官方 2026-05-28 Tips](https://developers.line.biz/en/tips/2026/05/28/how-to-count-messages/) | 以 API 发送请求和收件人数计，不以气泡数计 |
| 泰国 LINE OA 套餐 | [LINE Thailand](https://lineforbusiness.com/th/service/line-oa-features) | Free 300、Basic 15k、Pro 35k，月费以 THB 计 |
| 泰国额外发送价格 | [LINE Thailand 教学](https://lineforbusiness.com/th/learning-hub/OA-B-01) | Basic 0.10 THB/条、Pro 0.06 THB/条（当期公示） |
| LINE 自带 AI Chat | [官方 OA Chat Package](https://lineforbusiness.com/th/service/line-oa-features/oa-chat-package) | 555 THB/月的额外订阅，含 Q&A/PDF/图片的 AI 自动回复 Beta |
| LINE OA 第三方集成目录 | [LINE Thailand OA Store](https://lineforbusiness.com/th-en/line-oa-store) | 本地已有第三方接入/工具商业市场 |
| Module 概况 | [LINE Module](https://developers.line.biz/en/docs/partner-docs/module/) | 商用模块可扩展 OA，但需要申请与配套设施 |
| Module OAuth 连接 | [LINE Attach Module Channel](https://developers.line.biz/en/docs/partner-docs/module-technical-attach-channel/) | 需 OA 管理员授权；文档列出 region JP/TW，泰国待确认 |

**注意信息冲突：** 搜索中部分旧版 LINE OA 帮助页可能出现“Free 500”等旧数值。本计划采用 LINE Thailand 当前产品/教学页的 300 额度；付款或开发 quota 门控时，依客户实际 OA 套餐后台和官方当前 API 额度为准。

## Telegram

- [Telegram Bot API](https://core.telegram.org/bots/api)：Webhook/getUpdates、发送/群组、限制。
- [Bot 介绍/BotFather](https://core.telegram.org/bots)：用户自己创建并持有 Bot。
- [Managed Bots](https://core.telegram.org/api/bots/managed-bots)：用户作为所有者、经理 Bot 被授权操作的完整技术说明。
- [2026 Bot API Changelog](https://core.telegram.org/bots/api-changelog)：Managed Bot 相关能力的 2026 年 4 月更新。

## WhatsApp / Meta

- [Meta WhatsApp Developer Docs](https://developers.facebook.com/docs/whatsapp/)：以本渠道的 Meta 开发者官方文档及价格表为最终依据。
- [Meta Business Platform 产品页](https://business.whatsapp.com/products/business-platform)：商业用途与官方路线。
- [2026-10 Pricing 外部参考（非官方）](https://www.flowcall.co/blog/whatsapp-business-api-pricing)：近期每类消息的费用解释；必须回到 Meta 原价目表复核。
- [2026 通用 AI 平台限制外部报道](https://techcrunch.com/2025/10/18/whatssapp-changes-its-terms-to-bar-general-purpose-chatbots-from-its-platform/)：2026 年 1 月生效的第三方通用 AI 主用途限制，不等于禁止所有商户 AI 客服；以现行 Meta 正式条款为准。

## Agent / Tool 协议

- [Agent24 仓库 README](https://github.com/iDoris-ai/Agent24/blob/main/README.md)：Rust agent24d、REST/WS、OS/Attached 模块及现有模型路由状态；这里仅是 2026-10-21 的 README 核对，不替代最新源码证据。
- [iDoris 仓库 README](https://github.com/iDoris-ai/iDoris/blob/main/README.md)：Rust 生产实现、模型准入/容量/安全及 loopback 管理面。
- [A2A Protocol](https://a2a-protocol.org/v0.3.0/specification/)：面向可互换 Agent Host 的任务协议参考。
- [MCP 官方规范](https://modelcontextprotocol.io/specification/)：Agent 工具/资源连接，不承担 Relay 交付语义。

## 泰国现成市场案例（用于竞争分析，不是 iDoris 客户案例）

| 市场产品 | 公开能力 | 与本项目的差异 |
|---|---|---|
| [BOTNOI](https://botnoi.ai/) | 泰语/多渠道 AI Agent、LINE/WhatsApp/Webchat、知识库/工作流（供应商自述） | 更接近云端 Agent 产品平台；Bridge 强调**客户自持本地 Agent**与开源互通 |
| [AIYA AiOA](https://web.aiya.ai/th/products/ai-oa) | LINE OA Rich Menu、自动回复、客户分析/广播，官网展示按月套餐 | 可作为 LINE onboarding 和 UI/小店产品体验参考；Bridge 不复制完整 CRM |
| [AIYA Sales CRM](https://web.aiya.ai/th/products/sales-crm) | 多渠道 CRM、销售工作流、AI 助手（官网介绍） | 可能成为未来 Bridge 对接的外部业务系统，而非首版重建对象 |

这些厂商显示泰国 LINE 商家沟通、机器人和自动化需求存在，但营销页面的客户数、满意度和套餐价格属于**厂商自述**，不可直接作为可信市场规模或 iDoris 定价证据。G0/G1 可与 3–5 家清迈真实商家做匿名需求/开户和费用测试。

## 研究纪律

1. 引用时附发布日期/检查日；业务政策尽量依官方。
2. 平台价格、政策和 API 会变，公开用户文案必须重新确认。
3. 不确定的地区准入、自动注册、收费豁免等写“待验证”，禁止推导为已支持。
4. 竞争产品介绍仅用其公开功能说明，不杜撰部署架构、客户结果或合作关系。
