# 07 · 渠道费用、开源策略与非 SaaS 商业模式

**重要：平台资费、政策常变。下表按 2026-10-21 核对的资料用于预算估算，不是长期报价保证。** 实际账单由渠道商负责，iDoris Relay 托管费与 SNS 平台费分开。

## 1. LINE Thailand Official Account（OA）费用

LINE OA 在泰国的官方页面列出：

| 月方案 | 平台月费（THB，未含 VAT） | 每月可计费消息数 | 额外发送 |
|---|---:|---:|---|
| Free | **฿0** | 300 | Free 档不可另购超额；需升级 |
| Basic | **฿1,280** | 15,000 | **฿0.10 / 消息** |
| Pro | **฿1,780** | 35,000 | **฿0.06 / 消息** |

来源：[LINE Thailand 官方 OA 页面](https://lineforbusiness.com/th/service/line-oa-features)、[官方培训页面](https://lineforbusiness.com/th/learning-hub/OA-B-01)。不同页面或版本可能出现过时额度，以泰国客户后台和当期正式方案优先。

LINE Messaging API **Reply 消息不计入**上述配额；Push、Multicast、Broadcast、Narrowcast 计入配额。计算按**API 发送请求 × 目标收件人数**，同一请求的多个气泡/消息对象并非分别收费；不可达用户可能不计。详见 [LINE 官方计费](https://developers.line.biz/en/docs/messaging-api/pricing/) 和 [2026 官方解释](https://developers.line.biz/en/tips/2026/05/28/how-to-count-messages/)。

举例：月内 1,000 次客户发问、每次 Agent 在有效 reply token 期限内回复、没有超过 300 条计费主动通知时，LINE 平台费用可能为 **฿0**；**模型、电费、机器、网络、Relay 托管另算**。在同一个月向 1,000 个可达好友广播一次，可能消费约 1,000 条计费额度。不能因 Reply 免费，就把延时 Push、批量营销或无限次 Agent 交互承诺为免费。

### LINE B vs C 费用结论

- B：客户 OA + 自有 Messaging API Channel + Bridge；依据客户 OA 套餐及使用量计费。
- C：LINE Module Channel OAuth 连接客户 OA；**账号/消息费用仍存在**。优势是授权接入便利，不是免费通道；还需地区/公司申请资格。
- 两者均允许客户拥有自己的 OA。MVP 采用 B；C 除非 LINE Thailand 批准，否则不得宣传为可用。

### LINE 自有 AI Chat Package 是竞争基线

LINE Thailand 另提供可选 **OA Chat Package（฿555/月，未含 VAT）**，含 AI Chatbot Beta，可从 Q&A、PDF 和图片生成/选择自动应答。该套餐与上面的 OA 消息发送月费**不是同一个计费维度**，也不是 Bridge 运行的强制依赖。基础“能回答 FAQ”在本地已有竞争；Bridge 的独特价值应是接入**客户自己的 Agent24/模型、业务工具、审批及可替换的 Agent**。来源：[官方 OA Chat Package](https://lineforbusiness.com/th/service/line-oa-features/oa-chat-package)。

## 2. Telegram

官方 Bot API 的通常收发没有类似 LINE OA 的基础月度 Bot 套餐费，但存在平台发送/群组速率限制、潜在可选付费能力及自有服务器成本。客户可以 BotFather 创建；2026 官方支持 Managed Bot 的用户所有权/经理人授权创建流程。普通免费 Bot API 不意味着无流控、无反滥用政策。来源：[Telegram Bot API](https://core.telegram.org/bots/api)、[Managed Bots](https://core.telegram.org/api/bots/managed-bots)。

## 3. WhatsApp Business Platform

**与 LINE 不同。** WhatsApp Cloud API 采用 Meta 按消息类别、收件人市场等计价；2026-10-01 起第三方资料对政策变动描述为：服务类非模板回复在每个商业号码月度 1,000 条免费额度之后按相应地区费率计费，原本免费的某些 utility 模板在服务窗口内也改为收费。具体费率、Meta 条款、号码等级和 BSP 附加费，必须在 G4 使用**Meta 当期官方 pricing / rate cards**核对，不能仅依据第三方宣传或旧 2025 文档付款。公开参考：[Flowcall 2026-10 费率概述](https://www.flowcall.co/blog/whatsapp-business-api-pricing)、[Meta 开发者入口](https://developers.facebook.com/docs/whatsapp/)。

此外 Meta 2026 起限制把通用第三方 AI 助手作为 WhatsApp Business 解决方案的主要功能；商户自有业务客服/订购/预约 Agent 与“开放式 ChatGPT 替代品”应严格区分，需政策审核后才能承诺 G4 功能。参考：[政策变化报道](https://techcrunch.com/2025/10/18/whatssapp-changes-its-terms-to-bar-general-purpose-chatbots-from-its-platform/)。

## 4. 多种收费不可混为一谈

~~~text
客户月度总成本 =
    第三方 SNS 平台实际消息费
  + 客户本地设备电费/服务器与网络费
  + 客户所选择的本地或外部模型成本
  + （可选）官方 Relay 托管与运维服务费
  + （可选）安装/高级技术支持与企业集成费
~~~

Bridge 不代客户决定调用更昂贵云模型，更不将 iDoris 模型预算隐式计入 Relay 计费。每个租户在 UI 中独立显示“平台消息费估算（由平台结算）”与“Relay 服务订阅”，费用估算要标注取样日期与非最终账单。

## 5. 开源与实际仓库许可证

**当前仓库已存在的 LICENSE 是 Apache License 2.0。** 因此当前计划以 Apache-2.0 编写/发布开源通信桥协议、基础 Relay/Connector/适配器，不擅自改 AGPL 或宣称商业闭源许可已生效。

过去讨论过 AGPL、Open Core 和商业扩展，这些属于**备选策略**：

- Apache-2.0：开发者使用、二次开发、商业托管都较自由，有利于信任与渠道生态，**不能阻止竞争者经营自己的 Relay**。
- AGPL：可在未来独立新组件或经权利人同意进行许可方案审查后采用；不能在当前 Apache-2.0 项目里口头声明自动生效，也不构成阻止所有竞争托管的专有许可。
- Open Core：可对特定企业功能另设商业授权，但必须先划清贡献者版权、第三方依赖、社区契约与可替代基础功能，不应以破坏自托管可用性为代价。

该项目的护城河不是“只有我们有服务器”，而是**低门槛合法开户、长期可靠投递、泰语/本地化集成经验、平台伙伴资质、部署支持、安全可信及易于迁移**。商业价值可来自官方托管 Relay、SLA、技术支持、部署/运维及专用企业连接器服务，而不是封锁 Agent 核心。

## 6. 商业化实验（数字为假设，不是正式产品定价）

可测试：个人/小店低价或免费试运行 Relay，组织级托管按连接 Bot 数、设备数、可靠事件用量/保留窗口计费；公司/社区选购高级监控、合规服务和集成支持。**不推荐**直接把模型 Token、LINE 广播额度和 Relay 事件数混成一个不可解释的套餐。最终价格要用真实可靠成本、客服成本和渠道法规测算，不把先前讨论的 AI SaaS Starter/Business/Organization 月费直接照搬到此项目。
