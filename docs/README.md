# iDoris Bridge 文档总索引

**版本：** 产品/研究/架构规划 v0.2 · **日期：** 2026-10-21 · **状态：** 提案，未表示代码已实现或 P1-F0 已验收。

## 阅读顺序

| 文件 | 主题 | 关键问题 |
|---|---|---|
| [01-VISION-PRODUCT.md](01-VISION-PRODUCT.md) | 产品定位与范围 | 为什么存在、用户是谁、不是 SaaS、什么不做 |
| [02-CHANNEL-ONBOARDING.md](02-CHANNEL-ONBOARDING.md) | 渠道/账号/开户体验 | 一个 Bot 还是客户独立 Bot、B/C 授权、LINE/Telegram/WhatsApp |
| [03-SYSTEM-ARCHITECTURE.md](03-SYSTEM-ARCHITECTURE.md) | 技术架构 | Relay、Connector、Agent24、iDoris 的边界与集成 |
| [04-PROTOCOL-CONTRACTS.md](04-PROTOCOL-CONTRACTS.md) | 协议与数据模型 | Envelope、ACK、重试、AgentAdapter、平台差异 |
| [05-SECURITY-PRIVACY.md](05-SECURITY-PRIVACY.md) | 安全/隐私/授权 | 威胁、密钥归属、权限门控、平台原始明文、PDPA |
| [06-DEPLOYMENT-OPERATIONS.md](06-DEPLOYMENT-OPERATIONS.md) | 部署与可靠性 | 官方 Relay、自托管、联网/离线、监控、HA |
| [07-COST-OPEN-SOURCE.md](07-COST-OPEN-SOURCE.md) | 费用/许可/商业边界 | LINE 套餐、通信费、托管 Relay 的价值、Apache-2.0 |
| [08-ROADMAP-ACCEPTANCE.md](08-ROADMAP-ACCEPTANCE.md) | 当前 P1–P3 里程碑 | LINE 三步（个人→小店→组织）、Telegram/WhatsApp 扩展、开放生态 |
| [09-DECISIONS-OPEN-QUESTIONS.md](09-DECISIONS-OPEN-QUESTIONS.md) | 决策登记及风险 | 哪些已定、哪些有待技术验证或平台确认 |
| [10-SOURCES-RESEARCH.md](10-SOURCES-RESEARCH.md) | 官方来源及研究核验 | 各平台官方链接、法规/价格信息核对 |
| [11-OSS-REUSE-AUDIT.md](11-OSS-REUSE-AUDIT.md) | 开源参考项目分析 | 10 个 clone、许可证、可直接用的 SDK、值得借鉴的代码与禁止复用范围 |
| [../vendors/README.md](../vendors/README.md) | 上游 clone 复现 | 本地 vendors/ 克隆、固定 SHA、非产品依赖 |
| [archive/2026-10-21-G0-G5-baseline.md](archive/2026-10-21-G0-G5-baseline.md) | 旧版计划归档 | 保留原 G0–G5 的所有要求，当前以三阶段规划为准 |
| [adr/0001-local-first-agent-boundary.md](adr/0001-local-first-agent-boundary.md) | ADR 001 | 只提供通信桥，不重建 Agent |
| [adr/0002-account-ownership-and-credentials.md](adr/0002-account-ownership-and-credentials.md) | ADR 002 | 客户持有账号，最小凭据委托 |
| [adr/0003-delivery-and-cost-semantics.md](adr/0003-delivery-and-cost-semantics.md) | ADR 003 | 至少一次传输，业务幂等、付费发送显式授权 |
| [adr/0004-oss-reuse-boundary.md](adr/0004-oss-reuse-boundary.md) | ADR 004 | 官方 API Schema/Rust SDK 优先，AGPL 与专有代码研究隔离 |

## 文档中的状态词

- **方向已确认**：对话中明确确立的产品/架构边界；仍需开发验证。
- **建议方案**：可执行的设计建议；在 P1-F0 ADR/评审后冻结。
- **待验证**：需要读取实际代码、官方渠道确认或实测。
- **已实现**：只有当前仓库对应代码和测试证据可证明时才可以使用。目前此仓库没有已实现的 Bridge 服务。

## 项目与现有内核的关系

- [Agent24](https://github.com/iDoris-ai/Agent24)：本地 Agent Host、会话/运行/工具/权限/审批/知识库所在体系，Bridge 以它为首选 Agent Adapter。
- [iDoris](https://github.com/iDoris-ai/iDoris)：独立 Rust 模型管理、预算/准入/安全/容量/生命周期内核；Agent24 与它的集成仍需依据实际代码确认。
- [iDoris Bridge](https://github.com/iDoris-ai/iDoris-bridge)：中心化 SNS 的通信桥；保持 Agent 和模型执行在客户自己的环境。

本仓库 SNS **P1–P3** 是独立交付规划，不等于 Agent24 或 iDoris 已有的 **M0–M8** 里程碑。**P1 LINE** 分三步（个人 AI、商家 Agent、组织/社区），可扩展接口从 P1-F0 前置阶段设计。**P2** 扩展 Telegram、WhatsApp 等通信渠道；**P3** 完成通用 Agent 互通、正式自托管/运营与版本发布。

## 范围与原则摘要

1. 客户拥有各 SNS Official Account / Bot / Business Account。默认一客户独立 Bot，不是所有商家共享一个对外身份。
2. 中心 Relay 提供持久在线公网入口、验签、队列、投递、限流与运维；不是 AI 推理 SaaS。
3. Connector 本地主动建立出站安全连接，本地 Agent 不暴露任意公网端口/管理接口。
4. LINE 先行，Telegram 第二，WhatsApp 第三；支持其他 Agent Host 和以后其他渠道。
5. 两种正式运行方式：官方托管 Relay + 客户本地 Agent，或客户自托管 Relay + 客户 Agent。Telegram polling 可选无 Relay 模式。
6. 现有仓库采用 Apache-2.0；不应把 AGPL 或闭源功能当成已通过的许可政策。

主要参考与核验日期见 [来源](10-SOURCES-RESEARCH.md)。
