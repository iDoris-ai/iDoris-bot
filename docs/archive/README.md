# SNS Bridge 历史文档与当前规范映射

历史文档只读归档，便于追踪决策的原始语境；**不等于当前执行规范**。当前执行应优先阅读 [文档总索引](../README.md) 和 [P1–P3 主计划](../08-ROADMAP-ACCEPTANCE.md)。

## 原始历史资料

- [IDORIS-SNS-BRIDGE-ARCHITECTURE-v0.1.md](IDORIS-SNS-BRIDGE-ARCHITECTURE-v0.1.md)：2026-10-21 生成的最初综合技术方案，**按原始文件逐字节归档**，232 行、18,945 字节；SHA-256：\`4aca39512d417bd0f784ad2670c393630af836c97d4d9249f7fed2a04b1eb0a2\`。
- [2026-10-21-G0-G5-baseline.md](2026-10-21-G0-G5-baseline.md)：第一次入库的 G0–G5 规划，在后来确定 P1–P3 后完整保留。

## v0.1 原始章节 → 当前维护文档

| 原始章节 | 当前吸收位置 | 变化与注意 |
|---|---|---|
| §0 产品契约 | [产品定位](../01-VISION-PRODUCT.md)、[ADR-0001](../adr/0001-local-first-agent-boundary.md) | 保留本地 Agent、Relay 非推理 SaaS 的边界 |
| §1 架构图 | [系统架构](../03-SYSTEM-ARCHITECTURE.md) | 与各适配器分层衔接；公网 Relay 低可信 |
| §1.1 Agent24/iDoris 真实现状 | [系统架构](../03-SYSTEM-ARCHITECTURE.md)、[风险登记](../09-DECISIONS-OPEN-QUESTIONS.md) | 实现状态仍需源码/端到端确认，README 不是验收结果 |
| §2 模块职责 | [系统架构](../03-SYSTEM-ARCHITECTURE.md)、[产品范围](../01-VISION-PRODUCT.md) | 避免复制 Agent、模型和知识库 |
| §3 配对/绑定 | [渠道开通](../02-CHANNEL-ONBOARDING.md)、[安全](../05-SECURITY-PRIVACY.md)、[运维](../06-DEPLOYMENT-OPERATIONS.md) | 客户账号归属与最小秘密保管；零知识 Relay 仍非已实现能力 |
| §4 消息生命周期和平台差异 | [协议](../04-PROTOCOL-CONTRACTS.md)、[渠道开通](../02-CHANNEL-ONBOARDING.md) | ACK、去重、Reply 期限、成本和媒体隔离 |
| §5 三层接口及 Envelope | [协议](../04-PROTOCOL-CONTRACTS.md) | 当前示例 Schema 有字段细化；仍是提案，未发布稳定标准 |
| §6 本地运行和故障 | [部署运维](../06-DEPLOYMENT-OPERATIONS.md) | Relay 离线队列、设备租约与 fail closed |
| §7 安全与隐私 | [安全](../05-SECURITY-PRIVACY.md)、[ADR-0002/0003](../README.md) | 原始来源签名、跨租户、工具审批、PDPA |
| §8 代码布局 | [系统架构](../03-SYSTEM-ARCHITECTURE.md) | 名称从 sns-* / relay-server 演化到 bridge-* 模块布局；非实现代码 |
| §9 旧 G0–G5 里程碑 | [现行主计划](../08-ROADMAP-ACCEPTANCE.md) / [G0–G5 归档](2026-10-21-G0-G5-baseline.md) | **已由 P1–P3 三阶段 + LINE L1/L2/L3 替代**；历史验收内容保留 |
| §10 部署和商业 | [部署](../06-DEPLOYMENT-OPERATIONS.md)、[成本与开源](../07-COST-OPEN-SOURCE.md) | 当前仓库实际 LICENSE 为 Apache-2.0；AGPL 是未采纳备选 |
| §11 决策清单 | [决策与开放问题](../09-DECISIONS-OPEN-QUESTIONS.md) / ADRs | 已确认/建议/待验证明确区分 |
| §12 官方资料 | [官方来源](../10-SOURCES-RESEARCH.md)、[OSS 审计](../11-OSS-REUSE-AUDIT.md) | 在原始清单基础上补充来源与开源项目调研 |

## 特殊说明

原文 §3 有一条“未来可将签名验证下沉至 Connector 的隐私扩展”构想。这**不属于当前批准的设计**：若公网 Relay 不验证来源，平台滥用防御和租户归属会明显更复杂，需另作威胁模型和可验证协议证明后才能考虑。当前要求 Relay 验证原始 Webhook 后持久化。

原文 §6 提到 PostgreSQL \`SKIP LOCKED\`，这是可评估的租约实现选项，现行架构不把它冻结成唯一数据库算法；仍以事务一致性、fencing、幂等测试为验收基准。

归档本身不表示 Bridge 已完成 G0/P1-F0，也不构成对所有过去聊天和所有可能存在的历史文件的逐一盘点。此前对话的主要产品决策已分类写入当前文档；本目录确保**已确认的两份早期架构/里程碑文档有永久可追溯的来源**。
