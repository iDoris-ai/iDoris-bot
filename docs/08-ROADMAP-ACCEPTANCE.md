# 08 · G0–G5 开发里程碑与验收门禁

**状态：规划。** SNS Bridge G* 与 iDoris/Agent24 的既有 M*、P* 等路线完全独立。每阶段至少提交：实现/架构文档、可执行验收测试、风险/待办登记、变更日志、PR/CI 证据。阶段已完成必须有实际可复现证据。

## G0 · 合同与安全基线（先完成）

**交付：** 接口术语、明确非 SaaS 定位、账户/消息所有权 ADR、ChannelAdapter/ConnectorWire/AgentAdapter v1 JSON Schema 或 Rust 类型规范、失败状态机、威胁模型、成本门控、Agent24 集成 spike、LINE 官方案例/开户 PoC 文档。

**必验：**

1. 代码/README 核对当前 agent24d Sessions/Runs/Approval 接口、OS/Attached 扩展实际能力和 iDoris Provider 真正接入状态；不能用旧规划当成已存在能力。
2. 用模拟平台事件执行“验签→可信租户绑定→可靠投递→mock AgentAdapter→出站权限决策”；展示跨租户拒绝、过期 Token、不准许付费 Push。
3. 冻结错误码、事件 ID、ACK/重投、费用策略、Secrets 归属和离线状态；明确 unresolved decision 的 owner。
4. Architecture/Privacy/License 审核通过；明确 LINE B 默认路径和 C 的平台准入未知状态。

**Exit Gate：** ADR 和协议 fixture 可在 CI 验证；不能以 README 完成代表 G0 功能完成。

## G1 · LINE 真实纵向闭环

**交付：** Rust LINE ChannelAdapter、单节点持久 Relay、Connector OS daemon、最小安全 Pairing、Agent24 真实会话/运行适配、自有 OA 向导、Reply/预算门控、诊断面板 MVP。

**必验：**

1. 自有 OA 的真人消息进入 Relay，验签通过并 ACK 入库，本地 Connector 经 TLS 获得消息。
2. 真实 Agent24 Agent Loop 调用**当前实际可用的本地模型**完成回复；iDoris Provider 路径若尚未具备，必须独立标成集成阻塞/另行真实验收。
3. 使用一次性且未超期的 Reply Token 返回 LINE；超期仅在已批准/有预算时走 Push；免费 Reply 和主动发送用量分别记录。
4. 错误签名、Webhook 重投、断线、重复下单、跨租户投递、设备撤销等测试全绿。

**Exit Gate：** 面包店“库存询问→受控预订草稿→人工批准→回复”的端到端 demo，可解释每一条工具与费用决策。

## G2 · Telegram + 开放 Agent

**交付：** Telegram BotFather 手动接入、Webhook/可选 getUpdates、群权限/mention、Managed Bot 创建引导的 PoC/可选正式接入、第三方 A2A AgentAdapter。

**必验：** 相同客户 Agent 在 LINE 与 Telegram 保留**不同渠道身份域**并稳定收发；Managed Bot 仍为用户所有且可撤销；A2A Agent 可替换 Agent24（无需改 SNS Relay）；Webhook/polling 不同时启用。

**Exit Gate：** 双渠道可用、第三方 Agent 兼容测试通过。

## G3 · 可靠性、多租户与自部署

**交付：** Durable queue/租约/HA 设计、审计与可观测性、用量预算、密钥轮换、账号解绑、数据删除、Docker Compose 自部署、备份迁移、客户诊断 UX。

**必验：** 至少覆盖断网/重启/ACK 丢失/出站 ambiguous/Relay-DB 失效、受控恢复；多租户安全与凭据隔离；设备撤销；从官方 Relay 导出并迁移到自部署 Relay。

**Exit Gate：** 可重复故障注入与恢复报告、部署文档可由第三方走通。

## G4 · WhatsApp 商家业务通道

**交付：** Meta WABA/Cloud API 授权、Webhook 适配、业务号码映射、24h 服务窗口/模板/类别计费策略、合规审查与禁用路径。

**必验：** 真实商户授权/解绑；能收发合法业务咨询；费率/政策版本化；达到预算上限拒绝出站；平台不允许的开放式通用 AI Bot 功能默认禁用，企业业务 Agent 适用性由法务与渠道确认。

**Exit Gate：** 满足真实 Meta 限制且有收发与费用报告，而非仅通过 mock。

## G5 · 开源正式版与托管 Relay 运维

**交付：** 可复现构建、SBOM/安全指南、版本化 API、SDK/示例 Agent、Release/升级/回滚、社区贡献流程、许可证审计、官方 Relay 支持服务说明、维护者手册。

**必验：** 陌生开发者根据 README 能自行搭建 Relay、安装 Connector、连接自己合法拥有的 SNS Bot；第三方 Agent 不被迫安装 iDoris；线上官方 Relay 与自部署协议保持兼容；迁移/撤销流程可执行。

**Exit Gate：** 发布正式 Tag/Release，带 CI、冒烟测试、变更记录及未来兼容声明。商业支持可以同时提供，但不使开源基础部署失效。

## 分支/PR/质量策略

- 每个 G 拆成协议、Relay、Connector、平台适配、验证等**可独立评审的小 PR**；生产代码变更尽量 ≤300 行，特殊 ≤500 行解释；较大必须拆分。测试/fixtures/设计文档不计。
- 使用独立分支或 worktree；不 rebase/force-push 共享分支，不覆盖无关工作区改动。
- 所有 Rust 代码执行 fmt、clippy strict、unit/integration/contract/security tests，并通过 CI；文档执行链接/Markdown/术语/版本检查。
- 安全相关请求 review：Webhook 签名、设备授权、账单门控、事件幂等、任何连接 Agent 管理接口的变更。
- 满足组织既有合并门禁后合并；审查意见需修复且重新验证。每阶段完成写清 commit SHA、PR、测试与遗留风险，而不是只打勾。

## 依赖与优先级

1. **最关键依赖：Agent24 实际具备的 Agent Host API 和 iDoris Provider 状态。** 未具备完整接口不阻塞 LINE transport mock/本地模型 G1，但不能谎称 iDoris 全栈联动通过。
2. LINE Module Channel 的泰国权限/申请若未获批准，不阻塞 G1 B 模式。
3. WhatsApp 的服务定价和 AI 条款需在 G4 再查当期官方原文；不要提前锁定旧数值。
4. Managed Bot 是便利性增强，不应阻塞 Telegram 基础 BotFather 连接。
