# 08 · 三大阶段开发路线与验收门禁（当前主计划）

**版本：** 2026-10-21 v0.2 · **状态：** 规划，尚未开始功能实施；本版本取代以前的 G0–G5 六段主计划（完整历史版见 [归档](archive/2026-10-21-G0-G5-baseline.md)）。

## 总体承诺与不能延后的约束

**第一阶段 LINE：** 先让个人本地 Agent24 与自有 LINE OA 真实通信，逐步扩展到小商家和社区/组织，共 **LINE 三步**。**第二阶段其他 SNS：** Telegram → WhatsApp Business（基于官方 Cloud API），兼容更多渠道。**第三阶段开放生态与可运营：** 通用 AgentAdapter、正式开放自托管/托管 Relay、可移植性、发布与服务生态。

**可扩展架构从第 1 天就存在，不是到第三阶段才补上：** ChannelAdapter、ConnectorWire、AgentAdapter 分层，注册绑定、消息 Envelope、ACK、权限与费用语义在 P1 前置冻结。可以只做一个真实 LINE Adapter，但必须有一个 mock channel 和一个 mock Agent 验证替换，而不能写死 LINE/Agent24。

**安全从第 1 天就存在：** 先验签后入库、客户账号所有、租户/设备配对、受限 Agent 接口、Reply 有效期与付费 Push 拒绝、事件与工具幂等；不用“等到第三阶段再加安全”。

## P1 · LINE First（唯一先行渠道；3 个递进交付）

### P1-F0 · 契约与关键开源复用评审（进入第一步前的前置门禁，不单独计作 LINE 三步）

- 冻结 Product Scope / ADR、协议术语、ChannelAdapter/ConnectorWire/AgentAdapter v1、错误与投递状态机、账号与凭据保管设计。
- 优先核查 LINE 官方 [line-openapi](https://github.com/line/line-openapi) 作为 Rust schema/类型生成源；验证 HMAC 签名、replyToken 与平台返回数据，官方 SDK（Node/Go）作为一致性测试参考。
- 从 [开源借鉴清单](11-OSS-REUSE-AUDIT.md) 提取测试向量与借鉴清单；不得把 OpenClaw 的 Agent Loop 或 AGPL 代码直接混入本项目。
- 实际核对 Agent24 的 Run/Session/Approval/OS SDK 接入能力，以及 Agent24→iDoris Provider 的真实生产状态；未实现必须列明独立阻塞项。
- Mock 平台消息到 Mock Agent 的闭环、错误验签、错租户、重复事件、未知 paid outbound 均 fail closed；合同级自动化测试通过。

**Exit：** ADR 评审通过，Schema/契约测试运行可复现，明确真实 LINE 配置方案；不能用完成文档冒充 G0 代码已完成。

### P1-L1 · 个人 AI 基础版（第一步）

**用户：** 个人或开发者，自有 LINE OA，单设备本地 Agent24、一对一私聊；只有经过本人授权的 LINE 用户可访问。**不开放任意陌生客户对 Agent 的工具执行。**

**交付：** 最简 Rust SNS Relay HTTPS Webhook、LINE 真实 HMAC 验证及事件去重、队列/ACK、客户侧常驻 Connector 安全出站连接、Agent24 Native Adapter 调用真实 Session/Run、模型真实返回、LINE Reply API 回发；手动 B 模式 OA 开通向导及设备解绑。完整解耦平台与 Agent trait。

**验收：**
1. 自有 OA 真人发“你好”，经过 Relay → 本地 Agent24 → 已获准本地或外部模型 → LINE Reply，含唯一 trace/event ID。
2. 模型断线、Connector 不在线、LINE Reply Token 过期均显示明确失败，不偷偷改为远程收费模型/付费 Push。
3. 错误签名、事件重放、跨设备/账号、未授权用户、设备撤销及敏感日志审查测试通过。
4. Agent24+iDoris Provider 若当时真实可用，追加其模型路由 E2E；若尚缺失，须如实独立追踪，不能宣称整条集成已完成。

**Exit：** 个人能根据文档自己连接 OA，并连续可靠与本地 Agent24 聊天；记录真实消息收发证据。

### P1-L2 · 小店 / 3–20 人业务版（第二步）

**用户：** 面包店、个体经营、小公司。**交付：** 开放来自顾客的只读咨询（可配置公开/白名单）、菜单营业时间/FAQ/现有 Agent24 知识库、一个业务工具（如预订草稿/订单查询）以及人工确认/接管，简单接入向导，费用预算和平台 429 分类、简单媒体消息。

**验收：**
1. 未授权顾客只可读取获公开授权的信息，不能触发管理操作；店主自己的身份有明确独立绑定。
2. “还有法棍吗→查库存→预订草稿→店主同意→回复”真实流程，无重复订单；跨用户/跨会话不能读取私有数据。
3. Reply/Push 成本分离，未经授权的主动消息始终拒绝；窗口过期可解释，不通过免费回复伪装无限异步发送。
4. 商家能开关人工接管、连接多个授权店员，并撤销 Bot 绑定/设备。

**Exit：** 至少一家获同意的真实小商家完成上线演示和操作反馈；没有客户实际数据/账号所有权转移。

### P1-L3 · 社区 / 30–100+ 人组织版（第三步）

**用户：** 社区群组、中小企业多成员。**交付：** LINE 群消息及 mention/命令规则、角色与审批、多 Bot/租户归属与限额、事件持久恢复与租约 fencing、群发审批、人工接管的并发与审计、运维诊断、组织成员加入/退出。

**验收：**
1. 组织、成员、群组及 Bot 多租户隔离；普通群成员不能作为 Agent24 管理员调用工具。
2. 断网、Relay 重启、ACK 丢失、重复 Webhook、发送结果 ambiguous、配额耗尽的故障注入通过。
3. 对社区活动报名/成员问答/通知做受控真实演示；未授权群发必须为零。
4. 公开样例有负载边界、速率限制、备份和密钥轮换；不会因为“连接在线”错误声称模型可用。

**Exit：** LINE 个人→店铺→组织三种明确受控形态验收通过；有进入其他渠道的稳定基础。

## P2 · Multiple SNS（第二大阶段）

- **P2-T · Telegram：** Rust [teloxide](https://github.com/teloxide/teloxide) 为首选候选 SDK；BotFather 自有 Bot 必须可接入，Managed Bot 仅在 PoC 后可选；Webhook 与 getUpdates 不能同时使用；群权限、媒体及发送速率限额独立实现。
- **P2-W · WhatsApp Business：** 官方 Meta Business Platform / Cloud API / Embedded Signup 和相关当期政策为准；禁用非合规的开放式通用 AI 主用途；平台服务窗口/模板/地区收费要版本化、预算 fail closed。不得复用非官方 WhatsApp Web 会话代码替代 Business API。
- **P2-E · 其他渠道：** Web Chat、Messenger、Instagram、Discord 等根据客户实际需求排序，增添 ChannelAdapter；不修改 Agent24 Agent Loop 和 iDoris 模型管理。
- **持续验收：** 同一个 Agent 收到 LINE 与 Telegram 消息，身份 scoped 不互串；channel adapter plug/unplug 不破坏旧连接；不同频道账单/授权独立；WhatsApp 真实商户准入和政策证据齐全。

**Exit：** LINE + Telegram 实测可用，WhatsApp 在取得合规/官方授权条件下完成，不以强制所有客户使用三平台为要求。

## P3 · Open Interop & Operations（第三大阶段）

- **P3-A · 通用 Agent 接口：** 标准 AgentAdapter、A2A-compatible 适配器、能力协商、错误/审批与模型隐私策略声明；同一 Channel 能切换 Agent24 或兼容第三方 Agent。
- **P3-H · 运维可靠性：** 完整自部署 Docker/二进制、官方托管 Relay（只经营通信入口不经营 AI 推理 SaaS）、HA/备份/迁移、自助开户 UX、可观测性与安全监控。
- **P3-O · 开源发布：** Apache-2.0 依照当前仓库 LICENSE；可再审议商业许可，但不得偷偷更改；供应链审计（SBOM/NOTICE/锁版本）、协议兼容矩阵、贡献指南、可复现 Release 与升级/回滚。
- **验收：** 外部第三方不改 Relay 即可接自己的 A2A Agent；使用开源文档能独立自部署、导出迁移；官方托管与自托管协议互通；无账号或数据锁定。

**Exit：** 正式带 tag 的兼容发布、真实第三方自部署验收、运营和许可证审查完成。

## 原 G0–G5 的保留与映射

旧版包含的重要安全/功能/验收约束**没有删除**，完整保留在 [2026-10-21 G0–G5 归档](archive/2026-10-21-G0-G5-baseline.md)。当前统一执行的主计划为 P1/P2/P3：

| 旧计划 | 当前归属 |
|---|---|
| G0 契约与安全基线 | P1-F0（严格前置），安全贯穿所有阶段 |
| G1 LINE 纵向闭环 | P1-L1（个人）→ P1-L2（小店）→ P1-L3（组织） |
| G2 Telegram + 开放 Agent | Telegram 为 P2-T；通用接口骨架从 P1-F0 做，全面成熟在 P3-A |
| G3 可靠性/多租户/自部署 | 核心正确性从 P1 开始，组织级 P1-L3，运维/迁移扩展 P3-H |
| G4 WhatsApp | P2-W |
| G5 开源正式版/托管 Relay | 从第一个 commit 就开源，正式运维与版本发布在 P3-O |

## 开发工程规则

- 每一个工作单元在独立 branch/worktree，优先小 PR；生产代码建议 ≤300 行，特殊 ≤500 行需说明，超限拆分。无 force push/rebase 共享分支，不破坏无关工作区改动。
- 代码须 Rust fmt、strict clippy、单元/契约/故障注入/安全测试、CI 证据；评审、CI、mergeable 条件满足再合并，阶段结束补写 checkpoint/CHANGELOG。
- 第三方库引入前：确认 SPDX 与实际 LICENSE、固定 semver/SHA、跑依赖/漏洞/许可证审计、保留 NOTICE，避免静态拷贝大项目。
- P1 的真实 Agent24→iDoris Provider 路径属于与既有项目的集成验证，不允许新增第二套知识库、模型路由或 Agent Loop 作为“临时替代”。
