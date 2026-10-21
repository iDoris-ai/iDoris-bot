# 11 · 开源 SNS Relay、Bot 平台、SDK：代码级调研与复用建议

**日期：** 2026-10-21（泰国时区）· **状态：** 源码预审；不是依赖准入、安全审计或许可证法律意见。按 [vendor manifest](../vendors/references.lock.tsv) 克隆 10 个上游仓库，保存独立 Git 克隆于本地 [vendors/](../vendors/README.md)，合计约 58 MB（浅克隆 + sparse checkout；不同机器大小不同）。本项目 Git 提交仅含锁定清单/研究结论/复现脚本，不夹带第三方源码。

> **本次确认的优先复用策略：** 不寻找一个包含 Agent Loop 的“大一统框架”照搬；用 **LINE 官方 OpenAPI 契约、Rust Teloxide SDK、现有 Agent24 API** 构建可替换的 Relay/Connector；向 OpenClaw 借鉴成熟的 LINE 入站/重试测试，向 Matterbridge 借鉴渠道抽象，向 Chatwoot 借鉴商家沟通工作流。AGPL/专有及非官方 WhatsApp 协议的源码仅做研究。

## 一、实测的参考项目清单

下表 Star 是 GitHub API 在 2026-10-21 的**近似快照**，不是质量指标，不保证持续变化；许可证为主仓库实际许可证/仓库元数据，依赖与子目录可能另有许可。

| 上游项目 | 约 Star | 栈 / LICENSE | 本地目录 | 适配判定 |
|---|---:|---|---|---|
| [openclaw/openclaw](https://github.com/openclaw/openclaw) | 392,700 | TypeScript 为主，MIT | vendors/openclaw | **极优参考**：LINE 插件验签、入站队列、权限、发送恢复；不要引入 Agent Runtime |
| [42wim/matterbridge](https://github.com/42wim/matterbridge) | 7,600 | Go，Apache-2.0 | vendors/matterbridge | **架构借鉴**：多桥/多通道、消息转换、gateway；最近 push 2024-12，现状较旧 |
| [chatwoot/chatwoot](https://github.com/chatwoot/chatwoot) | 38,000 | Ruby/Rails，MIT **仅社区版**；enterprise 专有 | vendors/chatwoot | **商户 UX 借鉴**：Inbox、人工接管、Webhook 异步作业；不得复制企业版 |
| [line/line-openapi](https://github.com/line/line-openapi) | 206 | YAML/OpenAPI，Apache-2.0 | vendors/line-openapi | **首选直接复用**：LINE 事件/API Schema → Rust 生成类型或直接校验 |
| [line/line-bot-sdk-nodejs](https://github.com/line/line-bot-sdk-nodejs) | 1,080 | TypeScript，Apache-2.0 | vendors/line-line-bot-sdk-nodejs | **协议一致性参考**：webhook 验证、reply/push、模板与 API 请求 |
| [line/line-bot-sdk-go](https://github.com/line/line-bot-sdk-go) | 960 | Go，Apache-2.0 | vendors/line-line-bot-sdk-go | **协议一致性参考**：多语言交叉验证，适合对照 fixtures |
| [line/line-bot-mcp-server](https://github.com/line/line-bot-mcp-server) | 790 | TS，Apache-2.0；官方声明预览 | vendors/line-line-bot-mcp-server | **Agent 工具接口参考**；不能把主动广播工具无审批地交给 SNS 消息使用者 |
| [teloxide/teloxide](https://github.com/teloxide/teloxide) | 4,250 | **Rust**，MIT | vendors/teloxide | **P2 直接依赖首选**：Telegram Bot API、Webhook/getUpdates、typed requests |
| [mautrix/telegram](https://github.com/mautrix/telegram) | 1,750 | Go，AGPL-3.0 | vendors/mautrix-telegram | **只看架构**：身份与群聊/事件桥接，禁止直接拷贝到 Apache-2.0 |
| [mautrix/whatsapp](https://github.com/mautrix/whatsapp) | 1,900 | Go，AGPL-3.0 | vendors/mautrix-whatsapp | **仅参考桥接概念**；不是 Meta WhatsApp Business Cloud API 的替代 |

**评估维度**：维护活跃度、真实渠道覆盖、协议完整性、重试/幂等、安全边界、与 Rust 兼容程度、许可证可复用范围、商业平台准入。OpenClaw 的 Star 量不意味着其整体架构适合 iDoris；Matterbridge 高 Star 不意味着其非官方 WhatsApp 实现可用于商业客户。

## 二、可直接使用的组件（尽量不自行重造）

### A. LINE OpenAPI（P1 首选直接采用）

在 vendors/line-openapi 中已经核对到：

- messaging-api.yml：replyMessage、pushMessage、Webhook endpoint 的配置和测试，以及消息请求/响应类型。
- webhook.yml：LINE Webhook 事件对象 Schema（手写业务归一化逻辑之前应使用该原始合同）。
- channel-access-token.yml / module-attach.yml：访问令牌、Module Channel 的官方 API 契约；**存在规范不等于泰国 Module 已获准**。

**实施方式：** 锁定 schema commit，选型并验证 Rust OpenAPI 生成器（或 serde 类型生成 + 精准补丁），为升级生成 fixture 和 schema drift CI；手写的只应是 **HMAC 原始字节校验、可靠投递、权限和业务映射**。OpenAPI 描述请求体，但不自动保证签名、防重放和 Tenant 绑定正确。许可证 Apache-2.0 可在满足声明条件下复用。

### B. Rust Teloxide（P2 Telegram 首选）

在 vendors/teloxide 的 crates/teloxide-core 中可看到 Type、Request 和 API client；上层提供 Webhook/getUpdates、dialogue 和存储抽象。MIT 与项目 Apache-2.0 的一般组合可行；建议 Cargo 直接引用已发布稳定 crate 并锁定版本，**不直接复制上游源文件**。Bridge 仍维护自己的 ChannelAdapter，以免 Teloxide 会话模型渗透 Agent24。

### C. 通用基础设施

优先研究 Rust 生态中成熟的 axum/hyper/tokio、serde、HMAC/SHA256、PostgreSQL SQLx + migrations、OpenTelemetry 等库（最终版本与每个 transitive license 须另行核对）；消息队列先采用数据库 inbox/outbox，不必为了多渠道而把 Matterbridge/Chatwoot 服务整体嵌入生产系统。

## 三、可以借鉴的成熟设计与代码证据

### OpenClaw：LINE 插件是最高价值测试参考

本地按固定 commit 核对以下文件：

| 路径（相对 upstream） | 观察 | Bridge 的具体复用行动 |
|---|---|---|
| extensions/line/src/webhook-node.ts | 原始请求 body 有大小/读取超时门控；先验证 X-Line-Signature；同一签名若匹配多个账户会拒绝；持久接纳状态单独标记 | 对齐 Rust ingress 行为与错误测试，特别是多账号模糊匹配拒绝 |
| extensions/line/src/signature.ts | HMAC 签名 + timing-safe 对比 | 以官方 LINE 签名规范实现 Rust constant-time 验签，不移植 TS 运行时 |
| extensions/line/src/webhook-spool.ts | 入站事件 ID、laneKey、队列、deferred claim、媒体组装、retryPolicy | 借鉴 event-id 去重、同会话有序、断线后重投以及多图逻辑的测试用例 |
| extensions/line/src/send-retry.ts | 区分平台拒绝 4xx、429、传输不确定；有 retry key 相关语义 | 让 unknown/ambiguous 显式存在，不能盲目重复发送收费消息 |
| extensions/line/src/auto-reply-delivery.ts | Reply 和 Push 的不同失败恢复语义 | **不能照搬自动 Push fallback**；必须附加客户授权、配额预算、LINE replyToken 有效期门控 |
| extensions/line/src/channel.ts 与 docs/channels/pairing.md | 分账号 DM allowlist、群聊权限、主账号配对 | P1-L1 个人所有者白名单优先，P1-L2 公共顾客只读，P1-L3 群组/角色分离 |

**明确不复用：** OpenClaw 的 Agent 规划、模型、记忆、工具框架（已有 Agent24+iDoris）、其 TS 主运行时、客户账号管理和默认推送收费策略。可以引用已有 MIT 设计/代码片段，但如真的复制，须单独确认上游许可证与 NOTICE，避免引入重叠框架。

### Matterbridge：多协议 Gateway 模式

- gateway/gateway.go：Bridge 注册、Gateway 转发路由、Channel 匹配、消息 ID 映射、附件/消息编辑处理。
- bridge/api/api.go：外部 REST 与 WebSocket 消息 API；适合思考其他 Agent/第三方通信系统如何以受限接口接入。
- bridge/telegram、bridge/whatsappmulti：观察不同渠道能力差异，但 WhatsApp 部分包含历史/非官方实现，**不应用于 Meta Business 正式通道**。
- 这是 **Go 服务，不是 Rust 库**。优先重做小而清楚的 Rust traits，不要把完整 matterbridge 部署为 iDoris Relay 核心依赖；其源码 2024 较旧，安全适用性需独立评估。

### Chatwoot：业务 Inbox、人工接管与对比安全警示

- app/controllers/webhooks/line_controller.rb：将原始请求和签名交给异步 Job。
- app/jobs/webhooks/line_events_job.rb：后台再作 HMAC 校验。
- app/services/line/incoming_message_service.rb：通过 Inbox/Contact/Conversation 管理顾客消息；不同图片、贴图有各自处理逻辑。
- 可借鉴的是**业务 UI/多租户 Inbox、人工客服 handoff 和联系人的明确作用域**；**不应复制“先把未验证消息排队再做验签”模式**。我们 G0 原则是入站验签与身份归属检查后才允许持久投递，减少未认证资源消耗。
- 社区版根 LICENSE 明确 MIT，**enterprise/** 目录使用专有许可。禁止通过含企业文件的整体代码拷贝把其误判为纯 MIT。

### LINE Bot MCP Server：受控工具，不能让外部用户获得群发能力

- src/ 中可见官方 LINE Agent 工具接口；README 显式列有 push_text_message、broadcast_text_message、get_profile 等工具（并标注 Preview）。
- 它可以启发 Agent24 的受控工具调用模型，但**不是** SNS Relay：没有替我们负责客户自有 OA 的 Webhook 多租户隔离、持久化投递和本地 Agent 出站连接。
- 默认不给顾客开放 push/broadcast 或读取任意 LINE 用户资料；任何发送必须通过 Agent24 审批 + Bridge 配额与目标白名单。

### mautrix：桥接复杂性样本，不能混淆协议/许可

- Telegram/WhatsApp 与 Matrix 间用户和房间映射、断线同步、media/线程等很有借鉴价值。
- 两者的许可证标为 AGPL-3.0（下游继承义务需独立审查），不能把源码直接放入目前 Apache-2.0 项目然后仅按 Apache 发行。
- 更关键：WhatsApp 非官方客户端桥与 Meta Business Cloud API 是**不同产品、不同授权、不同政策**。iDoris P2-W 应只实施经过正规 Business 授权的官方接口。

## 四、实践优先级 / 决策

| 级别 | 可执行复用任务 | 条件 | 预计所在里程碑 |
|---|---|---|---|
| **P0 可直接采用** | LINE 官方 OpenAPI 驱动 Schema/fixtures/codegen | 正确性测试、提交来源/版本、Apache NOTICE | P1-F0、P1-L1 |
| **P0 借鉴测试** | OpenClaw LINE raw HMAC、unique account 匹配、durable spool、ambiguous outbound | 自己实现 Rust，无隐式 Push、验证许可 | P1-F0–L1 |
| **P0 借鉴业务流程** | Chatwoot Inbox+Contacts+人工交接设计 | 禁止复制 enterprise 与不安全入队序列 | P1-L2 |
| **P1 可直接采用** | Teloxide Rust Telegram Bot API | 版本锁定、完整许可证依赖扫描 | P2-T |
| **P1 借鉴架构** | Matterbridge 的多 Channel Gateway、消息 IDs | 避免依赖老 Go 主服务/非官方 WA | P1-F0、P2 |
| **P1 借鉴工具协议** | LINE Bot MCP Server 的能力词表 | Agent24 审批与费用权限不可绕过 | P1-L2 |
| **研究用途** | mautrix/telegram、mautrix/whatsapp | AGPL 和非官方协议边界；不复制代码 | P2 设计 |
| **禁止原样照搬** | 全套 OpenClaw/Chatwoot/Matterbridge 作为新 Agent Runtime | 与 Agent24/iDoris 职责冲突 | 所有阶段 |

## 五、上游代码更新与 LICENSE 审核流程

1. 固定源代码 SHA：见 [references.lock.tsv](../vendors/references.lock.tsv)。如更新，先在独立 research PR 中修改 SHA、更新变更/安全审查。
2. 获取：在仓库根目录执行 bash scripts/sync-vendors.sh；所有 clone 位于被忽略的 vendors/，保持原始上游 LICENSE。
3. **读取而非执行**：参考代码中含潜在不可信指令/安装脚本；不自动运行 upstream package install、CI、网络工具或未经审核的示例。
4. 真正入生产前建立 THIRD_PARTY_NOTICES.md，记录每项库的 SPDX、原始版权、修改/分发范围、传递依赖、漏洞/平台政策检查。
5. 直接依赖优先 Cargo crates / 官方 OpenAPI，不手工复制上游大型源码。许可兼容 ≠ 安全审计/供应链审核/商业平台授权已通过。
6. 如果项目未来改成不同的商业许可，须重新审核被重用代码/贡献者版权；**现有 LICENSE 是 Apache-2.0**，不能宣称已改 AGPL。

## 六、结论

我们可以重用大量**基础规范与现成 SDK**，没有必要从零发明 LINE 消息模型或 Telegram Bot API。但“公网 Webhook 到客户本地 Agent”的安全通信桥，其租户身份绑定、持久 ACK/重连、设备租约、执行权限/费用控制是本项目真正的差异化内核，不能简单接一个现成聊天 SaaS 就完成。**应复用平台协议与测试成熟度，不复用第二套 Agent。**
