# 06 · 部署形态、稳定运营与故障恢复

**核心定位：** SNS 平台需要稳定公网 Webhook，Bridge 提供中心化**通信连接**基础设施。Agent 和知识库仍由用户运行；官方托管的是 Relay，不是 Agent 推理 SaaS。

## 1. 三种可支持的部署模式

| 方案 | SNS 公网入口 | Connector/Agent | 管理者 | 面向谁 |
|---|---|---|---|---|
| A · 官方托管 Relay | iDoris 运营的可靠 Relay | 客户自己的 Mac/Linux/服务器与 Agent24/iDoris | 官方管 Relay，客户管 Agent | 面包店、个体户、社区、小公司 |
| B · 客户自部署 | 客户自己的域名、服务器和 Relay | 客户自己的 Connector/Agent | 客户 | 开发者、IT 团队、企业 |
| C · Telegram 本地轮询 | 可无 Relay（getUpdates） | 客户单机 Connector/Agent | 客户 | 技术用户、单 Bot 特殊场景 |

**关键区别：** 两种正式部署复用相同开源协议和代码，必须支持导出/迁移，不锁在官方服务器。C 只针对平台提供合法轮询机制的渠道，不能推导 LINE/WhatsApp 都无需公网服务。

## 2. MVP 最小资源/进程

~~~text
Public VM + DNS + TLS certificate
 ├─ bridge-relay (Rust, HTTPS webhook/device API)
 ├─ PostgreSQL (persistent event inbox/outbox, binding/device metadata)
 ├─ Secrets Store (encrypted scoped ingress credentials)
 └─ Monitoring/metrics + backups

Customer Mac/Linux
 ├─ bridge-connector (launchd/systemd, persistent outbound connection)
 ├─ agent24d (local Agent host; desktop is optional shell)
 ├─ idoris (optional local model management service; existing integration)
 └─ local or permitted external model / local knowledge / tools
~~~

建议从 PostgreSQL event inbox/outbox + transactional lease + 唯一索引实现，不急于引入 Kafka/NATS。多机 Relay 实例扩展时保持无状态 HTTP、中心数据库/队列和租约 fencing。需防单数据库瓶颈与负载高峰，容量上限由测量确定。

## 3. 本地守护进程生命周期

- macOS launchd / Linux systemd 开机自启；Windows 服务可在后续做。Agent24 Electron 窗口关闭不应影响 Connector/agent24d 自身生命周期。
- 与 Relay 连接由本地主动发起，具备断线指数退避与随机 jitter、心跳、短期凭据轮换、游标恢复与订阅重新授权。
- 检测 Agent 健康（Agent24 启动、模型可用、审批准入状态）必须与 Connector/Relay 健康分别展示，不能“Relay 在线”等于“Agent 可响应”。
- 多设备同一 Binding 要有 owner lease + fencing epoch，阻止双重执行具有副作用的订单/消息。
- 离线队列有上限、存储加密、TTL 到期标记；客户离线时不能承诺可靠的实时免费 Reply，也不能默认改用付费 Push。

## 4. 连接开通到退订的运营流程

~~~text
customer_sign_in (local)
  -> device_pairing (one-time code + key exchange)
  -> provision_sns_account (customer official account)
  -> connect_channel (verified binding)
  -> assign_agent + scoped policy
  -> test_inbound + outbound + offline
  -> activate
  -> monitor / rotate / backup
  -> suspend / revoke / export / delete
~~~

初期 UI 可走本地浏览器配置页或 Agent24 壳，公共 Relay 管理只维护账号连接状态与系统健康，不接管用户的知识库内容。Relay 管理端的组织创建、设备吊销及凭据变更必须强身份认证和显式授权。

## 5. 可靠性与排障状态

| 状态 | 用户看见什么 | 操作策略 |
|---|---|---|
| SNS Webhook 验签失败 | “平台配置错误或来源非法” | 记录无敏感细节、拒绝，不投递 |
| Relay 排队中 | “消息已接收，等待设备” | 有界排队、TTL、可查看滞留数量 |
| Connector 离线 | “客户本地服务离线” | 适度重投，不接管 AI |
| Agent 或模型不可用 | “Agent 暂不可用” | 现有 Agent/iDoris policy fail closed，不上云兜底 |
| awaiting_approval | “需要店主确认” | 不提前创建订单/转账/广播 |
| outbound ambiguous | “平台发送状态未知” | 不盲重发，人工/查询核实 |
| reply expired | “免费回复窗口过期” | 禁止静默 Push；可经批准发送后续通知 |
| platform quota/429 | “超额/限流” | 预算门控 + backoff，分类错误 |

建议健康度分为 inbound acceptance、queue health、device connection、Agent readiness、model readiness、outbound delivery 六个指标。绝不以 HTTP 200 或 iDoris health 代替业务完整可用证明。

## 6. 备份、升级与迁移

- Relay 数据库：数据库版本迁移、增量备份、复原演练；不要默认备份用户 SNS 原文。Secrets/keys 与 DB 分离。
- Connector：导出非敏感绑定配置（binding ID / channel / endpoint / Agent mapping），密钥由客户在目标机重新授权/导入到 OS 安全库；不能把明文 Access Token 包进普通备份。
- 官方↔自部署：可在 G3 提供迁移向导（重新配置 Webhook、冻结旧 Binding、排空旧队列、重建设备、切换验证并回滚）；迁移期不可让新旧 Relay 同时执行同一事件。
- 版本化协议：当前版本、兼容版本范围、强制迁移步骤、回滚策略写入 CHANGELOG 和发布说明。

## 7. 运维 SLO 与测量建议

正式 SLO 必须通过真实负载测试确认，不在 G0 阶段虚构 99.99% 保证。至少收集 p50/p95 webhook 接收延迟、入站验签失败率、event lag、ACK 时延、离线时长、消息过期率、出站 4xx/5xx、发送成本与租户分布。所有日志遮盖手机号、Token 与 SNS 消息文本。G3 的断网注入、Relay 重启、数据库恢复、租户权限测试均需存 CI/验收记录。
