# 03 · 系统架构：公共 Relay + 本地 Connector + 既有 Agent

**状态：建议架构，P1-F0 待冻结。** 架构目标是可靠桥接，不扩大云端可信计算范围。

## 1. 全景

~~~mermaid
flowchart TB
    subgraph SOCIAL["第三方中心化 SNS"]
      LINE["LINE OA"] --- TG["Telegram"] --- WA["WhatsApp Business"]
      OTHER["Web Chat / Messenger / 其他"]
    end
    subgraph RELAY["公网 SNS Relay（官方托管或客户自部署）"]
      WEB["HTTPS Webhook + 来源验证"]
      ROUTER["Channel Adapter / 可信账户映射"]
      OUTBOX["有界持久队列 + ACK / 重投 / TTL"]
      OPS["限流 / 监控 / 配额计数 / 设备注册"]
      WEB --> ROUTER --> OUTBOX
      ROUTER --> OPS
    end
    subgraph CUSTOMER["客户本机 / 局域网 / 自有服务器"]
      CONN["Connector Daemon（主动出站长连接）"]
      AA["Agent24 原生适配器"]
      AB["第三方 AgentAdapter（A2A 优先）"]
      AGENT["Agent24 agent24d / 其他 Agent Host"]
      IDORIS["iDoris Core / 模型管理与策略"]
      MODEL["本地模型 + 已授权云端模型"]
      DATA["客户知识库、工具、记忆、人工审批"]
      CONN --> AA --> AGENT
      CONN --> AB --> AGENT
      AGENT <--> IDORIS --> MODEL
      AGENT <--> DATA
    end
    SOCIAL <-->|"平台 Webhook + 发送 API"| RELAY
    OUTBOX <-->|"TLS + 设备身份；本地发起"| CONN
    CONN -. "本地保存渠道发送凭据；可直接调用官方发送 API" .-> SOCIAL
~~~

上图中 iDoris 是 Agent 可使用的模型决策内核，并非每个第三方 Agent 的强制依赖。iDoris 的能力包含模型发现/选择、容量/预算/准入、降级、生命周期、安全与审计；Bridge **不**重复实现。已有 Agent24 的记忆、工具、审批和会话语义同理。

## 2. 信任区与部署职责

| 单元 | 运行场所 | 必须完成 | 严禁 |
|---|---|---|---|
| Channel Adapter | Relay 的入站验证及本地/Relay 可选出站 | 平台事件解析、签名、回复时限、发送策略 | 任意 Agent 工具执行 |
| SNS Relay | 稳定 HTTPS 公网 | 安全 Webhook、租户路由、持久队列、去重、投递、有限告警/运营 | 托管模型/知识库、掌握 iDoris Admin/Agent24 管理凭据 |
| Connector Daemon | 客户侧守护进程 | 设备配对、权限检查、Agent 调用、持久恢复、出站发送 | 对 Relay 开放本地任意 TCP 转发 |
| Agent24 Adapter | 客户侧 | 将外部事件映射到现有会话/Run/审批协议 | 复制 Agent Loop、绕过审批 |
| Other Agent Adapter | 客户侧 | 标准 Task/Message 接口，标记能力缺失 | 伪造不支持的能力 |
| Agent24 + iDoris | 客户侧 | 客户授权的知识库/工具/模型工作 | 根据 Relay 请求静默改变模型隐私策略 |

**连接方向**：Connector 主动建立出站 TLS WebSocket/HTTP2 长连接（P1-F0 PoC 决定最终传输），不要求 NAT 穿透或对公网暴露本地端口。Heartbeat、租约与 reconnect/resume 必需。尽可能将 Relay 视为可被攻破的低可信组件。

**渠道凭据设计**：LINE 等平台接入签名校验需要某些渠道机密存在公网入口；建议 Relay 持有最小入站验证材料；发送 Access Token 优先留在本地 Connector，经 Connector 直接调用平台 API。若客户特别需要离线模板通知，由客户单独显式授权 Relay 的有限发送凭据及额度，并增加隔离审计。

## 3. 事件交付通路

~~~mermaid
sequenceDiagram
    actor Buyer as SNS 用户
    participant SNS as LINE / Telegram
    participant R as Relay
    participant C as 本地 Connector
    participant A as Agent24 / Agent
    participant M as iDoris / Model
    Buyer->>SNS: 顾客发消息
    SNS->>R: Webhook(event)
    R->>R: 验签、解析、去重、落盘
    R-->>SNS: 2xx (仅表示 Relay 已可靠接收)
    C->>R: 出站建立连接 + 身份认证
    R->>C: Delivery(event_id, cursor, reply_deadline)
    C->>C: 权限/租户/重复事件校验
    C->>A: 现有会话/Run
    A->>M: 已授权的模型请求（依 Agent 的 iDoris 集成现状）
    M-->>A: 模型结果
    A-->>C: 答复或需要审批
    C->>SNS: Reply / 合规 Push（本地 Token）
    SNS-->>C: 发送结果
    C->>R: 结果/幂等回执
~~~

注：当 Connector 离线时 Relay 可持久缓存有限 TTL 的事件，但**不能**替客户执行 Agent、假装 Agent 在线或在未经授权时由云端模型回复。平台 Webhook 的 2xx 只是接收确认，不是业务完成保证。

## 4. 与实际仓库的集成接点（2026-10-21 README 核验）

### Agent24

参见 [Agent24 README](https://github.com/iDoris-ai/Agent24/blob/main/README.md)。

- 生产 Agent Host 是 Rust **agent24d**；桌面 Electron 是壳。HTTP/WS v1 API 包含 sessions、runs、events、approvals 等。Bridge 应以 daemon 为调用目标，不依赖 UI 长期开启。
- 已有进程外领域 OS / agent24-os-sdk（原型）及 Attached Module 机制。**P1-F0 比较两条路径**：A. 作为 Agent24 Attached/OS 模块；B. 独立守护进程走受限本地 REST/WS Agent24Adapter。优先复用稳定接口，禁止为了 Bridge 修改 Agent24 权限模型。
- README 指出 Agent24 当前生产 ModelRouter 仍以 oMLX/Ollama 为主，而 iDoris Provider 完整对接属于后续工作；必须通过精确源码/测试/实际运行核查最新状态。**P1-L1 先证明真实 Agent24→本地模型路径；单独验收 Agent24→iDoris Provider 路径，不得把假实现当成已完成。**
- Agent24 的领域 OS 模块隔离不等于安全沙箱（同 UID/文件权限可带来旁路访问）。Bridge 的内容和插件必须由 Agent Host 实际执行安全策略。

### iDoris

参见 [iDoris README](https://github.com/iDoris-ai/iDoris/blob/main/README.md)。

- Rust 是唯一生产实现，TS 仅供参考；其管理与数据面接口必须保持隔离。
- 现有资料显示默认 loopback data-plane 8740、Admin 8741；端口是运行配置，不是 Bridge 协议固定依赖。
- SNS Relay 永远不得读取 iDoris Admin Token、虚拟模型 Key 或私有模型 catalog；Connector 到 Agent Host 使用本地最小权限凭据。不能将 Agent24 的内部连接凭据转发给远程 Relay。

### 外部 Agent

- AgentAdapter 以 Run/Task/Session 抽象为合同；优先实现 A2A-compatible Adapter，严格能力探测。
- MCP 用于 Agent 内部访问已授权工具与资源，**不替代** Relay 的可靠消息投递协议。
- 可以有受限 OpenAI-compatible 文本 Adapter，但必须标记无工具审批/异步任务/取消等能力，不能隐式假定其是完整 Agent。

## 5. 推荐实现与仓库结构

**生产语言：Rust（Tokio/axum/serde）**，与 Agent24/iDoris 技术栈一致；不依赖 TS 主后端。可单机部署的最小形态：

~~~text
crates/
  bridge-protocol/         Envelope / channel capability / codecs
  bridge-relay/            HTTP ingress, device sessions, event outbox, API
  bridge-connector/        outbound client, local state, OS daemon
  channel-line/            verify/parse/reply/push
  channel-telegram/        webhook/polling/managed-bot onboarding
  channel-whatsapp/        later Cloud API
  agent-adapter-agent24/   native v1 adapter
  agent-adapter-a2a/       other Agent hosts
deploy/                    compose, self-host, service examples
docs/                      design, ADR, operations and policies
tests/                     fixtures, contract, fault injection, E2E
~~~

MVP 队列建议 PostgreSQL inbox/outbox + 租约/游标，规模扩大后再抽象 NATS/Redis，不在 P1-L1 过早建复杂集群。所有客户端/服务使用明确版本握手和兼容矩阵。

**开源复用顺序（详见 [OSS Audit](11-OSS-REUSE-AUDIT.md)）：** LINE 消息类型优先以 [官方 line-openapi](https://github.com/line/line-openapi) 驱动 Rust codegen/Schema 兼容测试；OpenClaw 的 LINE 事件验签、持久队列、模糊账号拒绝和发送重试主要用作测试设计参考；后续 Telegram 可直接考虑 Rust Teloxide；Matterbridge 的 Go Gateway 和 Chatwoot 的 Rails Inbox 不作为第二个 Agent/Relay 运行时。所有复用需对应 LICENSE、固定提交和供应链审查。

## 6. 设计约束与非功能目标

- 租户隔离：客户 A 无法查看 B 的任何事件、设备、渠道绑定、日志或 Agent。
- 租户离线：保留有限队列与有意义的错误，绝不偷偷降级为云端付费模型。
- 预算：Push、模板、群发默认拒绝或需单独授权；对额度更新存在延迟要保守。
- 观察：成功收件率、队列滞留、失败原因、过期、重试、离线时长、被拒绝费用请求；日志脱敏。
- 性能：快速持久化后确认 Webhook，不等待模型输出；异步非阻塞处理。
- 可移植：使用相同协议同时支持官方 Relay 和自部署；不硬编码域名/平台商家身份。
