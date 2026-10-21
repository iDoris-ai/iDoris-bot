# 04 · 协议、数据模型与语义合同（提案）

**协议建议名：** sns-bridge/1。**本文件是 G0 设计草案，不是已经发布的 API 规范。**

## 1. 三个独立协议层

| 接口 | 用途 | 需要强制的规则 |
|---|---|---|
| **ChannelAdapter v1** | 官方 Webhook 验证/归一化/发送/capabilities | 不允许伪造来源、跨 Bot 回复、隐藏发送费用 |
| **ConnectorWire v1** | Relay ↔ 本地 Connector 的设备鉴权、事件投递、ACK/恢复 | 设备绑定租户与渠道、消息不丢不重复产生业务副作用 |
| **AgentAdapter v1** | Connector ↔ Agent24/第三方 Agent 的会话、任务、审批 | 不跳过 Agent 自身授权；能力声明按真实宿主运行能力 |

可以先写 Rust traits 并用 JSON Schema/兼容性 fixture 发布线协议。Relay 和 Connector 必须独立升级时仍能协商版本，拒绝重大不兼容。

## 2. Event Envelope

~~~json
{
  "schema": "sns-bridge/1",
  "event_id": "stable-internal-uuid",
  "provider_event_key": "scoped-provider-id",
  "tenant_id": "server-bound-org-id",
  "binding_id": "server-bound-bot-id",
  "channel": "line",
  "occurred_at": "2026-10-21T04:10:00Z",
  "received_at": "2026-10-21T04:10:01Z",
  "conversation": {
    "provider_conversation_id": "opaque-scoped-id",
    "kind": "direct",
    "sender_provider_id": "opaque-scoped-user"
  },
  "message": {
    "kind": "text",
    "text": "还有法棍吗？",
    "attachments": []
  },
  "response_policy": {
    "reply_deadline": "2026-10-21T04:11:00Z",
    "reply_available": true,
    "paid_push_fallback": false,
    "cost_class": "none"
  },
  "trace_id": "trace-id"
}
~~~

上述字段**不应该包含** LINE replyToken、API Token、客户本地虚拟模型 Key、私人完整设备证书。一次性 replyToken 需要密封的 channel-private 元数据机制，只能让授权的发送适配器读取；不可复制到模型输入、普通日志、可导出的事件 JSON。tenant_id 和 binding_id 必须由**可信注册绑定**生成，不能信任外部 HTTP Body 自报值。

### ID 域与跨渠道身份

所有外部用户/群组/会话 ID 均以**渠道 + 客户 Bot + provider** 为域；不存在默认的“LINE 用户 ID == Telegram 用户 ID”。跨渠道联系人合并需用户主动证明账号控制权并许可，且可解绑。

### ChannelCapabilities

至少声明：支持的媒体类型和附件限制；群组/mention；回复 Token 截止时间；主动消息权限；模板与审批限制；可否删除/编辑；平台单次发送上限、速率限制、费用等级、用量 API 可用性和查询时间戳。

## 3. Relay 状态机

~~~text
HTTP received -> signature_verified -> durable_accepted
    -> queued -> leased_to_device -> delivered_to_connector
    -> running_agent -> awaiting_approval?
    -> outbound_pending -> sent | failed | expired | cancelled
~~~

控制面 ACK 与业务完成应分开：delivery ACK 表示 Connector 已收到并持久接受；业务 completion ACK 表示 Agent 已完成/失败/过期；发送结果以 provider message ID 和出站 operation ID 关联。

## 4. 至少一次交付与幂等（不宣称 exactly-once）

1. 平台可能重复/乱序 Webhook：LINE 使用 webhookEventId+Bot scope；其他平台使用相应平台唯一 ID+scope。建唯一索引。
2. Relay 只有在**验签、归属校验、持久落盘成功**后才回复 2xx；否则返回合适状态供平台重试（依各平台协议）。
3. 消息队列租赁含 consumer ID、租约截止、fencing epoch；一个 binding 只能有一个有权执行副作用的主消费者。多个 Connector 可作热备/冷备，但不可双重执行。
4. Connector/Agent 处理前检查 event_id，工具副作用使用业务 operation_id 单独去重；“收到了两次消息”不能变成“两份订单”。
5. 若发送 API 超时而无法确认是否成功，则标记 **ambiguous**，查询平台能力或交人工处理，不在可能重复发送时盲目无限重试。
6. TTL 过期后终止投递，产生非敏感审计事件，不延长 LINE reply token，也不自动开付费 Push。

### 推荐 ConnectorWire 操作

~~~text
pair.start / pair.confirm / pair.revoke
hello {protocol_range, device_id, nonce, capabilities}
subscribe {binding_ids, resume_cursor}
deliver {cursor, envelope, sealed_channel_metadata}
delivery_ack {cursor, event_id, durable}
result {event_id, status, outbound_operation_id, provider_receipt}
heartbeat {device_health, agent_health, lease_epoch}
rotate_credentials / resync
~~~

网络传输推荐 TLS 1.3、短期设备身份凭据、租户与设备 scope，必要时 mTLS；配对码有短 TTL、一次性使用、防重放与管理员确认。协议消息有限长/有限深、严格版本验证。

## 5. AgentAdapter 操作合同

~~~text
capabilities() -> {sessions,async_tasks,cancellation,approvals,tools,media}
start_or_continue(conversation_key, content_blocks, context, policy) -> task_id
get_status(task_id) -> running | awaiting_approval | completed | failed
get_outputs(task_id) -> structured_messages + tool_side_effect_receipts
cancel(task_id) -> terminal status
~~~

Agent24 Native Adapter 应把 conversation 映射到已有 Session/Run，保留客户定义的角色权限、工具可见性和审批状态；不得在 Relay 收到一个 JSON 时直接绕过 Agent24 Policy 去执行动作。对于第三方 A2A Agent，用协定的 Task/Message 映射；能力不足时 fail closed 或退化为**明确标记的只读文本**模式，不伪造工具、记忆或审批。

## 6. 平台专属规则

**LINE:** replyToken 单次使用、建议在 1 分钟内使用（官方表示超时不保证）；接收 Webhook 时间与真实事件时间区别对待。Relay 记录 deadline，Connector 发送前重新校验；慢模型改先回复“正在处理”需 UX 明确，最终以 Push 回执需要预授权、额度验证。不能用一次 Reply 先发进度、稍后又用同一 Token 发最终结果。群发计费按**发送请求 × 实际接收人数**计算，而非消息气泡数量。

**Telegram:** Webhook/getUpdates 二选一；群组 Privacy Mode 默认可能只收到部分消息；Managed Bot Token 只向明确获授权的管理者可用。Bot 可能因封禁/群组权限不可用，需要错误分类。

**WhatsApp:** 业务号码/模板类别/客户服务窗口/消息国家费率分别建模；入站消息不能自动触发未审批的营销群发。任何政策不符、付费未授权场景拒绝发送。

**附件:** Relay 默认不永久下载媒体；若需取用，Connector 经允许的官方 endpoint 临时下载并限制大小、MIME、URL、下载域、病毒检查/过期清理，防 SSRF 与恶意媒体解析。

## 7. 交付测试矩阵（G0 编写、G1–G4 持续执行）

| 场景 | 期望 |
|---|---|
| 错误 LINE HMAC / Telegram secret | 400/401/403，绝不进入队列 |
| 平台重投相同事件 | 只产生一个事件和一份订单 |
| 多租户同名 Bot 映射 | 严格按 provider bot ID + binding scope 区分 |
| Connector 断线/重连、ACK 丢失 | 限定 TTL 内重投，不重复副作用 |
| 本地 Agent 离线或审批未通过 | 正确报告 offline/awaiting_approval，不执行工具 |
| LINE token 过期/Push 未授权 | 不发送付费消息、不伪装成功 |
| 模型拒绝或 local_only 不可用 | 明确错误，不偷偷改为云模型 |
| 429、费用达限、发送结果不明 | 明确退避/拒绝/ambiguous，不超过授权 |
| 撤销设备、解除 Bot 绑定 | 立即拒绝新收发，清理队列与凭据 |
