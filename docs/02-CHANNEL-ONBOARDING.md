# 02 · SNS 账号归属、授权与客户开通

**原则：** 一套 Bridge 服务连接多个**客户自有** SNS Bot / OA；不替客户持有品牌账号。任何自动化开户能力都必须走平台允许的官方授权流程。

## 0. LINE 生态中的四种开发形式

| 形式 | 特点 | 与 Bridge 的关系 |
|---|---|---|
| OA Manager 零代码 | 自动回复、菜单、群发和基础客服 | 适合完全没有开发能力的客户，Bridge 不替代它 |
| 第三方低代码 | BOTNOI、AIYA 等构建聊天/CRM 工作流 | Bridge 与其竞争的是“客户本地 Agent 接口”的定位，不复制整套 CRM |
| Messaging API + Webhook | 客户 OA 独立身份 + 自有开发服务 | **Bridge 主路线 B**：稳定 Relay 和本地 Connector |
| LIFF / LINE MINI App | 表单、订单、会员及其他富交互界面 | 作为未来业务前端可选，与消息 API/Agent 执行层互补 |

Bridge 不需要一个“专用 LINE Bot 账号”给所有客户。系统**只开发一套接入协议和适配器**，各小店和社区拥有自己的 OA，映射到自己 Agent24/其他 Agent。

## 1. 三种 LINE 使用模式

| 模式 | 谁对外展示品牌 | 谁持有 OA | 接入方法 | 结论 |
|---|---|---|---|---|
| A · iDoris 共用一个 Bot | iDoris | iDoris | 不同客户在同一外部账号共享入口 | 仅适合公共演示/试用；不适合正式商户 |
| **B · 客户独立 OA** | 客户商家/社区 | **客户** | 客户创建或已有 OA，开启 Messaging API，授权配置或授予最小凭据 | **LINE 初期主路线** |
| C · LINE Module Channel | 客户商家/社区 | **客户** | OA Admin 通过 OAuth 授权连接合资格的第三方 Module | 接入体验佳，但需要企业申请与地区资格验证 |

**B/C 的 LINE 账号收费由客户套餐与消息使用量决定，并不会因为 C 是 OAuth 或第三方 Module 而变成免费。** Module 是授权/集成模式，不是取消运营商计费的办法。

## 2. LINE B 模式开通向导（G1）

1. 用户本地安装 Connector，在 Agent24 中选定某个 Agent；Connector 产生设备身份并配对 Relay。
2. 已拥有 LINE OA 的用户直接跳到开启 Messaging API。其他用户从 LINE 官方 OA Manager 创建属于自己的 OA；普通个人亦可创建。
3. 在 OA Manager 开启 Messaging API（目前不能从 Developers Console 直接创建新的 Messaging API Channel）。
4. **用户选择自己控制的 Provider**；LINE 文档强调 Provider 一旦选定不能更改，且用户 ID 存在 provider 作用域差异。绝不可默认把不相关商家的 Channel 挂在 iDoris 公司自己的 Provider 下。
5. 用户通过最小管理员邀请或受保护的配置流程提供必需的 Channel Secret、访问 Token。这里的“授权”在 B 方案通常是管理员配置/凭据授予，**不是**普通 OAuth 一键授权。OA Manager 与 Developers Console 权限边界分别验证。
6. 提供专用 HTTPS Webhook URL 指向 Relay；验证原始请求签名、验证 Bot 身份，配置重投及测试。
7. 本地保管出站访问 Token，指定 Bot→Agent 映射、人工接管和付费 Push 上限；Relay 只保留必要的入站验签材料。
8. 实测消息收发及断线状态，启用；解绑时停用投递，吊销设备凭据，客户撤销/轮换渠道 Token。

**风险：** 如果为了“零操作”要求客户交出个人 LINE/Business ID 密码、在机器人控制的浏览器里自动绕过官方核验，会破坏账号所有权和安全边界；不是可接受 MVP 方案。可以自动化本平台的后续配置、Webhook API 校验及辅助向导，但不能假设存在通用的 LINE OA 注册 API。

### LINE C 模式

LINE Module 使用 OAuth 2.0 向 OA 管理员请求明确 scope，某些情况下可连接没有独立 Messaging API Channel 的 OA。官方标明需合资格公司事先申请；附着接口文档的 region 参数列示 JP、TW，**没有确认 TH 可用**。因此列为研究/商务合作路线，而不是对泰国客户的现有功能承诺。

## 3. Telegram 的两条正式路径

- **G2 保底：BotFather。** 用户在 Telegram 自己通过 @BotFather 创建 Bot，使用安全输入方式关联到 Connector，不把完整 Token 粘贴到可公开的客服对话或日志中。
- **G2 可选：Managed Bots。** Telegram 2026 Bot API/MTProto 增加由用户创建、经理 Bot 协助管理的流程（含深链、授权按钮）。**所有者仍是用户**，管理 Bot 有管理 Token 的能力；必须征得明确授权并提供撤销机制，不能冒充无需任何用户操作的自动代注册。首版先做可行性 PoC，技术与客户端兼容性通过后上线。
- Telegram 的 Webhook 和 getUpdates 不能同时使用。对于纯本地部署用户可支持 getUpdates 出站长轮询，绕开公网 Relay；统一模式仍推荐 Relay。

## 4. WhatsApp Business（G4）

客户拥有 Meta Business 资产、WhatsApp 商业号码、适当的 WABA/Cloud API 权限。首版建议通过 Meta 允许的 Business Onboarding/Embedded Signup 或官方人工接入流程；本地 Connector 负责业务 Agent 调用，Relay 处理其指定 Webhook。

WhatsApp API 的收费按类别、收件人国家/地区和版本变化；与 LINE Reply 免费规则不同。2026-10 起存在服务消息新费率与按号码的有限免费额度（详见费用文档）；上线前务必重查 Meta 原始价目表。特别注意 WhatsApp 对第三方**通用 AI 助手作为主要功能**的限制；本渠道只面向客户自己的业务客服/订单等符合条款的使用场景，并需要法务/渠道政策核查。

## 5. 后续渠道

**Web Chat**（网页嵌入，对方渠道费可能为零）为优先候选；随后 Messenger、Instagram DM、Discord、WeChat 或其他适用东南亚渠道。每个渠道独立处理 OAuth、付款、群聊、权限、媒体及速率限制，不采用“所有 API 都是一样的”错误抽象。

## 6. 运营界面设计

- **连接面板：** 账号所有者、渠道、Bot 显示名称、状态、最后成功收发时间、对应本地 Agent、Webhook 验证状态、错误指引。
- **授权面板：** 私聊/群聊范围、允许主动消息与否、允许查询哪些工具、审批人、渠道费用上限。
- **诊断面板：** 验签失败、Relay/Connector/Agent 离线、回复过期、额度不足、平台 429、人工接管中、送达结果。
- **解绑面板：** 明确哪些凭据/配对记录会被撤销，提示用户如何在各平台管理后台解除授权；保留可导出的非敏感配置。

详见 [安全策略](05-SECURITY-PRIVACY.md)、[收费与商业边界](07-COST-OPEN-SOURCE.md)。
