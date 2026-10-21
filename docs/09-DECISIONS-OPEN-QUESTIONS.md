# 09 · 决策记录、风险清单与未决问题

**决策状态约定：** “方向确认”=本次产品讨论确立的方向；“建议待 P1-F0 冻结”=技术方案有待原型与评审；“外部依赖”=官方 API/商业资格或其他仓库代码核验。本文不是当前服务上线声明。

## A. 产品方向确认

| ID | 结论 | 理由 | 参见 |
|---|---|---|---|
| P-01 | 项目为本地 Agent 的**通信服务插件**，不是 AI SaaS/新 Agent 内核 | 已有 Agent24 / iDoris 系统 | ADR-0001 |
| P-02 | 公网 Relay 独立、常驻、可托管或自部署 | LINE/WhatsApp 等中心平台需可达入口 | 架构/部署 |
| P-03 | 客户拥有 SNS 账号，默认独立 OA/Bot | 品牌归属、可迁移性、权限边界 | ADR-0002 |
| P-04 | 可对接非 Agent24 的 Agent Host，标准化 AgentAdapter | 开源生态、不锁特定模型/代理 | 协议 |
| P-05 | 初期 LINE B 模式，按 LINE→Telegram→WhatsApp 推进 | 泰国真实需求、难度与政策 | 路线 |
| P-06 | 生产 Rust-only，Agent24/iDoris 保持原有职责 | 避免重写 Agent/模型体系 | 架构 |
| P-07 | 本仓库当前 Apache-2.0，许可变更需单独审查 | 不背离现有法律文本 | 商业与许可 |

## B. 建议待 P1-F0 冻结

| ID | 建议 | 必须验证 |
|---|---|---|
| D-01 | Relay 验证平台原始 Webhook，最小 Secrets Store | LINE 验签/租户绑定 PoC、Secret 生命周期 |
| D-02 | Connector 独立 OS daemon，主动出站 TLS 长连接 | Mac launchd 运行、断线恢复、设备租约 |
| D-03 | 本地 Connector 持有出站渠道 Access Token | LINE Reply/Push 真实 E2E 能跑；离线回复 UX |
| D-04 | PostgreSQL inbox/outbox at-least-once + 幂等 | 崩溃、ACK 丢失、发送 ambiguous 的模拟测试 |
| D-05 | P1-L1 使用 Agent24 Native Adapter，P1-F0 冻结通用接口结构；A2A 完整实现于 P3-A | Agent24 当前 API、模块扩展接口是否稳定 |
| D-06 | 默认不得付费 Push，无授权工具不得执行 | 成本上限、审批机制、费用数据延迟 |
| D-07 | 群聊默认 mention/命令触发，禁止管理员身份推断 | 群事件示例、Agent 权限安全测试 |
| D-08 | 可托管 Relay 不托管 Agent 知识库或长期内容 | 数据留存、PDPA、运营监控能力 |

## C. 外部依赖与待研究

| 优先级 | 问题 | 下一步 |
|---|---|---|
| **P0** | Agent24 现有 Session/Run/API/审批有没有可靠独立进程调用点？ | 阅读 main 精确代码/测试；做 contract spike |
| **P0** | Agent24→iDoris Provider 真实生产是否完成？ | 端到端真实模型路由验证；若未完成按外部依赖追踪 |
| **P0** | LINE OA 用户最小操作能否完成 B 模式凭据授权、减少复制敏感 Token？ | 官方 Console 权限、管理员邀请能力/UX PoC |
| **P0** | LINE Reply 超时后最优交互 UX（即时 ACK vs 付费 Push）？ | 真实 Agent 延迟测量 + 用户授权策略 |
| **P1** | Telegram Managed Bot 的客户端覆盖率/经理权限撤销是否可稳定使用？ | PoC+平台官方核对 |
| **P1** | LINE Module Channel 对泰国 TH 的开通资格和商务门槛？ | 联系 LINE Thailand 官方/Partner，未获准不发布 |
| **P1** | 设备密钥如何 OS 存储、多设备故障转移如何 fencing？ | Threat modeling + 重启/被盗测试 |
| **P1** | GDPR/泰国 PDPA 等义务与数据区域是否要求分区部署？ | 正式运营前合规咨询与 DPA/隐私文档 |
| **P1** | WhatsApp 2026-10 新费率和“通用 AI 助手”限制边界是什么？ | P2-W 前读当期 Meta 官方条款/价格表 |
| P2 | Facebook Messenger、Instagram、Web Chat、Discord 的下一顺序？ | 客户需求/平台成本验证 |
| P2 | 从 Relay 手工部署迁移到官网托管及反向迁移的自动化成本？ | P3-H 试点客户演练 |

## D. 主要风险与缓解

| 风险 | 级别 | 缓解策略 |
|---|---|---|
| 对 LINE C 一键授权与泰国覆盖做不实宣传 | 高 | B 为默认；Module 标注申请与地区未证实 |
| Relay 泄露渠道凭据或完整 SNS 内容 | 高 | 验签 secret 独立、发送 token 本地、短留存、分租户加密、监控 |
| 群消息 prompt injection 导致本地工具执行 | 高 | Agent24 实际 Policy/Approval 强门控，默认只读 |
| 消息重试造成重复预订/通知/付款 | 高 | end-to-end 幂等，发送 ambiguous 状态禁止盲重投 |
| WhatsApp 通用 AI 使用违反 Meta 政策 | 高 | 只实现业务用途，客户授权，合规核验 |
| 本地 Agent 离线致 LINE 免费回复 Token 过期 | 中高 | 明确离线告知/超期策略，用户配置付费 fallback |
| 本地部署难度降低采用率 | 中 | 配对向导、示例配置、诊断页面、可选 Relay 托管 |
| 竞争平台复制 Relay 基础设施 | 中 | 运维可靠性、合规接入、客户信任/本地市场合作 |

## E. 不应被误写为既成事实的事项

- “已支持 LINE/Telegram/WhatsApp、已部署 Relay、P1-F0 已验收”：**尚未发生**。
- “所有客户可全自动创建 LINE OA”：**普通公开 API 无此保障**。
- “Module Channel 覆盖泰国”：**尚未验证**。
- “所有 WhatsApp Service 消息免费”：**2026-10 不能这样承诺**。
- “Agent24 所有模型请求都已经经 iDoris”：需按当前源代码与真实 E2E 证明。
- “Relay 到客户内容零知识端到端加密”：当前架构 Webhook 入口能接触明文，不得做虚假承诺。

接下来的有效状态改变应新增 ADR 和证据，而不是直接修改此文档的结论。
