# 12 · 私有接入层：官方 Tailscale 客户端 + 自建 Headscale 控制面 + idoris-vpnd 守护进程

**日期：** 2026-10-27（泰国时区）· **状态：** 方案已确认方向；`vpn/` 目录代码已实现并通过单测与 Docker 集成测试（含与已有 Tailscale 并存、局域网直连、子网网关）；`deploy/vpn` 已在本地整套拉起并通过 47 项隔离探针；尚未在公网域名与真实 TLS 上验收。

相关文档：[13 客户端模式](13-VPN-CLIENT-MODES.md)（与已有 Tailscale 并存）· [14 运维](14-VPN-OPERATIONS.md)（单组织默认、管理员、Headplane、网关策略）· [15 局域网与网关](15-VPN-LAN-AND-GATEWAY.md)（实测）· [16 加入码与网关向导](16-VPN-JOIN-AND-GATEWAY-WIZARD.md)。

## 1. 目标与非目标

Bridge 除了把 LINE / Telegram / WhatsApp 等中心化 SNS 桥接到客户本地 Agent 之外，还要解决另一条路：**组织成员从自己的设备直接访问本组织的 Local AI（Agent24 / iDoris）**。公网暴露 Local AI 端口不可接受，所以需要一层私有网络。

| 目标 | 说明 |
|---|---|
| 客户端零改动 | 成员设备只安装 **官方 Tailscale 客户端**（App Store / Homebrew / apt / MSI / iOS / Android），不分发修改版。**唯一例外**：`embedded` 模式（用来与成员已有的 Tailscale 并存）在 `idoris-vpnd` 进程内运行 Tailscale 官方开源库（`tsnet`），不是驱动已安装的官方客户端；它随 `idoris-vpnd` 发布，升级需要发新版 `idoris-vpnd`，见 [13](13-VPN-CLIENT-MODES.md) |
| 控制面自建 | 坐标服务器是我们运营的 **Headscale**（官方开源实现，不 fork），不连 Tailscale Inc. 的 SaaS |
| 无感加入 | 成员机器上跑一个后台守护进程 `idoris-vpnd`，它让 Tailscale 自动登录到我们的服务器地址，断线/过期自动续期 |
| 服务中小组织 | **默认一个组织**（十几个人加一台 Local AI）。多组织是显式的进阶选项：每个组织 = 一个 Headscale user + 一个专属 tag `tag:<租户>-local-ai`，ACL 按租户逐条授权；成员互不可达，只能访问本组织 Local AI 主机的指定端口 |
| 不打扰已有 Tailscale | 成员已经在用 Tailscale 连别的网络时，守护进程默认**不接管**；`auto` 模式改用进程内的用户态节点与它并存（本机回环端口转发或 SOCKS5），见 [13](13-VPN-CLIENT-MODES.md) |
| 管理员 | 与成员同一套客户端和注册流程；服务器端用 SSH + `ctl.sh`、Headplane（回环 / 局域网 / 仅 VPN 内可达）运维，见 [14](14-VPN-OPERATIONS.md) |
| 网关 | 不能装 Tailscale 的设备经办公室里一台 Linux 网关被远程成员访问，见 [14](14-VPN-OPERATIONS.md) 与 [15](15-VPN-LAN-AND-GATEWAY.md) |
| 建于互联网之上 | Headscale + 内嵌 DERP 中继 + STUN 在公网；成员在任何 NAT 后都能连上 |
| 基于开源方案改 | 直接运行 Headscale、Headplane；我们只新增**胶水**（守护进程、注册服务、ACL 模板、部署脚本） |

**非目标**：不自研 WireGuard/控制协议；不做 Tailscale 客户端 fork；不做多租户 SaaS 级别的 Headscale 水平扩展（Headscale 本身是单实例设计）；不替代 SNS Relay/Connector 那条消息通路。

## 2. 开源调研结论（2026-10-27 核验）

| 项目 | 版本 / 发布 | License | Star（约） | 角色 | 结论 |
|---|---|---|---|---|---|
| [juanfont/headscale](https://github.com/juanfont/headscale) | v0.29.6 · 2026-10-24 | BSD-3-Clause | 45,000 | 控制面 | **直接采用、不修改**。REST `/api/v1`（Bearer API key）、gRPC、preauthkey、用户、节点、HuJSON Policy、内嵌 DERP、OIDC、MagicDNS 全部具备 |
| [tailscale/tailscale](https://github.com/tailscale/tailscale) | v1.104.2 · 2026-10-21 | BSD-3-Clause | — | 客户端 + Go 库 | 官方客户端不改；守护进程直接 import `tailscale.com/client/local`（LocalAPI 客户端），与 `tailscale login` 走同一条路 |
| [tale/headplane](https://github.com/tale/headplane) | v0.8.2 · 2026-10-22 | MIT | 3,200 | 管理 UI | **首选**：最活跃、功能最全（节点/用户管理、ACL 查看、OIDC 登录）。镜像 `ghcr.io/tale/headplane:0.8.2`，标签不带 `v`。`policy.mode: file` 下 ACL 页面只读；Docker 集成需可写的 Headscale 配置和 docker.sock，本部署默认关闭 |
| [gurucomputing/headscale-ui](https://github.com/gurucomputing/headscale-ui) | 2026-03 最后发布 | BSD-3-Clause | 2,700 | 管理 UI | 备选；纯静态，功能少 |
| [GoodiesHQ/headscale-admin](https://github.com/GoodiesHQ/headscale-admin) | 活跃 | **GPL-3.0** | 1,100 | 管理 UI | 只可独立部署使用，不可把代码并入本仓库（Apache-2.0） |
| [MirageNetwork/MirageServer](https://github.com/MirageNetwork/MirageServer) | 活跃 | BSD-3-Clause | 200 | Headscale 中文 fork（带 UI） | 不采用：fork 跟进上游慢，我们原则是不 fork 控制面 |

关键事实（来源见文末）：

- Headscale REST：`POST /api/v1/preauthkey`（`user` 为 uint64 字符串、`reusable`、`ephemeral`、`expiration`、`aclTags`）、`GET /api/v1/node?user=`、`POST /api/v1/node/{id}/expire`、`POST /api/v1/user`、`GET/PUT /api/v1/policy`。Swagger 在服务器 `/swagger`。
- Tailscale 官方 `tailscale login` 的实现 = `SwitchToEmptyProfile()` + `Start(ipn.Options{AuthKey, UpdatePrefs{ControlURL,...}})`；LocalAPI 支持多 login profile（`ProfileStatus`/`SwitchProfile`），但**同一时刻只有一个 profile 在线**。
- macOS GUI 版（App Store 与 standalone）自带 CLI `/Applications/Tailscale.app/Contents/MacOS/Tailscale`，1.104 支持 `login --login-server --auth-key`；LocalAPI 通过 sameuserproof 机制对同用户进程开放，Go 的 `local.Client` 零值即可连上。本机实测：1.104.1、bundle `io.tailscale.ipn.macsys`。
- iOS/Android 官方客户端可在登录页选择 “自定义坐标服务器”；tvOS 需先设置再登录。移动端没有守护进程，走 Headscale 的 `/apple`、`/windows` 引导页或 OIDC。
- Headscale 内嵌 DERP 要求 `server_url` 为 https 并开放 udp/3478；`verify_clients: true` 可限制只有本 tailnet 节点能用中继。
- Headscale v0.29.6 拒绝低于 Tailscale v1.80 的客户端（启动日志 `minimum_version=v1.80`）。
- **Headscale 的 user 不是网络隔离边界**（本地实测）：`autogroup:member` 与 tag 对整个实例生效，没有策略文件时默认全通。v0.29.6 支持的 autogroup 只有 member、tagged、nonroot、self、internet、danger-all，**没有 `autogroup:admin`**。多租户隔离必须在 ACL 里按租户逐条写，见 3.2。

## 3. 方案

~~~mermaid
flowchart LR
    subgraph OPS["iDoris 运营（公网，Docker Compose）"]
      HS["Headscale v0.29.6<br/>控制面 + 内嵌 DERP/STUN"]
      HP["Headplane 0.8.2<br/>管理 UI"]
      EN["idoris-vpn-enroll<br/>注册服务（唯一持有服务用 Headscale API key）"]
      HP -->|REST/API key| HS
      EN -->|POST /api/v1/preauthkey| HS
    end
    subgraph ORG["组织 A（任意网络）"]
      subgraph M1["成员笔记本"]
        TS1["官方 Tailscale 客户端（不改）"]
        D1["idoris-vpnd<br/>后台守护进程"]
        D1 -->|LocalAPI| TS1
      end
      subgraph AI["Local AI 主机"]
        TS2["官方 Tailscale 客户端"]
        D2["idoris-vpnd（tag:acme-local-ai）"]
        A24["Agent24 / iDoris"]
        D2 -->|LocalAPI| TS2
      end
    end
    D1 -->|"1. 租户 token（HTTPS）"| EN
    EN -->|"2. 10 分钟一次性 preauthkey + control_url"| D1
    TS1 -->|"3. 注册/心跳（Noise over HTTPS）"| HS
    TS1 <-->|"4. WireGuard 点对点，或经 DERP 中继"| TS2
    TS2 --> A24
~~~

### 3.1 组件与职责

| 组件 | 来源 | 运行位置 | 职责 | 禁止 |
|---|---|---|---|---|
| Headscale | 上游镜像，不修改 | 运营侧 | 节点注册、密钥分发、ACL、MagicDNS、DERP | 存放任何 Agent / 模型数据 |
| Headplane | 上游镜像，不修改 | 运营侧 | 运维人员查看节点与 ACL、过期/删除节点；运维以自己的 Headscale API key 或 OIDC 登录 | 暴露给成员 |
| idoris-vpn-enroll | 本仓库 `vpn/cmd/idoris-vpn-enroll` | 运营侧 | `POST /v1/enroll`：校验租户 token → 向 Headscale 申请**一次性、短期**（默认 10 分钟）preauthkey → 返回 `control_url` + key；限流；审计日志。`GET /v1/discover`：只返回 `control_url` 与租户名，**不铸 key** | 把 Headscale API key 下发给任何客户端 |
| idoris-vpnd | 本仓库 `vpn/cmd/idoris-vpnd` | 成员设备 / Local AI 主机 | 让本机 tailscaled 登录到我们的 control URL、保活、续期、暴露本地状态 API、安装为 launchd/systemd 服务 | 修改/替换 Tailscale 客户端；打开任意端口到公网 |
| ACL 策略 | `deploy/vpn/headscale/policy.hujson` | Headscale | 按租户授权：`<租户>@` 只能访问 `tag:<租户>-local-ai` 的 8740/8742/443；成员之间、跨租户一律不可达 | 用 `autogroup:member` 之类的实例级通配授权 |

### 3.2 身份与网络模型

- **默认只有一个组织**（默认名 `office`），`bootstrap.sh init` 一条命令完成。`add-tenant` 才会引入第二个组织；本节后面讲的是每个组织的规则形状，单组织与多组织一致。
- **租户 = Headscale user + 专属 tag**。以 `acme` 为例：成员设备注册为 user `acme` 的个人节点，ACL 中写作 `acme@`。Local AI 主机通过带 `acl_tags: ["tag:acme-local-ai"]` 的注册条目入网。带 tag 的节点在 Headscale 里归特殊用户 `tagged-devices`，不归租户 user。
- **每个租户在 ACL 里一组规则**：`acme@` → `tag:acme-local-ai:8740,8742,443`；`tag:acme-local-ai` → `acme@:*`；`group:admins` → `tag:acme-local-ai:22`，外加一条 ssh 规则。新增租户就复制这一组规则。不使用 `autogroup:member` 这类实例级通配，否则一个租户的成员能连到所有租户的 Local AI，本地实测已复现。
- **管理员**：Headscale 没有 `autogroup:admin`，管理员是 `group:admins` 里列出的 Headscale 用户（写作 `name@`）。管理员设备不属于任何租户，实测只能访问各 Local AI 的 22 端口。只有 `group:admins` 能给节点打 Local AI tag，成员自行 `--advertise-tags` 会被忽略。管理员设备与成员走同一条注册路径：`bootstrap.sh init` 会创建 `admin` 用户和 `admin` 注册项（无 tag、每分钟 5 次、TTL 5 分钟），设备是 `admin` 用户的个人节点。Tailscale SSH 需要 ssh 规则加一条放行 22 端口的 ACL，只有 ssh 段不会开 22 端口。未配 OIDC 时，`check` 模式每次登录要运维在服务器上执行 `headscale auth approve --auth-id <id>`。
- **MagicDNS**：`base_domain: idoris.internal`，主机名是 `<hostname>.idoris.internal`，**不含租户名**，同名主机会被去重成 `-1` 后缀。所以 Local AI 主机的 hostname 必须带租户前缀，如 `acme-local-ai`，对成员可见为 `acme-local-ai.idoris.internal`。Bridge Connector 与 Agent24 客户端配置这个名字。
- **中继**：内嵌 DERP + 保留 Tailscale 公共 DERP 作为兜底（可改 `urls: []` 完全自包含，本地已验证可启动）。`verify_clients: true`。
- **成员间隔离**：ACL 没有任何成员 → 成员的授权。成员的 `tailscale status` 只看得到自己和本租户 Local AI。
- **更强隔离的备选**：对隔离要求高的组织，可以给它单独部署一套 `deploy/vpn`。这样就不依赖 ACL 书写正确，代价是每套都要单独运维。

### 3.3 注册与保活流程

~~~mermaid
sequenceDiagram
    participant D as idoris-vpnd
    participant T as tailscaled（官方）
    participant E as idoris-vpn-enroll
    participant H as Headscale
    opt 未固定 control_url
        D->>E: GET /v1/discover（只查地址，不铸 key）
    end
    D->>T: Status / GetPrefs / ProfileStatus
    alt 已有指向我们 control_url 的 profile
        D->>T: SwitchProfile(id)
    else 没有或当前登录在别的 tailnet
        D->>E: POST /v1/enroll（Bearer 租户 token，hostname/os）
        E->>H: POST /api/v1/preauthkey（一次性，10 分钟，aclTags）
        H-->>E: key
        E-->>D: {control_url, auth_key, expires_at}
        D->>T: SwitchToEmptyProfile → CheckPrefs → Start{AuthKey, Prefs{ControlURL, WantRunning, CorpDNS}} → StartLoginInteractive
        T->>H: 注册
    end
    loop 每 5s
        D->>T: Status
        Note over D: Running→connected；Stopped→EditPrefs WantRunning；NeedsLogin（节点被过期）→已有 node key 时先等约 15 秒的恢复窗口，仍未恢复才重新 enroll；连续失败时观望期 20s→40s→80s…封顶 10 分钟
    end
~~~

## 4. idoris-vpnd 守护进程行为

- **状态机**（`vpn/internal/vpnd/reconciler.go`）：`connected` / `starting` / `switching-profile` / `enrolling` / `needs-admin-approval` / `blocked-foreign-tailnet` / `error`。
- **与用户已有 Tailscale 账号共存**：`mode` 有三档，默认 `auto`。`auto` 只在不会抢占别人登录时才驱动系统客户端（未登录、全新安装、或已经在我们的控制面上）；系统 tailscaled 不可达，或已登录别的控制面而又没有显式 `takeover: true` 时，改用进程内的 `tsnet` 用户态节点：自有状态目录，不碰 TUN，不改系统 DNS，只在回环地址上提供端口转发与 SOCKS5。`takeover` 默认 **false**；显式 `takeover: true` 才会切走系统客户端并记录原 profile。判定表与限制见 [13](13-VPN-CLIENT-MODES.md)。移动端同一时刻只能有一个 VPN，官方 App 只能用多账号快速切换，不能并存。
- **网关角色**：`advertise_routes` 在 `system` 模式下写入 prefs 并纠正漂移，`embedded` 模式拒绝该配置。路由仍需 Headscale 批准（手动或 `autoApprovers`）；Linux 网关还要 `net.ipv4.ip_forward=1`。见 [14](14-VPN-OPERATIONS.md)、[15](15-VPN-LAN-AND-GATEWAY.md)。
- **登录调用顺序**：与官方 `tailscale up --auth-key` 完全一致：`CheckPrefs` → `Start` → `StartLoginInteractive`。实测证明只调 `Start` 时，全新节点会一直停在 NeedsLogin，从不联系控制面。`Start` 会重建控制客户端并清掉残留的浏览器登录 URL，所以随后的 login-interactive 一定使用这把 key，不会弹浏览器；它还会强制生成新 node key，过期续期正需要这一点。
- **一次性 key 的节约**：每次登录只领一把 key。登录后进入观望期，观望期内不再领 key：首次 20s，此后每次未能进入 Running 的连续尝试翻倍，封顶 10 分钟，进入 Running 后清零。健康节点被过期后，若本机已有 node key，会先等约 15 秒的恢复窗口（tsnet 重启时会短暂处于 NeedsLogin 并自己用已存的 key 恢复，此时再领 key 会取消恢复并浪费一把），超过窗口才续期。tailscaled 不可达等错误另按 2s→2min 指数退避加 ±20% 抖动。实测对照：修复前持续失败时约 2 分钟铸了 7 把 key，修复后在 +0s、+20s、+60s 各一把。
- **启动不铸 key**：未固定 `control_url` 时，守护进程启动只调 `GET /v1/discover` 获取地址。已注册节点重启不消耗任何 key，集成测试对此做了断言。
- **状态 API**：默认 `unix:~/.idoris/vpnd.sock`（0600）或 `tcp:127.0.0.1:<port>`（只允许回环）。`GET /healthz`（connected→200，否则 503）、`GET /v1/status`（JSON：phase、tailnet_ips、self_dns_name、key_expiry、last_error、login_attempts、previous_profile_id）。Bridge Connector 后续用它判断 Local AI 是否可达。
- **服务安装**：`idoris-vpnd service install --config ~/.idoris/vpnd.json` 生成 launchd LaunchAgent（macOS，KeepAlive）或 systemd user unit（Linux，Restart=always）。Windows 暂不内建安装器，可用 NSSM/任务计划运行 `idoris-vpnd run`。
- **配置**：JSON 文件 + `IDORIS_VPN_*` 环境变量 + flag 覆盖。推荐 `{"enroll_url": "...", "enroll_token_file": "..."}`；`control_url` 可留空，启动时经 `GET /v1/discover` 获取；若本地固定了 `control_url`，签发响应中的地址必须一致，否则拒绝（防止 token 被引到别的控制面）。
- **平台**：macOS GUI 版 LocalAPI 自动发现；Linux 默认 `/var/run/tailscale/tailscaled.sock`（容器/服务器用 `--tailscale-socket` 覆盖）；Windows 走命名管道（LocalAPI 库已支持，待实测）。iOS/Android 不跑守护进程，由 Headscale 引导页或 OIDC 手动登录。

## 5. 安全模型

| 风险 | 控制 |
|---|---|
| Headscale API key 泄露 = 全网管理权 | 服务用 key 只存在于 `idoris-vpn-enroll` 容器挂载的文件里，容器以非 root（bootstrap 以当前用户的 uid/gid 运行它，**以 root 执行 bootstrap 会让注册服务也以 root 运行**，应改用专用普通用户）、只读根文件系统、`cap_drop: ALL` 运行；客户端拿到的是**一次性、10 分钟**的 preauthkey。运维登录 Headplane 用各自的 API key，需单独保管与轮换 |
| 令牌泄露 | 令牌服务端只存 SHA-256（客户端保存的是**明文**令牌，被盗即可注册）；每台设备/每人单独签发邀请令牌（带标签），可单独撤销；按组织限流（默认 30/min）；每次签发写审计日志（tenant、hostname、令牌标签、来源地址） |
| 中间人改写 control_url | 注册 URL 强制 https（`enroll_allow_insecure` 仅限实验室）；客户端若固定了 `control_url`，服务端返回不一致即拒绝 |
| 守护进程劫持用户私有 tailnet | `takeover` 默认 false；`auto` 发现外部登录时改用独立的嵌入式节点，原登录不动（集成测试断言它全程保持 Running）；只有显式 `takeover: true` 才切换并记录 previous_profile；状态 API 显示 `mode` 与 `mode_reason` |
| 节点被盗/离职 | **先撤销该设备的邀请令牌，再 `expire`/`delete` 节点**（`ctl.sh offboard`）。只做 `expire` 或 `delete` 不够：守护进程会用同一枚令牌自动续期或重新注册，等于没撤销。成员节点 180 天过期来自本部署的 `node.expiry: 4320h`（Headscale 默认 0，即不过期），守护进程会自动续期；**带 tag 的 Local AI 节点永不过期**，失窃要撤销令牌后手动 expire/delete；ephemeral 租户用于临时设备。仍在使用整个组织共用的老令牌时，只能轮换这枚共用令牌，影响所有成员 |
| 横向移动 / 跨租户 | ACL 按租户授权，只放行 `<租户>@` → 本租户 Local AI 指定端口；Tailscale SSH 仅 `group:admins` 且 `check` 模式，不允许以 root 登录 |
| 中继被蹭 | DERP `verify_clients: true` |

## 6. 开发责任拆解（WBS）

| 编号 | 工作包 | 交付物 | 状态（2026-10-27） |
|---|---|---|---|
| VPN-S 服务端 | Headscale + Headplane Compose、配置模板、ACL 模板、bootstrap 脚本 | `deploy/vpn/compose.yaml`、`headscale/config.yaml`、`headscale/policy.hujson`、`headplane/config.yaml`、`enroll/Dockerfile`、`bootstrap.sh` | ✅ 本地以 Caddy 内部 CA 整套拉起验证，双租户隔离实测通过；需替换域名并配置 TLS 反代 |
| VPN-E 注册服务 | Headscale REST 客户端、租户 token、一次性 key 签发、限流、CLI（serve/token new/tenant ensure/check） | `vpn/internal/headscale`、`vpn/internal/enroll`、`vpn/cmd/idoris-vpn-enroll` | ✅ 已完成，单测覆盖 |
| VPN-C 客户端守护进程 | LocalAPI Backend 抽象、Reconciler 状态机、状态 API、配置、launchd/systemd 安装 | `vpn/internal/vpnd`、`vpn/cmd/idoris-vpnd` | ✅ 已完成，单测覆盖；Windows 安装器待做 |
| VPN-T 测试 | 单测（假 tailscaled、假 Headscale）、Docker 集成测试（真 Headscale + 真 tailscaled：首次注册、运维过期后自动续期、重启幂等）、CI | `vpn/internal/*/*_test.go`、`vpn/integration/`、`.github/workflows/vpn-ci.yml` | ✅ 本地通过；CI 待首次运行 |
| VPN-D 文档运维 | 本文、ADR-0005、README、vendor 锁定 | `docs/12-VPN-HEADSCALE.md`、`docs/adr/0005-*`、`vendors/references.lock.tsv` | ✅ |
| VPN-M 并存模式 | `mode: auto/system/embedded`、`tsnet` 用户态节点、本机端口转发与 SOCKS5、`takeover` 默认关闭 | `vpn/internal/vpnd/{mode,embedded,forward}.go`、`docs/13` | ✅ 单测 + Docker 集成测试通过 |
| VPN-O 运维 | 单组织 `bootstrap.sh init`、`add-tenant`、策略自动生成与重载、管理员入网、`ctl.sh`、Headplane 暴露档位、仅 VPN 内可达的管理面、可重复的隔离探针 | `deploy/vpn/{bootstrap.sh,ctl.sh,policy.py,test/probe.sh}`、`docs/14` | ✅ 47 项探针通过 |
| VPN-G 局域网与网关 | 同局域网直连、不在局域网时 DERP 中继、子网网关（手动批准与 `autoApprovers`）的实测 | `vpn/integration/lan_test.go`、`docs/15` | ✅ 三个集成测试通过 |
| VPN-W 加入码与网关向导 | 一个加入码入网，网络识别，网关一键推荐与启用，本机网页 | `docs/16` | ⏳ 开发中 |
| VPN-L 许可证 | 传递依赖许可证白名单检查、第三方声明文件、CI 守卫 | `make licenses`、`vpn/THIRD_PARTY_NOTICES.md` | ✅ |
| VPN-N 下一步 | 生产域名 + TLS + DERP 实测；OIDC 接入；Bridge Connector 读取 `/v1/status`；移动端引导页；Windows 服务；Headscale 备份/升级手册 | — | ⏳ 未开始 |

## 7. 测试与验收门禁

- `make test`：`go vet` + `go test -race`。覆盖：Headscale 客户端请求体/鉴权/错误；注册服务 token 校验（常量时间）、限流、上游失败、https 强制、配置校验；Reconciler 的状态路径（首次注册必须走到 login-interactive、过期续期与观望期、连续失败时观望期翻倍并封顶 10 分钟、进入 Running 后清零、外部 tailnet 接管并记录 previous profile、禁止接管、已有 profile 直接切换、Stopped 恢复、tailscaled 不可达/领 key 失败）、退避有界、URL 规范化、监听地址校验；配置加载与拒绝未知字段。
- `make lint`：golangci-lint v2（standard + errorlint/gosec/misspell/unconvert）零告警。
- `make integration`：Docker 起 `headscale/headscale:v0.29.6` 与 `tailscale/tailscale:v1.104.2`（纯 `tailscaled --tun=userspace-networking`，没有任何人替它登录），宿主机跑注册服务，容器内跑 `idoris-vpnd`。Headscale 在 443 端口提供 https，证书由测试运行时临时生成的 CA 签发（不入库），tailscaled 经 `SSL_CERT_FILE` 信任该 CA。断言：daemon 进入 `connected` 且只用了 1 把 key；Headscale 看到节点在线并分配了 100.64/10 地址；运维 `expire` 节点后 daemon 自动重新注册回到 `connected`；杀掉 daemon 重启后 `login_attempts` 为 0，且注册服务没有多铸任何 key。2026-10-27 本地连续通过 3 次，每次约 35–45 秒，全程共铸 2 把 key。
- **实测发现的生产约束**：Tailscale 客户端在短时间内重连控制面时会强制改走 **443 端口的 TLS**，即使 `server_url` 写的是别的端口。源码位置是 `control/controlhttp` 的 `forceNoise443` 与 `health.LastNoiseDialWasRecent`。因此生产环境 Headscale 必须在 **https://域名:443** 上可达。用非 443 端口或明文 HTTP 时，首次注册可能成功，但过期续期会一直失败。
- **部署包本地验证**（2026-10-27，OrbStack arm64，Caddy 内部 CA 提供 TLS）：`headscale configtest` 通过，另对 v0.29.6 源码逐个核对了配置键，因为 viper 会静默忽略未知键；`headscale policy check` 通过；Headplane 连上 Headscale，以 API key 登录可见节点；enroll 镜像约 7 MB，容器内 `idoris-vpn-enroll check` 通过；`bootstrap.sh` 在全新项目上端到端跑通且可重复执行。数据面用真实 tailscaled 节点和 `tailscale nc` 逐端口验证了 ACL。
- **多租户隔离实测**（同日）：测试网络里有 acme 与 globex 两个租户，各有成员和 Local AI 主机，另有一台管理员设备。29 个端口探测全部符合预期，0 个不符：
  - 成员只能访问本租户 Local AI 的 8740、8742、443，8080 不通。
  - 跨租户访问、成员之间互访一律不通，两台 Local AI 之间也不通。
  - 管理员通过 Tailscale SSH 登录两台 Local AI 成功，以 root 登录被拒。
  - 在 `policy.hujson` 里新增一个零节点租户的规则块，`policy check` 与 SIGHUP 重载都能通过。
  - 模板里的 `tests` 块默认注释掉：启用后，引用的租户必须已有节点，否则新增租户会被拒绝重载。各租户都有节点后，可以启用它防止规则写错；实测一条跨租户泄漏规则会被它拒绝。
- **并存、局域网与网关的集成测试**（2026-10-27，本机 Docker，各自独立复现通过）：
  - `TestEmbeddedAutoLeavesForeignTailscale`：系统 tailscaled 已登录另一台 Headscale 时，`auto` 选择嵌入式节点，原登录全程保持 Running；本机 `127.0.0.1:11434` 经转发把 65553 字节原样送到 `acme-local-ai`；过期后重新注册，重启沿用状态，全程共铸 2 把 key。
  - `TestLanDirect`：同一网段的两个节点不经 DERP，直连走局域网地址（`pong via 10.250.204.4:41641`，3ms），不需要额外配置。`TestLanAwayRelay`：在不同网络、内嵌 DERP 下，`pong via DERP(lan)`，TCP 仍通。
  - `TestGatewaySubnetRoute`：路由批准前不可达；手动批准与 `autoApprovers` 两种方式都能批准；批准后允许的端口通、其他端口被 ACL 拒绝；没开 `--accept-routes` 的成员拿不到路由。
  - `deploy/vpn/test/probe.sh`：两个组织加管理员加网关加仅 VPN 内可达的管理面，47 项断言全部通过，可重复执行。
  - 这些测试都是实验室明文注册或自签 CA，Docker 里的网络不能代替真实 NAT、Wi-Fi 客户端隔离、VLAN 与物理交换机，见 [15](15-VPN-LAN-AND-GATEWAY.md) 第 6 节。
- **进入生产前的门禁**：真实域名 + Let's Encrypt + 反代；两台不同 NAT 后的真实设备通过 DERP 互通并 `tailscale ping`；macOS GUI 版 + Homebrew 版 + Ubuntu 三种客户端各跑通一次 `service install`；Headplane 以 API key 登录可见节点；两个租户各自的 Local AI 互不可达，并在公网环境复测一次。

## 8. 运维

完整手册见 [14-VPN-OPERATIONS.md](14-VPN-OPERATIONS.md)。要点：

0. **前提**：Headscale 必须以 `https://<域名>`（443 端口）对外，见第 7 节的生产约束。宿主机需要 Docker Compose v2 和 python3，不需要 Go。
1. 把占位域名 `vpn.example.org` 换成真实域名（`headscale/config.yaml` 的 `server_url`，`headplane/config.yaml` 的 `base_url` 与 `public_url`）。反代把域名转到 `headscale:8080`，`/admin` 转到 `headplane:3000`，`enroll.<域名>` 转到 `enroll:8787`，透传 Host 与 X-Forwarded-Proto 并支持 Upgrade。STUN 端口生产中必须保持 udp/3478。
2. **一个组织**：`bash deploy/vpn/bootstrap.sh init [--org office] [--admin admin] [--lan-cidr 192.168.1.0/24]`。它建用户和 API key、生成 Headplane cookie secret、渲染该组织的策略块并 `policy check` 后重载、创建 `admin` / 成员 / Local AI（以及可选的网关）注册项并只打印一次 token。可重复执行，不覆盖已有密钥。
3. **再加一个组织**（进阶）：`bash deploy/vpn/bootstrap.sh add-tenant <名称>`。
4. **日常操作**：SSH 上服务器用 `deploy/vpn/ctl.sh`（节点、过期与删除、路由批准、策略检查与重载、API key、日志、备份与恢复）。
5. **管理 UI**：Headplane 默认只绑 `127.0.0.1`（配 SSH 隧道）；`HEADPLANE_BIND` 可改为办公室局域网地址；`--profile tailnet-admin` 让它只在 VPN 内可达，成员访问不到。
6. **隔离回归**：`bash deploy/vpn/test/probe.sh`，两个组织加管理员加网关，47 项允许/拒绝断言。
7. 备份内容：`db.sqlite`（含 `-wal`/`-shm`）、`noise_private.key`、`derp_server_private.key`、Headplane 数据卷。私钥必须和 sqlite 一起恢复。
8. 观测：注册服务每次签发写一行审计日志（含令牌标签与来源地址；只有配置了 `trusted_proxies` 才信任 X-Forwarded-For，否则记录的是反代地址）；`/readyz` 检查 Headscale 连通与 API key 有效期；客户端用 `idoris-vpnd status`。

## 9. 待决问题

已解决：

- **同机双 tailnet**：不再是限制。`auto`/`embedded` 模式用进程内 `tsnet` 节点与系统 Tailscale 并存，限制是只有本机回环转发与 SOCKS5、没有系统级路由和 MagicDNS，见 [13](13-VPN-CLIENT-MODES.md)。移动端仍只能一个 VPN。
- **共享实例还是每组织一套**：默认一个组织；多组织是显式的 `add-tenant`；隔离要求高的组织另起一套 `deploy/vpn`。
- **管理员设备入网与服务器运维入口**：见 [14](14-VPN-OPERATIONS.md)。

仍待决定：

- **Headscale 单实例**：官方定位 self-hoster，无 HA；中小组织规模可接受，需明确备份与升级流程。
- **审计日志的来源 IP**：注册服务目前不读 X-Forwarded-For，部署在反代后只能记录反代 IP。
- **OIDC**：Headscale 支持 OIDC 注册，可作为移动端与无守护进程设备的登录方式；与 token 注册并存时的用户归属需设计。
- **语言**：本组件用 Go 而非仓库其他部分规划的 Rust，理由见 [ADR-0005](adr/0005-vpn-tailscale-client-headscale-control.md)。
- **容器镜像发布**：见第 10 节，发布前要换掉 Alpine 基础镜像。

## 10. 许可证与合规

本节是工程层面的核对，不是法律意见。

- **整体结论**：本仓库以 Apache-2.0 发布没有许可证障碍。Headscale（BSD-3-Clause）、Headplane（MIT）作为独立容器运行，不修改、不链接、不随本仓库分发；官方 Tailscale 客户端只由用户自行安装，本仓库不分发。
- **链接进二进制的依赖**：对 `idoris-vpnd` 与 `idoris-vpn-enroll` 在 linux、darwin、windows 三个系统上扫描，共 42 个第三方模块，许可证只有 Apache-2.0、BSD-2-Clause、BSD-3-Clause、MIT、ISC，没有 copyleft（GPL / AGPL / LGPL / MPL），Apache-2.0 的依赖里也没有 NOTICE 文件。
- **自动守卫**：`make licenses`（`vpn/`）用固定版本的 go-licenses 检查，白名单之外的许可证（含 MPL、Unknown）直接失败，并检查 `vpn/THIRD_PARTY_NOTICES.md` 没有过期；`make notices` 重新生成该文件；CI 见 `.github/workflows/vpn-licenses.yml`。扩大白名单要经人工审阅，不是把许可证加进去让检查通过。
- **署名**：BSD 许可要求二进制分发时保留版权声明，`THIRD_PARTY_NOTICES.md` 负责这件事，发布二进制时要一并带上。
- **名称**：Tailscale 与 Headscale 的 LICENSE 第 3 条都禁止未经许可用版权人名字为衍生产品背书或推广。因此产品名不要含 Tailscale / Headscale，文档里只做描述性使用（"官方 Tailscale 客户端"、"基于 Headscale"），并写明与两者无隶属关系。没有查商标注册状态。
- **容器镜像**：`deploy/vpn/enroll/Dockerfile` 的最终阶段是 `alpine:3.23`，其中 busybox、apk-tools、alpine-baselayout 等是 GPL-2.0-only，`ca-certificates-bundle` 含 MPL-2.0。当前是运维方自己构建自己用，没有问题；**一旦我们发布构建好的镜像**，就要同时提供这些包的对应源码或书面获取要约。更简单的做法是发布前把最终阶段换成 `scratch` / distroless static，并把 HEALTHCHECK 改成二进制自带的子命令（现在用的是 busybox `wget`）。这一项尚未改。

## 来源（2026-10-27 核验）

- Tailscale 文档：[自定义控制服务器](https://tailscale.com/kb/1507/custom-control-server)、[多账号快速切换](https://tailscale.com/kb/1225/fast-user-switching)（同一设备同一时刻只有一个活跃账号、不能同时在多个 tailnet 收发包）
- Headscale 文档：[支持的客户端](https://headscale.net/stable/about/clients/)（只列官方 Tailscale 客户端）

- Headscale 文档：[API](https://headscale.net/stable/ref/api/)、[Features](https://headscale.net/stable/about/features/)、[DERP](https://headscale.net/stable/ref/derp/)、[OIDC](https://headscale.net/stable/ref/oidc/)、[Apple 客户端](https://headscale.net/stable/usage/connect/apple/)、[Web UI 列表](https://headscale.net/stable/ref/integration/web-ui/)、[Getting started](https://headscale.net/stable/usage/getting-started/)
- Headscale v0.29.6 [OpenAPI](https://github.com/juanfont/headscale/blob/v0.29.6/gen/openapiv2/headscale/v1/headscale.swagger.json)、[config-example.yaml](https://github.com/juanfont/headscale/blob/v0.29.6/config-example.yaml)
- Tailscale v1.104.2 [client/local 包](https://pkg.go.dev/tailscale.com@v1.104.2/client/local)、[cmd/tailscale/cli/login.go](https://github.com/tailscale/tailscale/blob/v1.104.2/cmd/tailscale/cli/login.go)、[up.go](https://github.com/tailscale/tailscale/blob/v1.104.2/cmd/tailscale/cli/up.go)
- Headplane v0.8.2 [config.example.yaml](https://github.com/tale/headplane/blob/v0.8.2/config.example.yaml)
- GitHub API 快照（Star、License、发布日期）：2026-10-27
