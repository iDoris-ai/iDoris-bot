# 12 · 私有接入层：官方 Tailscale 客户端 + 自建 Headscale 控制面 + idoris-vpnd 守护进程

**日期：** 2026-10-27（泰国时区）· **状态：** 方案已确认方向；`vpn/` 目录代码为首个可运行实现（单测 + Docker 集成测试通过）；`deploy/vpn` 已在本地以内部 CA 整套拉起验证；尚未在公网域名与真实 TLS 上验收。

## 1. 目标与非目标

Bridge 除了把 LINE / Telegram / WhatsApp 等中心化 SNS 桥接到客户本地 Agent 之外，还要解决另一条路：**组织成员从自己的设备直接访问本组织的 Local AI（Agent24 / iDoris）**。公网暴露 Local AI 端口不可接受，所以需要一层私有网络。

| 目标 | 说明 |
|---|---|
| 客户端零改动 | 成员设备只安装 **官方 Tailscale 客户端**（App Store / Homebrew / apt / MSI / iOS / Android），不分发修改版 |
| 控制面自建 | 坐标服务器是我们运营的 **Headscale**（官方开源实现，不 fork），不连 Tailscale Inc. 的 SaaS |
| 无感加入 | 成员机器上跑一个后台守护进程 `idoris-vpnd`，它让 Tailscale 自动登录到我们的服务器地址，断线/过期自动续期 |
| 服务中小组织 | 每个组织 = 一个 Headscale user + 一个专属 tag `tag:<租户>-local-ai`，ACL 按租户逐条授权；成员互不可达，只能访问本组织 Local AI 主机的指定端口 |
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

- **租户 = Headscale user + 专属 tag**。以 `acme` 为例：成员设备注册为 user `acme` 的个人节点，ACL 中写作 `acme@`。Local AI 主机通过带 `acl_tags: ["tag:acme-local-ai"]` 的注册条目入网。带 tag 的节点在 Headscale 里归特殊用户 `tagged-devices`，不归租户 user。
- **每个租户在 ACL 里一组规则**：`acme@` → `tag:acme-local-ai:8740,8742,443`；`tag:acme-local-ai` → `acme@:*`；`group:admins` → `tag:acme-local-ai:22`，外加一条 ssh 规则。新增租户就复制这一组规则。不使用 `autogroup:member` 这类实例级通配，否则一个租户的成员能连到所有租户的 Local AI，本地实测已复现。
- **管理员**：Headscale 没有 `autogroup:admin`，管理员是 `group:admins` 里列出的 Headscale 用户（写作 `name@`）。管理员设备不属于任何租户，实测只能访问各 Local AI 的 22 端口。只有 `group:admins` 能给节点打 Local AI tag，成员自行 `--advertise-tags` 会被忽略。管理员设备如何入网尚无正式入口，可用网页认证 `headscale auth register --user admin`，或单加一条注册条目。Tailscale SSH 需要 ssh 规则加一条放行 22 端口的 ACL，只有 ssh 段不会开 22 端口。未配 OIDC 时，`check` 模式每次登录要运维在服务器上执行 `headscale auth approve --auth-id <id>`。
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
        Note over D: Running→connected；Stopped→EditPrefs WantRunning；NeedsLogin（节点被过期）→立即重新 enroll；连续失败时观望期 20s→40s→80s…封顶 10 分钟
    end
~~~

## 4. idoris-vpnd 守护进程行为

- **状态机**（`vpn/internal/vpnd/reconciler.go`）：`connected` / `starting` / `switching-profile` / `enrolling` / `needs-admin-approval` / `blocked-foreign-tailnet` / `error`。
- **与用户已有 Tailscale 账号共存**：若机器已登录别的 tailnet，默认 `takeover: true`，守护进程记录原 profile ID 后切换到我们的 profile（Tailscale 同时只能一个 profile 在线，这是客户端限制）；配置 `--no-takeover` 则停在 `blocked-foreign-tailnet` 等待运维决定。
- **登录调用顺序**：与官方 `tailscale up --auth-key` 完全一致：`CheckPrefs` → `Start` → `StartLoginInteractive`。实测证明只调 `Start` 时，全新节点会一直停在 NeedsLogin，从不联系控制面。`Start` 会重建控制客户端并清掉残留的浏览器登录 URL，所以随后的 login-interactive 一定使用这把 key，不会弹浏览器；它还会强制生成新 node key，过期续期正需要这一点。
- **一次性 key 的节约**：每次登录只领一把 key。登录后进入观望期，观望期内不再领 key：首次 20s，此后每次未能进入 Running 的连续尝试翻倍，封顶 10 分钟，进入 Running 后清零。健康节点被过期后的第一次续期立即进行。tailscaled 不可达等错误另按 2s→2min 指数退避加 ±20% 抖动。实测对照：修复前持续失败时约 2 分钟铸了 7 把 key，修复后在 +0s、+20s、+60s 各一把。
- **启动不铸 key**：未固定 `control_url` 时，守护进程启动只调 `GET /v1/discover` 获取地址。已注册节点重启不消耗任何 key，集成测试对此做了断言。
- **状态 API**：默认 `unix:~/.idoris/vpnd.sock`（0600）或 `tcp:127.0.0.1:<port>`（只允许回环）。`GET /healthz`（connected→200，否则 503）、`GET /v1/status`（JSON：phase、tailnet_ips、self_dns_name、key_expiry、last_error、login_attempts、previous_profile_id）。Bridge Connector 后续用它判断 Local AI 是否可达。
- **服务安装**：`idoris-vpnd service install --config ~/.idoris/vpnd.json` 生成 launchd LaunchAgent（macOS，KeepAlive）或 systemd user unit（Linux，Restart=always）。Windows 暂不内建安装器，可用 NSSM/任务计划运行 `idoris-vpnd run`。
- **配置**：JSON 文件 + `IDORIS_VPN_*` 环境变量 + flag 覆盖。推荐 `{"enroll_url": "...", "enroll_token_file": "..."}`；`control_url` 可留空，启动时经 `GET /v1/discover` 获取；若本地固定了 `control_url`，签发响应中的地址必须一致，否则拒绝（防止 token 被引到别的控制面）。
- **平台**：macOS GUI 版 LocalAPI 自动发现；Linux 默认 `/var/run/tailscale/tailscaled.sock`（容器/服务器用 `--tailscale-socket` 覆盖）；Windows 走命名管道（LocalAPI 库已支持，待实测）。iOS/Android 不跑守护进程，由 Headscale 引导页或 OIDC 手动登录。

## 5. 安全模型

| 风险 | 控制 |
|---|---|
| Headscale API key 泄露 = 全网管理权 | 服务用 key 只存在于 `idoris-vpn-enroll` 容器挂载的文件里，容器以非 root、只读根文件系统、`cap_drop: ALL` 运行；客户端拿到的是**一次性、10 分钟**的 preauthkey。运维登录 Headplane 用各自的 API key，需单独保管与轮换 |
| 租户 token 泄露 | token 服务端只存 SHA-256；可按租户配多把 token 以便轮换；按租户限流（默认 30/min）；每次签发写审计日志（tenant、hostname、key id） |
| 中间人改写 control_url | 注册 URL 强制 https（`enroll_allow_insecure` 仅限实验室）；客户端若固定了 `control_url`，服务端返回不一致即拒绝 |
| 守护进程劫持用户私有 tailnet | 默认 takeover 但记录 previous_profile；`--no-takeover` 可禁用；状态 API 明确显示 `blocked-foreign-tailnet` |
| 节点被盗/离职 | 运维在 Headplane 或 API `expire`/`delete`；成员节点 180 天过期来自本部署的 `node.expiry: 4320h`（Headscale 默认 0，即不过期），守护进程会自动续期；**带 tag 的 Local AI 节点永不过期**，失窃只能手动 expire/delete；ephemeral 租户用于临时设备 |
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
- **进入生产前的门禁**：真实域名 + Let's Encrypt + 反代；两台不同 NAT 后的真实设备通过 DERP 互通并 `tailscale ping`；macOS GUI 版 + Homebrew 版 + Ubuntu 三种客户端各跑通一次 `service install`；Headplane 以 API key 登录可见节点；两个租户各自的 Local AI 互不可达，并在公网环境复测一次。

## 8. 运维

0. **前提**：Headscale 必须以 `https://<域名>`（443 端口）对外，见第 7 节的生产约束。宿主机需要 Docker Compose v2 和 python3，不需要 Go。
1. 把占位域名 `vpn.example.org` 换成真实域名，共三处：`headscale/config.yaml` 的 `server_url`，以及 `headplane/config.yaml` 的 `base_url` 和 `public_url`。`base_url` 不带 `/admin`。反代把 `vpn.example.org` 转到 `headscale:8080`，`/admin` 转到 `headplane:3000`，`enroll.example.org` 转到 `enroll:8787`。反代必须透传 Host 与 X-Forwarded-Proto，并支持 Upgrade。STUN 端口在生产中必须保持 udp/3478，因为 DERP map 通告的就是 3478。
2. `bash deploy/vpn/bootstrap.sh acme` 首次引导时依次做下列事情。之后再执行 `bash deploy/vpn/bootstrap.sh globex` 就是新增租户：追加注册条目并重启 enroll，不动已有 token。
   - 建 user，建 365 天服务用 API key，只写入 `deploy/vpn/enroll/headscale.apikey`。
   - 生成 Headplane 的 `headplane/cookie_secret` 和 `.env`。
   - 在容器里构建 enroll 镜像。为租户生成两条注册条目并打印两个 token：`<租户>` 给成员用；`<租户>-local-ai` 带 tag `tag:<租户>-local-ai`，限流 5 次/分钟。写入 `enroll/config.json`。
   - 校验 `server_url` 是 https 且端口为 443。`policy.hujson` 里没有该租户规则时只警告，不中断。
   - 拉起全部服务，最后执行 `check`。
   - 以上生成物均已 gitignore。脚本可重复执行，不会覆盖已有的 key、secret 与配置。
3. 在 `policy.hujson` 中为该租户复制 `TENANT BLOCK 1/3` 至 `3/3` 三块规则，执行 `headscale policy check -f /etc/headscale/policy.hujson`，再 `docker compose kill -s HUP headscale` 重载。
4. 给组织：成员 token（放 `~/.idoris/enroll.token`）与客户端配置；成员执行 `idoris-vpnd service install --config ~/.idoris/vpnd.json`。
5. Local AI 主机：使用带 `acl_tags: ["tag:<租户>-local-ai"]` 的注册条目和它的 token，hostname 设为 `<租户>-local-ai`。
6. 轮换：`headscale apikeys expire/create` 后替换文件并重启 `enroll`；租户 token 加新 hash → 下发 → 删旧 hash。
7. 观测：`metrics_listen_addr: 127.0.0.1:9090` 绑在容器内部，其他容器访问不到；要采集指标需改为 `0.0.0.0:9090`，且只放在内部网络、不发布端口。注册服务日志每次签发一行，`remote=` 目前记录的是反代 IP。客户端用 `idoris-vpnd status`。
8. 备份：`db.sqlite` 连同 `-wal`/`-shm`、`noise_private.key`、`derp_server_private.key`，以及 `headplane-data` 卷。

## 9. 待决问题

- **同机双 tailnet**：Tailscale 客户端同一时刻只能登录一个控制面。若成员本来就用公司 Tailscale，接管会断掉对方。备选方案是守护进程用 `tsnet` 在进程内自建一个用户态节点（不触碰系统 Tailscale），Bridge Connector 走该节点访问 Local AI；代价是失去系统级路由和 MagicDNS。需要产品决策。
- **Headscale 单实例**：官方定位 self-hoster，无 HA；中小组织规模可接受，需明确备份（见第 8 节）与升级流程。
- **共享实例还是每组织一套**：共享实例靠 ACL 按租户授权实现隔离，写错一条就会跨租户；每组织一套隔离最强，但运维成本线性增长。默认共享，由隔离要求高的客户选择独立部署，需要产品确认。
- **审计日志的来源 IP**：注册服务目前不读 X-Forwarded-For，部署在反代后只能记录反代 IP。
- **OIDC**：Headscale 支持 OIDC 注册，可作为移动端与无守护进程设备的登录方式；与 token 注册并存时的用户归属需设计。
- **许可证**：Headscale/Tailscale（BSD-3）、Headplane（MIT）与本仓库 Apache-2.0 兼容；`vpn/go.mod` 引入 `tailscale.com` 的传递依赖需在发布前跑一次许可证扫描并写入 THIRD_PARTY_NOTICES。
- **语言**：本组件用 Go 而非仓库其他部分规划的 Rust，理由见 [ADR-0005](adr/0005-vpn-tailscale-client-headscale-control.md)。

## 来源（2026-10-27 核验）

- Headscale 文档：[API](https://headscale.net/stable/ref/api/)、[Features](https://headscale.net/stable/about/features/)、[DERP](https://headscale.net/stable/ref/derp/)、[OIDC](https://headscale.net/stable/ref/oidc/)、[Apple 客户端](https://headscale.net/stable/usage/connect/apple/)、[Web UI 列表](https://headscale.net/stable/ref/integration/web-ui/)、[Getting started](https://headscale.net/stable/usage/getting-started/)
- Headscale v0.29.6 [OpenAPI](https://github.com/juanfont/headscale/blob/v0.29.6/gen/openapiv2/headscale/v1/headscale.swagger.json)、[config-example.yaml](https://github.com/juanfont/headscale/blob/v0.29.6/config-example.yaml)
- Tailscale v1.104.2 [client/local 包](https://pkg.go.dev/tailscale.com@v1.104.2/client/local)、[cmd/tailscale/cli/login.go](https://github.com/tailscale/tailscale/blob/v1.104.2/cmd/tailscale/cli/login.go)、[up.go](https://github.com/tailscale/tailscale/blob/v1.104.2/cmd/tailscale/cli/up.go)
- Headplane v0.8.2 [config.example.yaml](https://github.com/tale/headplane/blob/v0.8.2/config.example.yaml)
- GitHub API 快照（Star、License、发布日期）：2026-10-27
