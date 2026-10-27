# 13 · VPN 客户端模式：与已有 Tailscale 并存，以及办公室网关

**日期：** 2026-10-28（泰国时区）· **状态：** `vpn/` 已实现；`make test`、`make lint`（默认与 `-tags integration`）为零告警；嵌入式 Docker 集成测试与原有 `make integration` 的结果见第 10 节。本文只记录在 tailscale.com v1.104.2、Headscale v0.29.6、OrbStack arm64 上核实过的行为。2026-10-28 的状态查询连接、SOCKS5 字段长度，以及同日的注册与服务安装修正，门禁数字在第 10 节末尾。

[docs/12](12-VPN-HEADSCALE.md) 和 [ADR-0005](adr/0005-vpn-tailscale-client-headscale-control.md) 与本文一致：`takeover` 默认 **false**。显式 `takeover: true` 才会切走系统客户端上已有的外网登录。

## 1. 三种模式

Tailscale 客户端同一时刻只能登录一个控制面。`idoris-vpnd` 因此有三种启动模式。配置键 `mode`，环境变量 `IDORIS_VPN_MODE`，flag `--mode`。缺省是 `auto`。

| 模式 | 驱动谁 | 碰不碰系统 Tailscale |
|---|---|---|
| `system` | 本机官方 `tailscaled` 的 LocalAPI。行为与 docs/12 的守护进程相同：`CheckPrefs` → `Start(AuthKey, UpdatePrefs)` → `StartLoginInteractive` | 会。`takeover: true` 时会切走已有的外网登录 |
| `embedded` | 进程内 `tailscale.com/tsnet` 用户态节点。状态目录独立（`state_dir`，默认 `~/.idoris/vpn-state`，目录模式 0700）。`tsnet.Server.LocalClient()` 返回的 `*local.Client` 满足同一个 `Backend` 接口，所以仍由同一个 Reconciler 登录 | 不碰。没有 TUN，不需要 root，不改系统 DNS |

`embedded` 是「驱动官方客户端」的明确例外：Tailscale 的库跑在 `idoris-vpnd` 进程里面，不是本机安装的 `tailscaled`。库版本钉在 `vpn/go.mod` 的 `tailscale.com`（本文写作时为 v1.104.2）。升级这套库必须发一版新的 `idoris-vpnd`，不能靠用户单独升级官方客户端。
| `auto` | 启动时只探测一次系统 tailscaled，按第 2 节的表选定上面两者之一。决定之后不再改 | 仅当决定为 `system` 时才碰 |

嵌入式节点的 hostname：配置里的 `hostname`，否则 `os.Hostname()`，再否则 `idoris-vpnd`。这个名字同时传给 tsnet 和 Reconciler。`system` 模式仍只把配置里的 hostname（可以为空）交给 Reconciler。

## 2. auto 怎么选

决定是纯函数 `DecideMode`（`vpn/internal/vpnd/mode.go`），表驱动单测覆盖。`member` 和 `admin` 的 `auto` 只探测一次。`local-ai` 和 `gateway` 见下一节：`auto` 永不选 embedded。

探测只读：3 秒超时，只调 `Status`、`GetPrefs`、`ProfileStatus`。`Status` 失败（没装、没跑、套接字超时）视为不可达。`Status` 成功但 `GetPrefs` 失败，且状态是 Running / Starting / Stopped 时，control URL 记为 `unknown`，按外网登录处理，避免误切。磁盘上另有一个指向我们控制面的 profile（`HasOurProfile`）只作诊断，**不参与选择**。

下面这张表是 `member` / `admin`（以及未写 `role` 时的默认 `member`）。

| 请求 | 系统 tailscaled | 当前 control URL | 其他 | 选用 | `mode_reason` |
|---|---|---|---|---|---|
| `system` | 不看 | 不看 | — | system | `configured system` |
| `embedded` | 不看 | 不看 | — | embedded | `configured embedded` |
| `auto` | 不可达 | — | 即使 `takeover: true` | embedded | `tailscaled unreachable` |
| `auto` | 可达 | 已经是我们的 Headscale（尾斜杠、`:443` 按同一 URL 比较） | — | system | `system tailscaled is already on the iDoris control server` |
| `auto` | 可达 | 空，且后端不是 Running / Starting / Stopped | — | system | `system tailscaled is not logged in` |
| `auto` | 可达 | 外网，或上面的 `unknown`，或空 URL 但后端已是 Running / Starting / Stopped | `takeover` 没有被显式设为 true | embedded | `system tailscaled is logged into a foreign control server and takeover is not enabled` |
| `auto` | 可达 | 外网 | `takeover` 显式 true | system | `takeover explicitly enabled` |

非空、且不是我们控制面的 URL，在 Running、Starting、Stopped、NeedsLogin、NoState 里都算外网登录。空 URL 只在 Running、Starting、Stopped 时算外网（有的旧 profile 登录着 SaaS，却不报 ControlURL）。空 URL 加上 NeedsLogin 或 NoState 才是全新安装，可以登录。Tailscale SaaS 的几个登录域名经 `ipn.IsLoginServerSynonym` 互相视为同一个控制面；我们自己的 Headscale URL 不允许是这些域名。

### local-ai 与 gateway

配置键 `role`：`member`（默认）、`local-ai`、`gateway`、`admin`。加入码写入的就是这个字段。`/v1/discover` 若返回 `role`，以发现结果为准。

`local-ai` 和 `gateway` 要接收入站连接。`embedded` 没有 TUN，只能从本机向外拨号，不能当服务端。因此：

- `auto` **不会**选 embedded。系统 tailscaled 不可达时，阶段是 `waiting-for-tailscaled`，`last_error` 说明要安装并启动官方 Tailscale，守护进程以 2 秒起、翻倍、封顶 30 秒继续探测。状态服务在等待期间就已经在听，所以这个阶段能从状态 API 读到。`/healthz` 在阶段不是 `connected` 时返回 503。
- 显式 `mode: embedded` 配这两个角色是配置错误，进程直接退出。
- 系统 tailscaled 可达但登录在外网、且没有显式 `takeover: true` 时，仍用 system，**不切**那个登录，阶段 `blocked-foreign-tailnet`。提示写的是把 `takeover` 打开，不会建议改用 embedded。
- `admin` 与 `member` 一样，可以使用 embedded。

嵌入式 `member` 若既没有 `forwards` 也没有 `socks5_listen`，状态里的 `warnings` 会写明：本机其他程序没有进入 tailnet 的路径。

启动日志有一行 `vpn mode`，带 `mode` 和 `reason`。状态 API 同样暴露这两个字段。

## 3. takeover 默认改为 false

`TakeoverValue()` 只有在配置指针显式为 true 时返回 true。JSON 里省略、`null`、`false` 都是关闭。环境变量 `IDORIS_VPN_TAKEOVER` 接受 `1` / `true`。flag `--takeover` 与 `--no-takeover` 互斥。

因此：成员机器已经登录 Tailscale SaaS 或别的 Headscale 时，默认不再切走那个登录。`member` / `admin` 的 `auto` 改跑嵌入式节点。若有人把 `mode` 固定成 `system` 且未打开 takeover，Reconciler 停在 `blocked-foreign-tailnet`，不调用 `SwitchProfile`、`SwitchToEmptyProfile`，也不登录。`login_attempts` 保持 0。`last_error` 为：

```text
tailscaled is logged into <url>; takeover is disabled. Set mode: embedded to run alongside it, or takeover: true to switch this machine
```

检查发生在任何 profile 变更之前。磁盘上已经有一个 iDoris profile，不能当作切走当前外网登录的许可。受保护的状态是：当前 ControlURL 非空且不是我们的（Running、Starting、Stopped、NeedsLogin、NoState 都算），以及 ControlURL 为空但后端已是 Running、Starting 或 Stopped。NeedsLogin 且 ControlURL 为空不受保护，那是未配置的客户端。

`local-ai` / `gateway` 的同一情况不会建议 `mode: embedded`，提示改为打开 `takeover: true`。

要切走外网登录，必须显式 `takeover: true`（或 `--takeover`）。

官方 Tailscale GUI 和 `tailscale` CLI 不走控制器锁，锁排除不了它们。协调器在 `Start`、`StartLoginInteractive` 和 `EditPrefs`（路由、SSH 也在这条路径上）之前再读一次当前 prefs。控制面已经不是这一轮决定要改的那一台，就中止，不发出这次修改。`takeover: false` 且读到外网登录时，这一轮停在 `blocked-foreign-tailnet`。这把检查和修改之间的窗口收窄了，没有关上。

## 4. 嵌入式节点能做什么、不能做什么

能做（这次核实过的）：

- 与本机另一个 tailscaled 同时运行。集成测试里，成员容器的系统 tailscaled 一直 Running 在 `https://headscale-foreign`，节点 id 在注册、转发、过期续期、守护进程重启之后仍是 1。嵌入式节点另外注册到我们的 Headscale，地址 `100.64.0.2/32` 与 `fd7a:115c:a1e0::2/128`。
- 用自己的状态目录。重启读回同一个 node key，不新铸 pre-auth key（第 6 节）。
- 过期后续期。Headscale `expire` 之后，同一节点 id 2 用一把新 key 回到 Running。
- 经 MagicDNS 短名访问 tailnet 里的 TCP 服务。见第 5 节。
- 在 Docker 网络里经我们 Headscale 的内嵌 DERP（region 999，`verify_clients: true`，配置里不写公网 IPv4，STUN 口来自 `stun_listen_addr`）与对端互通。日志里 `udp=true`，本端 STUN 地址是容器网卡 `192.168.156.5`。

不能做：

- 不创建 TUN，不安装系统路由，不改系统 DNS。本机其他进程不能直接访问 `100.64.0.0/10`。要访问 tailnet，走第 5 节的转发或 SOCKS5。
- 不能做子网路由。`advertise_routes` 在 `mode: embedded` 时配置校验就拒绝；`auto` 若最终选了 embedded，启动前再拒绝一次。错误文本说明没有 TUN，并指向 `mode: system`、Linux `net.ipv4.ip_forward=1`、以及 Headscale 必须批准路由。
- 不转发 UDP / ICMP。转发和 SOCKS5 都是 TCP。
- 不要给本进程设置 `TS_AUTHKEY` 或 `TS_AUTH_KEY`。v1.104.2 的 `tsnet.Server.getAuthKey` 会读这两个变量。代码把 `Server.AuthKey` 留空，让 Reconciler 独占铸 key；环境变量里若再有一把 key，tsnet 会在 `Start` 里自己用掉。这次没有用这两个变量跑过实验，依据是该版本源码。
- 不调用 `tsnet.Server.Up`。登录由 Reconciler 完成。

## 5. 本机访问：转发与 SOCKS5

用户态网络下，Bridge Connector / Agent24 应连回环地址，而不是 tailnet IP。

```json
{
  "enroll_url": "https://enroll.example.org",
  "enroll_token_file": "/home/member/.idoris/enroll.token",
  "mode": "auto",
  "forwards": [
    {"listen": "127.0.0.1:8742", "target": "acme-local-ai:8742"}
  ],
  "socks5_listen": "127.0.0.1:1055"
}
```

`forwards[].listen` 与 `socks5_listen` 都走 `ValidateForwardListen`：回环 TCP（`127.0.0.1` 或 `::1`），或 `unix:<绝对路径>`。`0.0.0.0`、相对路径、全员可写的父目录都会拒绝。未知 JSON 字段仍然拒绝。环境变量 `IDORIS_VPN_FORWARDS` 是同一 JSON 数组。flag `--forward` 可重复，形式 `listen=target`。`--socks5-listen` 对应 `socks5_listen`。

转发是回环 TCP 监听，经一个小 `Dialer` 接口拨号：

- `embedded`：`tsnet.Server.Dial`。它会等到节点 Running，并能解析 MagicDNS。
- `system`：`&net.Dialer{}`，由内核路由把 tailnet IP 送进官方客户端。这条路径有单测（假 dialer），没有在 Docker 里再跑一遍。

上面这份配置没有写 `socks5_auth_file`，也没有 `socks5_allow_anonymous`。SOCKS5 因此默认认证：`StartAccess` 在 `<state_dir>/socks5.auth` 写入一行 `idoris:<随机密码>`，模式 0600。文件已经存在就接着用，不换密码。创建时 info 日志只打路径，不打密码。`idoris-vpnd status` 在 SOCKS5 活动时打印同一路径，形式是 `auth=<path>`。显式 `socks5_auth_file` 只读取、不创建。`socks5_allow_anonymous: true` 才不认证，并打出警告；它和 `socks5_auth_file` 不能同时出现。实现是本模块的 CONNECT（RFC 1928）加用户名密码（RFC 1929）。`tailscale.com/net/socks5` 的 `Serve` 没有用，原因在第 13 节。

Docker 里 `TestWireAccessForwardsAndSOCKS5` 用嵌入式节点连上真实 Headscale，核实了 TCP 转发、`unix:` 转发、SOCKS5 无凭据被拒、错误凭据被拒、生成的凭据能打到 tailnet 里的 echo、超过 `max_connections` 的连接被马上关掉，以及 unix 套接字和 `socks5.auth` 都是 0600。2026-10-27 单独跑这一项是 19.74s。整包 `make integration` 的计时以第 10 节为准。

单测（假 dialer，不起 tsnet）覆盖：半关闭、大包、拨号失败、监听关闭、关闭后无 goroutine 泄漏。Docker 里的 echo 是长度前缀帧（uint32 大端 + 正文），不依赖 TCP 半关闭；半关闭只在单测里验证。

**这次 Docker 核实的转发：** `127.0.0.1:11434` → `acme-local-ai:11434`，65553 字节原样返回。对端是 tailnet 里带 `tag:acme-local-ai` 的节点，MagicDNS 后缀 `it.idoris.internal`，用的是短名，不是 FQDN。对端 tailscaled 使用内核 TUN（`NET_ADMIN` + `/dev/net/tun`），所以它在 `0.0.0.0:11434` 上的普通 TCP 监听能收到 tailnet 连接。成员容器里的系统 tailscaled 仍是 userspace，以便和嵌入式节点并存。ACL 只放行 `acme@` → `tag:acme-local-ai:11434`。

Connector / Agent24 的配置应写成 `http://127.0.0.1:8742`（或你们实际监听的端口），不要写 `http://acme-local-ai:8742`。后者只有进了 tailnet 的进程才解析得了。

## 6. 登录、状态目录、重启不铸 key

v1.104.2 上对 tsnet 的观察：

- 空状态、控制面不可达：`Server.Start` 把 ControlURL 写入 prefs，因 NeedsLogin 自己调用 `StartLoginInteractive`，并停在 NeedsLogin。Reconciler 再执行 `CheckPrefs`、`Start(AuthKey, UpdatePrefs)`、`StartLoginInteractive`。这次 `Start` 替换掉没有 key 的那次登录。
- 从未注册过的目录，重启后仍是 NeedsLogin，在 Reconciler 要求之前不铸 key。
- 已经注册过的目录，重启后会短暂报 NeedsLogin，同时 tsnet 自己用磁盘上的 node key 做 `doLogin(regen=false)`。此窗口内若 Reconciler 再 `Start(AuthKey)`，日志是 `control: client.Shutdown` 和 `register request: context canceled`，那次恢复被取消，并白白铸一把 pre-auth key。2026-10-27 第一次集成测试就是这样失败的（重启铸出 `key_id=4`）。
- LocalAPI 的 `GetPrefs` 会剥掉私钥（`ipnlocal.stripKeysFromPrefs`）。不能靠 prefs 里的 `PrivateNodeKey` 判断「已经有节点身份」。`Status.HaveNodeKey` 来自未脱敏的 profile，这才是 LocalAPI 客户端能看见的信号。
- 因此：NeedsLogin / NoState 且 `HaveNodeKey`（或进程内 prefs 里确实还有公钥）时，先等 `persistedLoginSettle`（15 秒）。第一次只计时，不铸 key。进入 Running 后清零。15 秒后仍是 NeedsLogin，才当作过期。全新安装没有 node key，第一次就铸。
- 「状态文件已经存在」不能说明注册完成：`tsnet.Start` 会先把 `tailscaled.state` 写出来，注册若在中途被打断，下次看起来像是已有节点，却会停在 Starting。取代它的是 `<state_dir>/registration-complete`（0600，内容 `registered`）。这个标记在节点第一次进入 Running、或已经能看见节点身份时写下。`EmbeddedLoginMode` 必须在 `tsnet.Start` **之前**调用，否则 Start 自己创建的状态文件会被误判成中断。没有状态文件：立刻登录。有状态文件但没有标记：先等 15 秒（与 NeedsLogin 的观望钟分开），仍无身份才铸一把 key。标记已在：Starting 不铸 key。已有部署升级时目录里只有状态文件、没有标记；第一次回到 Running 会补上标记，不会因此再铸 key。

15 秒也作用于 `system` 模式：过期节点通常仍带着 node key，所以续期会比「立即重新 enroll」多等最多 15 秒。观望期（20 秒起、翻倍、封顶 10 分钟）不变。`CheckPrefs` 失败，以及 `Start` / `StartLoginInteractive` 失败，都计入这次观望：同一次本地失败不会在退避窗口里再铸第二把 key。铸 key 发生在 `CheckPrefs` 通过之后。

登录从当前 prefs（`GetPrefs`）拷贝，只改守护进程负责的字段：`ControlURL`、`WantRunning`、配置了才写的 `Hostname`、`CorpDNS`（`accept_dns`）、`RouteAll`（`accept_routes`）、配置了才写的 `AdvertiseRoutes`、以及 `RunSSH`（仅当 `ssh` 显式为 true 或 false）。不发送 `AdvertiseTags`。`ssh` 省略，或 `advertise_routes` 为空，表示不管理：操作员用 `tailscale set --ssh` 或 `tailscale set --advertise-routes` 设过的值，在重新 enroll 时保留。节点已经 Running 时，被管理的字段若漂移，用 `EditPrefs` 写回，不必重新 enroll。允许 TCP 22 的 ACL 不会打开 Tailscale SSH；Local AI 主机需要 `ssh: true`。

状态文件路径是 `<state_dir>/tailscaled.state`。删掉这个目录等于新节点，会再铸一把 key。注册标记不是下面第 11 节的身份绑定文件。

## 7. 网关（子网路由）

只在 `system` 模式。配置、环境变量、flag：

```json
{
  "mode": "system",
  "hostname": "office-gw",
  "advertise_tags": ["tag:acme-gateway"],
  "ssh": true,
  "advertise_routes": ["192.168.1.0/24"]
}
```

`IDORIS_VPN_ADVERTISE_ROUTES` 与 `--advertise-routes` 都是逗号分隔的 CIDR。`netip.ParsePrefix` 校验；主机位非零（如 `192.168.1.1/24`）拒绝。空列表表示不管理路由，Reconciler 不会改现有的 `AdvertiseRoutes`。

网关标签由加入码生成，形式是 `tag:<org>-gateway`（例如组织 `acme` 为 `tag:acme-gateway`），不是 `tag:acme-office-gw`。标签写在注册条目的 `acl_tags` 上。登录请求不带 `advertise_tags`：Headscale v0.29.6 会拒绝「预授权密钥 + 客户端自报标签」。

`ssh: true` 把 `prefs.RunSSH` 设为打开。Local AI 主机需要它；一条放行 `:22` 的 ACL 不够。省略 `ssh` 则完全不碰 `RunSSH`。

登录时，仅当配置了 `advertise_routes` 才写入 `prefs.AdvertiseRoutes`。运行中若实际路由与配置不一致（顺序无关），用 `EditPrefs` 且 `AdvertiseRoutesSet: true` 写回。假 Backend 单测覆盖了登录写入、漂移纠正，以及未管理的 SSH / 路由在重新 enroll 后仍在。

守护进程不改 sysctl，也不打开内核转发。Linux 网关需要运维自己设置：

```text
net.ipv4.ip_forward = 1
```

Headscale 还必须批准这些路由（生产环境由 ops 的 `autoApprovers` 处理）。这次没有做路由数据面测试，没有在宿主机上改 `ip_forward`。

## 8. 状态 API

原有字段保留。新增：

| JSON | 文本输出 | 含义 |
|---|---|---|
| `mode` | `mode:` | `system` 或 `embedded`（auto 已经落成二者之一） |
| `mode_reason` | `mode_reason:` | 第 2 节的原因 |
| `role` | `role:` | `member` / `local-ai` / `gateway` / `admin` |
| `phase` | `phase:` | 见下。节点已经 enroll 不等于主机可用 |
| `warnings` | 每行一条 | 降级说明。没有则为空 |
| `enroll_reachable` | `enroll: unreachable`（仅当为 false） | 这次启动没有连上注册服务 |
| `forwards[]` | `forward:` 每行 `listen -> target (state)`，失败再加 `error=<text>` | `listen` 是实际 `Listen` 地址（端口 0 会变成内核分配的端口）。`state` 为 `listening`、`failed` 或 `suspended` |
| `socks5` | `socks5:` 为 `listen (state)`，失败加 `error=<text>`，有凭据文件加 `auth=<path>` | JSON 是 `{listen, state, error, auth_file}`。未配置时省略。`auth_file` 只是路径 |

`phase` 除了原来的 `connected`、`starting`、`enrolling`、`needs-admin-approval`、`routes-pending-approval`、`blocked-foreign-tailnet`、`error`，还有：

- `waiting-for-tailscaled`：`local-ai` 或 `gateway` 在等官方 tailscaled。不是健康。
- `missing-node-tags`：这两个角色登录之后 `Self.Tags` 仍为空。阶段保持为这个值，并在 `warnings` 里说明。节点在线上不等于标签已经打上。

`/healthz` 仅当 `phase` 为 `connected` 时返回 200，否则 503，正文是阶段名。

`idoris-vpnd status` 走 `FormatStatus`，上表各项都打印。`idoris-vpnd status` 和本地页面的状态回调都调用 `QueryStatus`。它共用一个关掉 keep-alive 的 HTTP 客户端，每次查询的拨号地址放在请求上下文里，避免连到上一次的套接字。单测对回环上的状态服务打了 30 次，服务端新建的连接和关闭的连接对齐。

## 9. 平台

macOS、Windows、Linux 可以同时跑官方 Tailscale 和这个嵌入式节点。嵌入式节点不占用系统 VPN 槽。

iOS / Android 同时只允许一个活动 VPN。这次没有在手机上验证。这两端仍用官方 Tailscale App 的多账号快速切换，不跑 `idoris-vpnd`。

## 10. 验证记录（2026-10-27）

这一轮在 `vpn/`、分支 `work/vpn-hardening-client`、OrbStack arm64 上跑完。`go.mod` 没有新依赖。

单元与静态检查：

- `make test`（`go vet ./...`，然后 `go test -race -count=1 ./...`）退出码 0。`cmd/idoris-vpn-enroll` 1.635s，`cmd/idoris-vpnd` 2.790s，`internal/enroll` 2.176s，`internal/gateway` 1.662s，`internal/headscale` 3.784s，`internal/join` 4.228s，`internal/netdetect` 4.717s，`internal/ui` 3.494s，`internal/vpnd` 5.406s。`integration` 包带构建标签，不在这一轮里。
- `golangci-lint run ./...` 与 `golangci-lint run --build-tags integration ./...` 都是 `0 issues`。
- `make licenses`：linux、darwin、windows 的 amd64 与 arm64 都扫过，输出 `THIRD_PARTY_NOTICES.md is up to date`。
- `make build-linux`：`CGO_ENABLED=0 GOOS=linux GOARCH=arm64`，产出 `bin/idoris-vpnd-linux`。当时本节还没提交，版本串是 `ab8c177-dirty`。

`make integration`（`cd integration && go test -tags integration -count=1 -v -timeout 10m ./...`）退出码 0，包耗时 261.505s。

- `TestEmbeddedAutoLeavesForeignTailscale` 48.03s。系统 tailscaled 事先 Running 在 `https://headscale-foreign`，id=1，全程保持。`auto` 的 `mode_reason` 为 `system tailscaled is logged into a foreign control server and takeover is not enabled`。嵌入式节点 `connected`，`login_attempts=1`，计数 minter 为 1（`key_id=2`），Headscale 节点 id=2，地址 `100.64.0.2` 与 `fd7a:115c:a1e0::2`。local-ai 节点 id=1，地址 `100.64.0.1` 与 `fd7a:115c:a1e0::1`，tag `tag:acme-local-ai`。转发 `127.0.0.1:11434 -> acme-local-ai:11434` 返回 65553 字节。`ExpireNode` 后续期仍是节点 id 2，minter 变为 2（`key_id=3`）。同一 `state_dir` 再启动的日志行：`restart reused state; pre-auth keys minted in total: 2`。
- `TestHardAAwaitTailscaled` 3.07s。`role=local-ai`、`mode=auto`、套接字不存在。`phase=waiting-for-tailscaled`，`mode=system`。`last_error`：`role local-ai requires the official tailscaled because embedded mode cannot receive inbound connections. Install Tailscale, start it, and leave idoris-vpnd running; it keeps retrying`。没有拉起嵌入式节点。
- `TestHardAClientCore` 54.62s，compose 项目 `idoris-vpn-harda-<pid>`。
  - `foreign-stays` 16.02s。两个 profile，选中外网 `https://headscale-foreign`，状态文件里同时有 `https://headscale` 与 `https://headscale-foreign`。守护进程没有 `takeover`，`phase=blocked-foreign-tailnet`，`login_attempts=0`，self 与 control URL 不变。
  - `unmanaged-prefs` 25.74s。首次 enroll `key_id=2`，节点 id=2，地址 `100.64.0.2` 与 `fd7a:115c:a1e0::2`。手工 `tailscale set --ssh=true` 与 `--advertise-routes=192.168.88.0/24`。过期后续期 `key_id=3`，`ssh=true`，路由仍是 `192.168.88.0/24`，minter 总数 2。
  - `enroll-down` 5.82s。嵌入式节点先 `connected`（`key_id=4`，minter 总数 3）。关掉注册服务再拉起同一状态目录：`phase=connected`，`enroll_reachable=false`，`login_attempts=0`，minter 仍是 3。`warnings` 含有注册服务不可达、沿用已保存控制面，以及嵌入式没有转发或 SOCKS5 时应用没有入口。
- `TestEnrollConnectAndReauth` 34.53s。系统 tailscaled 首次注册后 `connected`，节点 `it-member`，地址 `100.64.0.1` 与 `fd7a:115c:a1e0::1`。`expire` 后续期铸了第二把 key（`key_id=1` 然后 `key_id=2`）。日志：`pre-auth keys minted in total: 2`。
- 既有套件同一轮也通过：`TestLanDirect` 29.74s，`TestLanAwayRelay` 23.37s，`TestGatewaySubnetRoute` 36.03s，`TestWizardGatewayJoin` 30.81s。

结束后 `docker ps -a`、`docker volume ls`、`docker network ls` 里没有 `idoris-vpn-*` 容器、卷或网络。

接线这一轮在 `work/vpn-wiring` 上又跑了一次门禁，数字如下。`make test` 退出码 0：`cmd/idoris-vpn-enroll` 1.422s，`cmd/idoris-vpnd` 1.691s，`internal/enroll` 3.452s，`internal/gateway` 5.102s，`internal/headscale` 2.635s，`internal/join` 2.113s，`internal/netdetect` 4.477s，`internal/ui` 4.331s，`internal/vpnd` 4.510s。两次 `golangci-lint`（第二次带 `--build-tags integration`）都是 `0 issues`。`make licenses` 扫完 linux、darwin、windows 的 amd64 与 arm64，输出 `THIRD_PARTY_NOTICES.md is up to date`。`make build-linux` 版本串是 `5797c87`（gosec 修正在这次编译之后才提交）。`make integration` 退出码 0，包耗时 275.545s。`TestWireAccessForwardsAndSOCKS5` 16.23s，日志是 `max_connections refusal in 0s` 和 `wire access ok: tcp, unix mode 0600, socks5 auth, cap refusal 0s`。这一项开始编译 `wireclient` 时，gosec 修正已经在磁盘上。同轮其余项：`TestEmbeddedAutoLeavesForeignTailscale` 48.73s，`TestHardAAwaitTailscaled` 3.37s，`TestHardAClientCore` 53.43s（`foreign-stays` 15.94s，`unmanaged-prefs` 25.51s，`enroll-down` 5.22s），`TestEnrollConnectAndReauth` 36.14s，`TestLanDirect` 28.95s，`TestLanAwayRelay` 22.59s，`TestGatewaySubnetRoute` 34.16s，`TestWizardGatewayJoin` 30.89s。结束后 `docker ps -a` 没有 `wire-*` 或 `idoris-vpn-*` 容器。

注册与服务安装这一轮在 `work/vpn-r2-go`（`0abdcb0`）上又跑了门禁。`make test` 退出码 0：`cmd/idoris-vpn-enroll` 1.502s，`cmd/idoris-vpnd` 1.682s，`internal/enroll` 8.027s，`internal/gateway` 2.324s，`internal/headscale` 3.732s，`internal/join` 3.927s，`internal/netdetect` 3.431s，`internal/ui` 2.138s，`internal/vpnd` 3.210s。两次 `golangci-lint`（第二次带 `--build-tags integration`）都是 `0 issues`。`GOOS=windows go build ./...` 与 `GOOS=windows go vet ./...` 退出码 0。`make licenses` 扫完 linux、darwin、windows 的 amd64 与 arm64，输出 `THIRD_PARTY_NOTICES.md is up to date`。`make build-linux` 版本串是 `0abdcb0`。`make integration` 退出码 0，包耗时 276.070s；这一轮给未自带项目名的 compose 调用设置了 `COMPOSE_PROJECT_NAME=idoris-vpn-r2g-7f3c1a`。`TestEmbeddedAutoLeavesForeignTailscale` 47.47s，`TestHardAAwaitTailscaled` 2.92s，`TestHardAClientCore` 53.02s，`TestEnrollConnectAndReauth` 34.79s，`TestLanDirect` 29.08s，`TestLanAwayRelay` 22.97s，`TestGatewaySubnetRoute` 34.13s，`TestWireAccessForwardsAndSOCKS5` 15.70s，`TestWizardGatewayJoin` 35.38s。结束后 `docker ps -a`、`docker network ls`、`docker volume ls` 里没有 `idoris-vpn-*` 容器、网络或卷。上面两轮按子测试拆开的秒数没有在这一轮重记。Windows 上的 `icacls` 没有在这台 macOS 上执行。

## 11. 身份绑定、环境变量、锁

### 身份与控制面

第一次 `/v1/discover` 成功之后，把可信的 control URL 记到状态文件。发现结果里的 `tenant` 和 `role` 是身份的依据（发现若没给 role，用配置里的 role）。文件里还有令牌指纹：注册令牌 SHA-256 的前 8 字节，十六进制，共 16 个字符。文件里没有令牌、加入码或 auth key。

路径：`state_file`，flag `--state-file`，环境变量 `IDORIS_VPN_STATE_FILE`。缺省时 Windows 用 `%AppData%\idoris\vpnd-state.json`，否则 `$XDG_STATE_HOME/idoris/vpnd-state.json`，再否则 `~/.idoris/vpnd-state.json`。模式 0600。这与嵌入式节点的 `state_dir` 不是同一个文件。

已绑定的 tenant 或 role 与这次凭证不一致时（换了租户、换了角色、管理员机器拿到成员令牌、成员 profile 拿到 Local AI 令牌），不把现有 profile 报成 `connected`。日志写下绑定值与期望值（不写下令牌），然后向正确身份重新 enroll。这次登录用的是我们自己的 profile，所以允许切换。同一条 control URL、不同的 tenant 或 role，同样重新 enroll。只有指纹变了、tenant 和 role 没变，不重新 enroll，只更新指纹。

还没有绑定（升级上来的旧状态文件，或第一次成功登录）时，接受当前 profile 并写下绑定。标签证明不了租户；这一条是升级路径，不是「换了租户还继续用旧节点」。

启动时发现失败：配置若钉了一条与已保存 URL 不同的 control URL，拒绝启动。否则用钉住的 URL，或已保存的 URL，继续跑，**不**为了探活去 enroll。只有节点确实需要登录时才 enroll。状态里 `enroll_reachable` 为 false，`warnings` 说明注册服务不可达、沿用已保存的控制面和节点身份。静态 auth key、没有 enroll URL 时，不算不可达。发现失败期间，已保存的 `local-ai` / `gateway` 角色仍然生效，不会因为发现失败而掉回 embedded。

以下取代「还没有绑定就接受当前 profile」。绑定在身份确认时写下正在跑的节点：self 的稳定 ID（`tailcfg.StableNodeID`）。系统模式在 LocalAPI 给出非空 profile ID 时一并写入；嵌入式不记 profile。每一轮正在跑的节点或（系统模式）profile 与绑定不一致，身份视为未确认，走和凭证变化同一条重新 enroll。租户、角色、节点、profile 都空的绑定不能把已经在跑的节点静默认证成当前凭证，必须先有一次确认过的 enroll。这一进程刚刚 enroll 成功、第一次看到 Running 的新装机可以写下绑定，不必再铸一把 key。只有指纹变了，tenant、role、节点和 profile 都没变，仍然不重新 enroll，只更新指纹。

发现失败时，已保存的角色只有在该绑定的令牌指纹与当前凭证指纹相同才采用。指纹缺失或不一致，配置里的角色不动。配置明确是 `local-ai` 或 `gateway` 时，不会被已保存的 `member` 或 `admin` 换下去，因此不会在发现失败时掉进 embedded、把旧成员节点报成 connected。注册服务恢复之后，下一次铸 key 之前先再 discover 一次，刷新身份和角色；discover 仍失败就不铸 key。

登录退避写在同一状态文件：下一次允许铸 key 的时间，以及连续未收敛的次数。请求 key 之前先落盘。写失败就不铸 key，内存也不提前记成已经退避。新进程遵守这个时间。没有存过身份的新节点允许立刻试一次。`SetIdentity` 和 `RememberControl` 只在文件替换成功之后改内存，写失败的下一轮仍是旧绑定。状态目录用 `EnsurePrivateDir`（拒绝符号链接、非属主、group 或 other 可写）。替换用独占临时文件再 rename，不写 `路径.tmp`，预置在旧临时名上的符号链接不会被跟着写出去。

### 环境变量与 flag

每个 JSON 键都有环境变量 `IDORIS_VPN_` + 键名的大写（`accept_routes` → `IDORIS_VPN_ACCEPT_ROUTES`）。未知的 `IDORIS_VPN_*` 让进程退出，错误里带这个变量名。布尔接受 `1` / `0` / `true` / `false` / `yes` / `no`。字符串列表用逗号。`forwards` 是 JSON 数组。

| JSON | 环境变量 | flag |
|---|---|---|
| `control_url` | `IDORIS_VPN_CONTROL_URL` | `--control-url` |
| `enroll_url` | `IDORIS_VPN_ENROLL_URL` | `--enroll-url` |
| `enroll_token` | `IDORIS_VPN_ENROLL_TOKEN` | `--enroll-token` |
| `enroll_token_file` | `IDORIS_VPN_ENROLL_TOKEN_FILE` | `--enroll-token-file` |
| `enroll_allow_insecure` | `IDORIS_VPN_ENROLL_ALLOW_INSECURE` | `--enroll-allow-insecure` |
| `auth_key` | `IDORIS_VPN_AUTH_KEY` | `--auth-key` |
| `auth_key_file` | `IDORIS_VPN_AUTH_KEY_FILE` | `--auth-key-file` |
| `hostname` | `IDORIS_VPN_HOSTNAME` | `--hostname` |
| `accept_routes` | `IDORIS_VPN_ACCEPT_ROUTES` | `--accept-routes` |
| `accept_dns` | `IDORIS_VPN_ACCEPT_DNS` | `--accept-dns`（省略则接受 DNS） |
| `ssh` | `IDORIS_VPN_SSH` | `--ssh`（省略则不管理 RunSSH） |
| `advertise_tags` | `IDORIS_VPN_ADVERTISE_TAGS` | `--advertise-tags`（逗号分隔；登录时不发送） |
| `takeover` | `IDORIS_VPN_TAKEOVER` | `--takeover` / `--no-takeover` |
| `mode` | `IDORIS_VPN_MODE` | `--mode` |
| `role` | `IDORIS_VPN_ROLE` | `--role` |
| `state_dir` | `IDORIS_VPN_STATE_DIR` | `--state-dir` |
| `state_file` | `IDORIS_VPN_STATE_FILE` | `--state-file` |
| `forwards` | `IDORIS_VPN_FORWARDS` | `--forward`（可重复，`listen=target`） |
| `socks5_listen` | `IDORIS_VPN_SOCKS5_LISTEN` | `--socks5-listen` |
| `socks5_auth_file` | `IDORIS_VPN_SOCKS5_AUTH_FILE` | `--socks5-auth-file` |
| `socks5_allow_anonymous` | `IDORIS_VPN_SOCKS5_ALLOW_ANONYMOUS` | `--socks5-allow-anonymous` |
| `max_connections` | `IDORIS_VPN_MAX_CONNECTIONS` | `--max-connections`（0 表示 64） |
| `dial_timeout` | `IDORIS_VPN_DIAL_TIMEOUT` | `--dial-timeout`（空表示 10s） |
| `advertise_routes` | `IDORIS_VPN_ADVERTISE_ROUTES` | `--advertise-routes` |
| `tailscale_socket` | `IDORIS_VPN_TAILSCALE_SOCKET` | `--tailscale-socket` |
| `listen` | `IDORIS_VPN_LISTEN` | `--listen` |
| `interval` | `IDORIS_VPN_INTERVAL` | `--interval` |
| `log_level` | `IDORIS_VPN_LOG_LEVEL` | `--log-level` |

`dial_timeout` 是时长字符串，例如 `10s`。空字符串用 10 秒。解析失败或小于等于 0 拒绝。`max_connections` 小于 0 拒绝，0 用默认 64。`socks5_allow_anonymous` 为 true 时再写 `socks5_auth_file` 是错误。

Unix 上，令牌文件、auth key 文件、状态文件、SOCKS5 凭据文件，以及在 JSON 里直接写了 `enroll_token` 或 `auth_key` 的配置文件，必须是普通文件、属主为当前用户、权限不含 group/other（`chmod 600`）。符号链接拒绝。错误文本里带有 `chmod 600`。只指向 `enroll_token_file`、自身没有 inline 密钥的配置文件可以是 0644。Windows 上同一检查只打警告，不拒绝。`service install`（用户级和 `--system`）在真正安装之前调用 `vpnd.CheckSecretFile`：登记令牌文件、auth key 文件、`socks5_auth_file`，以及含有 inline `enroll_token` 或 `auth_key` 的配置文件。失败就中止，错误里有 `chmod 600`。`--system` 的 root 检查在这之后。Windows 上这一步只警告。

### 控制器锁

改某个后端之前先拿操作系统的排他锁。system：套接字路径的 SHA-256，锁文件放在默认状态文件所在目录；套接字为空时键名是 `default`。embedded：`<state_dir>/controller.lock`。Unix 用 `flock`（`LOCK_EX|LOCK_NB`），进程活着就持有，`Close` 时释放。第二个守护进程立刻失败，错误含有 `another idoris-vpnd`。`local-ai` / `gateway` 在等待 tailscaled 之前就拿 system 锁，所以第二个进程不用等到 tailscaled 起来才失败。`member` 的 `auto` 只锁最终选中的那个后端：选了 embedded 就不会锁系统套接字。Windows 上是尽力创建锁文件，不保证互斥。

## 12. 限制与未决问题

- 15 秒是针对 v1.104.2 这次日志定的。若一次合法的 node key 恢复超过 15 秒仍停在 NeedsLogin，Reconciler 仍会铸一把新 key。没有把这个窗口做成配置。
- SOCKS5、TCP 转发和 `unix:` 转发在 Docker 里由 `TestWireAccessForwardsAndSOCKS5` 覆盖，见第 5 节。官方客户端的子网路由数据面、`ip_forward` 和 Headscale 批准，由 `TestGatewaySubnetRoute` 覆盖（见第 10 节）。`idoris-vpnd` 自己宣告的路由只核实了偏好被保留，没有再打一跳数据面。系统模式的 Gate 有表驱动单测，没有在 Docker 里用系统 tailscaled 再跑一遍。
- 嵌入式节点与官方客户端的 DERP / 打洞性能没有在真实 NAT 后测量。集成测试在同一个 Docker 网络里，STUN 看到的是容器地址。
- MagicDNS 只核实了短名 `acme-local-ai`。没有单独打 FQDN。
- Windows 命名管道上的 LocalAPI、macOS GUI 版与嵌入式节点并存，这次没有再测。
- iOS / Android 的单 VPN 限制没有在设备上验证。
- Windows 上的密钥文件检查和控制器锁没有在 Windows 上跑过。Unix 的 `flock` 与 `chmod 600` 拒绝在本机（darwin）单测里通过。Windows 构建能编过。

## 13. 本机转发与 SOCKS5 的访问控制

日期：2026-10-27。

回环地址上的 TCP 监听（`127.0.0.1` 或 `::1`）本机任何用户都能连。转发的目标如果说 HTTP，网页还可以通过 DNS rebinding 把浏览器指到这个端口，从而借用本节点的 tailnet 身份去访问内网。监听本身不区分是哪个用户、哪个页面发起的。

因此两件事要分开做：

- 传输层收紧。优先 `unix:<绝对路径>`，套接字创建后是 `0600`，只有拥有者能连。父目录不能是全员可写。已经有进程在听的套接字不会被清掉；没人听的残留文件会删掉再监听。SOCKS5 默认要用户名和密码（RFC 1929）。用户名和密码各自必须是 1 到 255 字节（按字节，不按字符），显式配置、`socks5_auth_file` 和生成的文件都在监听打开之前检查。256 字节的密码会让 `StartAccess` 失败，并且不返回监听器。凭据放在 `0600` 的 `socks5_auth_file`，文件内容一行 `user:password`，这个路径只读取、不创建。都不给时，在 `<state_dir>/socks5.auth` 生成用户名 `idoris` 和 64 位十六进制密码，模式 0600；重启继续用同一份。创建时 info 日志和 `idoris-vpnd status` 都只出现路径。只有显式 `socks5_allow_anonymous: true` 才不认证，进程会打出警告。它和 `socks5_auth_file` 一起写是配置错误。
- 应用自己再认证一次。转到 Local AI 的流量，Local AI 应用必须自己验身份。转发和 SOCKS5 只决定谁能用这条通道，不代替应用的登录。

每个监听单独限制。`max_connections` 默认 64，满了就立刻关掉新连接，不排队。`dial_timeout` 默认 10 秒。客户端在拨号期间断开，拨号的 goroutine 会跟着结束。`Accept` 遇到暂时错误会退避重试；致命错误把该监听的 `state` 写成 `failed`，并把错误放进状态的 `error` 字段。

系统模式如果还没有连上本组织的控制面，Gate 关闭。状态是 `suspended`（`failed` 和 `closed` 优先，只改写 `listening`）。新连接马上关掉，不会向外拨号。启动时 `accessOptions` 把 `AccessOpen` 接成 Gate。嵌入式模式始终打开。系统模式只在协调器快照的 `current_control_url` 与本进程的控制 URL 被 `SameControlURL` 判成同一台（忽略大小写、末尾斜杠、默认端口；Tailscale SaaS 的同义地址也算），并且 phase 是 `connected` 或 `routes-pending-approval` 时打开。状态里的 `control_url` 永远是本进程想要的地址，不拿来做这比较。其他模式关闭。

以下取代「嵌入式模式始终打开」和「只看协调器快照」。嵌入式和系统模式都要同时满足：身份已确认（不在 identity-mismatch，也不是 enrollment 失败），phase 是 `connected` 或 `routes-pending-approval`，并且 LocalAPI 当前的 control URL 与本进程是同一台。Gate 自己读 prefs 和 status，缓存不超过 1 秒；读失败按关闭。系统模式再对绑定里的节点 ID 和 profile ID，两边都非空且不同则关闭。协调器在 phase、控制面、profile 或身份变化时把所有权加一代。每个已接受的连接记下接受时的代；代变了且门已关闭，这条连接被关掉，包括还没返回的拨号。门仍然开着的代变化（例如 `connected` 到 `routes-pending-approval`）不拆已建立的流。

已知限制：官方 GUI 和 `tailscale` CLI 仍可能在两次 prefs 读取之间切走 profile，控制器锁排除不了它们。回环上的 TCP 转发让这台机器的每个本地用户都借用本节点身份；要收紧监听，用 `unix:`。

`tailscale.com/net/socks5` 的 `Server` 能做用户名密码，但它自己 `Accept`、用固定 5 秒和 `context.Background` 拨号、不限连接数，第一次 `Accept` 失败就退出。所以这里没有用它的 `Serve`，CONNECT 和认证是一层薄实现。
