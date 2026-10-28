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

官方 Tailscale GUI 和 `tailscale` CLI 不走控制器锁，锁排除不了它们。协调器在 `Start`、`StartLoginInteractive` 和 `EditPrefs`（路由、SSH 也在这条路径上）之前再读一次当前 prefs。控制面已经不是这一轮决定要改的那一台，就中止，不发出这次修改。`takeover: false` 且读到外网登录时，这一轮停在 `blocked-foreign-tailnet`。`SwitchProfile` 和 `SwitchToEmptyProfile` 的前一刻再读一次 prefs 和 profile status；这时已经是外网登录就同样停住，不发出切换。`takeover: true` 不做这道拒绝。这次再读和 LocalAPI 真正切换之间仍有一段非原子窗口。`TestR4CProfileFlipBeforeSwitchIsBlocked` 用一个在两次读取之间把当前 profile 换成外网的假后端核实了拒绝。

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

2026-10-28。共享机器上用 `unix:<绝对路径>` 监听，套接字创建后是 0600。回环 TCP 不做协议认证：本机其他用户连上原始 TCP 转发，就用这个节点的 VPN 身份。每个这种 TCP 监听在 `listenLocal` 里用 `slog.Default()` 打一条警告，正文说明任何本机用户都能连、原始转发因此给出节点身份、SOCKS5 仍核对自己的凭据。守护进程自己的 logger 不接收这条警告，所以 `--log-level=error` 不会把它消掉。`unix:` 监听不打这条警告。

`forwards[].owner_only` 为 true 时，只在 Linux 上对回环 TCP 生效。实现读 `/proc/net/tcp` 或 `/proc/net/tcp6`：已接受连接的 `RemoteAddr` 是客户端本地地址，`LocalAddr` 是服务器地址，按这个方向匹配客户端那一行。空白分开后 uid 在下标 7。IPv4 是小端十六进制（`127.0.0.1` 为 `0100007F`），IPv6 是四个小端 uint32（`::1` 末尾为 `01000000`）。对不上、两行 uid 不同、或文件读不到，连接关掉，不交给转发。查到的 uid 必须等于 `os.Getuid()`。真正加上这个过滤时不再打上面的警告。

本机是 darwin，没有读过真实的 `/proc`。单测用现场 TCP 连接的地址拼了一份快照，解析出 uid 42，并核对了上面两个地址格式。同一天在这台 Mac 上对 TCP 连接调用 `getpeereid` 和 `LOCAL_PEERCRED`，返回 uid 0 且错误是 nil，所以不能拿来做判断。darwin 和 Windows 上 TCP 的 `owner_only` 在 `Resolve` 失败，错误要求改用 `unix:`。`unix:` 再加上 `owner_only` 不报错，套接字仍是 0600。`--forward` 仍是 `listen=target`，没有这一项；字段走 JSON 或 `IDORIS_VPN_FORWARDS`。

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

2026-10-28。Unix 状态套接字在删除任何路径之前，先拿一把状态路径锁：`os.UserCacheDir()/idoris/locks/<sha256>.lock`。哈希输入是 `status`、一个 NUL、再加规范后的监听路径，因此不会和同一路径上的系统 LocalAPI 控制器锁撞车。这不是后端控制器锁。`Listen` 仍在打开节点之前返回，等待 tailscaled 时状态口先起来。锁持有到监听器 `Close`。

`Lstat` 看到符号链接或非套接字就停，不删除，启动失败。只删除当前用户拥有、并且 `Dial` 失败的套接字。本机单测：普通文件留在原地，内容仍是 `keep`，错误写明不是套接字；符号链接还在，目标文件仍是 `keep`；`bind` 之后关掉 fd 留下的残留套接字被换掉，新套接字模式 0600；已经在听的套接字上第二次 `Listen` 失败，第一次仍能拨通；事先持有同一把状态锁时，残留套接字不会被删。Windows 上查不到属主就拒绝删除。这条分支没有在 Windows 上执行，只做了 `GOOS=windows go vet`。属主不符和查不到属主是在 darwin 上用注入函数测的。

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

路径：`state_file`，flag `--state-file`，环境变量 `IDORIS_VPN_STATE_FILE`。这三者先于任何缺省。都空时，若 `STATE_DIRECTORY` 已设置，用 `$STATE_DIRECTORY/vpnd-state.json`。systemd 的 `StateDirectory=idoris` 会把这个变量设成 `/var/lib/idoris`；多个目录时值是冒号分隔的列表，取第一段，而且必须是绝对路径。Windows 路径不按冒号切开，因为盘符里就有冒号。`STATE_DIRECTORY` 设了但不是绝对路径，报错，错误文本里有 `STATE_DIRECTORY`，不会悄悄退回主目录。都没设置时，Windows 用 `%AppData%\idoris\vpnd-state.json`，否则 `$XDG_STATE_HOME/idoris/vpnd-state.json`，再否则 `~/.idoris/vpnd-state.json`。`STATE_DIRECTORY` 和 `HOME` 都没有时，错误同样点名 `STATE_DIRECTORY`，而不是只说 `$HOME is not defined`。模式 0600。这与嵌入式节点的 `state_dir` 不是同一个文件。嵌入式目录的顺序相同：显式 `state_dir` / `--state-dir` / `IDORIS_VPN_STATE_DIR`，然后 `$STATE_DIRECTORY/node`，然后 `~/.idoris/vpn-state`。

已绑定的 tenant 或 role 与这次凭证不一致时，不把当前节点报成 `connected`。过渡开始时记下当时的节点 ID 和节点公钥（LocalAPI `Self.PublicKey`）。系统模式再记下这次登录返回时所在的 profile。完成条件是 LocalAPI 显示 Running，并且节点公钥或节点 ID 与记下的不同；系统模式还要求当前 profile 就是登录返回时的那个。登录之后 profile 又被换成另一个，这次不认证，用屏幕上的节点重新开始过渡。`StartLoginInteractive` 会换一把节点公钥。真实 Headscale 对同一把机器钥重新认证时保持节点 ID，所以完成与否看这次登录事务，不看节点 ID 有没有被换掉。节点公钥不写进日志。

产品还没有发布，节点 ID 为空的旧绑定不另做迁移。tenant 和 role 已经对上、节点 ID 和 profile ID 仍空的绑定，在确认时补上这两个 ID，只写一次，不再铸 key。tenant、role、节点、profile 全空的绑定不能把已经在跑的节点静默认证成当前凭证，必须先 enroll 一次。只有指纹变了，tenant、role、节点和 profile 都没变，仍然不重新 enroll，写入时更新指纹。

没有 `enroll_url` 的静态 auth key 不做发现，身份标成 Static。绑定写成 Static 之后，门信任这把凭证正在跑的节点，只要节点 ID 以及系统模式的 profile ID 不和绑定矛盾。嵌入式的转发和 SOCKS5 因此可以打开。`TestR4CEmbeddedStaticAndRoleSwap` 在真实 Headscale 上先用静态 key 连上一个新的嵌入式节点（新节点先停在 NeedsLogin，静态 key 用了一次），再把凭证换成另一个角色：节点 ID 不变，只铸一把新 key，状态到 `connected`。

启动时发现失败：配置若钉了一条与已保存 URL 不同的 control URL，拒绝启动。否则继续跑，不因为探活去铸 key。指纹与已保存绑定相同，而且正在跑的节点 ID、系统模式的 profile ID 都不和绑定矛盾，访问保持打开，警告只说明注册服务不可达。指纹不同，或者节点 ID、profile ID 已经矛盾，保存的身份不算确认：访问保持关闭，状态里写明身份未确认，不为此再铸 key。节点本身需要登录时仍走原来的登录路径。

登录路径在铸 key 之前会再 discover 一次。发现出的角色要求系统模式（`local-ai`、`gateway`；`admin` 不要求）而当前后端是嵌入式时，不 enroll，停在错误状态。正文说明要安装官方 tailscaled、改用系统模式，并且不会 enroll。

进行中的过渡（不匹配的节点 ID 和节点公钥、profile、开始时间、登录是否已返回）写在同一状态文件。进程在退避里重启时读回这份记录，把未完成的过渡做完，不因为重启再铸一把 key。落盘失败则内存回到上一份。

能控制本机 tailscaled 的用户可以让 LocalAPI 谎报节点和 profile。守护进程信 LocalAPI。这是明确不做的目标。

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

Unix 上，令牌文件、auth key 文件、状态文件、SOCKS5 凭据文件，以及在 JSON 里直接写了 `enroll_token` 或 `auth_key` 的配置文件，必须是普通文件、属主为当前用户、权限不含 group/other（`chmod 600`）。符号链接拒绝。错误文本里带有 `chmod 600`。只指向 `enroll_token_file`、自身没有 inline 密钥的配置文件可以是 0644。Windows 上同一检查只打警告，不拒绝。用户级 `service install` 在安装前对这几份文件调用 `vpnd.CheckSecretFile`。`--system` 不走这一条：进程是 root 时，属主是调用 sudo 的用户的 0600 文件会被它拒绝。机器服务接受 0600 的普通文件，属主是 root，或者本进程是 root、`SUDO_UID` 已设置、并且 `stat` 的 uid 等于这个值。`SUDO_UID` 在非 root 进程上不放宽检查。接受之后把文件复制到服务状态目录（`enroll_token`、`auth_key`、`socks5.auth`），模式 0600、属主 root，安装进去的配置改指副本。复制中途失败会删掉已经写下的副本。`TestR4CServiceRootProofs` 在 Debian 容器里用 root 跑过：文件 chown 到 uid 1000 后，`SUDO_UID` 未设置或设成别的 uid 就拒绝，设成 1000 则接受，副本属主是 0；非 root 子进程即使带着 `SUDO_UID` 也不接受 root 拥有的文件。Windows 上这道属主检查直接返回，保护靠目录 ACL。`icacls` 没有在这台 Mac 上执行。

2026-10-28。注册令牌和 auth key 各是一整份凭证，inline 和文件二选一。优先级仍是配置文件、然后环境变量、然后 flag。更高一层写了其中一边，就清掉较低层留下的另一边。同一层两边都写（配置文件里两个字段、两个环境变量、或两个 flag）直接报错，错误里有 `both`。空白的环境变量不算设置。flag 只要出现在命令行上就算设置，空字符串也会清掉较低层。`Resolve` 只在 inline 为空时读文件；两边都还在则拒绝。单测对两份凭证各跑了文件、环境变量、flag 三层。

Windows 上 Go 把普通文件的权限报成 0666。SOCKS 凭据的加载不再用 0600 去比这些位，否则生成的 `socks5.auth` 每次重启都被拒绝。生成文件走三步 `icacls`：`/reset`、`/inheritance:r`、`/grant:r *<当前用户 SID>:F`。服务安装那套授予 SYSTEM 和 Administrators，因为那是机器目录；这份文件在用户配置里，所以只授予当前用户。操作者提供的 `socks5_auth_file` 不改 ACL，沿用所在目录的 ACL。`icacls` 没有在这台 Mac 上执行。单测注入运行器，核对参数，并核对第二步失败时第三步不跑。`CheckSecretFile` 在 Windows 上仍是警告后放行。

### 控制器锁

改某个后端之前先拿操作系统的排他锁。system：套接字路径的 SHA-256，锁文件放在默认状态文件所在目录；套接字为空时键名是 `default`。embedded：`<state_dir>/controller.lock`。Unix 用 `flock`（`LOCK_EX|LOCK_NB`），进程活着就持有，`Close` 时释放。第二个守护进程立刻失败，错误含有 `another idoris-vpnd`。`local-ai` / `gateway` 在等待 tailscaled 之前就拿 system 锁，所以第二个进程不用等到 tailscaled 起来才失败。`member` 的 `auto` 只锁最终选中的那个后端：选了 embedded 就不会锁系统套接字。Windows 上是尽力创建锁文件，不保证互斥。

2026-10-28 起，system 锁的位置如下。空套接字先换成 `paths.DefaultTailscaledSocket()`，再做 `Clean`；相对路径先 `Abs`；`EvalSymlinks` 解析已经存在的部分，最后一级还不存在就把缺失的尾巴拼回去。Windows 管道（前缀 `\\` 或 `//./pipe/`）不解析符号链接。root（euid 0）固定用 `/var/lib/idoris/locks`，不看 `STATE_DIRECTORY`、`HOME` 或 `XDG_*`。非 root 才是：`STATE_DIRECTORY` 已设置则 `$STATE_DIRECTORY/locks/<sha256>.lock`，否则 `os.UserCacheDir()/idoris/locks/<sha256>.lock`。Windows 上提升的令牌或 LOCAL SYSTEM（S-1-5-18）用 `%ProgramData%\idoris\locks`，没有 `ProgramData` 时是 `C:\ProgramData\idoris\locks`。目录经 `fsutil.EnsurePrivateDir`。文件模式 0600。打开时拒绝符号链接：Unix 用 `O_NOFOLLOW`，Windows 用 `FILE_FLAG_OPEN_REPARSE_POINT` 并检查 reparse 属性。显式写出的默认套接字和留空是同一把锁。embedded 仍是规范路径下的 `controller.lock`，符号链接目录和真实目录共用一把。状态套接字的 flock 在同一个锁目录里，键和控制器锁不同，所以它不是那把控制器锁。

本机用重新执行的测试进程核实了非 root 的两件：两个进程 `XDG_STATE_HOME` 不同、LocalAPI 套接字相同，第二个失败，错误含 `another idoris-vpnd`；一个进程锁空套接字，另一个用显式的默认套接字路径，同样失败。`TestR4CRootLockNamespace` 在 Debian 容器里以 euid 0 再跑：两个进程的 `STATE_DIRECTORY`、`HOME`、`XDG_*` 不同，第二进程被拒绝，锁在 `/var/lib/idoris/locks`。非 root 的用户守护进程和 root 机器服务仍是不同目录。支持的部署是每个后端恰好一个控制器。一个已经是管理员的 Windows 进程可以改 `ProgramData`，把机器锁目录指到别处。

状态文件在读或写之前先拿一把跨进程锁。锁文件是状态文件规范路径加 `.lock`，持有到进程退出。同一进程里对同一路径再打开一次可以成功。另一个进程失败，错误含 `another idoris-vpnd` 和 `state file backend`。本机重新执行的子进程核实过：父进程写下退避时间，子进程打不开，文件字节不变。systemd 里的第二实例也先撞上这把锁。Windows 用 `LockFileEx`，没有在 Windows 上执行。

Windows 用 `LockFileEx`（`LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY`，`golang.org/x/sys/windows`）。第二个持有者失败，错误同样含 `another idoris-vpnd`。这套代码没有在 Windows 上执行。`GOOS=windows go build` 和 `go vet` 通过。

## 12. 限制与未决问题

- 15 秒是针对 v1.104.2 这次日志定的。若一次合法的 node key 恢复超过 15 秒仍停在 NeedsLogin，Reconciler 仍会铸一把新 key。没有把这个窗口做成配置。
- SOCKS5、TCP 转发和 `unix:` 转发在 Docker 里由 `TestWireAccessForwardsAndSOCKS5` 覆盖，见第 5 节。官方客户端的子网路由数据面、`ip_forward` 和 Headscale 批准，由 `TestGatewaySubnetRoute` 覆盖（见第 10 节）。`idoris-vpnd` 自己宣告的路由只核实了偏好被保留，没有再打一跳数据面。系统模式的 Gate 有表驱动单测，没有在 Docker 里用系统 tailscaled 再跑一遍。
- 嵌入式节点与官方客户端的 DERP / 打洞性能没有在真实 NAT 后测量。集成测试在同一个 Docker 网络里，STUN 看到的是容器地址。
- MagicDNS 只核实了短名 `acme-local-ai`。没有单独打 FQDN。
- Windows 命名管道上的 LocalAPI、macOS GUI 版与嵌入式节点并存，这次没有再测。
- iOS / Android 的单 VPN 限制没有在设备上验证。
- Windows 上的密钥文件检查、控制器锁、`LockFileEx`、`icacls` 和 `schtasks` 没有在 Windows 上跑过。Unix 的 `flock` 与 `chmod 600` 拒绝在本机（darwin）单测里通过。`GOOS=windows go vet` 通过。macOS 的 `launchctl` 没有在这台 Mac 上执行，plist 只有 golden。
- 非 root 的用户守护进程和 root 机器服务用不同的锁目录。支持的部署是每个后端恰好一个控制器。
- `SwitchProfile` 之前的再读和 LocalAPI 调用之间仍有窗口。能控制本机 tailscaled 的用户可以谎报节点和 profile。
- 状态文件锁持有到进程退出。同一进程里第二次打开同一路径可以成功。
- 失败的 Windows 重装会删掉 `C:\ProgramData\idoris`，包括上一次成功安装留在那里的文件。顺序由注入的安装器核实：先保护目录，再写密钥；缺少 `auth_key_file` 时删掉这一次的部分安装。`icacls` 本身没有执行。

## 13. 本机转发与 SOCKS5 的访问控制

日期：2026-10-27。

回环地址上的 TCP 监听（`127.0.0.1` 或 `::1`）本机任何用户都能连。转发的目标如果说 HTTP，网页还可以通过 DNS rebinding 把浏览器指到这个端口，从而借用本节点的 tailnet 身份去访问内网。监听本身不区分是哪个用户、哪个页面发起的。

因此两件事要分开做：

- 传输层收紧。优先 `unix:<绝对路径>`，套接字创建后是 `0600`，只有拥有者能连。父目录不能是全员可写。已经有进程在听的套接字不会被清掉；没人听的残留文件会删掉再监听。SOCKS5 默认要用户名和密码（RFC 1929）。用户名和密码各自必须是 1 到 255 字节（按字节，不按字符），显式配置、`socks5_auth_file` 和生成的文件都在监听打开之前检查。256 字节的密码会让 `StartAccess` 失败，并且不返回监听器。凭据放在 `0600` 的 `socks5_auth_file`，文件内容一行 `user:password`，这个路径只读取、不创建。都不给时，在 `<state_dir>/socks5.auth` 生成用户名 `idoris` 和 64 位十六进制密码，模式 0600；重启继续用同一份。创建时 info 日志和 `idoris-vpnd status` 都只出现路径。只有显式 `socks5_allow_anonymous: true` 才不认证，进程会打出警告。它和 `socks5_auth_file` 一起写是配置错误。
- 应用自己再认证一次。转到 Local AI 的流量，Local AI 应用必须自己验身份。转发和 SOCKS5 只决定谁能用这条通道，不代替应用的登录。

每个监听单独限制。`max_connections` 默认 64，满了就立刻关掉新连接，不排队。`dial_timeout` 默认 10 秒。客户端在拨号期间断开，拨号的 goroutine 会跟着结束。`Accept` 遇到暂时错误会退避重试；致命错误把该监听的 `state` 写成 `failed`，并把错误放进状态的 `error` 字段。

系统模式如果还没有连上本组织的控制面，Gate 关闭。状态是 `suspended`（`failed` 和 `closed` 优先，只改写 `listening`）。新连接马上关掉，不会向外拨号。启动时 `accessOptions` 把 `AccessOpen` 接成 Gate。嵌入式模式始终打开。系统模式只在协调器快照的 `current_control_url` 与本进程的控制 URL 被 `SameControlURL` 判成同一台（忽略大小写、末尾斜杠、默认端口；Tailscale SaaS 的同义地址也算），并且 phase 是 `connected` 或 `routes-pending-approval` 时打开。状态里的 `control_url` 永远是本进程想要的地址，不拿来做这比较。其他模式关闭。

以下取代「嵌入式模式始终打开」和「只看协调器快照」。嵌入式和系统模式都要同时满足：身份已确认，phase 是 `connected` 或 `routes-pending-approval`，并且 LocalAPI 当前的 control URL 与本进程是同一台。静态 key 在绑定写成 Static 且节点不矛盾时也算确认。发现失败时只有同一指纹、且节点不矛盾，才保持打开。Gate 自己读 prefs 和 status，缓存不超过 1 秒；读失败按关闭。一次求值记下开始时的所有权代和求值序号。代已经变了，或者有更新的求值已经发表，这次结果不缓存，也不当作允许。`TestR4CStaleOwnershipEvaluationIsDiscarded` 在 `-race` 下核实过。系统模式再对绑定里的节点 ID 和 profile ID，两边都非空且不同则关闭。

协调器在 phase、控制面、profile 或身份变化时把所有权加一代。接受连接、拨号和登记流用同一次准入代。代过期就撤掉这条流和还没返回的拨号，即使门已经用另一个身份重新打开。`TestR4CAdmissionGenerationSurvivesReopen` 在 `-race` 下核实过。旧的匿名 SOCKS 入口不再导出。包内测试仍能打开它。守护进程只调用 `StartAccess`，匿名只来自显式的 `socks5_allow_anonymous`。

已知限制：官方 GUI 和 `tailscale` CLI 仍可能在再读和 `SwitchProfile` 之间切走 profile，控制器锁排除不了它们。能控制 tailscaled 的本地用户可以谎报 LocalAPI。回环上的 TCP 转发让这台机器的每个本地用户都借用本节点身份；要收紧监听，用 `unix:`。

`tailscale.com/net/socks5` 的 `Server` 能做用户名密码，但它自己 `Accept`、用固定 5 秒和 `context.Background` 拨号、不限连接数，第一次 `Accept` 失败就退出。所以这里没有用它的 `Serve`，CONNECT 和认证是一层薄实现。

2026-10-28。共享机器的默认应是 `unix:` 监听（0600）。TCP 转发留给单用户机器。原始 TCP 没有认证，本机其他用户连上就得到这个节点的 VPN 身份；启动警告见第 5 节。SOCKS5 的 TCP 监听也打同一条警告，连上之后仍要 SOCKS 凭据。`owner_only` 的平台范围和 `/proc/net/tcp` 的核对方式也在第 5 节。本机单测看到了 TCP 警告、确认 `unix:` 不警告，并在注入的对端 uid 与本进程不同时关掉连接。
