# 13 · VPN 客户端模式：与已有 Tailscale 并存，以及办公室网关

**日期：** 2026-10-27（泰国时区）· **状态：** `vpn/` 已实现；`make test`、`make lint`（默认与 `-tags integration`）为零告警；嵌入式 Docker 集成测试与原有 `make integration` 的结果见第 10 节。本文只记录这次在 tailscale.com v1.104.2、Headscale v0.29.6、OrbStack arm64 上核实过的行为。

[docs/12](12-VPN-HEADSCALE.md) 第 4 节和 [ADR-0005](adr/0005-vpn-tailscale-client-headscale-control.md) 仍写「`takeover` 默认 true」。那两份文档这次没有改。**当前代码的默认是 false。** 以本文为准。

## 1. 三种模式

Tailscale 客户端同一时刻只能登录一个控制面。`idoris-vpnd` 因此有三种启动模式。配置键 `mode`，环境变量 `IDORIS_VPN_MODE`，flag `--mode`。缺省是 `auto`。

| 模式 | 驱动谁 | 碰不碰系统 Tailscale |
|---|---|---|
| `system` | 本机官方 `tailscaled` 的 LocalAPI。行为与 docs/12 的守护进程相同：`CheckPrefs` → `Start(AuthKey, UpdatePrefs)` → `StartLoginInteractive` | 会。`takeover: true` 时会切走已有的外网登录 |
| `embedded` | 进程内 `tailscale.com/tsnet` 用户态节点。状态目录独立（`state_dir`，默认 `~/.idoris/vpn-state`，目录模式 0700）。`tsnet.Server.LocalClient()` 返回的 `*local.Client` 满足同一个 `Backend` 接口，所以仍由同一个 Reconciler 登录 | 不碰。没有 TUN，不需要 root，不改系统 DNS |
| `auto` | 启动时只探测一次系统 tailscaled，按第 2 节的表选定上面两者之一。决定之后不再改 | 仅当决定为 `system` 时才碰 |

嵌入式节点的 hostname：配置里的 `hostname`，否则 `os.Hostname()`，再否则 `idoris-vpnd`。这个名字同时传给 tsnet 和 Reconciler。`system` 模式仍只把配置里的 hostname（可以为空）交给 Reconciler。

## 2. auto 怎么选

决定是纯函数 `DecideMode`（`vpn/internal/vpnd/mode.go`），表驱动单测覆盖。`auto` 才探测；`system` / `embedded` 不探测，配置写什么就用什么，即使当时 tailscaled 不可达。

探测只读：3 秒超时，只调 `Status`、`GetPrefs`、`ProfileStatus`。`Status` 失败（没装、没跑、套接字超时）视为不可达。`Status` 成功但 `GetPrefs` 失败，且状态是 Running / Starting / Stopped 时，control URL 记为 `unknown`，按外网登录处理，避免误切。

| 请求 | 系统 tailscaled | 当前 control URL | 其他 | 选用 | `mode_reason` |
|---|---|---|---|---|---|
| `system` | 不看 | 不看 | — | system | `configured system` |
| `embedded` | 不看 | 不看 | — | embedded | `configured embedded` |
| `auto` | 不可达 | — | 即使 `takeover: true` | embedded | `tailscaled unreachable` |
| `auto` | 可达 | 空（未登录 / 全新安装） | — | system | `system tailscaled is not logged in` |
| `auto` | 可达 | 已经是我们的 Headscale（尾斜杠按同一 URL 比较） | — | system | `system tailscaled is already on the iDoris control server` |
| `auto` | 可达 | 外网 | 任一 login profile 已指向我们的控制面 | system | `system tailscaled has an iDoris profile` |
| `auto` | 可达 | 外网，或上面的 `unknown` | `takeover` 没有被显式设为 true | embedded | `system tailscaled is logged into a foreign control server and takeover is not enabled` |
| `auto` | 可达 | 外网 | `takeover` 显式 true | system | `takeover explicitly enabled` |

外网 URL 包括 NeedsLogin 和 Stopped：profile 还在，Reconciler 若走 system 就会去切它。空 URL 才算未登录。Tailscale SaaS 的几个登录域名经 `ipn.IsLoginServerSynonym` 互相视为同一个控制面；我们自己的 Headscale URL 不允许是这些域名。

启动日志有一行 `vpn mode`，带 `mode` 和 `reason`。状态 API 同样暴露这两个字段。

## 3. takeover 默认改为 false

`TakeoverValue()` 只有在配置指针显式为 true 时返回 true。JSON 里省略、`null`、`false` 都是关闭。环境变量 `IDORIS_VPN_TAKEOVER` 接受 `1` / `true`。flag `--takeover` 与 `--no-takeover` 互斥。

因此：成员机器已经登录 Tailscale SaaS 或别的 Headscale 时，默认不再切走那个登录。`auto` 改跑嵌入式节点。若有人把 `mode` 固定成 `system` 且未打开 takeover，Reconciler 停在 `blocked-foreign-tailnet`，`last_error` 为：

```text
tailscaled is logged into <url>; takeover is disabled. Set mode: embedded to run alongside it, or takeover: true to switch this machine
```

这是相对 docs/12 第 4 节和 ADR-0005 决策 6 的行为变化。要恢复旧行为，必须显式 `takeover: true`（或 `--takeover`）。

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

`listen` 与 `socks5_listen` 必须是回环地址（与状态 API 的 `ParseListen` 同一规则），否则配置拒绝。环境变量 `IDORIS_VPN_FORWARDS` 是同一 JSON 数组。flag `--forward` 可重复，形式 `listen=target`。`--socks5-listen` 对应 `socks5_listen`。

转发是回环 TCP 监听，经一个小 `Dialer` 接口拨号：

- `embedded`：`tsnet.Server.Dial`。它会等到节点 Running，并能解析 MagicDNS。
- `system`：`&net.Dialer{}`，由内核路由把 tailnet IP 送进官方客户端。这条路径有单测（假 dialer），没有在 Docker 里再跑一遍。

SOCKS5 用同模块的 `tailscale.com/net/socks5`（BSD-3，无新许可证）。不设用户名密码，即无认证。该库把出站拨号限制在 5 秒。单测覆盖了经 SOCKS5 打到 echo 服务；Docker 集成测试没有跑 SOCKS5。

单测（假 dialer，不起 tsnet）覆盖：半关闭、大包、拨号失败、监听关闭、关闭后无 goroutine 泄漏。Docker 里的 echo 是长度前缀帧（uint32 大端 + 正文），不依赖 TCP 半关闭；半关闭只在单测里验证。

**这次 Docker 核实的转发：** `127.0.0.1:11434` → `acme-local-ai:11434`，65553 字节原样返回。对端是 tailnet 里带 `tag:acme-local-ai` 的节点，MagicDNS 后缀 `it.idoris.internal`，用的是短名，不是 FQDN。对端 tailscaled 使用内核 TUN（`NET_ADMIN` + `/dev/net/tun`），所以它在 `0.0.0.0:11434` 上的普通 TCP 监听能收到 tailnet 连接。成员容器里的系统 tailscaled 仍是 userspace，以便和嵌入式节点并存。ACL 只放行 `acme@` → `tag:acme-local-ai:11434`。

Connector / Agent24 的配置应写成 `http://127.0.0.1:8742`（或你们实际监听的端口），不要写 `http://acme-local-ai:8742`。后者只有进了 tailnet 的进程才解析得了。

## 6. 登录、状态目录、重启不铸 key

v1.104.2 上对 tsnet 的观察：

- 空状态、控制面不可达：`Server.Start` 把 ControlURL 写入 prefs，因 NeedsLogin 自己调用 `StartLoginInteractive`，并停在 NeedsLogin。Reconciler 再执行 `CheckPrefs`、`Start(AuthKey, UpdatePrefs)`、`StartLoginInteractive`。这次 `Start` 替换掉没有 key 的那次登录。
- 从未注册过的目录，重启后仍是 NeedsLogin，在 Reconciler 要求之前不铸 key。
- 已经注册过的目录，重启后会短暂报 NeedsLogin，同时 tsnet 自己用磁盘上的 node key 做 `doLogin(regen=false)`。此窗口内若 Reconciler 再 `Start(AuthKey)`，日志是 `control: client.Shutdown` 和 `register request: context canceled`，那次恢复被取消，并白白铸一把 pre-auth key。2026-10-27 第一次集成测试就是这样失败的（重启铸出 `key_id=4`）。
- LocalAPI 的 `GetPrefs` 会剥掉私钥（`ipnlocal.stripKeysFromPrefs`）。不能靠 prefs 里的 `PrivateNodeKey` 判断「已经有节点身份」。`Status.HaveNodeKey` 来自未脱敏的 profile，这才是 LocalAPI 客户端能看见的信号。
- 因此：NeedsLogin / NoState 且 `HaveNodeKey`（或进程内 prefs 里确实还有私钥）时，先等 `persistedLoginSettle`（15 秒）。第一次只计时，不铸 key。进入 Running 后清零。15 秒后仍是 NeedsLogin，才当作过期，按原顺序铸一把新 key。全新安装没有 node key，第一次就铸。
- 状态文件在 `Start` 之前不存在或为空时，才置 `LoginWhileStarting`。此时若状态是 Starting 且还没有节点身份（`Self` 为空或公钥为零，且不在登录观望期），Reconciler 铸一把 key。重启时文件已在，该标志为 false，Starting 不会铸 key。

15 秒也作用于 `system` 模式：过期节点通常仍带着 node key，所以续期会比 docs/12 写的「立即重新 enroll」多等最多 15 秒。观望期（20 秒起、翻倍、封顶 10 分钟）不变。

状态文件路径是 `<state_dir>/tailscaled.state`。删掉这个目录等于新节点，会再铸一把 key。

## 7. 网关（子网路由）

只在 `system` 模式。配置、环境变量、flag：

```json
{
  "mode": "system",
  "hostname": "office-gw",
  "advertise_tags": ["tag:acme-office-gw"],
  "advertise_routes": ["192.168.1.0/24"]
}
```

`IDORIS_VPN_ADVERTISE_ROUTES` 与 `--advertise-routes` 都是逗号分隔的 CIDR。`netip.ParsePrefix` 校验；主机位非零（如 `192.168.1.1/24`）拒绝。空列表表示不管理路由，Reconciler 不会改现有的 `AdvertiseRoutes`。

登录时写入 `prefs.AdvertiseRoutes`。运行中若实际路由与配置不一致（顺序无关），用 `EditPrefs` 且 `AdvertiseRoutesSet: true` 写回。假 Backend 单测覆盖了登录写入和漂移纠正。

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
| `forwards[]` | `forward:` 每行 `listen -> target (state)` | `listen` 是实际 `Listen` 地址（端口 0 会变成内核分配的端口）。`state` 为 `listening` |
| `socks5` | `socks5:` | `{listen, state}`。未配置时省略 |

`idoris-vpnd status` 走 `FormatStatus`，上述四项都打印。

## 9. 平台

macOS、Windows、Linux 可以同时跑官方 Tailscale 和这个嵌入式节点。嵌入式节点不占用系统 VPN 槽。

iOS / Android 同时只允许一个活动 VPN。这次没有在手机上验证。这两端仍用官方 Tailscale App 的多账号快速切换，不跑 `idoris-vpnd`。

## 10. 验证记录（2026-10-27）

单元与静态检查，在 `vpn/`：

- `make test`：`go vet ./...` 与 `go test -race -count=1 ./...` 通过。新增表：`TestDecideMode`、`TestProbeSystem`、`TestHaveNodeKeyWaitsOutBriefNeedsLogin`、`TestPersistedNodeKeyWaitsOutBriefNeedsLogin`，以及转发、SOCKS5、路由漂移、takeover 默认、状态文本。
- `golangci-lint run ./...` 与 `golangci-lint run --build-tags integration ./...` 均为 `0 issues`。

嵌入式集成测试 `TestEmbeddedAutoLeavesForeignTailscale`（`vpn/integration/embedded_test.go`，compose 项目名 `idoris-vpn-client-<pid>`，端口 `127.0.0.1::443`，证书只在 `vpn/integration/.pki-embedded/`，不入库）。通过那一次 49.20 秒，`ok`：

- 系统 tailscaled 事先 Running 在 `https://headscale-foreign`，id=1。全程保持。
- `auto` 的 `mode_reason` 为 `system tailscaled is logged into a foreign control server and takeover is not enabled`，嵌入式节点进入 `connected`，`login_attempts=1`，计数 minter 为 1（`key_id=2`），Headscale 节点 id=2。
- 转发 `127.0.0.1:11434 -> acme-local-ai:11434` 返回 65553 字节。local-ai 节点 id=1，地址 `100.64.0.1/32` 与 `fd7a:115c:a1e0::1/128`，tag `tag:acme-local-ai`。
- `ExpireNode` 后续期，仍是节点 id 2，minter 变为 2（`key_id=3`）。
- `pkill` 后用同一 `state_dir` 再启动：`login_attempts=0`，minter 仍是 2。日志行：`restart reused state; pre-auth keys minted in total: 2`。

`make integration`（`go test -tags integration -count=1 -v -timeout 10m ./...`）同一轮还跑了原有的 `TestEnrollConnectAndReauth`，34.93 秒通过。系统 tailscaled 首次注册后 `connected`，节点 `it-member`，地址 `100.64.0.1/32` 与 `fd7a:115c:a1e0::1/128`。`expire` 后续期铸了第二把 key（两次签发间隔约 24 秒，其中包含最多 15 秒的 node key 等待）。重启后总数仍是 2，没有第三把 key。整包 `ok`，80.651 秒。这一轮里嵌入式测试又通过了一次（45.24 秒），断言与上面相同。

## 11. 限制与未决问题

- 15 秒是针对 v1.104.2 这次日志定的。若一次合法的 node key 恢复超过 15 秒仍停在 NeedsLogin，Reconciler 仍会铸一把新 key。没有把这个窗口做成配置。
- SOCKS5 未在 Docker 里跑过。网关路由的数据面、`ip_forward`、Headscale 批准路由，都没有端到端测试。
- 嵌入式节点与官方客户端的 DERP / 打洞性能没有在真实 NAT 后测量。集成测试在同一个 Docker 网络里，STUN 看到的是容器地址。
- MagicDNS 只核实了短名 `acme-local-ai`。没有单独打 FQDN。
- Windows 命名管道上的 LocalAPI、macOS GUI 版与嵌入式节点并存，这次没有再测。
- iOS / Android 的单 VPN 限制没有在设备上验证。
- docs/12 与 ADR-0005 仍写 takeover 默认 true。读那些文档的人会得到旧默认值。

## 12. 本机转发与 SOCKS5 的访问控制

日期：2026-10-27。

回环地址上的 TCP 监听（`127.0.0.1` 或 `::1`）本机任何用户都能连。转发的目标如果说 HTTP，网页还可以通过 DNS rebinding 把浏览器指到这个端口，从而借用本节点的 tailnet 身份去访问内网。监听本身不区分是哪个用户、哪个页面发起的。

因此两件事要分开做：

- 传输层收紧。优先 `unix:<绝对路径>`，套接字创建后是 `0600`，只有拥有者能连。父目录不能是全员可写。已经有进程在听的套接字不会被清掉；没人听的残留文件会删掉再监听。SOCKS5 默认要用户名和密码（RFC 1929）。凭据放在 `0600` 的 `socks5_auth_file`，文件内容一行 `user:password`；或者交给状态目录，首次生成 `socks5.auth`（用户名 `idoris`，密码随机），重启继续用同一份。只有显式 `socks5_allow_anonymous: true` 才不认证，进程会打出警告。
- 应用自己再认证一次。转到 Local AI 的流量，Local AI 应用必须自己验身份。转发和 SOCKS5 只决定谁能用这条通道，不代替应用的登录。

每个监听单独限制。`max_connections` 默认 64，满了就立刻关掉新连接，不排队。`dial_timeout` 默认 10 秒。客户端在拨号期间断开，拨号的 goroutine 会跟着结束。`Accept` 遇到暂时错误会退避重试；致命错误把该监听的 `state` 写成 `failed`，并把错误放进状态的 `error` 字段。

系统模式如果还没有连上本组织的控制面，Gate 关闭。状态是 `suspended`（`failed` 和 `closed` 优先）。新连接马上拒绝，不会向外拨号。Gate 由 daemon 在启动时接上：系统模式看协调器是否已经 `connected` 且控制 URL 是我们自己的；嵌入式模式 Gate 保持打开。

`tailscale.com/net/socks5` 的 `Server` 能做用户名密码，但它自己 `Accept`、用固定 5 秒和 `context.Background` 拨号、不限连接数，第一次 `Accept` 失败就退出。所以这里没有用它的 `Serve`，CONNECT 和认证是一层薄实现。
