# 16 · 加入码与办公室网关向导

**日期：** 2026-10-28（泰国时区）。加入码与办公室网关的 Docker 证据仍是项目 `idoris-vpn-wizard-1e19b7`（办公室网 `10.211.81.0/24`，回声设备 `10.211.81.10` 与 `10.211.81.11`），`TestWizardGatewayJoin` 37s PASS。本轮补上可单独吊销的凭证标签、登记服务 `/readyz`，以及 `idoris-vpnd service install --system`。2026-10-28 又核实了 `revoke --allow-empty`、`/readyz` 的 10 秒缓存、限速桶、受保护的可执行文件副本，以及 systemd 目录。系统单元在 OrbStack 的 Debian bookworm 容器里以 systemd 为 PID 1 启动后是 `active`（见第 12 节）。`deploy/**` 不在这次改动里。

## 1. 要做成什么样

小组织的人只做一件事：把加入码交给命令（文件或标准输入），确认登记主机，再确认计划。网关多一步：这台 Linux 机器自己认出办公室网卡，给出最窄的一条路由，再确认一次。

命令在送出凭证之前先打印登记主机（`enrollment-authority: host[:port]`）。没有 `--yes` 时要回答要不要联系这台主机。`--yes` 跳过这一问，但仍打印主机。

网关码接下来才问：**这台机器就是 Local AI 吗？** 回答「是」会被拒绝：这张码的角色是 gateway，不能当成 local-ai。要加入成 Local AI，用角色就是 `local-ai` 的码。登记服务如果在 `/v1/discover` 里返回了 `role`，以它为准；它和码里的角色不一致，命令报错，不写计划。发现失败时仍用码里的角色，并在 stderr 说明发现失败。

| 回答 | 结果 |
|---|---|
| 否（AI 盒子不能装 Tailscale） | 进入网关流程：只广告指定设备的 `/32`。 |
| 是 | 报错，不写配置。码的角色必须已经是 `local-ai`。 |

整段子网是显式选项，并带冲突警告。客户端不能给自己批路由。登记服务在 `/v1/discover` 里告诉客户端组织已经预批准的 CIDR（对应服务器策略的 `autoApprovers.routes`）。计划落在这份名单里，界面写「会自动批准」；否则阶段是 `routes-pending-approval`，并给出管理员命令。

网关只在 Linux 上支持和验证。macOS / Windows 上向导说明不支持，不推荐。改系统需要 root：不是 root 时不自行提权，打印确切的 `sudo` 命令。

## 2. 四种用法

加入码里的 `role` 是 `member`、`local-ai`、`gateway` 或 `admin`。推荐把码放在文件或标准输入里。还在用位置参数时，标志必须写在码前面（Go 的 flag 在第一个非标志参数处停止）。

| 角色 | 命令 | 守护进程配置 |
|---|---|---|
| 成员 | `idoris-vpnd join --yes --code-file <path>`，或 `--code-stdin` | `mode=auto`，`accept_routes=true`，不广告路由。回环 SOCKS5 优先 `127.0.0.1:1080`，被占用则用 1081–1096 中第一个能听的端口，并写进配置 |
| 本机就是 Local AI | 加入码角色为 `local-ai`，同样用 `--code-file` 或 `--code-stdin` | `mode=auto`，不广告路由，`accept_routes=false`，记录 tag `tag:<租户>-local-ai`。不写 SOCKS5 |
| 办公室网关 | `idoris-vpnd join --yes --device <IP> --code-file <path>`，或 `gateway setup` | `mode=system`，只广告该 IP 的 `/32`，`accept_routes=false`。不写 SOCKS5 |
| 管理员 | `join --yes --code-file <path>`（角色 `admin`） | 与成员相同：接受路由，不广告，回环 SOCKS5 同样按空闲端口选择 |

位置参数 `idoris-vpnd join --yes <code>` 仍能用。stderr 会警告：别的用户可以从进程列表和 shell 历史读到这串码。`--code-file`、`--code-stdin` 和位置参数只能给一个。标准输入只读一行，后面的行仍留给确认问题。终端上什么都没给时，提示输入且不回显。

`--role-override` 可以改角色，但登记服务已经返回了角色时，覆盖值必须和它一致，否则报错、不写计划。发现没有返回角色时，覆盖仍生效。`--no-service` 只写配置、不安装用户级服务。登录前就要跑的机器服务是另一条命令，见第 12 节。`--allow-insecure` 才允许 `http://` 登记地址；默认要求 `https`。`--expect-authority host[:port]` 和码里的登记主机不一致就拒绝，并且不会去连。`--replace` 才允许把一份已经写着另一个 `enroll_url` 的配置改去登记另一台主机；同一 URL 再写一次是幂等的，不需要这个标志。`gateway setup` 和 `gateway apply` 也有 `--replace`。

网关相关命令：

```text
idoris-vpnd gateway detect [--json]
idoris-vpnd gateway setup [--yes] [--device IP]... [--whole-subnet] [--replace]
idoris-vpnd gateway apply --plan FILE [--replace]
idoris-vpnd ui [--no-open]
```

`gateway setup --yes` 的意思是：这台机器**不是** Local AI，并且已经用 `--device` 或 `--whole-subnet` 说清要广告什么。两者不能同时给。

本地页面（中文）三步：识别网络 → 使用建议 → 启用。第一问原文是「这台机器就是 Local AI 吗？」。gateway 码选「是」、local-ai 码选「否」会被 `ValidateRoleChoice` 拒绝，并且发生在 `Discover` 之前。成员码和管理员码不问这一题：页面藏起网关相关控件，直接用 `gateway.SimplePlan`（`mode=auto`，接受路由，不广告），也不要求先识别网络。登记服务在 `/v1/discover` 里返回的 `role` 若和码不一致，计划接口返回 400，不生成计划。

## 3. 加入码的生命周期

码的形状是 `idoris-join-v1.<base64url(JSON)>.<crc32 十六进制>`。JSON 只有 `v`、`enroll_url`、`token`、`role`、`tenant`、`hostname_hint`。解码拒绝未知字段、超长、截断、校验和错误，以及（没有 `--allow-insecure` 时）非 https。码里嵌着登记令牌，是秘密：命令不会把它打到日志或 stdout。

加入码证明不了签发者。HTTPS 只核对码里面写的主机名，换一串码就会换一台登记主机。码必须由本组织的管理员经可信渠道交给操作员。命令在把凭证送出去之前打印 `enrollment-authority: host[:port]`（不补默认端口）。没有 `--yes` 时还要确认联系这台主机；拒绝则什么都不写，也不会去连。`--yes` 跳过确认，但仍打印主机。`--expect-authority` 给了一个便宜的核对：和打印出来的主机不一致就失败，即使带了 `--yes`，也不会去连。

签发（stdout 只有这一行码）：

```text
idoris-vpn-enroll invite --config F --entry E --label L --enroll-url U
```

`--hostname-hint` 和 `--allow-insecure` 仍可用。`--label` 可省略。省略时，非空且能放进加入码的 hostname hint 就是标签；hint 为空时标签是 `cred-` 加该哈希的前 8 位十六进制。hint 不是主机名标签（例如含空格）时邀请失败，配置文件不改。合法标签匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`。同一条目里非空标签不能重复。

它为该条目新造一个令牌，把带标签的凭证追加进去，原子写回并保持原文件权限。条目必须已经存在。`token_hashes` 可以是空数组；字段缺失仍然报 `token_hashes is required`。明文只在这一次出现。旧文件里的纯哈希字符串仍然合法，读入后当成没有标签、没有 `created_at` 的凭证。新写入的是对象 `{hash, label, created_at}`。`created_at` 是 UTC，截到秒。`invite`、`revoke`、`list-credentials` 整段读改写都用同一把文件锁，锁文件是配置路径加上 `.lock`，模式 0600，和配置在同一目录。Unix 上是阻塞的 flock。Windows 上只创建这个文件，重叠的 invite 和 revoke 没有被挡开。

每张凭证可以单独吊销。`--label` 和 `--hash-prefix` 只能给一个：

```text
idoris-vpn-enroll revoke --config F --entry E --label L
idoris-vpn-enroll revoke --config F --entry E --hash-prefix P
idoris-vpn-enroll revoke --config F --entry E --hash-prefix P --allow-empty
```

`--hash-prefix` 是 4 到 64 位十六进制，必须恰好命中一个哈希。stdout 一行：`revoked <条目> <标签> <12 位哈希前缀>`。空标签印成 `-`。不印完整哈希，不印令牌。不带 `--allow-empty` 时拒绝删掉最后一张凭证，错误原文是 `enroll: refusing to remove the last token hash`。带上 `--allow-empty` 之后，条目留在文件里，`token_hashes` 变成空数组，文件仍能加载。这个条目上的 `/v1/enroll` 和 `/v1/discover` 对任何令牌都是 401，正文 `{"error":"invalid token"}`，和未知令牌相同，也不签发预授权密钥。

列出凭证。没有表头，制表符分隔，三列是标签、12 位哈希前缀、`created_at`。空标签或空时间是 `-`：

```text
idoris-vpn-enroll list-credentials --config F --entry E
```

过期或删除 Headscale 节点不会收回登记权：守护进程还能再要一把预授权密钥。下线顺序是：先 `revoke`，再让正在跑的 `idoris-vpn-enroll serve` 重新读配置，然后才过期或删除节点。重新读配置靠 `SIGHUP` 或重启进程；compose 把 `config.json` 按单文件绑进容器，`revoke` 的 rename 会让绑定指着旧文件，SIGHUP 在那里不可靠，所以 `ctl.sh offboard` 用重启 enroll 容器。部署侧用 `ctl.sh offboard` 把这几步包起来。

`invite` / `revoke` 只改文件，不给进程发信号。`SIGHUP` 重新读配置；新文件不合法时保留旧配置并写日志。重载成功时 info 日志有 `size`、`mtime`（UTC）和 `credentials`（这次读入的凭证张数），不写令牌。吊销过的凭证在这次重载之后不能再登记。请求体读完之后还会再对当前配置核一次这张凭证；核不上就是和未知令牌一样的 401，也不扣该条目的登记桶、不签发密钥。`/v1/discover` 返回 `tenant`、`role` 和 `lan_cidrs`，不签发密钥。

扫令牌哈希之前有两道限速，`/v1/enroll` 和 `/v1/discover` 都走：`global_rate_per_minute` 默认每分钟 600，`per_ip_rate_per_minute` 默认每分钟 60。两道在同一把锁里一起判断：来源自己的桶已经空了，就不扣全局桶；全局桶已经空了，也不为这个新来源建桶。来源桶空闲 10 分钟删掉，最多留 4096 个。租户桶和全局桶不在这批淘汰里。IPv6 按 /64 共用一个来源桶，IPv4 仍是一个地址一个桶。通过认证之后，成功登记按条目另有一桶，`rate_per_minute` 默认 30；`/v1/discover` 再用同一默认值、但是分开的桶。`/healthz` 和 `/readyz` 不限速。`trusted_proxies` 是 CIDR 列表。只有 TCP 对端落在这份名单里才读 `X-Forwarded-For`，取最右边一个不在名单里的地址。对端不受信任时用 TCP 对端，伪造的头选不了桶。失败认证的日志每 10 秒最多一行。成功登记的审计行有 `remote`（只有 IP，没有端口）和凭证 `label`（空标签记成 `-`）。

`/readyz` 用一次带认证的便宜调用检查 Headscale 是否可达、API 密钥是否仍被接受。成功和失败的结果都缓存 10 秒。同一时刻只有一个刷新在跑，最多 32 个请求等这次结果；再多的请求不再另开探测。Headscale v0.29.6 的 `GET /api/v1/apikey` 只返回密钥前缀和 `expiration`（null 表示未知）。命中本密钥且带过期时间时，响应有 `api_key_expires_at`。剩余时间不足 30 天：HTTP 200，`status` 为 `warning`，`warning` 为 `api key expires in less than 30 days`。刚好 30 天不算警告，但仍带过期时间。已经过期、不可达，或密钥被拒（401/403），是 503。密钥列表 404 时改用列出用户：密钥有效，过期时间未知，这时 200 且 `status` 为 `ok`，没有过期字段。没有配置探针时立刻 503，这句话不进缓存。失败原因是固定短语（`api key rejected`、`headscale HTTP N`、`unreachable`、`api key expired`），不回传上游正文。登记服务的 `/healthz` 仍是正文 `ok` 加换行，不探 Headscale。守护进程自己的 `/healthz` 见第 7 节，那是另一条路径。

登记客户端和 Headscale API 客户端都不跟随重定向。对端把请求转到 `http://` 或另一台主机时，调用失败，bearer token 不会被送出去。

## 4. 网关计划：只广告 /32

检测只看一份快照：接口已启动、非回环、RFC1918 的 IPv4。排除 CGNAT `100.64.0.0/10`（tailnet）、`tailscale*` / `utun*`，以及 `docker0`、`br-*`、`veth*`、`virbr*`、`vmnet*`、`cni*`、`flannel*`。标出默认路由所在的网卡和网关。

候选网段和最终要广告的前缀必须整段落在 RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）里面。只看地址、不看掩码是不够的：`10.1.2.3/1` 掩完是 `0.0.0.0/1`，会被丢掉。`10.0.0.0/8` 整段都在 10/8 里，可以当候选。设备地址单独检查，不因为被一个过大的前缀罩住就放行。公网地址、链路本地和上面的 CGNAT 都不是办公室设备。

默认路由的目标必须是 `0.0.0.0/0`（掩码为 0）。OpenVPN 那种 `0.0.0.0/1` 不算默认路由，不会拿来推荐办公室网。隧道接口（名字以 `tun`、`utun`、`wg`、`tailscale`、`ppp`、`ipsec` 开头，以及点对点标志）排除在局域网候选之外。名字既不像已知局域网前缀、也不是隧道时，候选标成不确定，不当推荐；对它使用整段子网会报错，要改成设备地址。Linux 的 `ip route` 和 macOS 的 `netstat -rn` 用同一条规则读表。采集本身仍读 `/proc/net/route`，并且要求掩码字段是 0。

默认计划是设备 IP 的 `/32`。整段子网要显式打开，并警告这些常见家庭网段（广告整段会挡住成员家里的同网段）：

- `192.168.0.0/24`、`192.168.1.0/24`、`192.168.2.0/24`
- `10.0.0.0/24`、`10.0.1.0/24`
- `172.16.0.0/24`、`172.16.1.0/24`

`/32` 只挡住一个地址。不会扫描整段子网。可达性探测只对用户给出的一个 IPv4 做 TCP 拨号，端口 `11434`、`8740`、`8742`、`443`、`80`，每个 1 秒。

检查项：平台是 Linux、`ip_forward`、`/dev/net/tun`、root、`tailscaled` 可达、模式必须是 `system`（嵌入式节点不能当网关）。

令牌和计划跟配置走。相对的 `--config` 先变成绝对路径，再派生旁边的文件；写进计划 JSON 的也是这条绝对路径。只有没写 `--config`、要用默认路径时才需要家目录。默认的 `~/.idoris/vpn.json`（路径以 `/.idoris/vpn.json` 结尾的也算）的计划文件仍是同目录的 `gateway-plan.json`。它的令牌不用历史上的 `enroll.token`，而用和其它配置同一条规则：`<文件名>.enroll-token`，也就是 `vpn.json.enroll-token`。其它配置用同一目录下、保留完整文件名（含后缀）的 `<文件名>.enroll-token` 和 `<文件名>.gateway-plan.json`，所以 `office.json` 和 `office.conf` 不会共用令牌。应用前扫描所选配置所在目录里的其它 `*.json`。另一份已经存在的配置如果在 `enroll_token_file` 里指向即将写入的路径（绝对路径，或相对该配置自己目录的路径），这个路径只读，新令牌改写到所选配置自己的 sidecar，并且只改所选配置。计划 JSON 里的 `token_file` 不算共享。目录不存在就当作没有旁路配置。空文件跳过。不是 JSON 对象的 `*.json` 直接报错，错误里有文件名，不写任何文件。若另一份已有配置已经指向自己这份 sidecar，拒绝写入，错误以 `gateway: refusing to write` 开头，并列出路径和那些配置。两种迁移顺序都测过：先写默认配置，以及先写另一份配置再写默认配置。遗留的 `enroll.token` 设成 `0444` 后内容和模式都不变。这一条没有在 Windows 上执行。

应用是读改写。向导拥有的键是 `enroll_url`、`enroll_token_file`、`enroll_allow_insecure`、`hostname`、`accept_routes`、`advertise_tags`、`mode`、`role`、`listen`、`advertise_routes`。`enroll_token` 和 `enroll_token_file` 是同一个设置：装上令牌文件就去掉内联 `enroll_token`。配置里已经有 `auth_key_file` 时，内联 `auth_key` 同样去掉。已有的 `accept_dns`、`tailscale_socket`、`state_dir`、`forwards`、`takeover` 留下。`control_url` 在登记主机没变时留下；`--replace` 换了登记主机时删掉。计划警告原文是 `replacing the enrollment authority removes the previous control server pin; the next start discovers the new server and pins it; the old pin is not kept`。下一次启动发现新服务器并钉住它。计划里的 `discovery_control_url` 是确认登记服务器之后发现到的控制地址，不是秘密。删钉之后 Apply 的结果仍带这个地址、`tenant`，以及刚写入令牌的 `token_fingerprint`（短指纹，不是令牌）；写入配置的 `control_url` 为空。命令行不因此多打一行 `control:`，stdout 仍只在写入的 `control_url` 非空时打印它。不认识的键在写任何文件、安装任何服务之前拒绝，错误列出键名，以 `gateway: config has unsupported keys:` 开头。校验把这份字节交给 `vpnd.LoadConfig`（`DisallowUnknownFields`）。同一 `enroll_url` 再应用一次，配置字节不变。`enroll_url` 不同则拒绝，除非 `--replace`。文件用临时文件加 rename 写成 0600，不跟随已有的符号链接。`.idoris` 目录若已经是组或其它人可写，则拒绝，而不是把它 chmod 成 0700。Windows 上，私有目录和临时秘密文件在写入任何秘密字节之前先设当前用户的 DACL（`icacls` 重置、关掉继承、按该用户 SID 授予完全控制）。已有目录的 ACE 必须只属于该用户、SYSTEM 或 Administrators。命令顺序用注入的运行器测过。没有在真实 Windows 上执行 `icacls`。

成员和管理员在 `mode` 为 `auto`、`embedded` 或空时，若配置里还没有 `socks5_listen`，先试听 `127.0.0.1:1080`，被占用就继续到 1096，把选中的地址写进配置和 `access:`。不写 `socks5_allow_anonymous`。凭据路径：已有 `socks5_auth_file` 就用它；否则是显式 `state_dir` 下的 `socks5.auth`，再否则是 `$STATE_DIRECTORY/node/socks5.auth`，再否则是 `~/.idoris/vpn-state/socks5.auth`。配置放在 `.idoris` 下面也不改变这个顺序。单元测试设 `STATE_DIRECTORY=/var/lib/idoris`、配置为 `/root/.idoris/vpn.json`，`access:` 给出 `/var/lib/idoris/node/socks5.auth`。显式 `system` 不添加 SOCKS。local-ai 和网关不添加。成功时 stdout 有 `access:` 行：SOCKS5 地址、凭据文件路径（不是内容）、以及 MagicDNS 名 `<local-ai-hostname>.idoris.internal`（向导不知道那台机器的主机名）。本轮没有把这个代理真正连到一台 Local AI 上。文件写完并安装服务之后，stdout 还有 `identity: role=… hostname=… enroll=…`；装了服务时另有 `service: installed`，这三样是刚写进去的身份。

应用时写入配置和模式 `0600` 的令牌文件；计划 JSON 本身不含令牌。Linux 上且是 root 时，写 `/etc/sysctl.d/99-idoris-vpn.conf` 并尝试打开转发。`/proc/sys/net/ipv4/ip_forward` 已经是 `1` 就算成功，即使 `sysctl -w` 失败。不是 root 时，其余文件照写，并打印。计划路径用 POSIX 单引号，`$(id)`、反引号、空格、引号和换行都按字面处理：

```text
sudo idoris-vpnd gateway apply --plan <计划文件>
```

`join` 和 `gateway apply` 在没有 `--no-service` 时仍安装用户级服务（systemd `--user` / LaunchAgent），不会改成系统级单元。登录前就要跑，另执行第 12 节的 `service install --system`。安装发生在配置和令牌写完之后。向导自己提权的只有 `ip_forward` 这一步。

以 root 跑 `sudo idoris-vpnd gateway apply` 只做这一步：计划要开转发并且是 Linux 时调用 `EnableIPForward`。它不创建目录、不改用户的配置和令牌、不安装服务。计划文件必须是普通文件、不是符号链接、权限不宽于 0600、所在目录不能被组或其它人写，属主是 root，或者进程是 root 且属主等于 `SUDO_UID`。不要求用户的 `.idoris` 属主是 root。`SUDO_UID` 只在进程是 root 时才认。Docker 里用 uid 1000 建文件、再以 root 跑通过；属主不对、符号链接和 0666 会拒绝。没有在 Windows 上跑这条路径。

## 5. 预批准名单必须和策略逐条对齐

登记条目的 `lan_cidrs` 是客户端用来判断「会自动批准」的名单。Headscale 真正批准路由的是策略里的 `autoApprovers.routes`。两边要写**同一组前缀**。本轮 Docker 验证的是：键就是被广告的那条 `/32`，值是 `tag:wiz-gateway`。更宽的前缀能否自动批准它里面的 `/32`，这次没有测；不要假设。

节点要能在自己的状态里看到「已批准」，策略还必须让这个节点访问该前缀。Headscale v0.29.6 在构造 self 节点时用 `ReduceRoutes`：节点访问不了该前缀，`Status.Self.PrimaryRoutes` 就是空的。守护进程只看这一处（tailscale.com v1.104.2 把 `PrimaryRoutes` 和 `AllowedIPs` 抄到 Self）。实验室里曾经出现过：Headscale 日志已经是 `routes approved`，状态接口仍是 `routes-pending-approval`。把 `tag:wiz-gateway` 加进 ACL 的 `src` 之后，self 才能看到批准，阶段才变成 `connected`。

因此网关策略至少要有：

```hujson
{
  "tagOwners": {
    "tag:acme-gateway": ["group:admins"]
  },
  "autoApprovers": {
    "routes": {
      "192.168.50.10/32": ["tag:acme-gateway"]
    }
  },
  "acls": [
    {
      "action": "accept",
      "src": ["acme@", "tag:acme-gateway"],
      "dst": ["192.168.50.10/32:8740"]
    }
  ]
}
```

`acme@` 是成员，用来真正访问设备。`tag:acme-gateway` 在 `src` 里，是为了让网关节点自己的 netmap 带上已批准的路由。只写成员、不写网关 tag，路由可以在服务器上是批准的，向导仍会停在等待批准。

## 6. 标签从预授权密钥来，不从客户端请求来

Headscale v0.29.6 在 `createAndSaveNewNode` 里无条件拒绝「带预授权密钥、又在 hostinfo 里请求 tag」的注册，错误原文是 `requested tags [...] are invalid or not permitted`。把租户用户加进 `tagOwners` 不能绕过（本轮试过，错误不变）。`tailscale up --auth-key` 不传 `--advertise-tags` 时，标签只来自密钥上的 `acl_tags`，这和 `docs/15` 的实验室一致。

所以 `idoris-vpnd` 登录时**不发送** `AdvertiseTags`。配置里的 `advertise_tags` 仍会写上，作为操作员记录（网关是 `tag:<租户>-gateway`，Local AI 是 `tag:<租户>-local-ai`），但不会进登录偏好。节点上的 tag 来自登记条目的 `acl_tags`，登记服务把它们放进铸出的预授权密钥。`tagOwners` 仍要声明这些 tag（实验室里所有者是 `group:admins`，策略检查通过）；它管的是别人用 `--advertise-tags` 自助申请，不管预授权密钥。

## 7. 等待管理员批准

未批准时节点保持 Tailscale `Running`。状态 API 的 `phase` 是 `routes-pending-approval`，`routes` 为 `[{cidr, advertised:true, approved:false}]`，`admin_hint` 类似：

```text
headscale nodes approve-routes --identifier <ID> --routes 10.211.81.11/32  # <ID> is the numeric id of wiz-gw-wait from `headscale nodes list`
```

守护进程的 `/healthz` 在此阶段返回 **503**，正文是阶段名。只有 `connected` 才是 200 和 `ok`。这和登记服务的 `/healthz`、`/readyz` 不是同一个端口：登记服务是否连得上 Headscale，看第 3 节的 `/readyz`。

Headscale v0.29.6 的 `--identifier` 是数字节点 id。主机名会被拒绝，实测：

```text
Error: invalid argument "wiz-gw-wait" for "-i, --identifier" flag: strconv.ParseUint: parsing "wiz-gw-wait": invalid syntax
```

同一条路由用 `--identifier 3` 批准后，成员才能连上。提示里的主机名只用来在 `headscale nodes list` 里对行。

## 8. 实验室里实际发生的事

拓扑：Headscale v0.29.6 同时挂在办公室网和家庭网；两台 Linux 网关和两台非 Tailscale 的 TCP 回声（端口 8740）在办公室网；成员在另一座桥上，并用 iptables 丢掉办公室前缀、只留 `tailscale0`。登记服务跑在测试进程里，容器通过 `host.docker.internal` 访问。邀请用宿主机上的 `idoris-vpn-enroll invite`。

`policy check` 的输出是 `Policy is valid`。预批准的那条 `/32` 同时写进登记条目的 `lan_cidrs` 和 `autoApprovers.routes`。

已核对的结果（`make integration-wizard`，项目 `idoris-vpn-wizard-1e19b7`）：

- 网关在加入前就能在办公室网卡上 `nc` 到 `10.211.81.10:8740`，返回 `ok`。
- 检测只推荐办公室 CIDR（`10.211.81.0/24`）和它的网关；计划里的路由只有 `10.211.81.10/32`，stdout 写 `auto-approve: yes`、`role: gateway`、`ip-forward: enabled`。写出的 `vpn.json` 没有明文令牌，也没有办公室 `/24`。
- 没有执行 `approve-routes`。Headscale 节点 id 2 的该 `/32` 已批准。状态阶段 `connected`，`/healthz` 为 200。带 `--accept-routes` 的成员经 `tailscale0` 访问该回声，返回 `ok`。
- 另一台网关广告 `10.211.81.11/32`（不在 `autoApprovers` 里）。加入时 stdout 为 `auto-approve: no`。状态阶段 `routes-pending-approval`，`approved=false`，后端仍是 `Running`，`/healthz` 为 503 且正文含该阶段名。此时成员 `nc` 失败。用数字 id 批准之后，状态变为 `connected`，成员 `nc` 返回 `ok`。

容器入口脚本里的 `sysctl -w net.ipv4.ip_forward=1` 在这台 OrbStack 上是 `Read-only file system`。向导仍打印 `ip-forward: enabled`：`/proc` 里已经是 `1` 时，守护进程把这一步当作成功。

2026-10-28 早先一轮 `make integration` 全绿（286s，项目 `idoris-vpn-r3w2-wizard-c11edc`）。那一轮旁路断言里「未知键 `extra_kept` 会留下」和「`--replace` 后 `control_url` 仍是 `https://headscale`」已经不是现在的行为。当前用例期待：种子没有未知键；第一次加入（种子有 `control_url`、没有 `enroll_url`）仍留下 `control_url`；换成 `http://attacker.invalid:9` 时不带 `--replace` 失败且文件不变，带 `--replace` 后配置里没有 `control_url`，stdout 有上面那句删钉警告；令牌文件是 `keep.json.enroll-token` 和 `member.json.enroll-token`。成员码在容器 `HOME=/root` 且没有 `STATE_DIRECTORY` 时，SOCKS 仍是 `127.0.0.1:1080`（端口空闲），凭据路径是 `/root/.idoris/vpn-state/socks5.auth`。2026-10-28 本轮 `make integration` 全绿（`ok .../integration` 334.718s）。向导项目 `idoris-vpn-r3w2-wizard-7aac60`，`TestWizardGatewayJoin` 38.19s PASS，旁路日志是 `EVIDENCE first join kept control_url; --replace dropped it; member SOCKS5 default written`。`TestR4WSudoApplyHonoursUserOwnedPlan` 2.58s PASS，输出含 `R4W_HANDOFF_OK`。

## 9. 本地页面的安全模型

`idoris-vpnd ui` 只听 `127.0.0.1` 的随机端口。页面本身是静态的，HTML / JS / CSS 里没有秘密。自动打开时，先在用户缓存目录下的 `idoris/ui-launch`（目录 `0700`）写一个 `0600` 的启动页，该页向 `http://127.0.0.1:端口/bootstrap` 用 POST 提交一次性引导秘密。macOS 用 `open`，Linux 用 `xdg-open`，Windows 用 `rundll32 url.dll,FileProtocolHandler`。参数只有这个文件路径，没有秘密，也没有页面 URL。打开程序最多等 3 秒，不能把 `Start` 返回当成成功。退出码 0，或者超过 3 秒仍在跑，都当作已经启动，不杀掉那个进程（它可能就是浏览器）。退出码非 0，或者进程起不来，stdout 改为说明要自己用浏览器打开这个文件（它会登录再进入页面；只打开页面 URL 不能登录），并给出文件路径。只要当作已经启动，stderr 另有一行 `If the browser did not open, open this file:` 加上该启动页路径，这样 `xdg-open` 没有真正打开窗口时仍留着手动入口。成功时 stdout 仍只是不带秘密的页面 URL。用假的打开程序测过：退出码 0、退出码 1、挂起超过等待时间、以及找不到程序。挂起那条没有在 Windows 上跑。没有在真实图形浏览器里打开。`--no-open` 不启动浏览器，stdout 打出的 URL 把引导秘密放在片段 `#k=` 里（浏览器不会把片段发给服务器）。`app.js` 读到片段后向 `/api/bootstrap` POST 一次，再用 `history.replaceState` 清掉片段。成功交换后，引导秘密作废，启动页在交换成功时和进程退出时删除。Windows 的参数在 macOS 上用注入的 `GOOS=windows` 核对过。没有在真实 Windows 上打开浏览器。

引导秘密两分钟过期，且只能用一次。换到的会话能力放在 `sessionStorage`（按源隔离，包含端口），之后每个 API 请求带请求头 `X-Idoris-UI`。CSRF 令牌同一次交换发出，放在 `sessionStorage`，不写进 HTML。响应不设 cookie。查询参数 `?k=` 和 cookie 都不参与认证，所以旧的 `idoris_ui` cookie 既不能登录，也不会让下一次启动的正确引导失败。另一个听在 `127.0.0.1` 上的服务器收不到这个会话能力。

保存加入码只解码，不联系登记服务，并清掉勾选。页面显示登记 URL 的 `host[:port]`，并写明加入码不能证明签发者，必须来自组织管理员、经用户信任的渠道。确认要同时带上勾选、当时显示的登记主机，以及这次加入的 `join_rev`。未勾选，或主机、版本对不上时，「使用建议」和「启用」都被拒绝，`Discover` 不会发出。计划绑定它生成时的加入码版本和检测版本；加入码、检测、答案或角色再变，旧计划作废。第二次并发的「启用」被拒绝。gateway 与 local-ai 的答案和码不一致时，页面在 `Discover` 之前拿到 `gateway.ValidateRoleChoice` 的原文。发现返回的角色和码不一致时，计划接口 400。成员和管理员走 `SimplePlan`。配置路径用 `gateway.PathsFor(home, "")` 的默认名。「替换另一组织的现有配置」默认不勾；勾选才把 `replace_existing` 交给 `Apply`。换了登记主机时，计划带上删掉控制服务器钉的警告。`Apply` 的错误原文放在响应的 `error` 里，成功时响应带上 `AccessInfo`（若有）以及刚写入的 `role`、`hostname`、`enroll_url`，还有 `discovery_control_url`、`tenant` 和 `token_fingerprint`。页面用 `discovery_control_url`，没有它才用写入的 `control_url`，和 `role` 一起等守护进程状态对上，才把已连接或等待批准当成完成。删钉后写入的 `control_url` 为空，页面仍显示并等待发现到的那台控制服务器。状态对象里已经有非空的 `tenant` 或 `token_fingerprint` 时，这两项也要对上；今天的 `/v1/status` 只有 `control_url` 和 `role`，没有这两项。同角色替换、旧守护进程仍连着上一台控制服务器时，回环上的 HTTP 测试和 Node 冒烟都不把它当成完成。脚本没有在图形浏览器里点过。不是 root 时，「启用」返回 `sudo` 命令，不提权。

这些由真实回环监听上的 `net/http` 客户端（带 cookie jar）测过，`app.js` 的引导交换另有 Node 假 `fetch` / `sessionStorage` 冒烟。没有在图形浏览器里点过。

| 约束 | 行为 |
|---|---|
| Host | 必须等于绑定的 `127.0.0.1:端口`，挡 DNS 重绑定 |
| 引导秘密 | 只在启动页的 POST 正文，或手开 URL 的 `#k=` 片段里。两分钟、一次。不进 argv，不进 cookie，查询参数 `?k=` 无效 |
| 会话 | 头 `X-Idoris-UI`。没有这个头，或值不对，API 为 401。静态页 `GET /`、`/app.js`、`/app.css` 只查 Host，正文没有秘密 |
| 改状态的 POST | 引导交换之外：要有 `Origin: http://<绑定地址>` 或 `Sec-Fetch-Site: same-origin`（两个都缺则拒绝），再加 `X-CSRF-Token`。来源不对不会消耗引导秘密 |
| 缓存与 CSP | `Cache-Control: no-store`。CSP 为 `default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`。页面没有外链 |
| 请求体 | 超过 64KiB 拒绝 |
| 空闲 | 默认 15 分钟。计时只在成功的引导交换和已通过会话头的请求上更新 |
| 会话用户 | Linux 上若 `/proc/self/loginuid` 是别的用户，拒绝启动。读不到或是 `4294967295` 则放行 |
| 加入码 | 只留在该进程的内存里，响应不回显令牌。未确认登记服务器之前不发送凭证 |

加入码在页面里填写。页面不提示把加入码贴到命令行。

## 10. 部署侧要补的改动（本轮没有改 `deploy/`）

登记配置由 `deploy/vpn/bootstrap.sh` 写入 `enroll/config.json`。部署侧的 `ctl.sh token new|list|revoke` 和 `ctl.sh offboard` 已按第 3 节的顺序包好：`revoke`，重新加载（compose 里是重启 enroll 容器），再过期或删除节点。只删节点，凭证还在。

建议部署侧保持这些，而不是改客户端：

1. `ctl.sh` 在 enroll 容器里执行下面的 CLI，不要再包一层会把加入码写进日志的 echo。写完文件后让 enroll 重新读配置（裸进程发 `SIGHUP`；compose 部署里重启容器）。邀请、吊销、列出凭证的参数是：

```text
idoris-vpn-enroll invite --config F --entry E --label L --enroll-url U
idoris-vpn-enroll revoke --config F --entry E --label L
idoris-vpn-enroll revoke --config F --entry E --hash-prefix P
idoris-vpn-enroll list-credentials --config F --entry E
```

`--label` 与 `--hash-prefix` 互斥。`list-credentials` 只有标签、12 位哈希前缀和 `created_at`。

2. 网关条目增加 `role: "gateway"`、`lan_cidrs`（与下面的前缀逐条相同）、`acl_tags: ["tag:<租户>-gateway"]`。Local AI 条目保持 `acl_tags: ["tag:<租户>-local-ai"]`，并写上 `role: "local-ai"`。
3. 策略里为 `tag:<租户>-gateway` 增加 `tagOwners`（实验室用 `group:admins`）、`autoApprovers.routes` 的**精确前缀**，以及第 5 节那种同时包含租户用户和网关 tag 的 ACL。改完后 `headscale policy check`，再 `SIGHUP`。`policy.mode: file` 时 Headplane 的 ACL 页是只读的。
4. 不要让客户端在登录时带 `--advertise-tags`。标签放在登记条目的 `acl_tags` 上。

## 11. 边界

- 加入码放在命令参数里时，进程列表和 shell 历史能读到它。文档上的入口是 `--code-file`、`--code-stdin`，或终端上什么都没给时的不回显提示。位置参数仍接受，并在 stderr 警告。`join` 的 usage 文本在 `main.go`，本轮没有改那个文件。
- 加入码不证明登记主机属于本组织。核对打印出来的 `enrollment-authority`，或传 `--expect-authority`。
- 换一份配置的登记 URL 要 `--replace`。不带它时，原文件不动。
- 同一台 Headscale（相同 `control_url`）、相同角色、不同租户时，页面仍会把正在运行的旧守护进程当成完成。本轮没有改守护进程的状态快照；快照没有 `tenant`，也没有 `token_fingerprint`。
- 成员和管理员的 auto/embedded 配置默认有回环 SOCKS5。网关和 local-ai 没有。2026-10-28 `TestR5WWizardMemberSOCKS`（compose 项目 `idoris-vpn-r5w-64f1d4e0`，15.60s PASS）把向导的 `SimplePlan` / `Apply` 写出的成员配置跑了起来。登记令牌来自宿主机 `idoris-vpn-enroll invite`，条目是租户 `acme`、角色 member、没有 ACL 标签。计划把 `mode` 写成 `embedded`：这套夹具里的 userspace tailscaled 已经在跑且未登录，auto 会选 system。`listen` 写成 `tcp:127.0.0.1:7845`，因为空的 listen 在设了 `HOME` 时变成 unix socket，状态探针读不到。种子配置留下 `state_dir` `/var/lib/idoris/vpn-state`。容器里 `idoris-vpnd run --config` 到达 `connected`，模式 `embedded`，SOCKS5 为 `listening`。`AccessInfo` 给出 `127.0.0.1:1080` 和凭据文件 `/var/lib/idoris/vpn-state/socks5.auth`。匿名连接被拒绝。用该凭据经 SOCKS5 访问 Local AI 节点 `acme-local-ai:11434` 的回声（1024 字节），输出含 `echoed`。没有在宿主机上另起一条 tailnet。同一用例再跑一次：项目 `idoris-vpn-r5w-5b47384e`，15.64s PASS。这两次都是单独跑的，全套 `make integration` 的计时仍以第 8 节为准。
- 不是整段落在 RFC1918 里的前缀不会被广告。默认路由必须是 /0。隧道网卡不当办公室网。
- 客户端不能批准自己的路由。
- 空的 ControlURL 加上已登录状态（`Running` / `Starting` / `Stopped`）视为别人的 Tailscale SaaS，自动模式不接管。`NeedsMachineAuth` 加空 URL 仍当作全新安装。
- 不带 `--allow-empty` 时，吊销不能删掉条目的最后一张凭证。带上之后条目还在，但没有任何凭证。过期或删除节点不会吊销凭证。
- 守护进程的 `/healthz` 在等待批准时是 503。登记服务的 `/healthz` 不探 Headscale；那要看 `/readyz`。
- 嵌入式模式不能当网关。macOS / Windows 不推荐网关；本轮没有在那两个系统上跑网关。
- `join` 默认安装的是用户级服务，登录前不跑。开机即跑用第 12 节的 `--system`。
- 本地页面已不使用 cookie，认证方式见第 9 节；回环地址上的页面也不使用 HTTPS。gateway 与 local-ai 的页面答案必须和码一致。登记服务返回了角色时以它为准，和码不一致就拒绝。成员和管理员不回答网关问题。
- 更宽的 `autoApprovers` 前缀是否覆盖更窄的 `/32`，本轮没有验证。
- 没有在图形浏览器里点本地页面。没有在真实 Windows 上执行 `icacls`，也没有在真实 Windows 上打开浏览器。
- 第 8 节开头那些 `10.211.81.*` 的数字来自项目 `idoris-vpn-wizard-1e19b7`。本轮没有另起同名 compose 项目重跑那一次。本轮全套 `make integration` 是项目 `idoris-vpn-r3w2-wizard-7aac60`。

## 12. 机器服务：`service install --system`

不带 `--system` 时，`service install --config FILE` 仍是用户级。Linux 写 `~/.config/systemd/user/idoris-vpnd.service`（`NoNewPrivileges=yes`，`WantedBy=default.target`）。macOS 写当前用户的 LaunchAgent，标签 `ai.idoris.vpnd`。装完打印：用户级服务在这个用户登录之前不会跑；Linux 上同一句后面是 `loginctl enable-linger`。Windows 上不带 `--system` 的安装仍不支持。`join` 和 `gateway apply` 走的也是这套用户级安装，不会偷偷加上 `--system`。

用户级单元已经在跑时，重装要换掉正在跑的进程。Linux 写完单元后执行 `systemctl --user is-active idoris-vpnd.service`。退出码是 0 且标准输出去掉空白后恰好是 `active` 才算在跑；探测失败，包括连不上用户总线，当成没在跑。在跑则先 `systemctl --user daemon-reload`，再 `systemctl --user restart`。第一次安装是 `daemon-reload` 然后 `enable --now`。macOS 用 `launchctl print gui/<uid>/ai.idoris.vpnd` 判断是否已加载。已加载则 `bootout gui/<uid>/ai.idoris.vpnd`（这一步失败就返回）、`bootstrap gui/<uid>`、`kickstart -k gui/<uid>/ai.idoris.vpnd`。第一次只 `bootstrap`。打印分别是 `restarted` 和 `installed and started`。`installUserService` 把这次动作返回成 `started` 或 `restarted`。向导仍调用只返回 error 的 `installService`，还没改用这个返回值。命令顺序由注入的运行器核实，覆盖第一次安装和已经 active 的重装。同一套特权 bookworm 容器里没有 `/run/dbus`，`systemctl start user@<uid>` 的依赖作业失败，`loginctl enable-linger` 报 `Failed to connect to bus`，所以没有跑到真实的用户服务 PID 变化。`TestR5CSystemdUserServiceRestarts` 因此跳过。2026-10-28 这一轮 `make integration` 里它跳过 28.78s，日志仍是没有 `/run/dbus`、`user@1000.service` 依赖失败，以及 `Failed to connect to bus`。`launchctl` 没有在这台 Mac 上执行。

系统级：

```text
idoris-vpnd service install --system --config FILE
idoris-vpnd service uninstall --system
```

Unix 上不是 root 就失败，原文 `service install --system must run as root; re-run with sudo`，此时还没有写文件。系统单元还启用着的时候，再装用户级会被拒绝：Linux 看 `systemctl is-enabled idoris-vpnd.service` 是不是 `enabled`，macOS 看 `/Library/LaunchDaemons/ai.idoris.vpnd.plist` 在不在。

系统级安装不把当前可执行文件的路径写进 root 或 SYSTEM 的服务。它先复制一份。Linux 仍是 `/usr/local/lib/idoris/idoris-vpnd`，但复制之前会检查这条路径上每一个已经存在的祖先：必须是 root 拥有的目录，不能是符号链接，也不能被 group 或 other 写。有一环不合格就失败，错误点名那一环。macOS 上 Intel Homebrew 的 `/usr/local` 往往属于用户，所以机器服务改放到 `/Library/PrivilegedHelperTools/idoris/idoris-vpnd`。Windows 是 `%ProgramFiles%\iDoris\idoris-vpnd.exe`，`ProgramFiles` 为空时用 `C:\Program Files`；祖先检查在 Windows 上是空操作。目录和文件 0755，属主设为 root。单元、plist、计划任务都指向这份副本。卸载删掉副本，不删目录。用户级安装仍用当前可执行文件，不复制，也不做祖先检查。复制拒绝符号链接源，并用临时文件 rename 盖掉目标上预先放好的符号链接。单测在临时目录里核过模式、内容和符号链接祖先；属主和 group 可写这两环在 Debian 容器的 root 里核实过（`TestR4CServiceRootProofs`）。chown 在本机 Mac 的单测里被替换掉了。

Linux 单元是 `/etc/systemd/system/idoris-vpnd.service`，模式 0600。配置复制到 `/etc/idoris/vpn.json`（0600）。目录 `/etc/idoris` 是 0750。`enroll_token_file`、`auth_key_file`、`socks5_auth_file` 先按 docs/13 的 sudo 规则检查，再复制到 `/var/lib/idoris` 下的 `enroll_token`、`auth_key`、`socks5.auth`（0600，属主 root），装进去的 JSON 改指这些副本。没有这些字段时配置字节保持原样。安装程序不改配置里的 `state_dir`，也不设置 `IDORIS_VPN_STATE_DIR`。机器服务没有 `$HOME`，所以缺省位置不看家目录：显式配置、flag、`IDORIS_VPN_*` 优先；否则用 systemd 因 `StateDirectory=idoris` 导出的 `STATE_DIRECTORY`（`/var/lib/idoris`），状态文件是 `$STATE_DIRECTORY/vpnd-state.json`，嵌入式节点目录是 `$STATE_DIRECTORY/node`。root 的控制器锁固定在 `/var/lib/idoris/locks`，不看 `STATE_DIRECTORY`。`STATE_DIRECTORY` 不是绝对路径时，非 root 启动会报错并点名这个变量；root 忽略它。显式 `state_file` 的父目录会写进 `ReadWritePaths` 并建成 0750。安装程序不 chmod、不 chown `/srv` 这种已有的祖先，也不碰 `/run`、`/var/run`、`/run/user`。套接字落在这些共享目录下（例如 `unix:/run/user/1000/vpnd.sock`）时安装失败，错误要求改听 `unix:/run/idoris/`。单元不会写出 `RuntimeDirectory=user`。这次拒绝，以及凭据文件缺失，都发生在替换已安装的二进制、以及覆盖活的令牌或配置之前：先渲染单元，凭据复制到活状态目录旁边的暂存目录，然后才复制可执行文件，再把凭据和改好路径的配置换到活目录。失败时原来的令牌和配置字节不变，也不会 chmod `/run/user`。本机用临时目录核实，没有用 root 去写 `/etc` 或 `/var/lib`。macOS 的 LaunchDaemon 走同一条校验和暂存。

单元默认以 root 跑，才能打开 tailscaled 套接字并修改 prefs。单元里的注释写了另一种跑法：设 `User=idoris` 和 `Group=idoris`，并在主机执行 `tailscale set --operator=idoris`。加固是 `NoNewPrivileges=yes` 和 `ProtectSystem=strict`，所以 `/etc` 只读，配置文件不在 `ReadWritePaths` 里。单元还有 `StateDirectory=idoris`、`StateDirectoryMode=0750`、`RuntimeDirectory=idoris`、`RuntimeDirectoryMode=0750`，以及 `Environment=XDG_RUNTIME_DIR=/run/idoris`。没写 `listen` 时，状态套接字因此落在 `/run/idoris/vpnd.sock`。`ReadWritePaths` 一定有 `/var/lib/idoris` 和 `/run/idoris`，再加上绝对路径的 `state_dir`、`state_file` 的父目录，以及 `listen`、`socks5_listen` 和 `forwards[].listen` 里 `unix:` 套接字的父目录。`/run` 下面更深的路径不写进名单：重启后这些路径不在，名单里缺目录会让 systemd 建不了命名空间；父目录可写，守护进程自己建子目录。相对路径和 TCP 监听不会写进去。路径里出现 `..` 或控制字符，安装失败。安装程序为每一条 `ReadWritePaths` 建目录，模式 0750，并 chown 到 root。`WantedBy=multi-user.target`。日志是 `journalctl -u idoris-vpnd.service`。

第一次安装会 `systemctl daemon-reload`，再 `enable --now`。单元已经是 `active` 时，同一次安装改成 `daemon-reload` 然后 `systemctl restart`，这样新的配置和凭据会换掉正在跑的进程。同时尽力执行 `systemctl --user disable --now idoris-vpnd.service`。别的账号里如果还有用户单元，要那个账号自己停。卸载时，单元文件还在则 `systemctl disable --now` 必须成功；然后删除单元并 `daemon-reload`。`/etc/idoris/vpn.json` 和 `/var/lib/idoris` 留下，并打印配置还在。副本会删。`installService` 自己会把配置路径转成绝对路径并确认文件存在。向导调用的是这一函数，不经过 `service` 子命令里的那一次转换。

验证分两步，都在 OrbStack 上（`--privileged`、`--cgroupns=host`、挂载 `/sys/fs/cgroup`，systemd 为 PID 1）。镜像钉在 `debian:bookworm@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880`。包版本钉成 `systemd=252.39-1~deb12u2`、`systemd-sysv=252.39-1~deb12u2`、`procps=2:4.0.2-3`、`iproute2=6.1.0-3`、`ca-certificates=20250419~deb12u2`（2026-10-28 在这份 arm64 镜像里用 `apt-cache policy` 看到的候选）。`apt-get update` 仍会连镜像站；版本从站上消失时构建失败。第一步用 `sleep infinity` 脚本顶替可执行文件，只证明目录能建出来，这一步不能证明守护进程本身能跑：换成真二进制后立刻暴露出 `state file: home directory: $HOME is not defined`，服务被反复重启（`NRestarts=3`）。第二步是现在的证明。断言修正之后单独重跑 `TestR3svcSystemdMachineService` 为 37.17s PASS（该包 37.784s）。随后在 `8bb3134` 上的完整 `make integration` 里这项是 53.49s PASS。现场编译的 linux 二进制执行 `service install --system`，断言 `active`、空等 30 秒后 `NRestarts=0`、进程环境含 `STATE_DIRECTORY` 与 `XDG_RUNTIME_DIR`、`status --json` 有 `phase`、`/var/lib/idoris` 与 `/run/idoris` 为 0750、状态文件与锁文件 0600、`systemctl restart` 后仍 `active`。第二个 root 进程被状态文件锁拒绝，错误含 `state file backend`（`OpenState` 先于后端控制器锁）。然后用一份带 `state_file=/srv/idoris/vpnd-state.json` 的配置重装：单元含 `ReadWritePaths=/srv/idoris`，`/srv/idoris` 是 0750，`/srv` 的模式不变，`MainPID` 换成另一个，新状态文件里有新的 control URL。守护进程在没有 tailscaled 时停在协调循环里重试，不退出。正文由 `vpn/cmd/idoris-vpnd/testdata/idoris-vpnd.system.service` 锁住。完整集成里 `TestR4CServiceRootProofs` 13.66s PASS，覆盖可执行文件祖先和 sudo 凭据暂存。更早一次与当时仍失败的 systemd 项一起跑时，这项本身是 4.12s PASS。

macOS 需要 sudo。plist 写到 `/Library/LaunchDaemons/ai.idoris.vpnd.plist`（0600），标签仍是 `ai.idoris.vpnd`。`ProgramArguments` 里的可执行文件是 `/Library/PrivilegedHelperTools/idoris/idoris-vpnd`。配置同样是 `/etc/idoris/vpn.json`。凭据副本和 Linux 一样放在 `/var/lib/idoris`。plist 的 `EnvironmentVariables` 写入 `STATE_DIRECTORY=/var/lib/idoris`（与 systemd 同一约定），安装程序把 `/var/lib/idoris` 和 `/var/log/idoris` 建成 0700、属主 root，日志文件 `/var/log/idoris/vpnd.log`。这一段没有在 macOS 上执行过（没有 `launchctl bootstrap`），只有 golden 渲染和假的命令记录。还没加载时只 `launchctl bootstrap system`。已经加载时先 `bootout`，再 `bootstrap`，然后 `launchctl kickstart -k system/ai.idoris.vpnd`，让新的 plist 和进程一起换上。安装前还会 bootout 当前用户 gui 域里的同名任务。卸载只 bootout system 域并删除 plist 和副本，配置留下。

Windows 不引入新依赖，用系统自带的 `schtasks.exe`。任务名 `idoris-vpnd`，`ONSTART`，`/RU SYSTEM`，`/RL HIGHEST`。启动路径是 `%ProgramFiles%\iDoris\idoris-vpnd.exe`。配置复制到 `C:\ProgramData\idoris\vpn.json`。`schtasks` 没有环境变量字段，任务命令行是 `cmd /c set STATE_DIRECTORY=C:\ProgramData\idoris&& "…\idoris-vpnd.exe" run --config …`，状态因此落在已经收紧 ACL 的 ProgramData，而不是 SYSTEM 的用户配置目录；`/TR` 的引号和长度限制只有 golden 校验，没有在 Windows 上跑过。新文件先写到 `C:\ProgramData` 旁边的 `idoris-install-<随机>`，不写进 `C:\ProgramData\idoris` 里面，也不删除那个活目录。任务已经存在时：先暂存并核对，再 `schtasks /End`，然后轮询 `tasklist /FI IMAGENAME eq idoris-vpnd.exe /FO CSV /NH`，直到这个镜像没有别的进程（最多 30 秒，间隔 200 毫秒），才替换可执行文件、更新任务并 `/Run`。等待超时或替换失败时对旧任务 `/Run`，不执行新的 `/Create`。安装程序自己就是正在跑的那份 exe 时，不覆盖被映射的文件，任务改指向 `idoris-vpnd-<时间>.exe`。缺少凭据时原来的配置、令牌和 `vpnd-state.json` 字节不变，也不执行 `/End`，只删掉这一次的暂存目录。单测注入命令和临时目录。保护仍是 `icacls`：先 `/reset`，再 `/inheritance:r`，再 `/grant:r` 只给 `*S-1-5-18` 和 `*S-1-5-32-544`。目录权限是 `(OI)(CI)F`，文件是 `F`。命令行由 `vpn/cmd/idoris-vpnd/testdata/idoris-vpnd.icacls.txt` 锁住。读回不再比较 `icacls` 印出的 `HOST\alice` 这种名字，而是比较 SID 集合。服务路径必须恰好是显式允许的 SYSTEM 和 Administrators。属主是 SYSTEM 或 Administrators 都接受。继承 ACE、拒绝 ACE 和多出来的 SID 都失败。表驱动单测用假的安全描述符。`GOOS=windows` 编译了 `GetNamedSecurityInfo` / `GetAce`，没有在 Windows 上执行 `icacls` 或 `schtasks`。卸载是 `schtasks /Delete /TN idoris-vpnd /F`，再删掉 exe 副本，配置留下。任务参数由 `vpn/cmd/idoris-vpnd/testdata/idoris-vpnd.task.txt` 锁住。

这一节核实过的限制：非 root 用户守护进程和 root 服务锁目录不同；`launchctl`、`icacls` 和 `schtasks` 没有在对应系统上执行；用户级 systemd 的真实 PID 变化没有跑到，因为容器里没有系统 D-Bus；这一轮 `make integration` 里 `TestR5CSystemdUserServiceRestarts` 跳过 28.78s。祖先检查的成功路径和 sudo 属主只在 Debian 容器里跑过。Linux 的 `/usr/local` 在那份镜像里属于 root，所以安装能通过祖先检查。机器单元已经 active 时的 `restart` 仍由以前的集成测试覆盖；用户单元的 `restart` 只核实了命令顺序。失败重装不覆盖活的令牌和配置，这一项在本机临时目录里核实，没有对 `/etc` 或 `C:\ProgramData` 真写一次。

本机转发和 SOCKS5 谁能连上，写在 `docs/13-VPN-CLIENT-MODES.md` 第 13 节。那一节和这里的本地页面不是同一件事：页面有自己的秘密和 CSRF。回环 TCP 转发本身不认证。`unix:` 套接字是 0600。SOCKS5 默认要用户名和密码，凭据在 `socks5_auth_file`，或在 `<state_dir>/socks5.auth`（0600，创建时日志只打路径）。
