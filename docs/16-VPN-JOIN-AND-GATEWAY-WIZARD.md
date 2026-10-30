# 16 · 加入码与办公室网关向导

**日期：** 2026-10-27（泰国时区）。加入码与办公室网关的 Docker 证据仍是项目 `idoris-vpn-wizard-1e19b7`（办公室网 `10.211.81.0/24`，回声设备 `10.211.81.10` 与 `10.211.81.11`），`TestWizardGatewayJoin` 37s PASS。本轮补上可单独吊销的凭证标签、登记服务 `/readyz`，以及 `idoris-vpnd service install --system`。Linux 系统单元在 Debian bookworm 容器里 `systemd-analyze verify` 退出码为 0。`deploy/**` 不在这次改动里。

## 1. 要做成什么样

小组织的人只做一件事：粘贴一串加入码，确认。网关多一步：这台 Linux 机器自己认出办公室网卡，给出最窄的一条路由，再确认一次。

向导的第一问是：**这台机器就是 Local AI 吗？**

| 回答 | 结果 |
|---|---|
| 是 | 以 `local-ai` 角色加入，不广告路由，不做网关。这是首选。 |
| 否（AI 盒子不能装 Tailscale） | 进入网关流程：只广告指定设备的 `/32`。 |

整段子网是显式选项，并带冲突警告。客户端不能给自己批路由。登记服务在 `/v1/discover` 里告诉客户端组织已经预批准的 CIDR（对应服务器策略的 `autoApprovers.routes`）。计划落在这份名单里，界面写「会自动批准」；否则阶段是 `routes-pending-approval`，并给出管理员命令。

网关只在 Linux 上支持和验证。macOS / Windows 上向导说明不支持，不推荐。改系统需要 root：不是 root 时不自行提权，打印确切的 `sudo` 命令。

## 2. 四种用法

加入码里的 `role` 是 `member`、`local-ai`、`gateway` 或 `admin`。命令行标志必须写在加入码前面（Go 的 flag 在第一个非标志参数处停止）。

| 角色 | 命令 | 守护进程配置 |
|---|---|---|
| 成员 | `idoris-vpnd join --yes <code>` | `mode=auto`，`accept_routes=true`，不广告路由 |
| 本机就是 Local AI | 加入码角色为 `local-ai`，或网关码在第一问回答「是」 | `mode=auto`，不广告路由，`accept_routes=false`，记录 tag `tag:<租户>-local-ai` |
| 办公室网关 | `idoris-vpnd join --yes --device <IP> <code>`，或 `gateway setup` | `mode=system`，只广告该 IP 的 `/32`，`accept_routes=false` |
| 管理员 | `join --yes`（角色 `admin`） | 与成员相同：接受路由，不广告 |

`--role-override` 可以改角色。`--no-service` 只写配置、不安装用户级服务。登录前就要跑的机器服务是另一条命令，见第 12 节。`--allow-insecure` 才允许 `http://` 登记地址；默认要求 `https`。

网关相关命令：

```text
idoris-vpnd gateway detect [--json]
idoris-vpnd gateway setup [--yes] [--device IP]... [--whole-subnet]
idoris-vpnd gateway apply --plan FILE
idoris-vpnd ui [--no-open]
```

`gateway setup --yes` 的意思是：这台机器**不是** Local AI，并且已经用 `--device` 或 `--whole-subnet` 说清要广告什么。两者不能同时给。

本地页面（中文）三步：识别网络 → 使用建议 → 启用。第一问原文是「这台机器就是 Local AI 吗？」。页面上选「是」会按 `local-ai` 加入，即使加入码写的是成员；选「否」会走网关。成员加入仍用命令行。

## 3. 加入码的生命周期

码的形状是 `idoris-join-v1.<base64url(JSON)>.<crc32 十六进制>`。JSON 只有 `v`、`enroll_url`、`token`、`role`、`tenant`、`hostname_hint`。解码拒绝未知字段、超长、截断、校验和错误，以及（没有 `--allow-insecure` 时）非 https。码里嵌着登记令牌，是秘密：命令不会把它打到日志或 stdout。

签发（stdout 只有这一行码）：

```text
idoris-vpn-enroll invite --config F --entry E --label L --enroll-url U
```

`--hostname-hint` 和 `--allow-insecure` 仍可用。`--label` 可省略。省略时，非空且能放进加入码的 hostname hint 就是标签；hint 为空时标签是 `cred-` 加该哈希的前 8 位十六进制。hint 不是主机名标签（例如含空格）时邀请失败，配置文件不改。合法标签匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`。同一条目里非空标签不能重复。

它为该条目新造一个令牌，把带标签的凭证追加进去，原子写回并保持原文件权限。条目必须已经存在，而且文件里至少要有一张种子凭证（`Validate` 不允许空的 `token_hashes`）。明文只在这一次出现。旧文件里的纯哈希字符串仍然合法，读入后当成没有标签、没有 `created_at` 的凭证。新写入的是对象 `{hash, label, created_at}`。`created_at` 是 UTC，截到秒。

每张凭证可以单独吊销。`--label` 和 `--hash-prefix` 只能给一个：

```text
idoris-vpn-enroll revoke --config F --entry E --label L
idoris-vpn-enroll revoke --config F --entry E --hash-prefix P
```

`--hash-prefix` 是 4 到 64 位十六进制，必须恰好命中一个哈希。stdout 一行：`revoked <条目> <标签> <12 位哈希前缀>`。空标签印成 `-`。不印完整哈希，不印令牌。拒绝删掉最后一张凭证，否则文件通不过 `Validate`。

列出凭证。没有表头，制表符分隔，三列是标签、12 位哈希前缀、`created_at`。空标签或空时间是 `-`：

```text
idoris-vpn-enroll list-credentials --config F --entry E
```

过期或删除 Headscale 节点不会收回登记权：守护进程还能再要一把预授权密钥。下线顺序是：先 `revoke`，再让正在跑的 `idoris-vpn-enroll serve` 重新读配置，然后才过期或删除节点。重新读配置靠 `SIGHUP` 或重启进程；compose 把 `config.json` 按单文件绑进容器，`revoke` 的 rename 会让绑定指着旧文件，SIGHUP 在那里不可靠，所以 `ctl.sh offboard` 用重启 enroll 容器。部署侧用 `ctl.sh offboard` 把这几步包起来。

`invite` / `revoke` 只改文件，不给进程发信号。`SIGHUP` 重新读配置；新文件不合法时保留旧配置并写日志。吊销过的凭证在这次重载之后不能再登记。`/v1/discover` 返回 `tenant`、`role` 和 `lan_cidrs`，不签发密钥。

扫令牌哈希之前有两道限速，`/v1/enroll` 和 `/v1/discover` 都走：`global_rate_per_minute` 默认每分钟 600，`per_ip_rate_per_minute` 默认每分钟 60。通过认证之后，成功登记按条目另有一桶，`rate_per_minute` 默认 30；`/v1/discover` 再用同一默认值、但是分开的桶。`/healthz` 和 `/readyz` 不限速。`trusted_proxies` 是 CIDR 列表。只有 TCP 对端落在这份名单里才读 `X-Forwarded-For`，取最右边一个不在名单里的地址。对端不受信任时用 TCP 对端，伪造的头选不了桶。失败认证的日志每 10 秒最多一行。成功登记的审计行有 `remote`（只有 IP，没有端口）和凭证 `label`（空标签记成 `-`）。

`/readyz` 用一次带认证的便宜调用检查 Headscale 是否可达、API 密钥是否仍被接受。Headscale v0.29.6 的 `GET /api/v1/apikey` 只返回密钥前缀和 `expiration`（null 表示未知）。命中本密钥且带过期时间时，响应有 `api_key_expires_at`。剩余时间不足 30 天：HTTP 200，`status` 为 `warning`，`warning` 为 `api key expires in less than 30 days`。刚好 30 天不算警告，但仍带过期时间。已经过期、不可达，或密钥被拒（401/403），是 503。密钥列表 404 时改用列出用户：密钥有效，过期时间未知，这时 200 且 `status` 为 `ok`，没有过期字段。没有配置探针时 503。失败原因是固定短语（`api key rejected`、`headscale HTTP N`、`unreachable`、`api key expired`），不回传上游正文。登记服务的 `/healthz` 仍是正文 `ok` 加换行，不探 Headscale。守护进程自己的 `/healthz` 见第 7 节，那是另一条路径。

登记客户端和 Headscale API 客户端都不跟随重定向。对端把请求转到 `http://` 或另一台主机时，调用失败，bearer token 不会被送出去。

## 4. 网关计划：只广告 /32

检测只看一份快照：接口已启动、非回环、RFC1918 的 IPv4。排除 CGNAT `100.64.0.0/10`（tailnet）、`tailscale*` / `utun*`，以及 `docker0`、`br-*`、`veth*`、`virbr*`、`vmnet*`、`cni*`、`flannel*`。标出默认路由所在的网卡和网关。

默认计划是设备 IP 的 `/32`。整段子网要显式打开，并警告这些常见家庭网段（广告整段会挡住成员家里的同网段）：

- `192.168.0.0/24`、`192.168.1.0/24`、`192.168.2.0/24`
- `10.0.0.0/24`、`10.0.1.0/24`
- `172.16.0.0/24`、`172.16.1.0/24`

`/32` 只挡住一个地址。不会扫描整段子网。可达性探测只对用户给出的一个 IPv4 做 TCP 拨号，端口 `11434`、`8740`、`8742`、`443`、`80`，每个 1 秒。

检查项：平台是 Linux、`ip_forward`、`/dev/net/tun`、root、`tailscaled` 可达、模式必须是 `system`（嵌入式节点不能当网关）。

应用时写入 `~/.idoris/vpn.json` 和模式 `0600` 的令牌文件；计划 JSON 本身不含令牌。Linux 上且是 root 时，写 `/etc/sysctl.d/99-idoris-vpn.conf` 并尝试打开转发。`/proc/sys/net/ipv4/ip_forward` 已经是 `1` 就算成功，即使 `sysctl -w` 失败。不是 root 时，其余文件照写，并打印：

```text
sudo idoris-vpnd gateway apply --plan <计划文件>
```

`join` 和 `gateway apply` 在没有 `--no-service` 时仍安装用户级服务（systemd `--user` / LaunchAgent），不会改成系统级单元。登录前就要跑，另执行第 12 节的 `service install --system`。向导自己提权的只有 `ip_forward` 这一步。

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

## 9. 本地页面的安全模型

`idoris-vpnd ui` 只听 `127.0.0.1` 的随机端口。stdout 打出带一次性秘密的 URL（`?k=`）。浏览器是否被打开：macOS 用 `open`，Linux 用 `xdg-open`，`--no-open` 则不打开。这些约束由 `httptest` 和真实回环监听测过，没有在图形浏览器里点过。本轮对照 `vpn/internal/ui/server.go` 核对过，下面的约束没有改。

| 约束 | 行为 |
|---|---|
| Host | 必须等于绑定的 `127.0.0.1:端口`，挡 DNS 重绑定 |
| 秘密 | 首次用查询参数 `k`，之后用 cookie `idoris_ui`（HttpOnly、SameSite=Strict）或头 `X-Idoris-UI-Secret`。回环是 HTTP，cookie **不**设 Secure |
| 改状态的 POST | 要有 `Origin: http://<绑定地址>` 或 `Sec-Fetch-Site: same-origin`，再加页面注入的 `X-CSRF-Token`。两个来源信号都缺则拒绝 |
| 缓存与 CSP | `Cache-Control: no-store`。CSP 为 `default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`。页面是内嵌的 HTML / JS / CSS，没有外链 |
| 请求体 | 超过 64KiB 拒绝 |
| 空闲 | 默认 15 分钟没有请求就自己退出 |
| 会话用户 | Linux 上若 `/proc/self/loginuid` 是别的用户，拒绝启动。读不到或是 `4294967295` 则放行 |

加入码只留在该进程的内存里，响应不回显令牌。页面用 `history.replaceState` 去掉 URL 里的 `k`。不是 root 时，「启用」返回上面的 `sudo` 命令，不提权。之后页面轮询状态，直到已连接或等待批准。

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

- 客户端不能批准自己的路由。
- 空的 ControlURL 加上已登录状态（`Running` / `Starting` / `Stopped`）视为别人的 Tailscale SaaS，自动模式不接管。`NeedsMachineAuth` 加空 URL 仍当作全新安装。
- 吊销不能删掉条目的最后一张凭证。过期或删除节点不会吊销凭证。
- 守护进程的 `/healthz` 在等待批准时是 503。登记服务的 `/healthz` 不探 Headscale；那要看 `/readyz`。
- 嵌入式模式不能当网关。macOS / Windows 不推荐网关；本轮没有在那两个系统上跑网关。
- `join` 默认安装的是用户级服务，登录前不跑。开机即跑用第 12 节的 `--system`。
- 本地页面的 cookie 故意不设 Secure。页面「否」会强制走网关，「是」会强制走 local-ai，即使用加入码写的是成员。
- 更宽的 `autoApprovers` 前缀是否覆盖更窄的 `/32`，本轮没有验证。
- 没有在图形浏览器里点本地页面。
- 第 8 节的数字来自项目 `idoris-vpn-wizard-1e19b7`。本轮没有另起同名 compose 项目重跑那一节。

## 12. 机器服务：`service install --system`

不带 `--system` 时，`service install --config FILE` 仍是用户级。Linux 写 `~/.config/systemd/user/idoris-vpnd.service`（`NoNewPrivileges=yes`，`WantedBy=default.target`）。macOS 写当前用户的 LaunchAgent，标签 `ai.idoris.vpnd`。装完打印：用户级服务在这个用户登录之前不会跑；Linux 上同一句后面是 `loginctl enable-linger`。Windows 上不带 `--system` 的安装仍不支持。`join` 和 `gateway apply` 走的也是这套用户级安装，不会偷偷加上 `--system`。

系统级：

```text
idoris-vpnd service install --system --config FILE
idoris-vpnd service uninstall --system
```

Unix 上不是 root 就失败，原文 `service install --system must run as root; re-run with sudo`，此时还没有写文件。系统单元还启用着的时候，再装用户级会被拒绝：Linux 看 `systemctl is-enabled idoris-vpnd.service` 是不是 `enabled`，macOS 看 `/Library/LaunchDaemons/ai.idoris.vpnd.plist` 在不在。

Linux 单元是 `/etc/systemd/system/idoris-vpnd.service`，模式 0600。配置按原字节复制到 `/etc/idoris/vpn.json`（0600）。目录 `/etc/idoris` 和 `/var/lib/idoris` 是 0750。安装程序不改配置里的 `state_dir`。`state_dir` 为空时，守护进程用 root 的家目录，也就是 `/root/.idoris/vpn-state`。要把状态放进单元已经放开的目录，把 `state_dir` 写成 `/var/lib/idoris` 或它下面的子目录。

单元默认以 root 跑，才能打开 tailscaled 套接字并修改 prefs。单元里的注释写了另一种跑法：设 `User=idoris` 和 `Group=idoris`，并在主机执行 `tailscale set --operator=idoris`。加固是 `NoNewPrivileges=yes` 和 `ProtectSystem=strict`，所以 `/etc` 只读，配置文件不在 `ReadWritePaths` 里。`ReadWritePaths` 一定有 `/var/lib/idoris`，再加上绝对路径的 `state_dir`，以及 `socks5_listen` 和 `forwards[].listen` 里 `unix:` 套接字的父目录。相对路径和 TCP 监听不会写进去。路径里出现 `..` 或控制字符，安装失败。`WantedBy=multi-user.target`。日志是 `journalctl -u idoris-vpnd.service`。

安装会 `systemctl daemon-reload`，再 `enable --now`。同时尽力执行 `systemctl --user disable --now idoris-vpnd.service`。别的账号里如果还有用户单元，要那个账号自己停。卸载时，单元文件还在则 `systemctl disable --now` 必须成功；然后删除单元并 `daemon-reload`。`/etc/idoris/vpn.json` 和 `/var/lib/idoris` 留下，并打印配置还在。

这份单元在 Debian bookworm 容器里跑过 `systemd-analyze verify`（可执行文件换成空脚本，并建好 `ReadWritePaths` 的目录），退出码 0，没有警告。正文由 `vpn/cmd/idoris-vpnd/testdata/idoris-vpnd.system.service` 锁住。

macOS 需要 sudo。plist 写到 `/Library/LaunchDaemons/ai.idoris.vpnd.plist`（0600），标签仍是 `ai.idoris.vpnd`。配置同样是 `/etc/idoris/vpn.json`。日志目录 `/var/log/idoris`（0750），文件 `/var/log/idoris/vpnd.log`。先 `launchctl bootout` 用户域和 `system` 域里的同名任务，再 `launchctl bootstrap system`。卸载只 bootout system 域并删除 plist，配置留下。

Windows 不引入新依赖，用系统自带的 `schtasks.exe`。任务名 `idoris-vpnd`，`ONSTART`，`/RU SYSTEM`，`/RL HIGHEST`。配置复制到 `C:\ProgramData\idoris\vpn.json`。卸载是 `schtasks /Delete /TN idoris-vpnd /F`，配置留下。参数列表由 `vpn/cmd/idoris-vpnd/testdata/idoris-vpnd.task.txt` 锁住；单测不执行 `schtasks`。

本机转发和 SOCKS5 谁能连上，写在 `docs/13-VPN-CLIENT-MODES.md` 第 13 节。那一节和这里的本地页面不是同一件事：页面有自己的秘密和 CSRF。回环 TCP 转发本身不认证。`unix:` 套接字是 0600。SOCKS5 默认要用户名和密码，凭据在 `socks5_auth_file`，或在 `<state_dir>/socks5.auth`（0600，创建时日志只打路径）。
