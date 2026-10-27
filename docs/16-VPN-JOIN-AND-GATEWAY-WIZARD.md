# 16 · 加入码与办公室网关向导

**日期：** 2026-10-27（泰国时区）· **状态：** `vpn/` 内单测与 `make integration-wizard` 已通过。最后一次 Docker 跑在项目 `idoris-vpn-wizard-1e19b7`（办公室网 `10.211.81.0/24`，回声设备 `10.211.81.10` 与 `10.211.81.11`），`TestWizardGatewayJoin` 37s PASS。没有重跑 `make integration` 和 `make integration-lan`（前者的 compose 项目名固定，会和别的代理抢同一套容器）。`deploy/**` 本轮没有改。

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

`--role-override` 可以改角色。`--no-service` 只写配置、不安装用户级服务。`--allow-insecure` 才允许 `http://` 登记地址；默认要求 `https`。

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
idoris-vpn-enroll invite --config FILE --entry NAME [--hostname-hint H] --enroll-url URL
```

它为该条目新造一个令牌，把 SHA-256 哈希追加进 `token_hashes`，原子写回并保持原文件权限。条目必须已经存在，而且文件里至少要有一个种子哈希（`Validate` 不允许空的 `token_hashes`）。明文只在这一次出现。每个哈希可以单独吊销：

```text
idoris-vpn-enroll revoke --config FILE --entry NAME --hash-prefix XXXX
```

前缀是 4 到 64 位十六进制，必须恰好命中一个哈希。拒绝删掉最后一个哈希，否则文件会通不过 `Validate`。

`invite` / `revoke` 只改文件，不给进程发信号。正在跑的 `idoris-vpn-enroll serve` 要 `SIGHUP` 才重新读配置；新文件不合法时保留旧配置并写日志。重启进程也可以。登记服务的 `/v1/discover` 返回 `role` 和 `lan_cidrs`，不签发密钥。

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

服务安装沿用现有的用户级单元（systemd `--user` / launchd），不是系统级 root 单元。提权的只有 `ip_forward` 这一步。

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

`/healthz` 在此阶段返回 **503**，正文是阶段名。只有 `connected` 才是 200 和 `ok`。

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

`idoris-vpnd ui` 只听 `127.0.0.1` 的随机端口。stdout 打出带一次性秘密的 URL（`?k=`）。浏览器是否被打开：macOS 用 `open`，Linux 用 `xdg-open`，`--no-open` 则不打开。这些约束由 `httptest` 和真实回环监听测过，没有在图形浏览器里点过。

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

今天没有 `deploy/vpn/ctl.sh`。登记配置由 `deploy/vpn/bootstrap.sh` 写入 `enroll/config.json`，现有条目只有成员和 `*-local-ai`，没有 `role`、`lan_cidrs`，也没有网关 tag。策略文件 `deploy/vpn/headscale/policy.hujson` 也还没有 `autoApprovers`。

建议补这些，而不是改客户端：

1. 增加 `deploy/vpn/ctl.sh`（或在 bootstrap 旁加一段），在 enroll 容器里执行 `idoris-vpn-enroll invite` / `revoke`。邀请的 stdout 只有加入码，不要再包一层会把码写进日志的 echo。写完文件后对 enroll 进程发 `SIGHUP`（或重启容器）。bootstrap 今天是改完配置再 `docker compose restart enroll`。
2. 网关条目增加 `role: "gateway"`、`lan_cidrs`（与下面的前缀逐条相同）、`acl_tags: ["tag:<租户>-gateway"]`。Local AI 条目保持 `acl_tags: ["tag:<租户>-local-ai"]`，并写上 `role: "local-ai"`。
3. 策略里为 `tag:<租户>-gateway` 增加 `tagOwners`（实验室用 `group:admins`）、`autoApprovers.routes` 的**精确前缀**，以及第 5 节那种同时包含租户用户和网关 tag 的 ACL。改完后 `headscale policy check`，再 `SIGHUP`。`policy.mode: file` 时 Headplane 的 ACL 页是只读的。
4. 不要让客户端在登录时带 `--advertise-tags`。标签放在登记条目的 `acl_tags` 上。

## 11. 边界

- 客户端不能批准自己的路由。
- 空的 ControlURL 加上已登录状态（`Running` / `Starting` / `Stopped`）视为别人的 Tailscale SaaS，自动模式不接管。`NeedsMachineAuth` 加空 URL 仍当作全新安装。
- 吊销不能删掉条目的最后一个令牌哈希。
- `/healthz` 在等待批准时是 503。
- 嵌入式模式不能当网关。macOS / Windows 不推荐网关；本轮没有在那两个系统上跑网关。
- 服务单元是用户级的。
- 本地页面的 cookie 故意不设 Secure。页面「否」会强制走网关，「是」会强制走 local-ai，即使用加入码写的是成员。
- 更宽的 `autoApprovers` 前缀是否覆盖更窄的 `/32`，本轮没有验证。
- 没有在图形浏览器里点本地页面。
- 没有重跑 `make integration` 与 `make integration-lan`。
