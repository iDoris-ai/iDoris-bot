# 14 · VPN 运维：单组织默认、管理员、Headplane、子网网关

**日期：** 2026-10-27 · **状态：** 在本机 Docker 上用 Headscale v0.29.6、Headplane 0.8.2、`tailscale/tailscale:v1.104.2` 验证过。公网域名、真实 TLS 证书和一部手机的注册不在这次验收里。成员逐步操作见 `docs/17-VPN-MEMBER-ONBOARDING.md`。身份模型和「user 不是隔离边界」见 `docs/12-VPN-HEADSCALE.md`。

产品默认是**一个组织**（大约十几个人）加一台 Local AI。成员在办公室局域网里直接访问这台机器；在家里则通过 tailnet。多组织可以加在同一台 Headscale 上，那是显式的进阶操作，隔离只靠策略文件。

## 1. 第一次启动（一个组织）

1. 把 `deploy/vpn/headscale/config.yaml` 和 `deploy/vpn/headplane/config.yaml` 里的 `vpn.example.org` 换成你的公网主机名。`server_url` 必须是 `https://主机名`，不能带非 443 的端口。Tailscale 客户端之后会强制改拨 443。`bootstrap.sh` 在占位域名还在、或者 URL 不是 https/443 时会拒绝往下走。
2. 在装了 Docker Compose v2 和 python3 的服务器上：

```bash
bash deploy/vpn/bootstrap.sh init --org office --admin admin
```

省略 `--org` 时组织名是 `office`，省略 `--admin` 时管理员用户是 `admin`。这一次会：

- 写出 `headplane/cookie_secret`（恰好 32 个十六进制字符）、`enroll/headscale.apikey`、`enroll/config.json`、`headscale/managed.json`、`.env`、`.admin-mode`。这些都在 gitignore 里，不要提交。
- 明文 token 在拉起服务**之前**追加到 `enroll/minted-tokens.txt`（0600）。后面的步骤失败时，这是哈希已经写进配置之后唯一的明文副本。用完后把文件挪到别处再删。
- 在 `headscale/policy.hujson` 的 `BEGIN/END idoris-managed` 标记之间写入该组织的规则，跑 `headscale policy check`，再对 Headscale 发 SIGHUP。标记以外的手写规则会保留。
- 创建 Headscale 用户 `admin` 和 `office`。
- 建注册项并打印 token：`admin`（`role: admin`，个人节点，无 tag，每分钟 5 次，TTL 5 分钟）、`office`（`role: member`，TTL 10 分钟）、`office-local-ai`（`role: local-ai`，`tag:office-local-ai`，每分钟 5 次）。带了 `--lan-cidr` 时还有 `office-gateway`（`role: gateway`）。`--tailnet-admin` 时还有 `vpn-server`（只有 `tag:vpn-server`，没有 join role；sidecar 用原始 token 和 `acl_tags`）。新凭证写成 `token_hashes` 对象，标签是 `bootstrap-<注册项名>`（例如 `bootstrap-office`）。打印先一行标签，再一行 token。

`invite` 会把租户上的 `role` 写进加入码。角色为空时加入码写成 `member`。这次改动只作用于**新**写出来的注册项；已经存在的项再跑 `init` 不会补角色。给旧项补角色时，在 `enroll/config.json` 里加上 `"role"`（`admin`、`member`、`local-ai`、`gateway` 之一），再 `ctl.sh token new --entry <项> --label <标签>`。已有的十六进制字符串仍然能加载；`token list` 里没有标签的显示为 `-`。

再跑一次 `init` 是安全的：已有用户、API key、cookie、token 都不会换。已有注册项时日志是「enrollment entries already present; no new tokens minted」。上次铸出来的明文如果还在 `enroll/minted-tokens.txt` 里，会再打印一次。

Headscale v0.29 的 `policy check` 打到正在运行的服务器上的 gRPC，不能在一个没有 socket 的一次性容器里做。`bootstrap.sh` 因此先拉起 Headscale，建好用户，再检查，再 SIGHUP。策略文件是就地改写的：对单文件做 `rename` 会让容器里的绑定挂载失效。

注册服务用的 Headscale API key 以 `--expiration 8760h`（365 天）创建。轮换见第 12 节。

## 2. 注册容器不要以 root 运行

镜像 `USER` 是 `65532:65532`。`bootstrap.sh` 的规则：

- 操作员自己不是 root：`ENROLL_UID` / `ENROLL_GID` 用操作员的 uid/gid，这样 0600 的密钥文件进程读得到。
- 操作员是 root：改成 `65532:65532`，并在启动前把 `enroll/` 和里面的 `config.json`、`headscale.apikey`、`minted-tokens.txt` `chown` 给 `65532`。日志会写「refusing to run enroll as root」。
- 不会把注册容器设成 uid 0。

Headplane 镜像的用户是 `0`（root），cookie 文件保持 0600，不改属主。这次在 macOS 上以非 root 操作员跑通了探针和登录证明；没有在一台以 root 执行 `bootstrap.sh` 的 Linux 上再跑一遍 chown。

## 3. 管理员、MagicDNS、反向规则

管理员设备和普通成员用同一套客户端。差别只是 token 属于哪个注册项。逐步安装见 `docs/17-VPN-MEMBER-ONBOARDING.md`。

管理员能做的事写在策略里：

- `group:admins` → `tag:<组织>-local-ai:22`，外加一条 `ssh` 规则，`users` 是 `autogroup:nonroot`，`action` 是 `check`。这只打开了控制面的许可。Local AI 主机上还要执行 `tailscale set --ssh`，见第 11 节。`check` 会停住，等有人执行 `headscale auth approve --auth-id <id>`。
- 启用了 tailnet 管理面时：`group:admins` → `tag:vpn-server:3000` 和 `:22`。成员没有到 `tag:vpn-server` 的规则。

成员到本组织 Local AI 的端口是 8740（iDoris）、8742（Agent24）、443。管理员到不了成员的业务端口，成员之间也没有规则。不要在成员规则里加 `autogroup:member`、`autogroup:tagged` 或 `*`。

Tailscale ACL 是有状态的，成员先连出去的回包不需要反向规则。默认**不再**写 `tag:<组织>-local-ai -> <组织>@:*` 或 `tag:<组织>-gateway -> <组织>@:*`。被攻破的 Local AI 或网关因此不能主动扫成员的端口。需要 Local AI 主动连回来时，按组织打开窄端口：

```bash
bash deploy/vpn/bootstrap.sh add-tenant office --ai-callback-ports 22,8080
```

端口写入 `headscale/managed.json` 的 `ai_callback_ports`，只渲染这些端口。`none` 清空。每次运行都会重新校验已保存的 `managed.json`。

MagicDNS 是 `<主机名>.idoris.internal`（`base_domain: idoris.internal`）。组织名不在 DNS 里。Local AI 的主机名要自己带前缀，例如 `office-local-ai.idoris.internal`。`headscale/config.yaml` 里的注释按这个写；不要写成 `local-ai.acme.idoris.internal`。

`policy.hujson` 底部的 `tests` 块保持注释。Headscale 会在 `policy check` 和每次 SIGHUP 时用**当前活着的节点**跑测试；组织还没有节点时，测试会让重载失败。

## 4. 再加一个组织，以及前缀校验

```bash
bash deploy/vpn/bootstrap.sh add-tenant globex
bash deploy/vpn/bootstrap.sh add-tenant globex --lan-cidr 192.168.50.0/24
```

`--lan-cidr` 可以重复。`policy.py` 用网络计算，不用字符串相等：

- 不同组织的前缀只要重叠或互相包含就拒绝，例如 `192.168.0.0/16` 和 `192.168.50.0/24`，以及一个 `/32` 落在别人的 `/24` 里。
- 同一组织里重叠只警告，两条都保留。
- 与 tailnet 地址 `100.64.0.0/10`、`fd7a:115c:a1e0::/48` 重叠的前缀拒绝。回环、链路本地、多播、`0.0.0.0/0`、主机位未清零、带空白的文本都拒绝。
- 必须是私网：IPv4 的 RFC1918，或 IPv6 的 ULA。`169.254.0.0/16` 和 `100.64.0.0/10` 拒绝。公网前缀要显式 `--allow-public-cidr`，脚本会大声警告，并把它们记在该组织的 `public_cidrs` 里。这个开关**不能**放行 tailnet 地址段。

单测在 `deploy/vpn/test/test_policy.py`，`python3 -m unittest discover -s deploy/vpn/test -p 'test_*.py'`。需要更硬的边界时，另起一套 `deploy/vpn`，见第 9 节。

## 5. 在服务器上操作：`ctl.sh`

`bash deploy/vpn/ctl.sh help`。脚本按自己的路径找到 compose 目录。文件开头就是 `umask 077`，在任何复制之前。除了 `apikeys create` 和 `token new`，输出里的 pre-auth key 和完整 API key 会被抹掉。

| 命令 | 作用 |
|---|---|
| `status` / `health` | `compose ps` 和 `headscale health` |
| `users list` / `nodes list` | 用户、节点 |
| `nodes expire --identifier ID [--expiry RFC3339] [--disable]` | 让节点到期。空的 expiry 表示现在 |
| `nodes delete --identifier ID --force` | 删除。没有 `--force` 不会执行 |
| `preauthkeys list` / `preauthkeys expire --id ID` | 列出的是打码后的 key。注册服务自己签发，这里不新建 |
| `routes list` / `routes approve` / `routes clear` | 自动批准失败时用 approve |
| `policy check` / `policy reload` | 检查，reload 再发 SIGHUP |
| `apikeys list` / `apikeys create [--expiration 90d]` / `apikeys expire` | `create` 打出的是登录 Headplane 的个人 key，不是注册服务那把 |
| `token new --entry NAME --label LABEL [--enroll-url URL]` | 经 `docker compose run` 把 `--label` 传给 `invite`。标签写在该项的 `token_hashes` 对象上。明文先追加到 `minted-tokens.txt`，再用 `list-credentials` 核对标签，然后重启注册服务 |
| `token list --entry NAME` | 每行是标签、12 位哈希前缀、`created_at`，制表符分开。没有标签或时间时是 `-`。不打印 token，也不打印完整哈希 |
| `token revoke --entry NAME (--label LABEL \| --hash-prefix HEX)` | 两个选择器恰好一个，原样交给 CLI `revoke`。成功行是 `revoked <entry> <label或-> <12位前缀>`。最后一条会拒绝，先 `token new` |
| `offboard --entry NAME (--label LABEL \| --hash-prefix HEX) [--node-id N]` | **先**吊销这枚凭证。吊销失败则不 expire、不 delete。给了 `--node-id` 才 `nodes expire` 再 `nodes delete`。单独 expire 或 delete 节点不会吊销凭证 |
| `logs [service] [--tail N]` | 日志，secret 打码 |
| `backup [DIR]` | 见第 6 节 |
| `restore DIR --force` | 见第 6 节。没有 `--force` 拒绝 |
| `up [--published\|--tailnet-admin] [--instance NAME] [--headplane-access MODE]` | 按已保存的管理模式启动，并重新套用 `HEADPLANE_ACCESS` |
| `down` | `docker compose down`，**保留**数据卷和管理模式 |
| `upgrade` | 只打印升级步骤，不拉镜像 |
| `break-glass` | Headscale 挂了之后的 SSH 清单 |

`token new`、`token revoke` 和 `offboard` 的 `--label` 都交给 `idoris-vpn-enroll`。标签字符集是 `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`。同一注册项上重复的标签会被拒绝，错误里有 `already exists`。`--hash-prefix` 是 4 到 64 位十六进制，必须唯一命中一条。`token_hashes` 可以是旧的十六进制字符串，也可以是 `{"hash","label","created_at"}`；两种都能读，`invite` 写出对象。

注册服务在 SIGHUP 时会按路径重读 `config.json`（非法文件会留下上一份），并且这次重读不更换进程里的 Headscale 客户端。compose 把 `enroll/config.json` 按**文件**绑进容器。`invite` / `revoke` 用 rename 换掉这个文件，绑定还指着旧 inode。本机 Docker 上，rename 之后容器里该路径是 ENOENT，重启才重新绑上新文件。`ctl.sh` 因此在服务正在跑时执行 `docker compose restart enroll`，否则等下次启动。只换 API key、不重启，客户端仍是旧的，见第 12 节。

## 6. 恢复包

`ctl.sh backup [DIR]` 先停**当前**那个 Headplane 写入者和 Headscale，复制完再把刚才在跑的服务拉起来。另一个 Headplane 不会被启动。

包里有：

- `headscale/db.sqlite`，以及当时存在的 `db.sqlite-wal`、`db.sqlite-shm`
- `headscale/noise_private.key`
- `headscale/derp_server_private.key`，仅当容器里真有这个文件。Headscale v0.29.6 在 `derp.server.enabled: false` 时不创建它。探针和干净主机演练都关掉了内嵌 DERP，所以包里没有这把密钥
- Headplane 数据目录
- `state/`：`enroll/config.json`（token 哈希）、`enroll/headscale.apikey`、`headplane/cookie_secret`、`.env`、`headscale/managed.json`、部署中的 `config.yaml`、`policy.hujson`、`headplane/config.yaml`、`compose.yaml`
- `admin-mode` 和 `manifest.json`（镜像标签、id、digest、Headscale 版本、文件权限）。清单里出现 `idv1_`、`hskey-` 或 `ENROLL_TOKEN` 时拒绝写入

目录 0700，文件 0600。目标已存在且不是 0700 目录、或是符号链接时拒绝。`mkdir` 受 `umask 077` 影响，演练里用「先建再 chmod」造出一个 0755 目录来证明拒绝。

```bash
bash deploy/vpn/ctl.sh restore /path/to/bundle --force
```

恢复会写回上面全部文件，并只启动备份里记下的管理模式。noise 私钥必须和 sqlite 一起回来，否则节点要重新注册。内嵌 DERP 开着时，DERP 私钥也要一起回来；包里没有这把密钥时，恢复不会凭空造一把。不要把旧 sqlite 恢复进已经迁移过的更新 minor 版本。新打的包不含 `state/enroll/token-labels.json`。旧包里如果还有这个文件，`restore` 打印 `ignoring obsolete`，不把它复制回去；包里没有它也照常恢复。

异地副本不要把明文目录拷走。仓库里不放 age 或 gpg 的密钥。`backup` 结束时打印的 cron（每天 03:15 UTC；`\%` 是为了让 cron 不把 `%` 当成换行）：

```cron
15 3 * * * umask 077; tar -C /var/backups -cf - idoris-vpn-YYYYmmddTHHMMSSZ | age -r AGE_RECIPIENT -o /mnt/offhost/idoris-vpn-$(date -u +\%Y\%m\%d).tar.age
```

把路径换成 `backup` 实际打印的那次目录。systemd timer 跑同一条命令即可。age 的身份放在另一台机器上。看 `/mnt/offhost` 上最新文件的时间，超过一天没有新文件就当备份停了。

干净主机演练是 `bash deploy/vpn/test/restore-drill.sh`：在 `deploy/` 下复制一份栈（compose 的构建上下文要能找到 `vpn/`），注册一个节点，备份，`down -v`，删掉原目录，在空副本上 `restore`，检查原节点仍在列表里，并且**同一枚** token 还能再注册一个节点。2026-10-27 项目 `idoris-vpn-ctl-771396` 退出码 0，日志以 `drill: ok` 结束。0755 目录和符号链接目标被拒绝；恢复后 `drill-member` 仍在列表里，同一枚 token 又注册了 `drill-member-2`。`token list` 把恢复出来的旧哈希显示为 `-`，没有打出完整哈希。新包里没有 `token-labels.json`。随后把这个文件放进包里再 `restore --force`，退出码 0，输出里有 `ignoring obsolete`，目标树没有这个文件，`drill-member` 还在，`token list` 仍是那一行 `-`。同一轮用注册镜像的 `list-credentials` 读了一份混合配置：旧的十六进制字符串列成 `-`、`aaaaaaaaaaaa`、`-`，对象标签 `bootstrap-acme` 列成该标签、`bbbbbbbbbbbb` 和 `2026-10-27T00:00:00Z`。这一轮内嵌 DERP 是关的，包里没有 DERP 私钥。

## 7. Headplane 的四种访问

只有一个旋钮：`.env` 里的 `HEADPLANE_ACCESS=tunnel|lan|tailnet|proxy`，或 `bootstrap.sh --headplane-access`，或 `ctl.sh up --headplane-access`。它同时改 `headplane/config.yaml` 的 `base_url` 和 `cookie_secure`、主机绑定，以及哪一个 Headplane 在跑。四种配置互斥。`/admin` 默认不挂在 Headscale 的公网主机名上。

| 模式 | 谁听得到 | `base_url` | `cookie_secure` |
|---|---|---|---|
| `tunnel`（默认） | `127.0.0.1:$HEADPLANE_PORT` | `http://127.0.0.1:<端口>` | `false` |
| `lan` | 拒绝绑在 `127.0.0.1`。用 `HEADPLANE_BIND` 或 `HEADPLANE_LAN_HOST` | `http://<局域网主机>:<端口>` | `false`，并打印三条警告 |
| `tailnet` | 没有主机端口。`vpn-sidecar` + `headplane-tailnet` | `http://vpn-server.idoris.internal:3000` | `false` |
| `proxy` | 仍是 `127.0.0.1`。前面的 TLS 反代转到这里 | `HEADPLANE_BASE_URL`，必须是 `https://` | `true` |

`proxy` 的主机名如果等于 `server_url` 的主机名，会拒绝，除非 `HEADPLANE_ALLOW_PUBLIC_ADMIN=1`。反代要传 `Host` 和 `X-Forwarded-Proto`。Headplane 在 `policy.mode: file` 时 ACL 页只读。

`--tailnet-admin` 不能和别的 `--headplane-access` 一起用。`ctl.sh up` 不带访问参数时，按 `.env` 里的 `HEADPLANE_ACCESS` 再套一次（默认 `tunnel`）。保存的 `tailnet` 只在管理模式已经是 `tailnet-admin` 时保留；发布模式配上 `tailnet` 会被改回 `tunnel`。

隧道：

```bash
ssh -L 3000:127.0.0.1:3000 user@server
```

浏览器打开 `http://127.0.0.1:3000/admin`。登录用 `ctl.sh apikeys create` 打出的 key，表单字段是 `api_key`。

局域网明文 HTTP 时 cookie 不能带 `Secure`，否则浏览器会丢掉。同一二层上的人可以偷走会话。能用隧道就用隧道。

tailnet 管理面：

```bash
bash deploy/vpn/bootstrap.sh init --org office --tailnet-admin
bash deploy/vpn/ctl.sh up --tailnet-admin
```

`vpn-server` 的 token 在 `enroll/minted-tokens.txt`。sidecar 有持久状态（`tailscaled.state` 非空）时**不再**铸一把新 key。`VPN_SERVER_LOGIN_SERVER` 经 compose 传进容器；留空时用注册服务返回的 `control_url`。预授权 key 已经带了 tag，sidecar 不要再传 `--advertise-tags`。两个 Headplane 共用数据卷，不能同时跑。

`deploy/vpn/test/headplane-login.sh` 对四种模式都做了登录：`POST /admin/login`，带上返回的会话 cookie 再 `GET` 管理页。匿名是非 200，带 cookie 是 200。2026-10-27 的结果是四条都通过（`tunnel` / `lan` / `proxy` 的 `secure` 分别是 0、0、1；`tailnet` 是 0）。`tailnet` 这一条是在 sidecar 的网络命名空间里访问 `127.0.0.1:3000`，发布出来的主机端口是关的，sidecar 入口被换成了 `sleep`，所以它证明的是 cookie 和 `base_url`，不是从 `100.64.0.0/10` 走完一次真实登录。tailnet 上管理员打得开、成员打不开，由隔离探针检查。

## 8. 管理模式要活过 backup、restore、up

选中的模式写在 gitignore 的 `.admin-mode` 里，值是 `published` 或 `tailnet-admin`。`bootstrap.sh`、`ctl.sh up` / `down` / `backup` / `restore` / `upgrade` 只停**当时在写**的那个 Headplane，恢复时也只拉起原来在跑的服务。发布出来的 `headplane` 和 `headplane-tailnet` 不会一起跑。

探针在 `tailnet-admin` 下做 backup 和 restore，并检查发布出来的 Headplane 仍然是停的、它的主机端口仍然拒绝连接。数字见第 15 节。

## 9. 每套部署一个 compose 项目

`bootstrap.sh` 把 `COMPOSE_PROJECT_NAME` 写进 `.env`。`--instance office` 得到 `idoris-vpn-office`。名字已经是 `idoris-vpn` 或 `idoris-vpn-` 开头时保持原样。默认是 `idoris-vpn`。`.env` 里已经有一个不同的名字时拒绝改掉。和正在运行的、compose 文件不是这一份的项目撞名时拒绝。

第二套要放在另一个目录，并使用另一组端口：`HEADSCALE_PORT`、`HEADPLANE_PORT`、`ENROLL_PORT`、`DERP_STUN_PORT`。

STUN 要单独看。compose 把宿主机的 `DERP_STUN_PORT` 映射到容器里的 `3478/udp`。DERP 地图广播的是 `headscale/config.yaml` 里的 `stun_listen_addr`（默认 `0.0.0.0:3478`），也就是容器内端口，不是宿主机映射端口。第二套如果只改 `DERP_STUN_PORT=3479`，客户端仍会向公网 UDP 3478 发 STUN，打到第一套。要让第二套的 STUN 可用：把 `stun_listen_addr` 改成客户端能够到达的端口，并且宿主机以**同一个**端口发布（例如 `3479:3479`）。生产上第一套应保持 3478，因为客户端从地图学到的就是这个端口。这次没有在一台机器上同时跑两套开着内嵌 DERP 的实例。

## 10. 子网网关和 Local AI 的路由

优先把 `idoris-vpnd` 装在 Local AI 主机上，用 `<组织>-local-ai` 的 token，主机名用 `<组织>-local-ai`。成员走 tag 规则，不需要网关。

网关是给**不能跑 Tailscale** 的设备用的。办公室里一台 Linux 宣布局域网前缀，远程成员经它访问该前缀。

```bash
bash deploy/vpn/bootstrap.sh init --org office --lan-cidr 192.168.1.0/24
```

脚本会加上 `tag:office-gateway`、注册项 `office-gateway`、`autoApprovers.routes`（只有这个 tag 能自动批准该前缀），以及 `office@` 到该前缀的 ACL。端口是 8740、8742、443，再加 11434（局域网里的 Ollama）。成员到带 tag 的 Local AI 主机没有 11434。

没有「网关 → 成员」的规则。子网流量默认做 SNAT，回包来自网关节点自己的地址，有状态的 ACL 放行回包。不要把局域网前缀写成源。

`idoris-vpnd` 的配置有 `advertise_routes` 和 `accept_routes`。空列表表示**不管理**路由，不会把已经宣布的前缀清掉。嵌入模式拒绝 `advertise_routes`（没有 TUN）。网关和要宣布前缀的 Local AI 用 system 模式，并在 Linux 上打开转发：

```json
{
  "enroll_url": "https://enroll.example.org",
  "enroll_token_file": "/etc/idoris/enroll.token",
  "hostname": "office-gateway",
  "mode": "system",
  "accept_routes": true,
  "advertise_routes": ["192.168.1.0/24"]
}
```

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

持久化写进该发行版的 `sysctl.d`。批准仍由 Headscale 的 `autoApprovers` 完成；失败时用 `ctl.sh routes approve`。

主机上已有官方 `tailscaled` 时，注册之后也可以手动宣布，这是替代办法：

```bash
sudo tailscale set --advertise-routes=192.168.1.0/24
```

成员侧要接受路由（配置里的 `accept_routes: true`，或 `tailscale set --accept-routes`）。同在办公室局域网里的人访问的是局域网地址，包不进 tailnet。

本机探针（内核模式的 tailscale 容器，网关带 `net.ipv4.ip_forward=1`）检查：`autoApprovers` 把 `10.88.88.0/24` 批给网关 tag；本组织成员的路由走 `tailscale0`，`:8740` 通、`:22` 不通；另一组织没有这条路由。实验室里如果宿主机自己还有一条到该前缀的路由，包会绕开 tailnet。

## 11. Linux 要在登录前就跑起来；Tailscale SSH

`idoris-vpnd service install` 今天只写**用户**服务：Linux 是 `systemctl --user`，单元在 `~/.config/systemd/user/idoris-vpnd.service`，`WantedBy=default.target`，`NoNewPrivileges=yes`。它不会执行 `loginctl enable-linger`。用户单元在这个用户登录之前不会启动。

网关和 Local AI 这种必须在有人登录前就在线的主机，用下面两种之一。`service install --system` 还没有进二进制，下面是现在就能用的手工做法。

让用户单元在开机时启动：

```bash
sudo loginctl enable-linger "$USER"
```

或者写一个系统单元（路径按发行版放在 `/etc/systemd/system/idoris-vpnd.service`）：

```ini
[Unit]
Description=iDoris VPN membership daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/idoris-vpnd run --config /etc/idoris/vpnd.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now idoris-vpnd.service
```

这次是在 macOS 上读代码写的配方，没有在一台 Linux 上安装这个系统单元。system 模式要能连上本机 `tailscaled` 的套接字；嵌入模式不需要，也不能宣布路由。

Tailscale SSH 同样不由策略单独打开。`vpn/` 里的守护进程没有设置 `RunSSH`。ACL 放行 tcp/22 只表示有人可以连这个端口。Local AI 主机在 system 模式注册完成之后还要：

```bash
sudo tailscale set --ssh
```

然后管理员的 SSH 才会走到策略里那条 `action: check`，并停在 `headscale auth approve --auth-id <id>`。这次没有对一台真实 Local AI 执行 `tailscale set --ssh`。

macOS 的 `service install` 写的是 launchd 用户代理。Windows 今天会失败，原文是 `service install is not supported on windows; run idoris-vpnd run under your service manager`。见 `docs/17`。

## 12. 该看的检查

每天或接到告警时看这四件。`/healthz` 今天只写 `ok\n`，不检查 Headscale。建议 Go 增加 `GET /readyz`：用当前的 API key 打一次 Headscale（例如列出用户），成功返回 200，key 过期或 Headscale 不可达返回 503。另一个代理来实现。在那之前，用下面的命令。

注册服务的 API key 是 365 天（`--expiration 8760h`）。`ctl.sh apikeys list` 能看到前缀和到期时间。轮换：

```bash
bash deploy/vpn/ctl.sh apikeys create --expiration 8760h
# 把打印出来的 hskey-api-... 写进 enroll/headscale.apikey，模式 0600
docker compose restart enroll
bash deploy/vpn/ctl.sh apikeys expire --prefix <旧前缀>
```

`SIGHUP` 只重读 `config.json` 里的租户，进程里的 Headscale 客户端仍是启动时读到的那把 key，所以要 `restart`。写文件之前先把旧 key 留在备份里。Headplane 的个人登录 key 是另一把，`apikeys create` 的默认 90 天就是给它的；换登录 key 不必重启注册服务。

证书在反代上。`headscale/config.yaml` 的 `tls_cert_path` 和 `tls_key_path` 是空的，Headscale 自己不提供 TLS。看 `server_url` 和注册服务主机名的证书剩余天数（`openssl s_client` 或反代自己的检查）。这次没有对一台公网反代做这件事。

备份新鲜度看第 6 节异地文件的时间。`bash deploy/vpn/ctl.sh health` 是 `headscale health`。

## 13. 镜像和 Actions 钉在摘要上

`deploy/vpn/compose.yaml` 和 `deploy/vpn/enroll/Dockerfile` 使用 `name:tag@sha256:...`。标签留下来是为了可读，拉取以摘要为准。`ops-lib.sh` 里修卷用的 alpine 也钉了摘要。注册服务自己的镜像仍是本地构建的 `idoris-vpn-enroll:local`。

`.github/workflows/` 下的 Action 钉在完整 commit SHA 上，后面跟 `# vX.Y.Z`。注解标签要剥到 commit（`refs/tags/<tag>^{}`）；轻量标签的 SHA 就是 commit。

更新时：

```bash
docker buildx imagetools inspect headscale/headscale:v0.29.6
git ls-remote https://github.com/actions/checkout refs/tags/v4.4.0
```

把新的索引摘要写回 `image:` 行，保留标签。然后在 `deploy/vpn` 里 `docker compose pull`，并构建一次注册镜像确认 Dockerfile 的 `FROM` 仍能解析。不要用浮动的 `latest`。这次对三张第三方镜像做了 `docker compose pull`，并对钉了摘要的 Dockerfile 做了一次 `docker build`。

## 14. CI

`.github/workflows/vpn-deploy.yml` 在 `deploy/vpn/**` 变更时跑：shellcheck、`py_compile`、策略单测（含对抗前缀）、`docker compose config -q`（默认和 `tailnet-admin`）。这些在每次 push / pull request 上跑。

隔离探针需要 Docker 和 `/dev/net/tun`，还会拉起多台 tailscale 容器。托管的 `ubuntu-latest` 经常没有 TUN，所以探针只在 `workflow_dispatch` 和每天 `17 6 * * *` 的 schedule 上跑。便宜检查不在 schedule 上重复。

`.github/workflows/vpn-ci.yml` 的路径过滤包含 `deploy/vpn/**`。`.github/workflows/vpn-licenses.yml` 只跟 Go 模块（许可证清单来自 Go，不来自 shell）。

推 `vpn-v*` 标签时，`.github/workflows/vpn-release.yml` 为 linux、darwin、windows 的 amd64 和 arm64 构建 `idoris-vpnd` 和 `idoris-vpn-enroll`，附上 `SHA256SUMS` 和 `vpn/THIRD_PARTY_NOTICES.md`。用的是工作流自带的 `GITHUB_TOKEN`，仓库里没有密钥。这次没有推标签，所以还没有一个可下载的 Release。

## 15. 隔离探针

```bash
bash deploy/vpn/test/probe.sh
```

脚本自选 compose 项目名和端口，复制一份实验室配置（`server_url` 改成 `http://headscale:8080`，关掉内嵌 DERP），拉起两个组织、管理员、一台网关和一台模拟的局域网主机，然后拆掉卷。不会改仓库里的 `server_url`。生产配置仍然拒绝明文和非 443。

最近一次（2026-10-27，compose 项目 `idoris-vpn-ctl-245872`，退出码 0）：`probe: 52 passed, 0 failed`，然后 `probe: ok`。其中 38 条是节点之间的允许/拒绝：成员只能打本组织 Local AI 的 8740/8742/443，打不到 22 和 8080，打不到另一组织，打不到管理员；Local AI 打成员的 22 和 8740 被拒绝；管理员只能打两台 Local AI 的 22。其余是路由自动批准、经 `tailscale0` 的局域网 8740 允许和 22 拒绝、另一组织没有该路由、管理员能打开 tailnet 上的 Headplane（当时是 `100.64.0.7:3000`）、两个成员不能，在 `tailnet-admin` 下 backup 和 restore 之后发布出来的 Headplane 仍是停止的、主机端口（当时 `127.0.0.1:51614`）仍拒绝连接，以及凭证生命周期：`token new --label laptop-a` 可以注册，再铸 `laptop-b`，重复标签被拒绝，吊销 `laptop-a` 之后登记返回 401，`laptop-b` 仍可登记，`offboard --label laptop-b --node-id` 先吊销再 expire 再 delete，最后一枚凭证拒绝删除。内嵌 DERP 关着，备份跳过了容器里不存在的 `derp_server_private.key`。

这是实验室明文注册，不覆盖生产上的 https:443 重拨。

## 16. Headscale 挂了

用服务器自己的 SSH，不要用 Tailscale SSH（那条路依赖 Headscale）。`ctl.sh break-glass` 打的是同一份清单：SSH 只允许密钥；公网只开 443/tcp、3478/udp、22/tcp；Headplane 和 enroll 不要出现在公网网卡上；反代做速率限制。Headscale 停着的时候，已经连上的 WireGuard 会话会维持到 map 过期。用 compose 把进程拉起来，或 `ctl.sh restore`。
