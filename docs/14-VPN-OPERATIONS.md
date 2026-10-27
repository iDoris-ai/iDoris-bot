# 14 · VPN 运维：单组织默认、管理员、Headplane、子网网关

**日期：** 2026-10-27 · **状态：** 在本机 Docker 上用 Headscale v0.29.6、Headplane 0.8.2、`tailscale/tailscale:v1.104.2` 验证过。公网域名和真实 TLS 代理不在这次验收里。

产品默认是**一个组织**（大约十几个人）加一台 Local AI。成员在办公室局域网里直接访问这台机器；在家里则通过 tailnet。多组织仍然可以加在同一台 Headscale 上，那是显式的进阶操作，隔离只靠策略文件，做不到 SaaS 那种硬边界。

身份模型、端口和「user 不是隔离边界」见 `docs/12-VPN-HEADSCALE.md`。这里只写怎么把 `deploy/vpn` 跑起来、怎么管。

## 1. 第一次启动（一个组织）

1. 把 `deploy/vpn/headscale/config.yaml` 和 `deploy/vpn/headplane/config.yaml` 里的 `vpn.example.org` 换成你的公网主机名。`server_url` 必须是 `https://主机名`，不能带非 443 的端口。Tailscale 客户端之后会强制改拨 443。`bootstrap.sh` 在占位域名还在、或者 URL 不是 https/443 时会拒绝往下走。
2. 在装了 Docker Compose v2 和 python3 的服务器上：

```bash
bash deploy/vpn/bootstrap.sh init --org office --admin admin
```

省略 `--org` 时组织名是 `office`，省略 `--admin` 时管理员用户是 `admin`。这一次会：

- 写出 `headplane/cookie_secret`（32 字节）、`enroll/headscale.apikey`、`enroll/config.json`、`headscale/managed.json`。这些都在 gitignore 里，不要提交。
- 在 `headscale/policy.hujson` 的 `BEGIN/END idoris-managed` 标记之间写入该组织的规则，跑 `headscale policy check`，再对 Headscale 发 SIGHUP。标记以外的手写规则会保留。
- 创建 Headscale 用户 `admin` 和 `office`。
- 建注册项并**只在本次打印** token：`admin`（个人节点，无 tag，每分钟 5 次，TTL 5 分钟）、`office`（成员，TTL 10 分钟）、`office-local-ai`（`tag:office-local-ai`，每分钟 5 次）。

再跑一次 `init` 是安全的：已有用户、API key、cookie、token 都不会换。本机第二次 `init` 的日志是「enrollment entries already present; no new tokens minted」，三个密钥文件的 SHA-256 不变。

Headscale v0.29 的 `policy check` 是打到正在运行的服务器上的 gRPC，不能在一个没有 socket 的一次性容器里做。`bootstrap.sh` 因此先拉起 Headscale，建好用户，再检查，再 SIGHUP。策略文件是就地改写的：对单文件做 `rename` 会让容器里的绑定挂载失效。

## 2. 管理员和成员怎么加入

管理员设备和普通成员用同一套客户端、同一条注册路径。差别只是 token 属于哪个 Headscale 用户。

1. 安装官方 Tailscale。
2. 把对应 token 放到 `enroll_token_file`，写 `~/.idoris/vpnd.json`：

```json
{"enroll_url": "https://enroll.example.org", "enroll_token_file": "/home/me/.idoris/enroll.token"}
```

3. `idoris-vpnd service install --config ~/.idoris/vpnd.json`。

管理员用 `admin` 那条 token。设备是 `admin` 用户的个人节点，不打 tag。`group:admins` 里列出 `admin@`。Headscale 没有 `autogroup:admin`。

管理员能做的事，策略里写死了，没有别的：

- `group:admins` → `tag:<组织>-local-ai:22`，外加一条 `ssh` 规则，`users` 是 `autogroup:nonroot`，`action` 是 `check`。Tailscale SSH 要这条 ACL **和** 这条 ssh 规则同时在。`check` 会停住，等有人执行 `headscale auth approve --auth-id <id>`（id 在 SSH 横幅和 `<server_url>/auth/<id>`）。
- 若启用了下面的 tailnet 管理面：`group:admins` → `tag:vpn-server:3000`（Headplane）和 `:22`。成员没有到 `tag:vpn-server` 的规则。

管理员到不了成员的业务端口，成员之间也没有规则。Local AI 对成员开放的端口是 8740（iDoris）、8742（Agent24）、443。不要在成员规则里加 `autogroup:member`、`autogroup:tagged` 或 `*`，那些是整台 Headscale 范围的。

MagicDNS 名字是 `<主机名>.idoris.internal`，里面没有组织名。Local AI 主机名要用带组织前缀的，例如 `office-local-ai`。

`policy.hujson` 底部的 `tests` 块保持注释。Headscale 会在 `policy check` 和每次 SIGHUP 时用**当前活着的节点**跑测试；组织还没有节点时，测试会让重载失败。

## 3. 再加一个组织（进阶）

```bash
bash deploy/vpn/bootstrap.sh add-tenant globex
bash deploy/vpn/bootstrap.sh add-tenant globex --lan-cidr 192.168.50.0/24
```

`--lan-cidr` 可以重复。同一条前缀不能属于两个组织，脚本会拒绝。需要更硬的边界时，另起一套 `deploy/vpn`，不要靠这一份策略文件。

## 4. 在服务器上操作：`ctl.sh`

`bash deploy/vpn/ctl.sh help`。脚本按自己的路径找到 compose 目录，当前工作目录无所谓。除了 `apikeys create`，输出里的 pre-auth key 和完整 API key 会被抹掉。

| 命令 | 作用 |
|---|---|
| `status` / `health` | `compose ps` 和 `headscale health` |
| `users list` | 用户 |
| `nodes list` | 节点 |
| `nodes expire --identifier ID [--expiry RFC3339] [--disable]` | 让个人节点到期 |
| `nodes delete --identifier ID --force` | 删除。没有 `--force` 不会执行 |
| `preauthkeys list` / `preauthkeys expire --id ID` | 列出的是打码后的 key。注册服务自己签发，这里不新建 |
| `routes list` / `routes approve --identifier ID --routes CIDR` / `routes clear --identifier ID` | 对应 `nodes list-routes` 和 `nodes approve-routes`。自动批准失败时用 approve |
| `policy check` / `policy reload` | 检查，reload 再发 SIGHUP |
| `apikeys list` / `apikeys create [--expiration 90d]` / `apikeys expire --prefix PFX` | `create` 会把新 key 打出来。这是登录 Headplane 的个人 key，不是注册服务那把 |
| `logs [headscale\|headplane\|enroll\|vpn-sidecar\|headplane-tailnet] [--tail N]` | 日志，secret 打码 |
| `backup [DIR]` | 先停 Headscale 和 Headplane，再复制 sqlite 和密钥 |
| `restore DIR --force` | 停服务，把备份拷回去，再启动。没有 `--force` 拒绝 |
| `up [--tailnet-admin]` | 启动。见第 5.3 节 |
| `down` | `docker compose down`，**保留**数据卷 |
| `upgrade` | 只打印升级步骤，不拉镜像 |
| `break-glass` | Headscale 挂了之后的 SSH 清单 |

备份内容：`db.sqlite`、存在的话还有 `db.sqlite-wal` 和 `db.sqlite-shm`、`noise_private.key`、`derp_server_private.key`、Headplane 数据目录。策略文件和 compose 在 git 里，不在卷里。noise 和 DERP 私钥必须和 sqlite 一起回来，否则节点要重新注册。不要把旧 sqlite 恢复进已经迁移过的更新 minor 版本。本机一次 `ctl.sh backup` 得到了 `db.sqlite`、两把私钥和 `hp_persist.db`；这次停服务之后没有 wal/shm 文件，脚本在它们不存在时会跳过。`restore` 的代码路径和它打印的说明在，这次没有把备份再写回一台正在跑的服务器。

升级：Headscale 不能跳 minor，也不能往下降 minor。先 `backup`，改 `compose.yaml` 里的镜像标签，`docker compose pull`，`up -d`，再 `health` 和 `policy check`。

## 5. 管理面怎么暴露

三个档位，由 `HEADPLANE_BIND` 决定主机上的监听地址。容器里面 Headplane 仍然听 `0.0.0.0:3000`。默认是 `127.0.0.1`。不要把 Headplane（3000）或 enroll（8787）绑到公网网卡。注册服务在 compose 里固定是 `127.0.0.1`。

### 5.1 本机 + SSH 隧道（默认）

`HEADPLANE_BIND` 不设。本机实测 `docker port` 为 `3000/tcp -> 127.0.0.1:<端口>`，`GET /admin` 返回 302（转到登录页）。

```bash
ssh -L 3000:127.0.0.1:3000 user@server
```

浏览器打开隧道另一端。若 `base_url` 仍是 `https://你的主机名`，用该 https 源，让代理转到本机端口。登录用 `ctl.sh apikeys create` 打出的 key，字段在 Headplane 里叫 API key。

### 5.2 办公室局域网

`HEADPLANE_BIND=192.168.x.x` 或 `0.0.0.0`，然后 `docker compose up -d headplane`。本机把绑定改成 `0.0.0.0` 之后，`docker port` 为 `3000/tcp -> 0.0.0.0:<端口>`，`/admin` 仍是 302。

`headplane/config.yaml` 里 `cookie_secure` 默认 `true`。本机对 `POST /admin/login`（表单字段 `api_key`）的响应是：

- `cookie_secure: true`：`Set-Cookie: _hp_auth=…; Path=/admin; Secure; SameSite=Lax`。浏览器在明文 HTTP 上会丢掉带 `Secure` 的 cookie，登录留不住。
- `cookie_secure: false` 并且 `base_url` 写成 `http://127.0.0.1:<端口>`：同一请求的 `Set-Cookie` 没有 `Secure`。这次登录返回 302。

办公室若真用明文 HTTP，必须两处一起改：`cookie_secure: false`，`base_url` 写成浏览器地址栏里的那个 http 源（含端口）。cookie 随后在局域网里明文传输，同一二层上的人可以偷走会话。能用 SSH 隧道就用隧道。`HEADPLANE_BIND` 不会自动改 `cookie_secure`。

前面有 TLS 反代时保持 `cookie_secure: true`，`base_url` 用 `https://主机名`（不要带 `/admin`）。反代要传 `Host` 和 `X-Forwarded-Proto`，并限制 Headscale 和 enroll 的请求速率。这次没有另起一台反代来验这条路径。

Headplane 在 `policy.mode: file` 时 ACL 页只读。配置和策略以文件为准。

### 5.3 只在 tailnet 上开 Headplane（已在容器里验证）

```bash
bash deploy/vpn/bootstrap.sh init --org office --tailnet-admin
export VPN_SERVER_ENROLL_TOKEN='<刚打印的 vpn-server token>'
bash deploy/vpn/ctl.sh up --tailnet-admin
```

`vpn-sidecar` 用注册项 `vpn-server` 以 `tag:vpn-server` 加入，内核模式，需要 `/dev/net/tun`。Headplane 使用 `network_mode: service:vpn-sidecar`，没有主机端口。两者共用 Headplane 的数据卷，不能和上面那个发布出来的 `headplane` 同时跑。`ctl.sh up --tailnet-admin` 会先停掉发布出来的那个；不带这个参数的 `ctl.sh up` 会停掉 profile。

策略：`group:admins` → `tag:vpn-server:3000,22`。成员没有规则。

本机探针里：管理员节点对 sidecar 的 tailnet 地址（当时是 `100.64.0.7:3000`）发 `GET /admin`，收到 HTTP 响应；`acme` 和 `globex` 的成员节点在同样的地址上拿不到 HTTP 响应。预授权 key 已经带了 tag，sidecar **不要**再传 `--advertise-tags`，tagOwners 会拒绝节点自己申请的 tag。

sidecar 的登录服务器默认用注册服务返回的 `control_url`（生产上是 `https://主机名`）。容器访问不到这个地址时（头发夹 NAT），设 `VPN_SERVER_LOGIN_SERVER`。

### 5.4 Headscale 挂了

用服务器自己的 SSH，不要用 Tailscale SSH（那条路依赖 Headscale）。`ctl.sh break-glass` 打的是同一份清单：

- SSH 只允许密钥。留一把不在 tailnet 节点上的本地管理员密钥。
- 公网防火墙只开 443/tcp（反代后面的 Headscale）、3478/udp（内嵌 DERP 的 STUN）、22/tcp。
- Headplane 和 enroll 不要出现在公网网卡上。
- 反代对 Headscale 和 enroll 做速率限制。
- Headscale 停着的时候，已经连上的 WireGuard 会话会维持到 map 过期；新注册和重新登录会失败。在 `deploy/vpn` 里用 compose 把进程拉起来，或 `ctl.sh restore`。私钥必须和 sqlite 一起回来。

## 6. 子网网关

优先把官方客户端和 `idoris-vpnd` 装在 Local AI 主机上，用 `<组织>-local-ai` 的 token，主机名用 `<组织>-local-ai`。这样成员走 tag 规则，不需要网关。

网关是给**不能跑 Tailscale** 的设备用的（另一台 NAS、没有权限安装客户端的盒子）。办公室里一台 Linux 宣布局域网前缀，远程成员经它访问该前缀。

```bash
bash deploy/vpn/bootstrap.sh init --org office --lan-cidr 192.168.1.0/24
```

脚本会加上 `tag:office-gateway`、注册项 `office-gateway`、`autoApprovers.routes`（只有这个 tag 能自动批准该前缀），以及 `office@` 到该前缀的 ACL。端口是 8740、8742、443，再加 11434（局域网里的 Ollama）。成员到带 tag 的 Local AI 主机**没有** 11434，那是网关前缀上才有的。

反向只允许 `tag:<组织>-gateway` → `<组织>@:*`，也就是网关这台机器访问自己的成员。不要把局域网前缀写成源：Tailscale 对子网流量默认做 SNAT，回包已经来自网关节点自己的地址；把整段局域网写成源，会让该网段里任意主机主动连成员。

Headscale v0.29 的 `autoApprovers.routes` 是「前缀 → 批准者列表」。空对象合法，表示不自动批准，那时用 `ctl.sh routes approve`。本机 `headscale policy check` 对空对象、对 `10.88.88.0/24`、对 `192.168.50.0/24` 都返回 `Policy is valid`。`0.0.0.0/0` 不会被自动批准。

网关主机：

```bash
sudo sysctl -w net.ipv4.ip_forward=1
# 持久化写进 sysctl.d，这里不代写具体发行版的文件名
sudo tailscale set --advertise-routes=192.168.1.0/24
```

`idoris-vpnd` 已有 `accept_routes`（成员要收下别人宣布的路由），**没有** `advertise_routes`。网关若用守护进程注册，注册之后仍要在主机上执行上面的 `tailscale set`。这是代码缺口，见文末。

成员侧要接受路由（`idoris-vpnd` 的 `accept_routes: true`，或 `tailscale set --accept-routes`）。不接受的话，客户端根本没有到该前缀的路由。

同在办公室局域网里的人，访问的是 Local AI 的局域网地址，包不进 tailnet。这是组网方式，不是这次在一张真实办公网卡上测得的数字。远程成员才走网关。

本机探针（内核模式的 tailscale 容器，网关带 `net.ipv4.ip_forward=1`）看到的是：

- `autoApprovers` 把 `10.88.88.0/24` 批给了 `tag:acme-gateway`。
- `acme` 成员的 `ip route get 10.88.88.10` 走 `tailscale0`。对 `:8740` 的 TCP 通，对 `:22` 不通。成员节点日志里有 `rejected due to acl`。
- `globex` 成员没有这条 tailscale 路由（`ip route get` 不走 `tailscale0`），对 `:8740` 不通。Headscale 没有把另一组织的前缀装进它的路由表。

实验室里如果宿主机自己还有一条到该前缀的路由，包会绕开 tailnet，ACL 管不到。生产上不要让公网或别的租户有一条直达你办公室前缀的路由。

## 7. 隔离探针

```bash
bash deploy/vpn/test/probe.sh
```

脚本自选 compose 项目名和端口，复制一份实验室配置（`server_url` 改成 `http://headscale:8080`，关掉内嵌 DERP，这样节点不会在注册之后被强制改拨 443），拉起两个组织、管理员、一台网关和一台模拟的局域网主机，然后拆掉卷。不会改仓库里的 `server_url`。生产配置仍然拒绝明文和非 443。

最近一次结果：`probe: 47 passed, 0 failed`，然后 `probe: ok`。其中 38 条是节点之间的允许/拒绝（成员只能打本组织 Local AI 的 8740/8742/443，打不到 22 和 8080，打不到另一组织，打不到管理员；Local AI 可以回连本组织成员；管理员只能打两台 Local AI 的 22）。其余是路由自动批准、经 tailscale0 的局域网 8740/22、另一组织没有该路由，以及管理员能打开 tailnet 上的 Headplane、两个成员不能。

这是实验室明文注册，不覆盖生产上的 https:443 重拨。

## 8. 这次没有改 Go，但网关宣布路由需要一处

`idoris-vpnd` 的配置有 `accept_routes` 和 `advertise_tags`，没有 `advertise_routes`，也不会把前缀写进 prefs。网关今天的做法是注册之后在主机上执行 `tailscale set --advertise-routes`。若要让守护进程自己宣布，需要在 vpnd 配置里增加该字段并设置 `prefs.AdvertiseRoutes`。注册服务和 Headscale 策略这边已经能发出 `tag:<组织>-gateway` 并自动批准。
