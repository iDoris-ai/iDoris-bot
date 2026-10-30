# 14 · VPN 运维：单组织默认、管理员、Headplane、子网网关

**日期：** 2026-10-28 · **状态：** 在本机 Docker 上用 Headscale v0.29.6、Headplane 0.8.2、`tailscale/tailscale:v1.104.2` 验证过。公网域名、真实 TLS 证书和一部手机的注册不在这次验收里。成员逐步操作见 `docs/17-VPN-MEMBER-ONBOARDING.md`。身份模型和「user 不是隔离边界」见 `docs/12-VPN-HEADSCALE.md`。

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
- 建注册项并打印 token：`admin`（`role: admin`，个人节点，无 tag，每分钟 5 次，TTL 5 分钟）、`office`（`role: member`，TTL 10 分钟）、`office-local-ai`（`role: local-ai`，`tag:office-local-ai`，每分钟 5 次）。带了 `--lan-cidr` 时还有 `office-gateway`（`role: gateway`），并且把同一批前缀写进该项的 `lan_cidrs`（已有项只补前缀，不换 token）。`--tailnet-admin` 或 `--headplane-access tailnet` 时还有 `vpn-server`（只有 `tag:vpn-server`，没有 join role；sidecar 用原始 token 和 `acl_tags`）。这两个旗标在生成策略之前归一，见第 7 节。新凭证写成 `token_hashes` 对象，标签是 `bootstrap-<注册项名>`（例如 `bootstrap-office`）。打印先一行标签，再一行 token。

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

`restore` 用包里校验过的 `ENROLL_UID` / `ENROLL_GID`（缺省 65532，拒绝 0）做同样的属主处理，目录也算在内：不跟随符号链接，目录 0700，文件 0600。操作员不是 root、而且 id 已经一致时只 `chmod`。不是 root 且 id 对不上时拒绝，提示以 root 再跑 `restore`。这次的 root 属主检查跑在一个临时 Alpine 容器里（容器自己的文件系统，不是 macOS 绑定挂载）：65532 和另一个 uid 都能读到密钥，非 root 去改成别的 uid 会被拒绝。演练见第 6 节。

## 3. 管理员、MagicDNS、反向规则

管理员设备和普通成员用同一套客户端。差别只是 token 属于哪个注册项。逐步安装见 `docs/17-VPN-MEMBER-ONBOARDING.md`。

管理员能做的事写在策略里：

- `group:admins` → `tag:<组织>-local-ai:22`，外加一条 `ssh` 规则，`users` 是 `autogroup:nonroot`，`action` 是 `check`。这只打开了控制面的许可。Local AI 主机在 system 模式的 idoris-vpnd 配置里写 `"ssh": true`，见第 11 节。策略里的 SSH 规则仍然决定谁可以连。`check` 会停住，等有人执行 `headscale auth approve --auth-id <id>`。
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
| `token revoke --entry NAME (--label LABEL \| --hash-prefix HEX) [--allow-empty]` | 两个选择器恰好一个，原样交给 CLI `revoke`。给了 `--allow-empty` 就一并传下去。成功行是 `revoked <entry> <label或-> <12位前缀>`。不带这个旗标时，最后一条会拒绝，先 `token new`。带上之后允许把这一项的最后一枚也吊销 |
| `offboard --entry NAME (--label LABEL \| --hash-prefix HEX) [--node-id N] [--allow-empty]` | **先**吊销这枚凭证。吊销失败则不 expire、不 delete。给了 `--node-id` 才 `nodes expire` 再 `nodes delete`。单独 expire 或 delete 节点不会吊销凭证。最后一枚同样要 `--allow-empty`；不带时拒绝，节点保持不动 |
| `logs [service] [--tail N]` | 日志，secret 打码 |
| `backup [DIR]` | 见第 6 节 |
| `restore DIR --force [--adopt-existing-volumes]` | 见第 6 节。没有 `--force` 拒绝。已有卷没有本目录标记时还要这个旗标 |
| `up [--published\|--tailnet-admin] [--instance NAME] [--headplane-access MODE]` | 按已保存的管理模式启动，并重新套用 `HEADPLANE_ACCESS` |
| `down` | `docker compose down`，**保留**数据卷和管理模式 |
| `upgrade` | 只打印升级步骤，不拉镜像 |
| `break-glass` | Headscale 挂了之后的 SSH 清单 |

`token new`、`token revoke` 和 `offboard` 的 `--label` 都交给 `idoris-vpn-enroll`。标签字符集是 `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`。同一注册项上重复的标签会被拒绝，错误里有 `already exists`。`--hash-prefix` 是 4 到 64 位十六进制，必须唯一命中一条。`token_hashes` 可以是旧的十六进制字符串，也可以是 `{"hash","label","created_at"}`；两种都能读，`invite` 写出对象。

注册服务在 SIGHUP 时按路径重读 `config.json`（非法文件会留下上一份）和 `headscale_api_key_file`（读不到、为空或探测失败会留下旧的 Headscale 客户端，日志里没有 key）。compose 把这两个文件都按**文件**绑进容器。`invite` / `revoke` 用 rename 换掉 `config.json`，绑定还指着旧 inode：本机 Docker 上 rename 之后容器里该路径是 ENOENT，重启才重新绑上新文件；在 Linux 上没有验证，按 bind mount 的语义容器可能一直读到旧内容，吊销就会悄悄不生效。所以 SIGHUP 在这套部署里不可靠，`ctl.sh` 在服务正在跑时执行 `docker compose restart enroll`，否则等下次启动。换 API key 见第 12 节。

`bootstrap.sh` 和 `policy.py` 改 `enroll/config.json` 时，和 `idoris-vpn-enroll` 用同一把 `<config>.lock`。Go 侧是 `flock(2)`，Python 侧是同一个文件上的 `fcntl.flock`。配置发放之后属于注册运行用户（镜像 USER，一般是 65532；非 root 操作员则是该操作员的 uid）。锁文件模式 0600。root 建锁时把属主改成这个 uid（拒绝 uid 0），之后 root 和这个用户进的是同一笔事务。改写用同目录里单独的临时文件，换上之后保留原来的属主和模式。`ctl.sh` 的吊销在容器里跑 CLI，用户是 `ENROLL_UID:ENROLL_GID`（缺省 `65532:65532`）。并发时一边吊销，一边 bootstrap 或 policy 拿着旧快照回写，被吊销的哈希不会回来。2026-10-28 在 macOS 上证明了本机进程里 Python flock 和 Go flock 互斥。属主、chown，以及两个容器抢同一把锁，是在 Docker Desktop 的 Linux 虚拟机里用命名卷做的，不是原生 Linux 宿主机，也不是穿过 virtiofs 的宿主机绑定挂载。这台 Docker Desktop 把 macOS 上的 0600 文件在容器里显示成 `0:0`，绑定挂载并不保留 Linux 属主。`idoris-vpn-enroll invite` 和 `revoke` 在调用者不是 root、且 uid/gid 与文件不一致时，在创建锁和写临时文件之前拒绝，错误给出 `sudo -u \#<uid> -g \#<gid> -- idoris-vpn-enroll invite --config <path>`。root 在 rename 之前把临时文件 chown 成原来的 uid/gid，并保留模式。root 新建的锁 chown 给配置属主，chown 失败则删除这把新锁。`vpn/integration/r5o_owner_test.go` 在这台 Docker Desktop 的 Debian bookworm 容器里以 root 跑过（容器自己的文件系统）：配置模式 0640、属主 65532，invite 和 revoke 之后配置仍是 65532，锁是 65532 且模式 0600，随后 uid 65532 再 invite 成功，属主不变。uid 65531 的 invite 失败，文件字节不变，没有留下锁，错误含 `sudo -u \#65532`。修复前同一次测试里 root invite 把配置写成 `uid=0 gid=0`，65531 的错误是 `permission denied`。没有在原生 Linux 宿主机上跑。

`list-credentials` 和其他只读路径打开这把锁时不创建文件。锁不存在，说明还没有写入者，直接读。锁在但打不开（权限或只读挂载）时同样退回无锁读。写入者打不开就失败，并且仍然会创建锁文件。只读不会留下一把新锁。root 创建的锁、再由 uid 65532 去改，以及只读列出时不创建锁，都在 Docker Desktop 的 Linux 虚拟机里看过。

`--allow-empty` 的转发用 `deploy/vpn/test/test_allow_empty.sh` 对 `ctl.sh` 的参数看过，没有连上一台活的 Headscale。

## 6. 恢复包

`ctl.sh backup [DIR]` 先停**当前**那个 Headplane 写入者、`vpn-sidecar`（如果容器在）和 Headscale，复制完再把刚才在跑的服务拉起来。另一个 Headplane 不会被启动。默认目录是 `$here/backups/<UTC 时间戳>`。父目录 `backups` 不存在时建成 0700。它若是符号链接，或已经存在但不是 0700，就拒绝，也不会把一个过宽的目录 chmod 成 0700。别的路径仍然要求父目录事先存在。

包里有：

- `headscale/db.sqlite`，以及当时存在的 `db.sqlite-wal`、`db.sqlite-shm`
- `headscale/noise_private.key`
- `headscale/derp_server_private.key`，仅当容器里真有这个文件。空文件在恢复时拒绝，而且是在停容器之前。Headscale v0.29.6 在 `derp.server.enabled: false` 时不创建它。探针和干净主机演练都关掉了内嵌 DERP，所以包里没有这把密钥
- Headplane 数据目录
- `sidecar/state.tar`，仅当 tailnet-admin 的 sidecar 卷里有非空的 `tailscaled.state`。这是管理节点的私钥：目录 0700，文件 0600，离开这台机器之前要加密。清单里不写密钥内容。没有 sidecar 时省略这个文件
- `state/`：`enroll/config.json`（token 哈希）、`enroll/headscale.apikey`、`headplane/cookie_secret`、`.env`、`headscale/managed.json`、部署中的 `config.yaml`、`policy.hujson`、`headplane/config.yaml`、`compose.yaml`（只放在包里，见下）
- `admin-mode` 和 `manifest.json`（镜像标签、id、digest、Headscale 版本、文件权限）。清单里出现 `idv1_`、`hskey-` 或 `ENROLL_TOKEN` 时拒绝写入

目录 0700，文件 0600。目标已存在且不是 0700 目录、或是符号链接时拒绝。`mkdir` 受 `umask 077` 影响，演练里用「先建再 chmod」造出一个 0755 目录来证明拒绝。

包是数据，不是代码。`restore` 在改宿主机文件、停任何容器之前先检查整棵树：拒绝符号链接、特殊文件、绝对路径和 `..`。`state/compose.yaml` 不写回，检出目录里的那份留下；两边不一致时打印 `restore: bundle compose.yaml differs from this checkout; keeping the checkout file`。`.env` 只接受项目名、端口、绑定地址、uid/gid、URL 和访问模式这一列；`ENROLL_IMAGE`、`IDORIS_VPN_VERSION` 和未知键都拒绝。普通文件 `state/enroll/token-labels.json` 仍然忽略（打印 `ignoring obsolete`）。同名符号链接按符号链接拒绝，不走忽略。

目的项目在改动之前就定下来：包里的 `COMPOSE_PROJECT_NAME`，否则是当前目录的项目名。和当前 shell 里的 `COMPOSE_PROJECT_NAME` 冲突就拒绝。撞名检查对当前项目和恢复后的项目各做一次。之后每一次 `docker compose` 都带 `-p`，子进程里的 `COMPOSE_PROJECT_NAME` 设成同一个名字。

数据库写入者必须全部停干净。中途停失败就把已经停掉的服务拉起来，宿主机文件还没动。通过之后先把将被覆盖的文件和卷复制到一个 0700 的临时目录。空的 DERP 私钥在停容器之前就拒绝。非空但不是 sqlite 的数据库会过前面的检查，在 `up --wait` 失败后回滚。

`ctl.sh down` 留下命名卷。快照不看容器还在不在：Headscale 容器在时仍用 `docker cp`；容器没了就用 Alpine 从 `headscale-data` 把 `db.sqlite`、noise、DERP、wal/shm 读出来，Headplane 卷和 sidecar 的 `tailscaled.state` 同样归档。空卷（没有 sqlite）也记成已有数据，回滚不会删它。sqlite 非空但拷不出来，就在改卷之前失败。

从记下快照起，失败会回滚。先写回原来的宿主机文件。快照 META 每行是 `kind rel uid gid mode`。`d enroll` 只恢复 `enroll` 目录的属主、组和模式，调用者是 root 才 chown。`f` 行写回文件后再 chmod，root 再 chown。`enroll/config.json.lock` 在快照里就按文件写回；快照时没有的路径记在 MISSING，失败的恢复若新建了锁，回滚会删掉。只删除这一次恢复**新造出来**的容器、卷和网络：动手前的名单里已经有的卷留下，不执行 `down -v`。然后用**失败前的配置** `up -d --force-recreate`，不用 `start`（`start` 不改已经按恢复配置发布出去的端口）。接着核对实际绑定；快照里有 headscale 时还要 `headscale health`。恢复启动之后跑 `idoris-vpn-enroll check`（最多 10 次，间隔 2 秒）。非法的注册 JSON 会在 Headplane 已经按新绑定重建之后把恢复判失败，再按原来的配置重建。回滚任一步失败就留下快照，打印 `restore: rollback incomplete; keeping snapshots` 以及 `host=`、`vol=`、`snap=` 的路径，不删除。还没改数据（phase 0）就失败时，临时目录仍会删掉。写回卷之后，回滚成功还要恢复出来的 `db.sqlite` 和快照 SHA-256 一致；服务健康不够。`docker cp`、解包、chown、删除 journal 在 `if !` 里执行，`set -e` 不管函数体，所以每一步都显式失败返回。对不上或某步失败就留下快照。回滚成功才删快照。sidecar 身份同样写回留下的 `vpn-sidecar-state`，不看 `vpn-sidecar` 容器还在不在；快照里没有 `sidecar-state.tar` 时，删掉卷上的 `tailscaled.state`。

另一份部署目录不能往这套留下的卷上恢复。Compose 5.1.2 在这台 Docker Desktop（Docker 29.4.0，linux/arm64）上不给卷打 `working_dir` 或 `config_files`；`down` 会删掉带着这些标签的容器，`docker compose ls` 也不再列出项目。`start_stack_for_mode` 和成功的 `restore` 在 `headscale-data` 里写 `/data/.idoris-deploy-dir`，内容是这份目录的物理路径。卷或网络上若真有 `working_dir` / `config_files` 且指向别处，同样拒绝。没有标签也没有标记时，`up` 仍不当成外来卷：直接 `docker compose up`、从没走过 `ctl.sh up` 的卷就是这样。同一目录在 `down` 之后对 `up` 不是碰撞。`restore` 要覆盖已经存在的卷时，必须先有正面证据：`headscale-data` 上的 `.idoris-deploy-dir` 解析后等于这份目录，或者这些卷根本不存在。没有标记就拒绝，错误写出卷名和 `--adopt-existing-volumes`。带上这个旗标会在 stderr 打印 `restore: --adopt-existing-volumes will overwrite:` 和卷名，然后继续，不交互询问。标记在但读不出来（不是普通文件，或 docker 读失败）一律拒绝，文案含 `unreadable marker`，不当成空标记，旗标也不放行。标记指向别的目录时仍然拒绝，文案里有 `has volume`。`deploy/vpn/test/test_restore_volumes.sh` 在这台 Docker Desktop 上用真实卷看过：外来标记拒绝；同一目录和无标记对 `up` 放行；无标记卷从另一个目录 `restore` 被拒绝，库字节仍是 `original-bytes`；加上旗标后打印卷名并进入 `creating stopped containers`（空 compose 随后失败，回滚完成，字节不变）；标记做成目录时，带不带旗标都拒绝，且没有 `will overwrite`。拿掉这道门之后，同一条无标记恢复会走到 `creating stopped containers`。把读失败当成空标记时，`reject_project_named` 对目录标记返回 0。没有容器时字节能写回；并用替身 docker 看过回滚命令是 `up -d --force-recreate`，不是 `start`，也不是 `down -v`，回滚失败时三个快照目录还在。同一支替身还看过：noise 私钥那次 `docker cp` 失败、后面的命令成功、读回的库又被写成和快照一样的字节时，拿掉 `|| return 1` 会打印 `rollback complete` 并删掉快照；加上之后输出含 `rollback incomplete`，三个快照还在，Alpine 解包也跑了。每次 docker 都退出 0、读回的库却是 `nope` 时，输出含 `does not match snapshot` 和 `rollback incomplete`，快照留下。拿掉容器这条路径上的校验后，同一次打印 `rollback complete`。`deploy/vpn/test/test_r5o_sidecar_rollback.sh` 在这台 Docker Desktop 上先让 Headscale 健康，`down` 留卷，卷里的 `tailscaled.state` 是 `original-sidecar`。再从带另一份 sidecar 身份和非法注册 JSON 的包 `restore`。注册容器报 `enroll-1 is unhealthy`（`up --wait` 在 `idoris-vpn-enroll check` 之前就失败），回滚打印 `rollback complete`，卷上的身份回到 `original-sidecar`。拿掉写回 sidecar 卷的那一步后，同一次仍打印 `rollback complete`，身份却是 `bundle-sidecar`。没有 tar 的快照会删掉事先写入的 `tailscaled.state`。`deploy/vpn/test/test_r5o_enroll_meta.sh` 在这台 Docker Desktop 的 Alpine 容器自己的文件系统上以 root 跑过：目录 0750、`config.json` 和 `config.json.lock` 0640，属主都是 65532。`chown_enroll_runtime 65531` 把它们改成 0700/0600 之后，回滚回到 0750/0640 和 65532，随后 uid 65532 的 `list-credentials` 和 `invite` 成功。跳过目录的 chmod 和 chown 时，目录停在 `(65531, 65531, 448)`（0700），期望是 `(65532, 65532, 488)`（0750）。macOS 绑定挂载不保留 Linux 属主，这一步没有在绑定挂载上验证。原生 Linux 宿主机上没有跑过。2026-10-28 干净主机演练项目 `idoris-vpn-r2d-533526`（Headscale 端口 65370）退出码 0，日志以 `drill: ok` 结束。`down` 之后从另一个目录 `restore` 被拒绝，输出里有 `has volume`，留下的数据库校验和不变。同一目录对一份垃圾库 `restore` 失败后，卷还在，校验和仍是 `down` 之后的那一份，随后脚本自己的 `down -v` 才删卷。局域网包把访问改成 `lan`、绑定改成 `0.0.0.0`，注册配置写成非法 JSON：恢复失败后 Headplane 仍发布在 `127.0.0.1`，回滚完成（没有 `rollback incomplete`），`headscale health` 通过且 `drill-member` 还在。同一轮导出 `COMPOSE_PROFILES=tailnet-admin` 再 `up --headplane-access tunnel`，第二个 Headplane 没有起来。只读凭证列表用夹具文件属主的 `--user` 跑，打印了 `credential shapes ok`。这台 Docker Desktop 把 macOS 上的 0600 文件在容器里显示成 `0:0`，`--user` 仍然读得到；这一步没有证明原生 Linux 上「锁属主和读者不一致」的回退。

成功的恢复用 `up -d --force-recreate`，不用 `start`。随后用 `docker compose port` 和 inspect 核对实际绑定。每次 `docker compose` 都按 `.env` 设置子进程的环境，`.env` 里没有的键会从子进程里去掉。父进程的环境不动。所以 `HEADPLANE_BIND=0.0.0.0 ctl.sh up --headplane-access tunnel` 仍然把 Headplane 绑在 `127.0.0.1`。注册文件的属主按恢复出来的 `ENROLL_UID` / `ENROLL_GID` 处理，见第 2 节。

tailnet-admin 的包如果带了 `sidecar/state.tar`，先解进卷再启动 sidecar 和 `headplane-tailnet`。没有这份 tar、shell 里也没有 `VPN_SERVER_ENROLL_TOKEN` 时，不把整个恢复判失败：Headscale 和注册服务照常起来，并打印补登记（`ctl.sh token new --entry vpn-server --label recovery ...`，再 `ctl.sh up --tailnet-admin`）。这次探针走的是有 tar 的那条路，没有执行这条补登记。

```bash
bash deploy/vpn/ctl.sh restore /path/to/bundle --force
```

已有卷但没有本目录的部署标记时，再加上 `--adopt-existing-volumes`。命令会先打印要覆盖的卷名。读不出标记、或标记属于别的目录时，这个旗标无效。

noise 私钥必须和 sqlite 一起回来，否则节点要重新注册。内嵌 DERP 开着时，DERP 私钥也要一起回来；包里没有这把密钥时，恢复不会凭空造一把。不要把旧 sqlite 恢复进已经迁移过的更新 minor 版本。

异地副本不要把明文目录拷走。仓库里不放 age 或 gpg 的密钥。每次都要先打一个新包，再归档这一次的目录。`deploy/vpn/offhost-backup.sh` 读 `backup_dir=`，用 `manifest.json` 的 `created_utc` 做归档名，成功后把这个时间写进 `OFFHOST_DIR/idoris-vpn-backup.created`。备份、tar 或 age 失败时不更新这个文件。看这个时间，不要看归档的 mtime。`backup` 结束时打印的 cron（每天 03:15 UTC）调用的是这个脚本。`AGE_RECIPIENT` 换成自己的 age 公钥，路径换成部署目录：

```cron
15 3 * * * umask 077; AGE_RECIPIENT=AGE_RECIPIENT OFFHOST_DIR=/mnt/offhost bash /path/to/deploy/vpn/offhost-backup.sh
```

打印时用 `%q` 给路径加引号。age 的身份放在另一台机器上。这条命令在临时目录里用替身 `ctl.sh` 和 `age` 跑过两轮：两次得到两个快照和两个归档，戳等于第二次的 `created_utc`；age 或 backup 失败时戳不动。没有在一台真实的 cron 上装过。

干净主机演练是 `bash deploy/vpn/test/restore-drill.sh`：在 `deploy/` 下复制一份栈（compose 的构建上下文要能找到 `vpn/`），注册一个节点，备份，`down -v`，删掉原目录，在空副本上 `restore`，检查原节点仍在列表里，并且**同一枚** token 还能再注册一个节点。副本和源目录对过指纹。2026-10-28 项目 `idoris-vpn-r2d-128161`（Headplane 端口 58578）退出码 0，日志以 `drill: ok` 结束。同一轮还检查了：临时 Alpine 容器里 root 把注册树交给 65532 和 65531，非 root 改成别的 uid 被拒绝（`ownership ok`）；0755 目录和符号链接目标被拒绝；`backups` 父目录是符号链接时拒绝，删掉链接后默认备份父目录和子目录都是 0700；`HEADPLANE_BIND=0.0.0.0 ctl.sh up --headplane-access tunnel` 实际绑在 `127.0.0.1:58578`，`lan` 绑在 `0.0.0.0:58578`，再把原包 `restore` 之后回到 `127.0.0.1` 且 `drill-member` 还在；符号链接、名叫 `token-labels.json` 的符号链接、`ENROLL_IMAGE` 和空 DERP 私钥都在停 Headscale 之前被拒绝；一份非 sqlite 的数据库触发回滚，`drill-member` 还在并且 Headscale 恢复健康；包里的 `compose.yaml` 多了一行注释，恢复打印 `restore: bundle compose.yaml differs from this checkout; keeping the checkout file`，目标文件的 sha256 仍是检出目录那份。恢复后 `drill-member` 仍在列表里，同一枚 token 又注册了 `drill-member-2`。`token list` 把恢复出来的旧哈希显示为 `-`，没有打出完整哈希。新包里没有 `token-labels.json`。随后把这个文件放进包里再 `restore --force`，退出码 0，输出里有 `ignoring obsolete`，目标树没有这个文件。同一轮用注册镜像的 `list-credentials` 读了一份混合配置：旧的十六进制字符串列成 `-`、`aaaaaaaaaaaa`、`-`，对象标签 `bootstrap-acme` 列成该标签、`bbbbbbbbbbbb` 和 `2026-10-27T00:00:00Z`。这一轮内嵌 DERP 是关的，包里没有 DERP 私钥。演练本身不删 sidecar 卷；删卷之后靠 `sidecar/state.tar` 回来是探针做的，见第 15 节。

## 7. Headplane 的四种访问

只有一个旋钮：`.env` 里的 `HEADPLANE_ACCESS=tunnel|lan|tailnet|proxy`，或 `bootstrap.sh --headplane-access`，或 `ctl.sh up --headplane-access`。它同时改 `headplane/config.yaml` 的 `base_url` 和 `cookie_secure`、主机绑定，以及哪一个 Headplane 在跑。四种配置互斥。`/admin` 默认不挂在 Headscale 的公网主机名上。

| 模式 | 谁听得到 | `base_url` | `cookie_secure` |
|---|---|---|---|
| `tunnel`（默认） | `127.0.0.1:$HEADPLANE_PORT` | `http://127.0.0.1:<端口>` | `false` |
| `lan` | 拒绝绑在 `127.0.0.1`。用 `HEADPLANE_BIND` 或 `HEADPLANE_LAN_HOST` | `http://<局域网主机>:<端口>` | `false`，并打印三条警告 |
| `tailnet` | 没有主机端口。`vpn-sidecar` + `headplane-tailnet` | `http://vpn-server.idoris.internal:3000` | `false` |
| `proxy` | 仍是 `127.0.0.1`。前面的 TLS 反代转到这里 | `HEADPLANE_BASE_URL`，必须是 `https://` | `true` |

`proxy` 的主机名如果等于 `server_url` 的主机名，会拒绝，除非 `HEADPLANE_ALLOW_PUBLIC_ADMIN=1`。反代要传 `Host` 和 `X-Forwarded-Proto`。Headplane 在 `policy.mode: file` 时 ACL 页只读。

`--tailnet-admin` 不能和别的 `--headplane-access` 一起用。两个旗标在参数解析之后、生成策略和注册项之前就归一：`--headplane-access tailnet` 等于 `--tailnet-admin`，会建 `vpn-server`。冲突在调用 docker 之前拒绝。这一步用真实的 `policy.py` 和一个不拉容器的 docker 替身测过，不是一整次 `bootstrap.sh` 拉起的 tailnet。`ctl.sh up` 不带访问参数时，按 `.env` 里的 `HEADPLANE_ACCESS` 再套一次（默认 `tunnel`）。保存的 `tailnet` 只在管理模式已经是 `tailnet-admin` 时保留；发布模式配上 `tailnet` 会被改回 `tunnel`。

子进程的 compose 环境以 `.env` 为准，见第 6 节。shell 里导出的 `HEADPLANE_BIND` 不会盖过 `tunnel` 写进去的 `127.0.0.1`。`COMPOSE_PROFILES`、`COMPOSE_FILE`、`COMPOSE_PATH_SEPARATOR` 在每一次 `docker compose` 和直接的 `docker`（查卷、写部署目录标记）里都会从子进程去掉。`COMPOSE_PROJECT_NAME` 仍由脚本设置。发布模式点名启动 `headscale enroll headplane`。tailnet 模式先点名 `headscale enroll`，只有 shell 里有 `VPN_SERVER_ENROLL_TOKEN`，或 sidecar 卷里已经有非空的 `tailscaled.state`，才再启动 `vpn-sidecar headplane-tailnet`。发布模式在启动前先停掉 `headplane-tailnet`；核对时它若仍在跑，启动失败。`COMPOSE_PROFILES=tailnet-admin` 导出后再 `up --headplane-access tunnel`，替身 docker 的日志里没有把第二个 Headplane 拉起来。两个方向都在 `deploy/vpn/test/test_compose_env.sh` 里用替身测过。演练项目 `idoris-vpn-r2d-533526` 里导出 `COMPOSE_PROFILES=tailnet-admin` 后再 `up --headplane-access tunnel`，第二个 Headplane 没有起来。

端口、绑定和 `base_url` 只算一次，同时写进 `headplane/config.yaml` 和 `.env` 的 `HEADPLANE_PORT`、`HEADPLANE_BIND`、`HEADPLANE_ACCESS`。`lan` 再写 `HEADPLANE_LAN_HOST`，`proxy` 再写 `HEADPLANE_BASE_URL`。`.env` 里是 `HEADPLANE_PORT=3000`、命令前导出 `HEADPLANE_PORT=3300` 时，生成的 `base_url` 和写回的 `.env` 都是 3300。`deploy/vpn/test/test_headplane_port.sh` 用替身 docker 看过，没有拉起 Headplane。

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

`vpn-server` 的 token 在 `enroll/minted-tokens.txt`。sidecar 有持久状态（`tailscaled.state` 非空）时**不再**铸一把新 key。管理模式已经是 `tailnet-admin` 时，普通 `ctl.sh up` 在这份状态还在的情况下不要求 `VPN_SERVER_ENROLL_TOKEN`。token 只在第一次登记、卷里还没有非空 `tailscaled.state` 时才要。`deploy/vpn/test/test_sidecar_identity.sh` 用替身 docker 看过：两者都缺时退出并提示先 export；状态在时，启动行是 `up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet`。2026-10-28 探针项目 `idoris-vpn-r2d-309640` 在删卷恢复之后执行 `ctl.sh down`，再在没有 `VPN_SERVER_ENROLL_TOKEN` 的 shell 里 `ctl.sh up`，sidecar 和 `headplane-tailnet` 重新起来。`VPN_SERVER_LOGIN_SERVER` 经 compose 传进容器；留空时用注册服务返回的 `control_url`。预授权 key 已经带了 tag，sidecar 不要再传 `--advertise-tags`。两个 Headplane 共用数据卷，不能同时跑。

`deploy/vpn/test/headplane-login.sh` 对四种模式都做了登录：`POST /admin/login`，带上返回的会话 cookie 再 `GET` 管理页。匿名是非 200，带 cookie 是 200。2026-10-27 的结果是四条都通过（`tunnel` / `lan` / `proxy` 的 `secure` 分别是 0、0、1；`tailnet` 是 0）。`tailnet` 这一条是在 sidecar 的网络命名空间里访问 `127.0.0.1:3000`，发布出来的主机端口是关的，sidecar 入口被换成了 `sleep`，所以它证明的是 cookie 和 `base_url`，不是从 `100.64.0.0/10` 走完一次真实登录。tailnet 上管理员打得开、成员打不开，由隔离探针检查。

## 8. 管理模式要活过 backup、restore、up

选中的模式写在 gitignore 的 `.admin-mode` 里，值是 `published` 或 `tailnet-admin`。`bootstrap.sh`、`ctl.sh up` / `down` / `backup` / `restore` / `upgrade` 只停**当时在写**的那个 Headplane，恢复时也只拉起原来在跑的服务。启动用的是第 7 节点名的服务列表，不继承 shell 里的 `COMPOSE_PROFILES`。发布出来的 `headplane` 和 `headplane-tailnet` 不会一起跑：发布模式不留下正在跑的 `headplane-tailnet`，tailnet 模式停掉发布出来的 `headplane`。两个方向的替身测试见第 7 节。2026-10-28 探针项目 `idoris-vpn-r2d-309640` 里，导出 `COMPOSE_PROFILES=tailnet-admin` 后 `up --published --headplane-access tunnel`，发布出来的 Headplane 在跑、`headplane-tailnet` 停着；再 `up --tailnet-admin`，发布出来的停、tailnet 的在跑。

探针在 `tailnet-admin` 下做 backup 和 restore，并检查发布出来的 Headplane 仍然是停的、它的主机端口仍然拒绝连接。备份带上 `sidecar/state.tar`。随后删掉全部卷、清掉 shell 里的 `VPN_SERVER_ENROLL_TOKEN`，再 `restore`：sidecar 和 `headplane-tailnet` 起来，状态文件的 sha256 和备份前一致，发布出来的 Headplane 仍然停止。数字见第 15 节。没有 sidecar 状态、也没有 token 时的补登记命令见第 6 节；这次没有走那条路。

## 9. 每套部署一个 compose 项目

`bootstrap.sh` 把 `COMPOSE_PROJECT_NAME` 写进 `.env`。`--instance office` 得到 `idoris-vpn-office`。名字已经是 `idoris-vpn` 或 `idoris-vpn-` 开头时保持原样。默认是 `idoris-vpn`。`.env` 里已经有一个不同的名字时拒绝改掉。和正在运行的、compose 文件不是这一份的项目撞名时拒绝。`down` 之后容器没了，卷还在，撞名还要看卷，见第 6 节的部署目录标记。没有标记、也没有 `working_dir` 标签的卷不会被当成另一套部署。

第二套要放在另一个目录，并使用另一组端口：`HEADSCALE_PORT`、`HEADPLANE_PORT`、`ENROLL_PORT`、`DERP_STUN_PORT`。

STUN 要单独看。compose 把宿主机的 `DERP_STUN_PORT` 映射到容器里的 `3478/udp`。DERP 地图广播的是 `headscale/config.yaml` 里的 `stun_listen_addr`（默认 `0.0.0.0:3478`），也就是容器内端口，不是宿主机映射端口。第二套如果只改 `DERP_STUN_PORT=3479`，客户端仍会向公网 UDP 3478 发 STUN，打到第一套。要让第二套的 STUN 可用：把 `stun_listen_addr` 改成客户端能够到达的端口，并且宿主机以**同一个**端口发布（例如 `3479:3479`）。生产上第一套应保持 3478，因为客户端从地图学到的就是这个端口。这次没有在一台机器上同时跑两套开着内嵌 DERP 的实例。

## 10. 子网网关和 Local AI 的路由

优先把 `idoris-vpnd` 装在 Local AI 主机上，用 `<组织>-local-ai` 的 token，主机名用 `<组织>-local-ai`。成员走 tag 规则，不需要网关。

网关是给**不能跑 Tailscale** 的设备用的。办公室里一台 Linux 宣布局域网前缀，远程成员经它访问该前缀。

```bash
bash deploy/vpn/bootstrap.sh init --org office --lan-cidr 192.168.1.0/24
```

脚本会加上 `tag:office-gateway`、注册项 `office-gateway`、`autoApprovers.routes`（只有这个 tag 能自动批准该前缀），以及 `office@` 到该前缀的 ACL。同一批前缀写入该项的 `lan_cidrs`，`GET /v1/discover` 原样返回。端口是 8740、8742、443，再加 11434（局域网里的 Ollama）。成员到带 tag 的 Local AI 主机没有 11434。

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

`idoris-vpnd service install` 不带 `--system` 时只写**用户**服务：Linux 是 `systemctl --user`，单元在 `~/.config/systemd/user/idoris-vpnd.service`，`WantedBy=default.target`，`NoNewPrivileges=yes`。它不会执行 `loginctl enable-linger`。用户单元在这个用户登录之前不会启动。

网关和 Local AI 这种必须在有人登录前就在线的主机，用 `sudo idoris-vpnd service install --system --config FILE`：Linux 写 systemd 系统单元，macOS 写 LaunchDaemon，Windows 用开机以 SYSTEM 运行的计划任务。细节、权限和卸载见 docs/16 第 12 节。

系统服务进程没有 `$HOME`。Linux 单元的 `StateDirectory=idoris` 让 systemd 导出 `STATE_DIRECTORY=/var/lib/idoris`（多个 `StateDirectory=` 时是冒号分隔列表，守护进程用第一段，必须是绝对路径）。身份文件是 `$STATE_DIRECTORY/vpnd-state.json`，嵌入式节点目录是 `$STATE_DIRECTORY/node`，控制器锁和状态套接字锁都在 `$STATE_DIRECTORY/locks`。单元还有 `Environment=XDG_RUNTIME_DIR=/run/idoris`，所以没写 `listen` 时状态套接字是 `/run/idoris/vpnd.sock`。2026-10-28 在上面那个 systemd 容器里把 `HOME` 去掉、只留 `XDG_RUNTIME_DIR=/run/idoris`，`idoris-vpnd status` 去连的就是 `unix:/run/idoris/vpnd.sock`，不读主目录。两个都没设置时，状态命令仍会落到临时目录；机器服务的单元不会走那条。

macOS 的 LaunchDaemon 在 plist 里写 `EnvironmentVariables`，`STATE_DIRECTORY` 为 `/var/lib/idoris`。安装程序创建 `/var/lib/idoris` 和 plist 要写的 `/var/log/idoris`，模式 `0700`，属主 root。用户级 LaunchAgent 不设 `STATE_DIRECTORY`。没设 `XDG_RUNTIME_DIR` 时，状态套接字落在 `$STATE_DIRECTORY/vpnd.sock`。Windows 上 SYSTEM 的 `os.UserConfigDir()` 在系统配置文件目录里，不该拿来放机器状态。计划任务的启动命令是 `cmd /c set STATE_DIRECTORY=C:\ProgramData\idoris&& ...`，状态、节点目录和锁都在安装程序已经用 icacls 收紧的 `C:\ProgramData\idoris`。这两边只核对了 golden 渲染，以及 `GOOS=windows go build ./...` 和 `GOOS=windows go vet ./...`。没有在 macOS 或 Windows 上把机器服务跑起来。

2026-10-28 在 OrbStack 上用 Debian bookworm 的 systemd 252.39 做 PID 1（`docker run --privileged --cgroupns=host`，挂载 `/sys/fs/cgroup`，`--tmpfs /run` 和 `/run/lock`）。镜像是 `debian:bookworm` 加上 `systemd systemd-sysv procps iproute2 ca-certificates`。先用修复前的 linux/arm64 二进制复现：`/etc/idoris/vpn.json`（0600）内容为 `{"control_url":"https://vpn.example.org","auth_key":"hskey-lab","mode":"system"}`，`/tmp/idoris-vpnd service install --system --config /etc/idoris/vpn.json`，然后 `systemctl daemon-reload` 和 `systemctl start idoris-vpnd`。`systemctl is-active` 停在 `activating`，`NRestarts` 一直增加。journal 原文：

```text
idoris-vpnd: state file: home directory: $HOME is not defined
```

然后用修复后的 linux/arm64 二进制再装一次（不是 sleep 桩，也不是刚才那个修复前的二进制）。`systemctl is-system-running` 为 `running`。服务到达 `active` 后空等 30 秒，`NRestarts=0`。进程环境里有 `STATE_DIRECTORY=/var/lib/idoris` 和 `XDG_RUNTIME_DIR=/run/idoris`，没有 `HOME`。容器里没有 tailscaled。守护进程保持运行并重试，不退出。`XDG_RUNTIME_DIR=/run/idoris`、`HOME` 为空时，`idoris-vpnd status --json` 能读到带 `phase` 的状态。`/var/lib/idoris` 模式 0750（单元的 `StateDirectoryMode`），`vpnd-state.json` 0600，内容有 `https://vpn.example.org`，没有 auth key。`/var/lib/idoris/locks` 0700，锁文件 0600。`/run/idoris` 0750，`/run/idoris/vpnd.sock` 0600。`systemctl restart` 之后仍是 `active`，`NRestarts` 仍是 0。再用 root、同一份配置、`STATE_DIRECTORY=/var/lib/idoris`、另一个 `--listen unix:/tmp/r3svc-second.sock` 手工起第二个进程，立刻失败，错误含 `another idoris-vpnd` 和 `system backend`。第一个服务仍是 `active`。容器和镜像随后删除。

这套检查写在 `vpn/integration/r3svc_systemd_test.go`（`//go:build integration`），`make integration` 会跑到它。2026-10-28 在这台机器上 `make integration` 全绿，`go test` 315s，其中 `TestR3svcSystemdMachineService` 34.55s PASS。宿主不能起带 `--privileged` / cgroup 的 systemd 容器时，测试跳过并写明原因，而不是失败。下面那段手工单元配方仍然没有按文档里的原文在 Linux 上安装过。

没法用 `--system` 时，下面两种手工做法仍然可用。

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

Tailscale SSH 同样不由策略单独打开。Local AI 主机在 system 模式的 idoris-vpnd 配置里写 `"ssh": true`。策略里的 SSH 规则仍然决定谁可以连。管理员的 SSH 会走到策略里那条 `action: check`，并停在 `headscale auth approve --auth-id <id>`。

macOS 的 `service install` 写的是 launchd 用户代理。Windows 今天会失败，原文是 `service install is not supported on windows; run idoris-vpnd run under your service manager`。见 `docs/17`。

## 12. 该看的检查

每天或接到告警时看这四件。`/healthz` 只写 `ok\n`，不检查 Headscale。`GET /readyz` 用当前的 API key 打一次 Headscale：成功返回 200（API key 不足 30 天到期时带 `warning`）；key 已过期、401/403 或 Headscale 不可达返回 503，响应里是固定短语，不回传上游正文。两个端点都不限速。也可以用下面的命令手动看。

注册服务的 API key 是 365 天（`--expiration 8760h`）。`ctl.sh apikeys list` 能看到前缀和到期时间。轮换：

```bash
bash deploy/vpn/ctl.sh apikeys create --expiration 8760h
# 把打印出来的 hskey-api-... 写进 enroll/headscale.apikey，模式 0600
docker compose restart enroll
bash deploy/vpn/ctl.sh apikeys expire --prefix <旧前缀>
```

`SIGHUP` 也会重读 `headscale_api_key_file`，读不到、为空或探测失败时保留旧客户端。但这个文件是单文件绑定：只有原地写入（同一个 inode，例如 `cat > enroll/headscale.apikey`）容器才看得到；用编辑器或 `mv` 换文件看不到。最稳妥的是写完后 `docker compose restart enroll`，不管文件怎么换的都有效。写文件之前先把旧 key 留在备份里。Headplane 的个人登录 key 是另一把，`apikeys create` 的默认 90 天就是给它的；换登录 key 不必重启注册服务。

证书在反代上。`headscale/config.yaml` 的 `tls_cert_path` 和 `tls_key_path` 是空的，Headscale 自己不提供 TLS。看 `server_url` 和注册服务主机名的证书剩余天数（`openssl s_client` 或反代自己的检查）。这次没有对一台公网反代做这件事。

备份新鲜度看第 6 节异地文件的时间。`bash deploy/vpn/ctl.sh health` 是 `headscale health`。

## 13. 镜像和 Actions 钉在摘要上

`deploy/vpn/compose.yaml`、`vpn/integration/**/compose*.yaml` 的 `image:` 行、`deploy/vpn/enroll/Dockerfile` 的 `# syntax=` 和 `FROM` 默认值，以及探针、演练、`tailnet-entrypoint.sh`、`credentials.sh`、`headplane-login.sh` 里拉起的第三方镜像，都是 `name:tag@sha256:...`。标签留在名字或注释里，拉取以摘要为准。`ops-lib.sh` 里修卷和属主检查用的 alpine 也钉了摘要。注册服务自己的镜像仍是本地构建的 `${ENROLL_IMAGE:-idoris-vpn-enroll:local}`。恢复拒绝用包里的 `ENROLL_IMAGE` 或 `IDORIS_VPN_VERSION` 换掉它。

`FROM` 的摘要写在 `ARG` 的默认值上。构建时传入另一个 `GO_IMAGE` 或 `RUNTIME_IMAGE` 仍然可以换掉。`.github/workflows/vpn-ci.yml` 没有 `services:` 或 `container:` 镜像；`make integration` 用的是上面那些 compose 文件。

`.github/workflows/` 下的 Action 钉在完整 commit SHA 上，后面跟 `# vX.Y.Z`。注解标签要剥到 commit（`refs/tags/<tag>^{}`）；轻量标签的 SHA 就是 commit。

更新时：

```bash
docker buildx imagetools inspect headscale/headscale:v0.29.6
git ls-remote https://github.com/actions/checkout refs/tags/v4.4.0
```

把新的索引摘要写回 `image:` 行，保留标签。然后在 `deploy/vpn` 里 `docker compose pull`，并构建一次注册镜像确认 Dockerfile 的 `FROM` 仍能解析。不要用浮动的 `latest`。这次跑了 `docker compose config -q`（`deploy/vpn/compose.yaml` 的默认和 `tailnet-admin`，以及 `vpn/integration/compose.yaml`，项目名是一次性的 `idoris-vpn-r2d-cfg` / `idoris-vpn-r2d-int`）。隔离探针拉起了钉过摘要的 Headscale、Headplane 和 tailscale 容器，并构建了注册镜像。没有另跑一遍 `docker compose pull`。

## 14. CI

`.github/workflows/vpn-deploy.yml` 在 `deploy/vpn/**` 变更时跑：shellcheck（含 `offhost-backup.sh`、探针、演练、登录证明和三个 shell 测试）、`py_compile`（`policy.py` 和 `bundle.py`）、策略和包的单测、`docker compose config -q`（默认和 `tailnet-admin`）。这些在每次 push / pull request 上跑。本机这次跑过同一组 shellcheck、`bash -n`，以及 `python3 -m unittest discover -s deploy/vpn/test -p 'test_*.py'`（32 个测试通过）。没有触发 GitHub 上的这次工作流。

隔离探针需要 Docker 和 `/dev/net/tun`，还会拉起多台 tailscale 容器。托管的 `ubuntu-latest` 经常没有 TUN，所以探针只在 `workflow_dispatch` 和每天 `17 6 * * *` 的 schedule 上跑。便宜检查不在 schedule 上重复。

`.github/workflows/vpn-ci.yml` 的路径过滤包含 `deploy/vpn/**`。`.github/workflows/vpn-licenses.yml` 只跟 Go 模块（许可证清单来自 Go，不来自 shell）。

推 `vpn-v*` 标签时，`.github/workflows/vpn-release.yml` 为 linux、darwin、windows 的 amd64 和 arm64 构建 `idoris-vpnd` 和 `idoris-vpn-enroll`，附上 `SHA256SUMS` 和 `vpn/THIRD_PARTY_NOTICES.md`。用的是工作流自带的 `GITHUB_TOKEN`，仓库里没有密钥。这次没有推标签，所以还没有一个可下载的 Release。

## 15. 隔离探针

```bash
bash deploy/vpn/test/probe.sh
```

脚本自选 compose 项目名和端口，把部署树复制到 `deploy/.probe-src`（和 `deploy/vpn` 同级，compose 的构建上下文才能找到 `vpn/`）。实验室改写只发生在副本上：`server_url` 改成 `http://headscale:8080`，关掉内嵌 DERP。结束时对源目录里的 `.admin-mode`、`.env`、compose 和注册文件对指纹，包括在 `docker compose build` 之前就退出的那一次。不会改仓库里的 `server_url`。生产配置仍然拒绝明文和非 443。

最近一次（2026-10-28，compose 项目 `idoris-vpn-r2d-309640`，Headscale 端口 53276，Headplane 端口 53280，退出码 0）：`probe: 58 passed, 0 failed`，然后 `probe: ok`。这一轮多确认了两件事：导出 `COMPOSE_PROFILES=tailnet-admin` 后，发布模式只留下发布出来的 Headplane，tailnet 模式只留下 `headplane-tailnet`；删卷恢复之后 `down`，再在清掉 `VPN_SERVER_ENROLL_TOKEN` 的 shell 里 `up`，sidecar 和 `headplane-tailnet` 重新起来。前一次同一天的 `idoris-vpn-r2d-438232` 是 `probe: 55 passed, 0 failed`，没有这两项。438232 的记录：其中 38 条是节点之间的允许/拒绝：成员只能打本组织 Local AI 的 8740/8742/443，打不到 22 和 8080，打不到另一组织，打不到管理员；Local AI 打成员的 22 和 8740 被拒绝；管理员只能打两台 Local AI 的 22。其余是 `GET /v1/discover` 给 `acme-gateway` 返回了 `10.88.88.0/24`、路由自动批准、经 `tailscale0` 的局域网 8740 允许和 22 拒绝、另一组织没有该路由、管理员能打开 tailnet 上的 Headplane（当时是 `100.64.0.7:3000`）、两个成员不能，在 `tailnet-admin` 下 backup 和 restore 之后发布出来的 Headplane 仍是停止的、主机端口（当时 `127.0.0.1:56046`）仍拒绝连接，删掉全部卷并清掉 shell 里的 `VPN_SERVER_ENROLL_TOKEN` 之后 sidecar 状态的 sha256 和备份一致、发布出来的 Headplane 仍然停止，以及凭证生命周期：`token new --label laptop-a` 可以注册，再铸 `laptop-b`，重复标签被拒绝，吊销 `laptop-a` 之后登记返回 401，`laptop-b` 仍可登记，`offboard --label laptop-b --node-id` 先吊销再 expire 再 delete，最后一枚凭证拒绝删除。内嵌 DERP 关着，备份跳过了容器里不存在的 `derp_server_private.key`。同一天用 `PROBE_EARLY_ABORT=1` 在 `docker compose build` 之前退出：源目录的 `.admin-mode`（内容 `mode=tailnet-admin`）sha256 前后都是 `af2ee253b422d1620f160b3f23261b6ecd61bbc648e2801efebc26c643ba42ab`，清理没有报告源目录被改过。

这是实验室明文注册，不覆盖生产上的 https:443 重拨。

## 16. Headscale 挂了

用服务器自己的 SSH，不要用 Tailscale SSH（那条路依赖 Headscale）。`ctl.sh break-glass` 打的是同一份清单：SSH 只允许密钥；公网只开 443/tcp、3478/udp、22/tcp；Headplane 和 enroll 不要出现在公网网卡上；反代做速率限制。Headscale 停着的时候，已经连上的 WireGuard 会话会维持到 map 过期。用 compose 把进程拉起来，或 `ctl.sh restore`。
