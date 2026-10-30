# 17 · VPN 成员上手

**日期：** 2026-10-27。运维侧的启动、备份和策略见 `docs/14-VPN-OPERATIONS.md`。

这里只写已经对上代码或对上 Headscale v0.29.6 容器 `--help` 的步骤。没有推 `vpn-v*` 标签，所以 GitHub Release 里还没有二进制。没有用一部手机完成注册。没有在 Windows 上安装任务计划，也没有在 Linux 上安装系统单元。

## 1. 程序从哪来

标签 `vpn-v*` 被推上去之后，`.github/workflows/vpn-release.yml` 会构建：

- `idoris-vpnd` 和 `idoris-vpn-enroll`
- linux、darwin、windows
- amd64 和 arm64（Windows 带 `.exe`）
- `SHA256SUMS`
- `vpn/THIRD_PARTY_NOTICES.md`

`CGO_ENABLED=0`。Action 钉在 commit SHA 上。工作流只用自带的 `GITHUB_TOKEN`。

在有 Release 之前，在仓库里构建本机架构：

```bash
cd vpn
CGO_ENABLED=0 go build -trimpath -o idoris-vpnd ./cmd/idoris-vpnd
```

把二进制放到 `PATH` 里。校验和以 Release 上的 `SHA256SUMS` 为准；本地构建没有那份文件。

官方 Tailscale 客户端仍然要装。`idoris-vpnd` 负责向 iDoris 的 Headscale 注册并保持登录。手机和平板用官方 App，见第 6 节。

## 2. 每个平台都一样的三件事

操作员给你两样东西：注册服务的公网地址（`https://enroll.example.org` 这种，没有路径），以及一枚 token 或一条加入码（`idoris-join-v1.` 开头）。

1. 控制服务器必须**逐字**等于 Headscale 的 `server_url`：`https`，端口 443，没有路径，没有多余的斜杠。多一个端口、用了 `http`、或写成注册服务的地址，客户端都会走到别的协调服务器。实验室里的 `http://headscale:8080` 只存在于探针，不能写进成员的配置。
2. token 放在只有自己可读的文件里，例如 `chmod 600 ~/.idoris/enroll.token`，文件内容就是那一行 token。
3. MagicDNS 名字是 `<主机名>.idoris.internal`。组织名不在里面。Local AI 的主机名用 `office-local-ai` 这种带前缀的。

加入码里的 `role` 来自注册项。`bootstrap.sh` 现在会给新建的项写上 `admin`、`member`、`local-ai` 或 `gateway`。旧项没有 `role` 时，加入码会写成 `member`；预授权 key 仍然使用该项的 `acl_tags`。`vpn-server` 没有 join role，sidecar 用原始 token。

丢了 token、节点过期、设备被偷、域名写错，见第 8 到 11 节。

## 3. macOS 成员

安装官方 Tailscale。然后：

```bash
mkdir -p ~/.idoris
chmod 700 ~/.idoris
printf '%s\n' '把操作员给的 token 贴在这里' > ~/.idoris/enroll.token
chmod 600 ~/.idoris/enroll.token
```

`~/.idoris/vpnd.json`：

```json
{
  "enroll_url": "https://enroll.example.org",
  "enroll_token_file": "/Users/你/.idoris/enroll.token",
  "accept_routes": true
}
```

```bash
idoris-vpnd service install --config ~/.idoris/vpnd.json
idoris-vpnd status
```

`service install` 在 macOS 上写的是当前用户的 launchd 代理。管理员用自己的 `admin` token，命令相同。设备是管理员用户的个人节点，不打 tag。

有加入码时也可以 `idoris-vpnd join 'idoris-join-v1....'`。网关码会问这台是不是 Local AI；`--yes` 会跳过提问，那时网关还要 `--device` 或 `--whole-subnet`。程序不会自己提权，它打印需要的 `sudo` 命令。

## 4. Linux 成员

配置和 macOS 相同，token 路径按家目录改。然后：

```bash
idoris-vpnd service install --config ~/.idoris/vpnd.json
```

这写的是用户级 systemd：`~/.config/systemd/user/idoris-vpnd.service`，`WantedBy=default.target`。用户还没登录时它不会跑。个人电脑可以接受。要在开机、无人登录时就在线（网关、Local AI），先：

```bash
sudo loginctl enable-linger "$USER"
```

或者用 `sudo idoris-vpnd service install --system --config FILE` 装成机器级服务（见 `docs/16` 第 12 节和 `docs/14` 第 11 节）。这次没有在 Linux 真机上执行 `loginctl` 或以 root 安装系统单元。

成员要收下别人宣布的路由时，配置里写 `"accept_routes": true`。

## 5. Windows 成员

`idoris-vpnd service install` 在 Windows 上直接失败，输出是：

```text
service install is not supported on windows; run `idoris-vpnd run` under your service manager
```

今天的做法：安装官方 Tailscale，把和 macOS 一样的 JSON 放到一个只有该用户能读的路径，在登录后的终端里前台跑：

```text
idoris-vpnd.exe run --config C:\Users\你\.idoris\vpnd.json
```

需要开机自启时，由操作员自己用任务计划程序在用户登录时启动这条命令。仓库里没有一份已验证的任务 XML。状态端口在 Windows 上默认是 `tcp:127.0.0.1:7845`。

## 6. iOS 和 Android

装官方 Tailscale。应用里的入口各版本用词不同（自定义协调服务器、备用服务器，或登录页上的服务器地址）。把那一栏设成和 `server_url` 完全相同的 URL，例如 `https://vpn.example.org`。不要填注册服务的地址，不要加 `/admin`，不要加端口。

官方 App 不会读 `idoris-vpnd` 的 token。操作员在服务器上注册这台设备。下面的子命令和标志是 2026-10-27 用镜像 `headscale/headscale:v0.29.6`（`--help`，`--network none`）核对过的。没有用手机走完。

用户 id 是数字。先查：

```bash
bash deploy/vpn/ctl.sh users list
```

设备在 App 里提交之后，Headscale 里会出现一条待注册记录。v0.29 的 `nodes register` 仍在，帮助里标明弃用，要改用：

```bash
docker compose exec headscale headscale auth register --auth-id <id> --user <用户名>
```

也可以发一把预授权 key 给这台手机（`--user` 是数字 id，不是名字；默认 1 小时过期）：

```bash
docker compose exec headscale headscale users list
docker compose exec headscale headscale preauthkeys create --user <数字id> --expiration 1h
```

需要标签时再加上 `--tags`。可重复或临时节点用 `--reusable`、`--ephemeral`。别名 `preauthkey`、`authkey`、`pre` 指向同一组命令。key 只显示一次。

`ctl.sh preauthkeys` 只列出和作废，不创建。成员电脑优先走注册服务，不要把这种长寿命 key 当成日常办法。

## 7. Local AI 主机的主人

向操作员要 `<组织>-local-ai` 的 token，不要用成员那枚。

```json
{
  "enroll_url": "https://enroll.example.org",
  "enroll_token_file": "/etc/idoris/enroll.token",
  "hostname": "office-local-ai",
  "mode": "system",
  "accept_routes": true
}
```

主机名决定 MagicDNS：`office-local-ai.idoris.internal`。

这台机器要在开机时就在线，用第 4 节的 linger 或系统单元。嵌入模式可以当成员用，但不能宣布路由。

Local AI 主机在 system 模式的 idoris-vpnd 配置里写 `"ssh": true`。策略里的 SSH 规则仍然决定谁可以连。管理员连上来时会停在待批准，操作员执行：

```bash
docker compose exec headscale headscale auth approve --auth-id <id>
```

id 在 SSH 横幅和 `<server_url>/auth/<id>` 上。这条没有对真实主机会话执行过。

## 8. 网关主人

只能是 Linux，而且是 system 模式。先让操作员用 `--lan-cidr` 建好 `tag:<组织>-gateway` 和自动批准。然后：

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

`advertise_routes` 为空时，守护进程不碰已经宣布的路由，也不会把它们清掉。嵌入模式会拒绝这个字段。手工替代是注册之后 `sudo tailscale set --advertise-routes=192.168.1.0/24`。

开机自启用系统单元或 `loginctl enable-linger`，见第 4 节。网关没有到成员端口的 ACL；回包靠有状态的规则。不要在策略里把整段局域网写成源。

## 9. token 丢了

操作员在服务器上补一枚。`--label` 传给 `idoris-vpn-enroll invite`，写进该项的 `token_hashes` 对象：

```bash
bash deploy/vpn/ctl.sh token new --entry office --label laptop-2 --enroll-url https://enroll.example.org
```

输出里有 token、加入码和 12 位哈希前缀。明文在后续检查之前追加到 `enroll/minted-tokens.txt`（0600，gitignore）。`ctl.sh` 再用 `list-credentials` 核对这个标签，然后重启注册服务。把新 token 写进那台电脑的 `enroll.token`，重启 `idoris-vpnd`。

查看这一项已有的凭证。不打印 token，也不打印完整哈希：

```bash
bash deploy/vpn/ctl.sh token list --entry office
```

每行是标签、12 位前缀、`created_at`，用制表符分开。没有标签或时间时是 `-`。

吊销某一枚。`--label` 和 `--hash-prefix` 恰好给一个，原样交给 CLI：

```bash
bash deploy/vpn/ctl.sh token revoke --entry office --label laptop-2
```

`--hash-prefix` 是 4 到 64 位十六进制，必须唯一命中一条。成功行是 `revoked office laptop-2 <12位前缀>`。同一项上重复的标签会被拒绝。最后一枚删不掉，错误里有 `refusing to remove the last token hash`；先 `token new` 留下一把，再吊销要废的那把。

## 10. 节点过期

`headscale/config.yaml` 里 `node.expiry` 是 `4320h`（180 天）。旁边的注释写：成员设备要重新注册，带 tag 的节点（Local AI）不过期。这次没有把一台带 tag 的节点放到过期时间之后去核对，注释就是注释。

个人节点到期后，`idoris-vpnd` 在仍持有有效注册 token 时会再取一把预授权 key 并登录（代码在 `vpn/internal/vpnd/reconciler.go`）。这次没有把 expiry 拨到过去再看它自己回来。

操作员立刻让一台节点重新登录：

```bash
bash deploy/vpn/ctl.sh nodes expire --identifier <数字id>
```

Headscale v0.29.6 的帮助写明：expire 保留节点，并要求它重新认证。`--expiry` 是 RFC3339，空着表示现在。`--disable` 关掉到期。别名包括 `logout`。

## 11. 设备被偷

在服务器上先废掉这枚凭证，再处理节点。顺序写死在 `ctl.sh offboard` 里：先 `revoke`，再重启注册服务，然后 `nodes expire`，最后 `nodes delete`。吊销失败时不会 expire，也不会 delete，stderr 里有 `the node was not expired or deleted`。单独执行 `nodes expire` 或 `nodes delete` 不会吊销凭证；设备上的 token 还能再要一把预授权 key。

```bash
bash deploy/vpn/ctl.sh nodes list
bash deploy/vpn/ctl.sh offboard --entry office --label laptop-2 --node-id <数字id>
```

`--hash-prefix` 可以代替 `--label`，两者恰好一个。不给 `--node-id` 时只吊销凭证，节点还在。最后一枚 token 会被拒绝，节点保持不动；先给该项 `token new` 一把留下，再 offboard 被偷的那把。

被偷的电脑上如果还有加入码或 `minted-tokens.txt` 的副本，那枚凭证已经作废。给用户一台新设备时发新 token，不要把旧的文件拷过去。

## 12. 域名写错

症状是客户端一直在连一个不存在的协调服务器，或连上了官方 Tailscale。把配置和 App 里的服务器改成和 `server_url` 相同的那一条 `https` URL，然后重新注册。

注册服务（`enroll_url`）和控制服务器（`server_url`）是两台不同的名字。token 交给注册服务；Tailscale 进程要去的是 `server_url`。写反了就不会进来。

Headplane 的 `/admin` 不在 `server_url` 那台主机名上。成员不需要打开它。
