# unbound 安全订阅升级

源码基线：`19229fbc64ec744a8f24d9d9b3ad2adef6f6f375`。本次只升级 `unbound.sh` 和配套 `unbound_start.sh`；该提交没有 VPS `sing-box.sh`，`sb.sh`、`frps.sh`、`frps_start.sh` 保持原样。

## 两套证书的用途

* `devil ssl www add ... le le` 和保活的 `check_ssl_cert()`：用于 **HTTPS 订阅网站**，原申请、续期函数保留。
* TUIC/HY2 的 `cert.pem`、`private.key`：仍由 OpenSSL 生成 P-256 自签名证书，3650 天，有与 SNI 一致的 DNS SAN；不向 ACME 申请代理协议证书。

服务器持久化目录为 `~/.config/salksd/api.<用户名>.<域名>/`，目录权限 700、秘密文件 600。保存证书、私钥、服务器配置、订阅令牌和恢复元数据。这里的服务器配置包含认证信息，**不得公开或当成客户端配置导入**。

Serv00 PHP 的 `open_basedir` 不允许读取上述私有目录，前端又要求入口 PHP 可读。因此发布副本分开存放：`public_html/secure-sub.php`（644）只含路由/鉴权代码，无任何节点凭据；`public_html/.salksd-data/`（700）中的 `bundle.json`（600）只含客户端订阅内容、token 摘要和供已认证面板使用的分享索引，由同账户 PHP-FPM 读取，目录内 `.htaccess` 另行拒绝所有 HTTP 访问。服务器私钥始终不进入网站目录。发布数据和代码都在私有目录生成并检查，再原子替换，避免临时源码泄露。

启动时仍将证书复制到原来的运行目录；运行成功后，仍删除 `unbound`、`unbound.conf`、运行目录里的 `private.key`、`cert.pem`、`sb.log`、`core`、`fake_useragent_0.2.0.json`。保活脚本继续保留，二进制名称不变。

订阅生成只读取已有证书；不会生成或申请证书。持久化证书损坏、过期或与私钥不匹配时停止，不会无提示换证书。证书替换后，保活检测 SHA-256 变化，通过重启使实际服务证书和订阅一致。

旧版证书没有 SAN，而且其分享链接 SNI 是 `www.bing.com`，与 CN 不一致，无法直接用于现代客户端的名称验证。新安装/首次旧版迁移保留原代理 SNI `www.bing.com`，签发同名 SAN 的自签名证书；网站 HTTPS 仍使用站点域名。迁移前先备份，若磁盘上仍有私钥则尽量复用。指定旧版会删除运行证书，因此部分机器无法恢复旧证书；这种情况只能建立新的持久化身份。原来跳过验证的客户端继续可用，采用安全订阅的客户端应更新订阅。不能保证手工固定旧证书的客户端无需更新。

这台测试服务器此前已发布站点域名 SAN 的持久证书，当前升级保留该证书及安全节点的现有 SNI，避免破坏已固定的身份。兼容节点恢复原 `www.bing.com` SNI；无需换证书。已有 `TLS_SERVER_NAME` 会继续使用，缺失时只从现有有效证书选择原 SNI 或既有站点名，不静默覆盖证书。

## 订阅地址

按用户最后确认，唯一默认自用订阅地址改为 `https://api.<用户名>.<域名>/<64位TOKEN>`，菜单 2 显示地址与二维码，浏览器访问同一地址进入管理面板。复用已经生成的 64 位密钥，不重新随机轮换。不增加 `/sub/` 前缀；原 8 位自用入口停止下发自用节点，返回宣传页。各客户端填写同一个地址，由 User-Agent 选择格式：

| 客户端 | 返回内容 |
|---|---|
| v2rayN、其他普通 URI 客户端 | 整体 Base64 的五行 URI：VLESS、跳过验证的 TUIC/HY2 标准链接，以及两条携带 PEM 的 v2rayN 原生链接 |
| NekoBox/Nekoray、sing-box 系列、Karing | 原生 sing-box outbound JSON，五个节点，安全节点内嵌 PEM |
| FlClash/Mihomo/Clash 系列 | 原生 Mihomo YAML（JSON 表示），五个节点，安全节点固定完整证书 SHA-256 |

五节点组合为：VLESS 一条、TUIC 安全版和旧版兼容版各一条、HY2 安全版和旧版兼容版各一条。兼容版名称包含“不验证证书”，这是用户追加要求，安全版保持验证。每份订阅在内部生成时先单独检查安全节点，再合并兼容节点，防止错误地把所有节点都设成跳过验证。

旧 v2rayN 或其他不认识 `v2rayn://` 的普通 URI 客户端可能只导入三个标准节点；不能声称它们能显示或使用带 PEM 的两个节点。NekoBox 1.4.2 用原生 JSON：它将整体 Base64 解码后只尝试 URI，不会再次解析 JSON，不能直接把 JSON 整体 Base64 后宣称兼容。用户已确认保留原脚本的格式差异：普通订阅 Base64，Clash/sing-box 原生 YAML/JSON。

Mihomo 配置需要支持 TUIC 的内核，不代表旧 Clash 内核支持 TUIC。其他 GUI 必须支持相应的原生格式；静态字段支持不等于完整 GUI 导入实测。自定义 User-Agent 会改变格式选择，应保留客户端默认标识。

这次从 8 位自用入口迁移到 64 位是用户明确要求的变更，需要更新一次订阅 URL；之后更新订阅和换端口不会改变 64 位地址。直接包含端口的 `tuic://` 分享 URI 必然随端口变化，客户端须更新订阅。Base64 是编码而不是加密；原 HTTPS 网站证书流程及私密 token 保护继续保留。

## 浏览器管理面板

网站根目录 `/` 显示公开的环保宣传首页（节能、减塑、绿色出行），不展示节点、订阅链接或面板入口，不加载外部脚本、图片或统计资源。按本次追加要求替换原首页；替换前保存在私有 `backups/landing-*`，相同内容不重复覆盖。首页模板也内嵌两个混淆脚本。

浏览器打开上述订阅 URL（`User-Agent` 含 Mozilla，`Accept` 接受 `text/html`）时显示面板；已知代理客户端仍获取订阅。也可以直接访问 `/manage/管理密钥`，该专用路径不依赖浏览器识别。管理密钥与 64 位自用订阅使用同一值，不向分享订阅提供。浏览器需要查看原始订阅时追加 `?raw=1`。菜单 2 同时显示管理地址。

面板显示三个当前端口，每行可只更换该协议的端口，也可点击“更换全部端口”。单独操作只释放/分配选中协议的端口，其他两个端口不变；核心重启会使连接短暂中断。按钮提交 POST 请求，自动展示排队、执行和成功/失败状态。GET/HEAD、浏览器预取和普通订阅更新都不更换端口。证书、UUID/密码、订阅 token 和 URL 沿用现有换端口事务；完成后客户端需更新订阅。命令行 `--change-ports tuic`（或 `vless` / `hysteria2`）同样支持，省略协议继续更换全部。

* 默认不设额外密码，仍要求完整 256 位令牌链接。持有该链接的人拥有面板管理权限，不能把它公开。无密码模式不是匿名公开操作。
* 面板可设置或更换密码，保存 PHP `password_hash`，不会保存明文；取消密码需验证当前密码。设置变化使其他登录失效；密码仅保护面板，不改变客户端订阅流程。
* 8 字符分享地址只能在面板创建，使用独立协议账号；不提供管理权限。旧 8 位自用入口不会自动变成分享，也不会继续下发自用凭据。
* 使用 HTTPS、Secure/HttpOnly/SameSite=Strict 会话 Cookie、随机 CSRF 令牌、登录限速及重复请求保护。不加载第三方页面资源、不传出 token。

受 `open_basedir` 限制，PHP 只向 `public_html/.salksd-data/request.json` 写入固定的换端口、创建分享、撤销分享及历史清理请求；不会执行用户提供的 shell 命令。现有保活每五秒检查一次，调用同一套先备份再换端口、重启、发布、失败恢复事务，日常证书/端口维护仍每五分钟执行。有有效分享时增加一个临时到期守护，仍由现有 `unbound_start.sh --share-watch` 执行，无第三个部署脚本；核心替换后旧守护自行退出。面板不提供初始化或重装入口。

面板密码摘要、会话和请求结果也在 `.salksd-data` 下，目录 700、文件 600、HTTP 直读被拒绝；它们不属于客户端订阅。每次密码修改前保留旧设置副本；换端口前原有全站备份包含这些文件。`panel-operation.log` 位于站外私有状态目录，面板不会显示其内容。

保活停止时请求不会被执行，五分钟后过期；进程异常终止可能留下 `running.json` 或操作锁，面板会提示等待超时而不自动重做。应先核对实际端口/服务并备份，再清理确认已无执行进程的请求状态。忘记管理密码需要 SSH 恢复备份中的 `panel.json` 或显式重置该文件，分享 URL 不能进入管理面板或绕过密码。

## 限时分享和访问伪装

面板填写名称和有效分钟数（1–527040 分钟，默认一天），点击“生成分享订阅”。保活先备份，再为分享生成独立 VLESS UUID、TUIC UUID/密码和 HY2 密码，更新服务并发布一个 8 字符地址。每份分享仍按客户端格式提供五节点；兼容节点与安全节点共享本份分享账号，不共享自用账号。可提前撤销。已过期或已撤销记录显示“删除记录”，也可点击“清理全部已失效记录”；有效分享须先撤销。最多保留 128 条可见记录，删除历史记录后即可释放名额。清理仅更新记录和页面，不重启核心；若服务端尚未移除该账号，会拒绝删除并等待既有撤销流程完成。随机数或账号校验失败时，不替换原账号文件。

已删除记录的 ID 和短链接 SHA-256 保存在站外私有 `share-retired.json`（600），不包含分享名称和协议凭据，不计入可见记录数，用于避免旧地址重新分配。不要手动删除该文件；恢复时随其他私有状态一起恢复。已有私有备份仍保留删除前记录，按原备份策略由管理员管理。

分享地址只接受明确支持的代理客户端 User-Agent：v2rayN/v2rayNG、NekoBox/Nekoray、sing-box/SFM/SFI/SFA、Karing、FlClash/Clash/Mihomo、Shadowrocket/Hiddify/Streisand/Loon。识别只决定页面表现，不能证明请求来自真实软件。任何人拿到分享密钥并仿冒客户端标识，仍可在有效期内获取该分享；没有管理权限。

未知路径/密钥、非代理客户端访问分享、分享过期或撤销，均返回 HTTP 200 环保宣传页，不暴露接口是否存在。分享永不进入面板，即使浏览器已经登录自用面板。ACME 的 `.well-known/acme-challenge/` 路径保留平台原处理，以免破坏原网站 HTTPS 证书申请和续期；Serv00 在 PHP 运行前拒绝的隐藏配置/700 私有目录路径（例如 /.htaccess、/.salksd-data/bundle.json）仍返回平台 403，无法在保持原访问权限的前提下由本脚本替换为宣传页。普通错误路径和无效分享直接 200 宣传页；旧订阅文件名被 Apache 拒绝时 302 跳到首页，最终 200。这个平台层例外尚未满足所有路径同样页面的要求，不以放宽私有目录权限绕过。

有效期用服务器时间判断。HTTP 在到期时停止下发；保活每五秒同步账号，单独的到期守护每两秒检查最近期限并结束对应核心，连已经建立的会话也关闭。正常撤销有几秒调度延迟，随后保活移除到期账号并恢复服务；自用连接也有短暂重启中断。保活意外停止时守护仍会关闭旧核心，服务需等保活恢复。若账户的所有进程都被暂停/杀死，无法保证按墙钟执行；不能宣称无运行进程时仍能强制计时。创建、撤销、重启失败时不会通过恢复旧配置重新启用过期账号。

私有 `shares.json` 保存期限和协议凭据（600），备份包含它；网站只保存分享客户端配置及供已认证面板使用的索引，仍处于 700/600 受保护目录。自用地址已经分享给他人时，其已获取的自用凭据不会因新增分享机制自动失效；本次不静默轮换自用账号。

## 三个服务器 IP 的诊断

原 `get_ip()` 从 `devil vhost list` 选择一个地址，TUIC/HY2 仅绑定这个地址；并非自动在三个 IP 上监听。未监听的地址超时不能证明 UDP 被防火墙封锁。三地址测试只临时增加独立监听，不改变正式脚本的选 IP 行为或服务器的长期绑定；结果见 TEST-RESULTS.md。

## 客户端机制及源码核对

核心源码核对日期：2026-11-19，统一订阅和面板修正日期：2026-11-20。实际运行测试与源码检查的区别详见 `TEST-RESULTS.md`。

| 客户端 | 核对版本/源码 | 采用的验证机制 |
|---|---|---|
| v2rayN | `7.25.6`，提交 `1883178b5f1e222b6c6db2782e7a3d989b7cc18f` | `ProfileItem.Cert` 保存 PEM，`StreamSecurity:"tls"`、`AllowInsecure:"false"`；真实生成器写入 `tls.certificate` 并将 `insecure` 设为 false |
| NekoBox Android | `1.4.2`，提交 `5768494d8ae3c74a057bb6d46c0f8dc071b0d821` | outbound JSON 原样保存为 `ConfigBean`，嵌入 PEM，使用证书链和 SAN 验证 |
| NekoBox 核心 | `1.12.19-neko-1`，提交 `aed32ee3066cdbc7d471e3e0415c5134088962df` | `tls.certificate` 构建专用根证书池；不使用 1.13 才新增的公钥固定字段 |
| Mihomo | `v1.19.34` | `fingerprint` 是证书 DER 的 SHA-256，不是公钥/SPKI SHA-256；`skip-cert-verify:false`、`reduce-rtt:false` |
| FlClash | `v0.9.4`，内置核心子模块提交 `5b453f80dbcee6b3ecfb0415bcace24a48c88707` | 核心源码具备同一 TUIC 指纹验证链；FlClash GUI 本身未运行 |

v2rayN 当前版本已不是旧 `ProfileItemDtoJson` 订阅数组结构。`InnerFmt.ResolveSingle()` 解析 `v2rayn://协议/base64url(JSON)`，要求 `ConfigVersion:4`。TUIC 使用 `ConfigType:8`、`CoreType:24`，UUID 放在 `Username`，密码放在 `Password`，拥塞控制放在 `ProtoExtraObj.CongestionControl`。仅写 `CertSha` 不足以保证 sing-box 应用信任材料，因此这里使用 `Cert` PEM。

NekoBox 的 TUIC 标准 URI 解析器不导入 CA PEM；它的节点设置虽有 `caText`，不能据此假定 URI 中任意 `cert=` 参数有效。原地址的 NekoBox 分支使用 `RawUpdater.parseJSON()` 支持的 `outbounds`，经 `ConfigBean` / `CustomSingBoxOption` 保留原 TLS JSON。禁用全局“跳过证书验证”，避免用户配置覆盖安全意图。

Mihomo 的 `fingerprint` 与 `client-fingerprint:chrome` 完全不同。其指纹验证器在内部接管默认 TLS 验证，拒绝不匹配的证书；不能仅看到内部 `InsecureSkipVerify=true` 就断言无验证。**固定叶证书时，Mihomo 验证器不额外检查证书过期时间和 SNI 名称**；生成端仍验证证书有效期、SAN 和 SNI 一致。这属于完整证书固定机制的实际语义，不能声称它与 PEM 链验证完全相同。

### 导入

1. v2rayN 7.25.6：订阅分组设置 → 新增 → URL 填菜单 2 的 64 位自用订阅地址或面板创建的有效分享地址 → 更新订阅。TUIC 使用 sing-box。原生导出时选择 v2rayN 原生格式；转回普通 `tuic://` 分享格式可能丢掉 PEM。旧版不支持原生格式时，可尝试支持 sing-box outbound 自定义订阅的功能，或使用同一订阅中明确标注“不验证证书”的兼容节点，不能声称任意旧版安全兼容。
2. NekoBox 1.4.2：分组 → 新建订阅分组 → 填同一个 64 位自用地址或有效分享地址 → 更新。节点类型显示自定义 sing-box outbound 是预期行为，证书在 JSON 内。普通 URI 导出不能替代这个订阅。
3. FlClash：配置/Profiles → 添加远程配置 → 填同一个 64 位自用地址或有效分享地址 → 更新并启用配置。不要自行覆盖 `skip-cert-verify` 或删除 `fingerprint`。

上游依据：

* https://github.com/2dust/v2rayN/blob/7.25.6/v2rayN/ServiceLib/Handler/Fmt/InnerFmt.cs
* https://github.com/2dust/v2rayN/blob/7.25.6/v2rayN/ServiceLib/Models/Entities/ProfileItem.cs
* https://github.com/2dust/v2rayN/blob/7.25.6/v2rayN/ServiceLib/Services/CoreConfig/Singbox/SingboxOutboundService.cs
* https://github.com/MatsuriDayo/NekoBoxForAndroid/blob/1.4.2/app/src/main/java/io/nekohasekai/sagernet/group/RawUpdater.kt
* https://github.com/MatsuriDayo/NekoBoxForAndroid/blob/1.4.2/buildScript/lib/core/get_source_env.sh
* https://github.com/MatsuriDayo/sing-box/blob/aed32ee3066cdbc7d471e3e0415c5134088962df/common/tls/std_client.go
* https://github.com/MetaCubeX/mihomo/blob/v1.19.34/adapter/outbound/tuic.go
* https://github.com/MetaCubeX/mihomo/blob/v1.19.34/component/ca/fingerprint.go
* https://github.com/chen08209/Clash.Meta/blob/5b453f80dbcee6b3ecfb0415bcace24a48c88707/component/ca/fingerprint.go

## 全部修改位置

| 文件 | 函数/位置 | 修改 |
|---|---|---|
| `unbound.sh` | 初始化、`install_unbound()`、`download_unbound()` | 载入公共实现；安装前备份；恢复身份和 token；重用证书；保存配置；0-RTT 关闭 |
| `unbound.sh` | `secure_fetch_worker()`、`restart_unbound()`、`changge_ports()`、菜单 | 新增菜单 5；先备份并更新配套混淆保活，再执行重启/端口事务；不用安装/初始化路径重启 |
| `unbound.sh` | `get_links()`、`generate_sub_link()`、`get_nodes()` | 保持原单一自适应订阅地址与二维码，按客户端下发五节点；在服务器本地生成 JSON/YAML；移除向第三方转换站发送节点凭据的流程 |
| `unbound.sh` | `install_keepalive()`、`quick_command()` | `%q` 保存 shell 变量；默认入口改为 `unbound` 分支混淆文件 |
| `unbound_start.sh` | 证书生成、配置生成、主循环、命令行 | 重用私有状态；检查证书变化；保活重启时同步订阅；新增 `--restart` / `--change-ports`；五分钟维护间隔内轮询面板请求 |
| `unbound_start.sh` | `download_unbound_binary()` | 保持 URL/名称，增加 HTTP 错误检查和下载失败返回，避免把错误页当二进制 |
| `lib/unbound-secure.sh` | 全文件 | 共用证书、备份、订阅、HTTPS handler、受控进程重启、端口更换与失败恢复；入口 644、站内发布目录 700/600；FreeBSD 使用分开的 ps 输出参数，清理本服务 sleep 子进程；构建时嵌入两个产物，服务器不依赖第三个脚本 |
| `lib/unbound-shares.sh` | 全文件 | 分享账本、独立账号生成/筛选、专用订阅、到期同步和核心期限守护；内嵌两个混淆产物 |
| `lib/sub-router.php` | 全文件 | 原订阅地址的客户端分流、浏览器面板、可选密码和会话、CSRF、固定请求队列及状态显示；构建时一起嵌入两个产物 |
| `lib/public-index.html` | 全文件 | 根目录环保宣传页，手机/电脑响应式；替换原首页前备份，不含服务链接或秘密 |
| `tools/build_obfuscated.py` | 全文件 | 把共用代码嵌入两个脚本，gzip + base64 混淆，保留菜单 stdin、脚本路径和命令行参数；这不是加密 |
| `.github/workflows/encrypt-and-deploy.yml` | 全文件 | main 更新时检查并生成混淆产物，unbound 分支只保留两文件，普通提交推送，不重写历史 |
| `.gitattributes`、`.gitignore` | 全文件 | 固定 shell LF，忽略本地产物和测试缓存 |
| `tests/*` | 全文件 | 证书、转义、安全/兼容分离、FreeBSD 进程筛选、端口回退、原行为保持、混淆一致性、真实 TLS 核心测试、v2rayN 原生回环测试 |
| `README.md`、`docs/*` | 文档 | 默认混淆入口、导入、版本、限制、测试记录、回滚 |

## 回滚

每次迁移/重启/换端口前创建私有备份，命令输出恢复目录；`last-backup` 记录最近一次路径。备份包括 `site.tgz`（logs、public_html）、旧状态文件、平台端口清单、重启前恢复用配置及私有诊断日志。备份包含服务器秘密，只能经 SSH 保存。

恢复时先停止**这个目录的**保活和 unbound 进程，根据 `port-snapshot`/`ports.txt` 恢复平台原端口；用 `tar -xzpf` 将 `site.tgz` 解压到站点目录，`-p` 用于恢复原权限，避免 077 umask 使网站 PHP 变成 600 而返回 404。将存在的旧状态文件恢复到私有目录；原来不存在的新增 `secure-sub.php`、`.salksd-data/` 要移到私有备份中。再从原来的运行目录启动恢复后的 `unbound_start.sh`。不要执行初始化系统。对首次旧版迁移，原脚本的临时证书已经被删除，无法保证回到曾经驻留内存中的那张旧证书。首次人工备份的压缩包含站点目录这一层，须解压到 `$HOME/domains`；脚本自动备份含 `logs/public_html`，须解压到对应站点目录。

源码回滚可以直接取指定基线的两个文件。部署分支须重新生成与该源码对应的混淆产物；仅回滚 main 不会改变已经安装的服务器脚本。发布已获用户授权，使用 Git-think 身份完成普通提交/推送。发布前 main 的 `5c208aa` 和 unbound 的 `1e849da` 保留在各自历史中，未强制推送。

应用完整补丁到干净基线：

```bash
git switch -c review-tuic 19229fbc64ec744a8f24d9d9b3ad2adef6f6f375
git apply --check /path/to/complete.patch
git apply /path/to/complete.patch
python3 tools/build_obfuscated.py
```

直接运行 `dist/unbound.sh` 和 `dist/unbound_start.sh` 是两个完整、自包含混淆脚本；源码目录中的两个 `.sh` 需要同仓库 `lib/`，不能单独复制源码入口。默认云端命令使用 unbound 分支的两个混淆文件。Actions 已实际完成测试、构建和发布；服务器直接下载运行的验证范围见 TEST-RESULTS.md。

## 已知限制

* 只有拥有网站 HTTPS 信任的订阅更新才安全；令牌泄露后须主动轮换，自动轮换会破坏固定 URL。无额外密码时，完整管理密钥授予换端口和密码设置权限；原短订阅 token 不自动授予管理权限。
* 自动备份保留在私有目录，不擅自清除历史备份，管理员需按磁盘容量保留需要的恢复点。
* 首次迁移存在一个短暂重启窗口；已固定旧证书的客户端需更新订阅。
* 全新系统安装、系统初始化、CT8 真实主机、完整客户端 GUI 均未作为本次远端测试对象。
* 手工替换证书须同时提供匹配的 key/SAN；本脚本不将失败降级为安全订阅跳过验证。
* 协议配置兼容不等于所有 GUI 版本兼容；已明确测试和未测试的范围以测试记录为准。

逐段检查不必要改动的结果见 `CHANGE-AUDIT.md`，其中列出撤回的路径/拆分/明文 URI/下载超时改动及保留其他改动的理由。
