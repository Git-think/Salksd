# 持久化编码与本地规则转换

基于指定提交 `19229fbc64ec744a8f24d9d9b3ad2adef6f6f375`；本轮追加需求日期：2026-11-28。以 `TEST-RESULTS.md` 中实际执行记录为准，未部署和未执行的检查不算实测。

## 本轮改动

| 文件 | 内容 |
|---|---|
| `lib/unbound-storage.sh`、`lib/storage-codec.php` | 版本化编码、SHA-256 完整性检查、流式单进程编解码、旧数据兼容、限定目录的迁移及原件映射 |
| `lib/unbound-rules.sh`、`lib/php-runtime.php` | 本地 ACL4SSR INI 编译、公开规则预设、自定义模板、编码 PHP 执行入口 |
| `lib/sub-router.php` | 单字母格式路径、临时模板参数、默认模板设置、编码会话/任务/密码设置、备份清理界面 |
| `lib/unbound-backups.sh` | 列出自动备份、保留数及删除预览、完整恢复点保护、拒绝符号链接及过时清单 |
| `lib/unbound-secure.sh`、`lib/unbound-shares.sh` | 持久读写适配、短英文节点名、本地规则应用、编码发布内容 |
| `unbound.sh`、`unbound_start.sh` | 读取编码保活配置、复用身份、保留原核心/临时配置清理；保活新增文件解码入口供恢复 |
| `tools/build_obfuscated.py`、workflow | 所有库仍嵌入两个部署文件；PHP 模板也嵌入，服务器无需新增源码文件 |
| `tests/` | 编码互通/损坏/迁移、路由及模板、备份清理和原客户端回归 |

网站 HTTPS 申请/续期、初始化函数、安装端口函数、核心名称 `unbound` 与原临时文件删除命令保持基线；本轮实机禁止全量安装或初始化。旧在线订阅转换器已由本地生成替代；此前遗漏分流规则是实现缺陷，不是证书固定的必要条件，本轮补上本地规则与策略组。

## 一个地址与单字母路径

自用地址仍是 `https://域名/64位密钥`；分享仍是面板生成的 `https://域名/8位分享密钥`。以下路径加在密钥后，不新增 `/sub`，不保留数字或长客户端名称别名。

| 路径 | 内容 |
|---|---|
| 无后缀路径 | 按客户端 User-Agent 自动识别 |
| `/c` | Mihomo 原生 YAML（JSON 表示），含规则、规则提供者和策略组 |
| `/b` | URI 列表整体 Base64，v2rayN 使用混合标准 URI 和原生 PEM 节点 |
| `/s` | sing-box outbound JSON |
| `/n` | NekoBox outbound JSON，与 `/s` 使用相同兼容 1.12 的证书字段 |

`?f=c`、`?f=b`、`?f=s`、`?f=n` 也可固定格式。路径与参数冲突、未知路径仍返回伪装页。分享的到期、撤销和非代理 User-Agent 拒绝规则优先于强制格式；参数不授予管理权限。自用地址使用明确格式时，浏览器也能取得相应内容。

## ACL4SSR

内置预设使用 ACL4SSR 官方 `master/Clash/` 下的公开 `.list`：LocalAreaNetwork、UnBan、BanAD、BanProgramAD、GoogleCN、SteamCN、Telegram、ProxyMedia、ProxyLite、ChinaDomain、ChinaCompanyIp。生成局域网/国内直连、广告拒绝、媒体/消息选择和最终兜底规则。节点与模板在本机合并，不向模板站上传订阅 URL、节点口令或证书。客户端自行下载公开规则集。该预设是本项目基于公开规则集的模板，不声称逐字复制旧转换站的私有默认模板。

内置 AUTO 排除 `[SkipVerify]` 节点；兼容节点仍可手动选择。节点名固定为 `PL-s16-VLESS`、`PL-s16-TUIC [Verify]`、`PL-s16-TUIC [SkipVerify]`、`PL-s16-HY2 [Verify]`、`PL-s16-HY2 [SkipVerify]`；国家可通过保存的 `NODE_COUNTRY` 调整。模板组名不影响节点协议与验证。

管理面板可选择内置模板、粘贴 INI 或从 HTTPS 地址导入；保存前验证，后台重新生成订阅，操作不重启核心。URL 导入保存当时的模板快照，需要更新模板时再次导入；模板引用的规则集按 86400 秒更新。

支持 `[custom]` 的 `ruleset`、`custom_proxy_group`、`enable_rule_generator=true`、`overwrite_original_rules=true`，以及 `select`、`url-test`、`fallback`、`load-balance`、正则节点筛选、`[]` 组引用、公开 HTTPS 文本规则集和常用内联规则。不支持脚本选择器、任意文件导入、SSID 组、provider 特殊选择器或未实现的 INI 选项；遇到它们明确拒绝，不悄悄删规则。空区域组回退为 DIRECT，界面中仍可见；最后必须有 FINAL/MATCH。自定义模板可自行选择兼容节点，但不能修改节点 TLS/认证字段。

一次请求临时覆盖模板：`https://域名/密钥/c?a=BASE64URL`，或 `https://域名/密钥?f=c&a=BASE64URL`。这里 `BASE64URL` 是模板 HTTPS URL 的 UTF-8 字节经过 URL-safe Base64 编码、去掉末尾 `=`。这样模板地址里的完整客户端名称不会直接出现在请求 URL。它只替换该响应，默认模板不变。下载/解析失败返回 422，不返回只有 MATCH 的缩水配置。下载限 256 KiB、公网 HTTPS、无账号、固定解析后的公网 IPv4；不转发访客 Cookie、订阅 token 或 Referer。短期缓存内容编码保存，最多 32 项、1 小时，清理仅限这些缓存文件。

## 持久化与边界

编码封装为 `SALKSD-STORE-1`、明文 SHA-256 和替换字母表的 Base64，每 4 字符换行避免随机字串偶然拼出完整关键词。用途是不能一眼看出内容；这不是加密，公开源码可以恢复。SHA-256 用于损坏检查，不是有密钥的防篡改认证。

私钥仍在站外 `~/.config/salksd/站点域名/private.key`，该文件、server.json、token、分享账号、keepalive.conf、持久订阅、发布 bundle、面板设置/会话、模板和备份均编码。公开证书、端口及其他不含秘密的元数据无需编码。核心实际读取的 `unbound.conf` 和 cert/key 临时副本保持正常格式并按原模式清除；不编码核心二进制。

部署文件仍仅 `unbound.sh` 与 `unbound_start.sh`；生成的 PHP 保持普通执行方式，将包含客户端名称的字符串及页面文本编码；不在 eval 中执行程序，以适配 Serv00 安全限制。持久订阅使用 `p01`—`p09` 等中性名。旧客户端命名文件先编码留存，再迁移到中性名称；旧生成 PHP 和旧格式文件的原件保存在站外编码映射。迁移只检查本服务状态、网站私有数据和既有 `~/.config/salksd-unbound` 审计备份，不遍历或清理其他项目。历史备份不按日期自动删除。

单字母路径避免完整格式名称进入 URL；`a` 参数也使用编码。脚本可检查其管理的文件名/内容不包含用户禁止的字样。平台访问日志可能记录客户端自行发送的 User-Agent、历史 URL 或恶意请求；平台内部缓存也不由脚本控制。本次扩大检查实际发现站点 logs/error.log 含历史请求关键词，该平台日志未清空。本脚本不宣称能保证整个共享服务器磁盘不存在任何该字符串，也不擅自删平台日志。源码仓库和本机审阅材料保留可读说明，不部署到服务器。

## 备份清理与回滚

面板显示自动备份的时间、大小、保护原因和删除预览。默认不删除；保留数量为 1–1000，另保留最近完整恢复点与 last-backup 指针。请求绑定当前清单 SHA-256，清单变化则拒绝。清理只删除指定根目录下符合自动名称的普通文件，拒绝符号链接和嵌套目录，不使用递归删除，不重启核心，不产生额外全量备份。手动审计、迁移原件映射、首页及密码历史备份不在此清理范围。

编码备份不能直接交给 tar。用本轮混淆保活脚本的只读入口解码，例如 `bash unbound_start.sh --decode-file /绝对路径/site.tgz | tar -tzf -` 查看目录。恢复站点前应先停止本服务核心/保活，再按 `TUIC-UPGRADE.md` 的备份层级将解码流交给 `tar -xzpf -`；私有状态也须解码。不要执行初始化。

回退旧版脚本必须同时恢复其匹配的明文状态/网站备份；旧版无法读取新封装。逐文件迁移原件在 `storage-before` 中，map 内的原路径也经过 Base64 编码。保留本轮两个脚本作为解码工具，先验证所需归档能列出并解码，再恢复。不能只替换保活文件而保留编码状态。

## 客户端范围

v2rayN 7.25.6 使用原生 DTO PEM，NekoBox 1.4.2 / 1.12.19-neko-1 用 `tls.certificate`，Mihomo 1.19.34 用完整证书 DER SHA-256；原机制和测试要求保持。FlClash 0.9.4 仍按 Mihomo 格式处理，完整 GUI 未实测。

自动识别扩展到同类 sing-box 客户端 SFA/SFI/SFM、Nekoray、Karing、Hiddify；Mihomo 家族通过 Clash/Mihomo User-Agent 或 `/c`；普通 URI 客户端 Shadowrocket、Streisand、Loon、Happ、V2Box 按 Base64 标准 URI 获取可识别的兼容节点。这些客户端不统一宣称全部协议/PEM 已实测，无法使用原生 v2rayN DTO 的软件不下发假装可验证的 PEM URI。

2026-11-28 源码检查：v2rayNG 2.3.15 的 `V2rayNShareItem.kt` 注释 `Cert`，`ConfigType=8` TUIC 未实现；自动 Base64 响应仅提供 VLESS 和明确 `[SkipVerify]` HY2 两节点，不能声称有五节点或安全 TUIC。Hiddify v5.9.15 下载后交由核心校验/生成完整配置，其 GUI/PEM 保留仍未实测；Karing v1.2.26.2934 发布信息已确认，完整导入未实测。始终优先使用前述三类已验证的核心机制。
