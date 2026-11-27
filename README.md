## Serv00|CT8一键三协议安装脚本vless-reality|hy2|tuic5
```
bash <(curl -fLsS https://raw.githubusercontent.com/Git-think/Salksd/refs/heads/unbound/unbound.sh)
```

默认使用 `unbound` 分支的 `unbound.sh` 和配套 `unbound_start.sh` 混淆产物。

新增本地 ACL4SSR、自定义模板、`/c` `/b` `/s` `/n` 格式路径、持久秘密编码和备份清理：[使用与回滚说明](docs/STORAGE-AND-RULES.md)。
本次源码基于 `19229fbc64ec744a8f24d9d9b3ad2adef6f6f375`；支持持久化自签名证书、64 位自用及限时分享五节点订阅（包含安全版和明确标注的旧版兼容节点）、重启迁移及保留订阅地址的换端口。

浏览器访问订阅地址，或访问 `/manage/管理密钥`，可在管理面板点击换端口。支持设置管理密码；不设密码时仍需持有完整私密令牌链接。客户端订阅更新不触发端口操作。

详细修改、客户端导入、验证机制和回滚见 [升级说明](docs/TUIC-UPGRADE.md)，测试范围见 [测试记录](docs/TEST-RESULTS.md)。

发布前在本地运行 `python3 tools/build_obfuscated.py`，`dist/` 生成可独立部署的两个脚本。

默认入口为 `https://域名/64位TOKEN`，浏览器进入管理面板，可创建 8 字符限时分享订阅，账号到期撤销；普通 URI 返回 Base64，Clash/sing-box 保持原生配置格式。无关改动审查见 [审查清单](docs/CHANGE-AUDIT.md)。

未知路径、无效密钥，以及分享地址的非代理客户端访问或过期访问，统一显示环保宣传页。分享标识可被仿冒，实际权限依靠独立密钥和服务端账号撤销。
