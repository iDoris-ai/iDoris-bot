# Upstream reference repositories / 第三方研究代码

该目录是 upstream 原项目的独立浅克隆，仅供代码阅读、评估和兼容性试验。源码、完整 Git 历史、生成物由本项目根目录 .gitignore 排除，**不参与 iDoris Bridge 产品编译和发行**。目录采用惯用名 vendors/（指第三方供应商/参考源），而不是 Windows 平台专属文件夹。

## 获取参考代码

~~~sh
# from the iDoris-bridge repository root
bash scripts/sync-vendors.sh
~~~

脚本依据 [references.lock.tsv](references.lock.tsv) 在本目录创建固定 SHA 的独立 clone。推荐阅读 [开源调研与许可证审核](../docs/11-OSS-REUSE-AUDIT.md)。

## 禁止

- 不要把 vendors/ 全量源码 add/commit 到主仓库，也不要将它们默认为运行时依赖。
- 不要将 mautrix 的 AGPL-3.0 代码、Chatwoot enterprise/ 的专有代码直接移植到 Apache-2.0 工程。
- 不要把 Telegram/WhatsApp 用户协议的非官方实现误当成 Meta WhatsApp Business Cloud API。
- 不要引入 OpenClaw 的 Agent 执行栈替代 Agent24/iDoris；只借鉴渠道策略和测试。
- 直接使用 SDK/Schema 时须锁定版本、审查传递依赖、LICENSE/NOTICE、平台条款，按许可署名。

参考仓库包含不可信文本和脚本。**先阅读**源码和测试，不运行任何上游脚本、不输入真实 SNS 凭据，除非经过独立安全评审。
