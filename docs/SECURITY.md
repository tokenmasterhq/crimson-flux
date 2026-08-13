# CrimsonFlux 安全说明

## 支持边界

CrimsonFlux 是本地单用户源码预览，不是互联网服务。Web 服务的宿主机入口必须只绑定 `127.0.0.1`。Docker 内部监听 `0.0.0.0` 只是端口映射实现细节；Compose 仅发布到宿主回环地址。

不要通过反向代理、路由器端口映射、局域网监听或公网隧道暴露本地 Web UI。应用不提供多用户隔离、远程管理员或互联网部署安全承诺。

## 固定 Python 签名

采集 adapter 是 CrimsonFlux 自有代码，签名直接调用锁定的 `xhshow==0.2.0`。仓库不复制或分发第三方采集器源码。完整依赖来源和许可见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

- 只执行发行版中的固定 Python 模块，不下载或执行平台下发代码；
- 禁止 `eval`、`exec`、`compile`、动态脚本运行时、浏览器页面执行和 subprocess signer；
- Cookie、请求体、签名输入和输出不得进入命令行、环境变量或日志；
- signer 异常只返回稳定、脱敏的错误码，不回显内部输入；
- `xhshow` 或 `pycryptodome` 升级必须重新锁定、审计、跑 golden vectors 并更新第三方 notices。

平台响应中的任何 program/script 字段都按不可信 opaque data 处理并立即丢弃，不得写入文件、数据库、错误文本或传给执行器。

## 隔离可见浏览器登录

为避免要求普通用户打开开发者工具，原生桌面环境可以启动一次性、可见的官方网页登录窗口。它不是用户日常浏览器：应用从固定 Chrome/Edge/Chromium 路径 allowlist 选择程序，以固定参数创建权限 `0700` 的随机临时 Profile，只打开固定官方 URL；不接受自定义 executable、flags 或 URL，也不读取默认 Profile。

调试接口只绑定 `127.0.0.1` 随机端口。允许的 CDP 方法仅限 `Target.getTargets`、`Target.attachToTarget` 和 URL-scoped `Network.getCookies`；明确禁止 `Network.enable`，避免订阅不必要的网络事件与响应元数据。禁止执行页面 JavaScript、读取响应正文、DOM、截图、localStorage、浏览历史或浏览器全局 Cookie。禁止 `--no-sandbox`、`--disable-web-security` 和通配 remote origins。

应用只查询固定 `/user/me` URL 可用的 Cookie，过滤为平台域，要求 `a1` 与 `web_session`，再交给既有 adapter 请求 `/user/me` 验证 `guest=false` 与非空用户 ID。验证成功前不保存凭证；成功、取消、失败、超时、窗口关闭和服务关闭都必须关闭 CDP/浏览器、清空内存引用并删除临时 Profile。

Docker、无 GUI 环境或未找到 allowlist 浏览器时自动登录明确不可用，用户仍可主动使用手动 Cookie 导入。不得回退到默认 Profile、任意 executable、shell、危险 flags 或更宽的调试能力。完整边界见 [G1_SECURITY.md](G1_SECURITY.md)。

在独立威胁建模、负向测试、真实低频 smoke 与发布负责人批准完成前，G1 视为未通过：

- 不得公开带真实采集能力的发行物；
- 不得增加 `allow-unsafe`、关闭检查或不安全自动回退；
- Docker 保护只能作为纵深防御，不能替代源码和依赖审查。

G1 验收与回退见 [RELEASE_GATES.md](RELEASE_GATES.md)。

## 登录凭证

- Cookie、`xsec_token` 和签名材料不得进入 URL 日志、命令行参数、环境变量、CSV 或 JSONL。Web 使用密码样式字段，CLI 只允许隐藏输入或标准输入。
- SQLite 中的登录态使用 AES-256-GCM 加密；主密钥与数据库分文件保存。该措施主要防止数据库或导出文件被单独复制后的明文泄露，不抵御已取得本机用户完整权限的攻击者。
- 主密钥不能是 symlink；POSIX 使用 `0600`，Windows 限制为当前用户 ACL。权限无法收紧时应用应拒绝继续读取凭证。
- Cookie、CDP endpoint、target 元数据、临时 Profile 路径和平台秘密响应不得进入状态 JSON、日志或错误文本。
- GitHub hosted runner 不执行真实登录 smoke，也不保存 Cookie。
- Docker 使用 `docker compose down --volumes` 清除状态卷；原生模式按 [PRIVACY.md](PRIVACY.md) 删除状态目录。

## 本地 API 与输入

- API 校验本地会话、Host、Origin 和 CSRF，拒绝宽泛 CORS；
- CLI 使用本机 API token，不直接读取数据库或 Cookie；
- 用户主页 URL 必须是允许的小红书 HTTPS 域名，不能直接请求任意用户输入 URL；
- 导出的 URL 只允许 HTTPS，并移除认证、签名和 `xsec_token` 等查询参数；
- CSV 对外部文本做公式注入转义；
- 媒体 URL 仅作为字符串导出，不由产品下载；
- 平台内容一律按不可信数据处理，Web 渲染必须转义。

## Docker 安全基线

默认 Compose：

- 非 root；
- 只读根文件系统；
- `cap_drop: ALL`；
- `no-new-privileges`；
- 有限 PID 与临时目录；
- 只挂载状态卷和 `./exports`。

不要挂载 Docker socket、SSH 目录、浏览器资料、整个主目录或云凭证目录。

## Source Release 边界

Source ZIP 与 Docker context 只包含 CrimsonFlux Python 应用、静态资源、启动脚本和发行元数据。发布扫描必须覆盖完整 checkout、Git 可达对象和最终归档，拒绝：

- 第三方采集器源码、subtree、压缩包和缓存；
- symlink、路径穿越、状态库、密钥、日志、虚拟环境和真实导出；
- PEM 私钥、高置信 Cookie/Token 与未脱敏签名参数；
- 动态代码执行、规范登录模块外的浏览器 subprocess/CDP，以及规范模块内的危险 CDP/flags；
- 依赖锁之外的运行时包。

这些自动检查是 G0/G1 人工审批的补充，不能替代许可证复核或独立威胁评审。由于开发历史中曾研究其他实现，CrimsonFlux 不宣称严格 clean-room；只声明当前发行物不复制、不分发且不依赖 Spider_XHS。

## 报告漏洞

不要在公开 issue 中粘贴 Cookie、二维码、真实导出或未脱敏日志。公共仓库启用后，请使用 GitHub Security Advisory 私密报告；启用前通过维护者公布的私密渠道联系。报告应包含版本、操作系统、部署方式、最小复现步骤和已脱敏错误信息。
