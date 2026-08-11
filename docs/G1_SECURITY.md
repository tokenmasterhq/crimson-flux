# G1：固定 Python 签名与页面内扫码边界

## 目标

G1 要证明 CrimsonFlux 的登录和采集路径只运行随发行版锁定、可审计的 Python 代码，不执行平台响应中的程序文本，不启动浏览器自动化，也不存在不安全回退。

签名能力来自直接依赖 `xhshow==0.2.0`。应用在 Python 进程内调用其公开签名 API；依赖由 `uv.lock` 和带哈希的 `requirements.lock` 固定。仓库不包含任何第三方采集器源码或签名脚本副本。

机器检查通过不等于发布审批通过。独立安全 reviewer、真实低频扫码 smoke 和发布负责人审批仍是必需条件。

## 数据流

```text
固定 HTTPS 登录接口
        │
        ├─ 有界响应；未知字段按不可信数据处理
        └─ 响应中的 program/script 文本不得执行、保存或转发
        ▼
固定 Python 请求构造 + xhshow 0.2.0 本地签名
        ▼
qrcode/create → 校验 QR URL → 内存生成 PNG → 同源 no-store 图片 API
        ▼
userinfo / qrcode/status 有界轮询
        │
        ├─ code_status 必须为成功状态
        └─ 正式 session 必须非空且不同于 visitor session
        ▼
/user/me：success=true 且 guest=false
        ▼
AES-256-GCM 加密持久化登录态
```

二维码 URL 只接受固定的小红书 HTTPS host，不得含端口、用户名或密码。QR value、qr_id、code 和 PNG 只存在于当前登录会话内存；成功、取消、失败、超时或关闭时清除。受保护的 `GET /api/v1/auth/browser/qr` 路径名为兼容旧 API 保留，实际实现不启动或控制浏览器。

## 固定接口边界

登录客户端只允许发布评审中列明的固定小红书 HTTPS endpoint。当前页面内扫码所需核心路径为：

- `/api/sns/web/v1/login/qrcode/create`
- `/api/qrcode/userinfo`
- `/api/sns/web/v1/login/qrcode/status`
- `/api/sns/web/v2/user/me`

若登录初始化还需要安全配置 endpoint，其 origin、path、响应大小、超时和可读取字段也必须逐一进入 allowlist。endpoint 不能由 UI、环境变量或平台响应动态指定。

轮询默认每 2 秒一次、总计最多 180 秒。平台返回待扫码、待手机确认、成功和过期状态时必须分别显示；429、风控或持续网络错误按产品策略失败或暂停，不得重建设备、轮换代理或提高并发规避限制。

## Python 签名边界

- 只允许导入锁定依赖 `xhshow==0.2.0` 的公开 API；禁止从网络下载模块或运行时代码。
- Cookie、请求体和协议字段只在进程内传递，不进入 argv、环境变量、临时文件或日志。
- 每次签名输入和输出都执行类型、长度和字段 allowlist 校验；异常只映射为脱敏错误码。
- 禁止 `eval`、`exec`、`compile`、`execjs`、`js2py`、浏览器页面执行以及把响应文本传给 subprocess。
- 禁止运行时 monkey patch、动态 import 路径、未锁定 signer fallback 和从 CDN/平台获取“补丁”。
- `xhshow` 升级必须重新固定版本与哈希、复核源码差异、更新 notices、跑 golden vectors 和真实低频 smoke。

## 登录持久化强制条件

匿名 activate 得到的 visitor session 不能直接保存。扫码成功后必须：

1. 调用固定状态接口并验证成功状态；
2. 取得有界、非空的正式 session，并证明它不同于 visitor session；
3. 显式替换 `web_session`；
4. 调用固定 `/user/me`，要求 `success=true` 且 `guest is false`；
5. 仅在上述步骤全部成功后加密保存 Cookie。

任何顺序变化、跳过 guest 检查、保留 visitor session 或提前持久化都属于发布阻断。

## 页面内二维码 API

`GET /api/v1/auth/browser/qr`：

- 只返回 `image/png`；
- 要求本机 Host、同源 Origin 以及本地 Web 会话或 CLI token；
- 强制 `private, no-store, max-age=0, must-revalidate`、`Pragma: no-cache`、`Expires: 0` 与 `nosniff`；
- 不返回 QR value、Cookie、签名输入、平台响应、错误原文或调试状态；
- QR PNG 不写入 SQLite、文件、导出或日志。

Docker 与原生使用同一纯 HTTP 实现，均不需要图形环境或宿主浏览器。

## 全树策略与对抗测试

发布扫描必须覆盖 checkout 全树、Git 可达对象、Source Release 投影、最终 ZIP 与容器上下文，并拒绝：

- 第三方采集器源码、副本、subtree、压缩包或构建残留；
- JavaScript/浏览器运行时、动态代码执行和网络下载代码路径；
- Chrome/Chromium/Edge 启动参数、CDP、DevTools endpoint、WebSocket 调试和浏览器 Profile；
- program/script 写文件、记录日志、返回给调用方、持久化或传给任意执行器；
- 未评审 endpoint、宽泛字段提取、未丢弃秘密响应和提前持久化；
- 未锁定签名依赖、备用 signer、运行时 patch 和 symlink 逃逸。

合成响应只存在于测试，不构成演示模式。正则、AST 和秘密扫描都不是形式化证明；evidence 必须记录 release 文件 SHA-256 与 tree digest，源码或锁文件变化会使旧 evidence 失效。

## Evidence

生成与验证：

```bash
python scripts/verify_g1.py --output dist/g1/g1-native.json
python scripts/verify_g1.py --verify dist/g1/g1-native.json
```

容器一致性：

```bash
python scripts/verify_g1.py \
  --container-image crimson-flux:local \
  --output dist/g1/g1-container.json
```

CI 应保存 Windows、macOS、Linux 和构建镜像证据。

## 仍需真人完成

- 独立 reviewer 复核从平台响应到签名、二维码与 session 持久化的完整数据流；
- 逐文件复核 `xhshow==0.2.0` 及 `pycryptodome==3.23.0` 在实际调用路径中的能力边界；
- 维护者使用授权测试账号低频完成扫码、nonguest 验证与关键词/用户采集 smoke；
- 确认 QR value、二维码、Cookie、签名输入和平台秘密响应不进入日志、文件或错误文本；
- 分别验证成功、取消、失败、超时和关闭后的二维码内存清理；
- 发布负责人核对 evidence 的 commit/tree digest 与三平台/容器结果，创建私有审批记录。
