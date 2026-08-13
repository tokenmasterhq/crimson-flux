# G1：隔离可见浏览器登录与固定 Python 签名边界

## 目标

CrimsonFlux 为降低普通用户取得 Cookie 的门槛，会启动一个**临时、隔离、可见**的官方网页登录窗口。用户只在该窗口内扫码及完成平台可能要求的短信验证；应用随后通过最小 CDP 接口读取指定官方 URL 可用的 Cookie，并交给既有 `/user/me` 校验路径。校验成功前不会持久化任何凭证。

G1 要证明这条便利路径不会控制用户日常浏览器资料、执行页面脚本、读取页面内容、扩大 Cookie 范围或留下调试入口。签名仍只使用发行版锁定的 Python 代码与 `xhshow==0.2.0`；页面响应中的程序文本始终是不可信数据。

机器检查通过不等于发布审批通过。独立安全 reviewer、真实低频 smoke 和发布负责人审批仍是必需条件。

## 固定数据流

```text
用户点击“打开登录窗口”
        ▼
从固定操作系统 allowlist 选择 Chrome / Edge / Chromium
        ▼
创建权限 0700 的随机临时 Profile
        ▼
固定 argv 启动可见窗口
  ├─ 固定官方 URL：https://www.xiaohongshu.com/explore
  ├─ CDP：127.0.0.1 + 随机端口
  └─ 不复用默认 Profile，不使用 shell，不接受自定义 flags / executable
        ▼
最小 CDP：Target.getTargets / attachToTarget
        ▼
Network.getCookies(urls=[固定 /user/me URL])
  ├─ 只保留 xiaohongshu.com 域 Cookie
  ├─ 字段、数量和总大小均有界
  └─ 必须包含 a1 与 web_session
        ▼
既有 adapter 使用 Cookie 请求固定 /user/me
  └─ guest=false 且 user_id 非空
        ▼
关闭 CDP 与浏览器，删除临时 Profile
        ▼
在 commit guard 内再次检查取消/deadline
        ▼
AES-256-GCM 加密持久化并标记 committed
```

Cookie 的唯一 CDP 查询范围是：

`https://edith.xiaohongshu.com/api/sns/web/v2/user/me`

登录页、Cookie 查询 URL、浏览器候选路径、启动参数和 CDP 方法都由源码常量固定，不能由 UI、环境变量、请求参数或平台响应指定。

## 浏览器进程边界

- 仅允许规范模块 `src/xhs_insight/browser_login.py` 启动或控制浏览器；其他产品模块出现浏览器自动化/CDP 标记即发布阻断。
- 只从按操作系统审计的 Chrome、Edge、Chromium 固定路径中选择可执行文件；Windows 根目录必须由 `SHGetKnownFolderPath` 取得并拼接源码固定的 vendor suffix，不能读取 `PATH`、`PROGRAMFILES`、`PROGRAMFILES(X86)`、`LOCALAPPDATA` 或其他环境变量。Known Folder API 失败时自动登录 fail closed。禁止任意路径、PATH 注入、下载浏览器或自定义 executable。
- 每次登录创建全新的随机临时 `--user-data-dir`，权限为 `0700`；禁止读取、复制或挂载用户默认 Profile。
- CDP 只监听 `127.0.0.1`，使用浏览器分配的随机端口；严格校验 `DevToolsActivePort` 内容、端口范围和回环调试地址。
- `subprocess` 只接受固定 argv 列表，`shell=False`，stdout/stderr 丢弃；Cookie 不进入 argv、环境变量、工作目录或输出。
- Windows 关闭窗口时只能对本次 `Popen` 返回的正整数 PID 调用系统目录中的 `taskkill.exe /PID <pid> /T /F`；禁止 `/IM`、进程名、通配符或任何外部 PID。调用必须 `shell=False`、输入输出丢弃且有严格超时，失败后只允许对同一 owned `Popen` 做有界 `kill/wait`。
- 禁止 `--no-sandbox`、`--disable-web-security`、通配 `--remote-allow-origins=*` 以及关闭同源/沙箱保护的参数。
- Docker、无 GUI 环境或没有 allowlist 浏览器时明确显示“不支持自动登录”，保留用户主动手动导入入口；不得静默降级到不安全启动方式。

## 最小 CDP 能力

允许的方法仅限于建立目标会话及读取指定 URL Cookie 所需集合：

- `Target.getTargets`
- `Target.attachToTarget`
- `Network.getCookies`，且参数必须为 `urls=[COOKIE_SOURCE_URL]`

明确禁止：

- `Runtime.evaluate`、`Runtime.callFunctionOn` 或任何页面 JavaScript 执行；
- `Network.enable`；读取指定 URL Cookie 不需要启用 Network domain，不得扩大事件与响应元数据表面；
- `Network.getResponseBody`、`Fetch.getResponseBody`、DOM、截图、键盘或表单自动化；
- `localStorage`、`sessionStorage`、IndexedDB 或浏览历史读取；
- `Storage.getCookies`、`Network.getAllCookies` 等浏览器全局 Cookie 读取；
- 任意页面导航、任意 URL Cookie 查询、扩展加载和远程调试端口复用。

CDP 消息 ID、method、sessionId、JSON 深度、单条消息和累计输入都有边界；未知事件立即丢弃。状态 API 只返回固定本地状态/错误码，不返回 Cookie、页面 URL、target 信息、Profile 路径、CDP endpoint 或上游原文。

## 凭证验证与生命周期

自动读取的候选 Cookie 必须经过与手动导入相同的标准化规则：字段名合法、无重复、总长不超过 16 KiB，且包含 `a1` 与 `web_session`。同名 Cookie 按固定域名/路径优先级确定，不接受页面或用户控制的选择逻辑。

候选值仅在内存中交给 `Backend.import_cookie`。`RednoteAdapter.verify_cookie` 必须请求固定 `/user/me`，验证 `guest is false` 和非空 `user_id`。随后必须先完成关闭 CDP、终止本次浏览器进程树和删除临时 Profile 的 cleanup barrier，才能进入 commit guard。commit guard 使用同一会话锁将最终取消/deadline 检查、加密持久化和 `committed` 标记线性化：取消或 deadline 先取得锁时不得保存；持久化先取得锁且成功时，迟到的取消不得把成功改写为失败。清理失败必须阻止保存并保留引用供再次清理。

每个终止路径都必须：关闭 CDP socket、终止浏览器；必要时有界等待后 kill；清空进程/端口/会话/Cookie 引用；删除临时 Profile。删除失败必须返回脱敏错误并记录不含路径和凭证的本地错误码，不能把残留 Profile 当作可恢复会话。

## 固定 Python 签名边界

- 只允许导入锁定依赖 `xhshow==0.2.0` 的公开 API；禁止网络下载模块或运行时代码。
- Cookie、请求体和签名材料只在进程内传递，不进入 argv、环境变量、临时文件或日志。
- 禁止 `eval`、`exec`、`compile`、`execjs`、`js2py`、页面执行和把平台响应文本传给 subprocess。
- 禁止动态 import、未锁定 signer fallback、运行时 patch 和 CDN/平台下发“补丁”。
- 依赖升级必须重新固定版本与哈希、复核源码差异、更新 notices、跑 golden vectors 与真实低频 smoke。

## 全树门禁与 Evidence

发布扫描覆盖 checkout 全树、Git 可达对象、Source Release、最终 ZIP 与容器上下文，并拒绝：规范模块外的浏览器自动化；规范模块内的危险 CDP 方法或启动参数；第三方采集器源码；动态代码执行；秘密、状态库、Profile 与构建残留。

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

## 仍需真人完成

- 独立 reviewer 复核固定 argv、可执行文件 allowlist、随机回环 CDP 和 Cookie URL scope；
- 在 Windows、macOS、Linux 支持范围分别确认不会复用默认 Profile；
- 使用授权测试账号低频完成扫码、可选短信验证、`/user/me` nonguest 与采集 smoke；
- 对成功、取消、验证失败、超时、窗口关闭和服务退出分别确认进程、CDP 与临时 Profile 已清理；
- 确认 Cookie、CDP endpoint、Profile 路径、页面内容和平台秘密响应未进入 API、日志、文件或错误文本；
- 发布负责人核对 evidence 的 commit/tree digest 与三平台/容器结果，并创建私有审批记录。
