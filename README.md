# CrimsonFlux

CrimsonFlux 是一个本地运行、开源的小红书公开笔记采集与标准化导出工具，同时提供 Web UI 和 CLI。

```text
页面内扫码登录 → 创建关键词或用户任务 → 分页采集 → 可选补全详情 → CSV / JSONL 导出
```

v0.1 只做真实采集，不包含演示模式、内置样例数据、内容分析、AI、评论采集、媒体下载或自动发布。测试使用的合成响应不能从产品入口启用。

## 设计边界

- Web UI 直接显示二维码；不弹出浏览器窗口，不读取浏览器 Profile，也不使用浏览器自动化。
- 一个关键词可指定最多采集条数；用户任务只接受完整的小红书用户主页 HTTPS URL，并枚举当前登录账号实际可见的公开笔记。
- 基础模式只采集列表字段；选择正文、标签、互动或媒体字段后才逐条请求详情。
- 单进程、单 worker、同一时间只运行一个采集任务；SQLite 保存任务、游标、去重结果和加密登录态。
- 默认随机间隔 2–4 秒；遵守 `Retry-After`，不提供代理轮换、验证码绕过或风控规避。
- CSV、JSONL 和 manifest 来自同一唯一笔记集合；取消、限流或部分详情失败时仍可生成明确标记的部分导出。

CrimsonFlux 的采集 adapter 由本项目维护，签名只依赖 PyPI 锁定包 `xhshow==0.2.0`。仓库不包含 Spider_XHS 源码或 subtree，也不在运行时依赖它。历史参与者曾研究过相关实现，因此本项目明确不宣称严格意义上的 clean-room 开发；完整来源与许可说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## Docker Compose（推荐）

前置条件：Docker Engine/Desktop 与 Compose v2。

```bash
docker compose up -d --build
```

打开 [http://127.0.0.1:8765](http://127.0.0.1:8765)，在页面内扫描二维码并完成手机确认。应用不会在桌面弹出 Chrome 或其他浏览器窗口。

- 状态与加密登录态：Docker 命名卷 `crimsonflux_state`。
- 导出：仓库下 `./exports/`。
- 停止并保留状态：`docker compose down`。
- 删除状态卷中的登录态、任务和本地密钥：`docker compose down --volumes`。

保持服务运行，可在另一个终端调用同一容器内的 CLI：

```bash
docker compose exec app crimsonflux login
docker compose exec app crimsonflux collect keyword --keyword "露营装备" --limit 50 --preset basic
docker compose exec app crimsonflux collect user --url "https://www.xiaohongshu.com/user/profile/USER_ID" --all --preset full
docker compose exec app crimsonflux jobs show JOB_ID --watch
docker compose exec app crimsonflux jobs confirm-details JOB_ID --preset basic
docker compose exec app crimsonflux export JOB_ID --format all --output-dir /app/exports/JOB_ID --yes
```

不要使用 `docker compose run` 执行客户端命令；新容器中的 `127.0.0.1` 不是已运行的服务。

## 原生源码启动

前置条件：

- Python 3.12.x；
- Git（下载 GitHub Source ZIP 时可不安装）。

macOS、Linux 和 Windows 使用同一入口：

```bash
python scripts/start.py
```

脚本检查 Python 版本、创建项目 `.venv`、按带哈希的 `requirements.lock` 安装依赖、初始化状态库并启动服务。它不会安装系统环境、请求管理员权限或修改 shell、代理和防火墙。

只准备环境而不启动：

```bash
python scripts/start.py --prepare-only
```

保持服务运行，在另一个终端使用 CLI：

```bash
.venv/bin/crimsonflux login
.venv/bin/crimsonflux collect keyword --keyword "露营装备" --limit 50 --preset basic
.venv/bin/crimsonflux collect user --url "https://www.xiaohongshu.com/user/profile/USER_ID" --all --preset full
.venv/bin/crimsonflux jobs show JOB_ID --watch
.venv/bin/crimsonflux jobs confirm-details JOB_ID --preset basic
.venv/bin/crimsonflux export JOB_ID --format all --output-dir ./exports/JOB_ID --yes
```

Windows 将 `.venv/bin/crimsonflux` 换为 `.venv\Scripts\crimsonflux.exe`。

普通用户直接在 Web UI 扫码。CLI 的 `login` 会启动同一登录会话并提示打开本地 Web 页面，不会在终端输出二维码原始值。不要复制、分享或缓存二维码，也不要把 Cookie 放进命令行参数、环境变量、聊天或公开 issue。

完整步骤见 [快速开始](docs/QUICKSTART.md)，常见故障见 [排错指南](docs/TROUBLESHOOTING.md)。

## 开发检查

```bash
python scripts/doctor.py
python scripts/check_skeleton.py
python scripts/check_locks.py
python scripts/scan_release.py --source .
docker compose config
uv sync --frozen --extra dev
uv run pytest
uv run ruff check src tests scripts
uv run mypy src
```

真实接口 smoke 只能由维护者在本机使用授权测试账号低频执行；CI 只使用合成 fixture，且不得保存 Cookie。

## 发布、安全与许可

公开发布前必须同时通过：

- G0：交付树、Git 历史、Source ZIP 与容器上下文均无未授权第三方源码；依赖版本、哈希、许可和 notices 完整；
- G1：不存在远程程序文本执行或浏览器自动化回退；页面内二维码、正式 session 验证和秘密扫描均通过独立复核。

项目原创代码使用 [Apache License 2.0](LICENSE)。`xhshow` 使用 MIT License，`pycryptodome` 部分为公有领域、部分为 BSD 2-Clause；准确版本与许可文本见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

- 字段定义：[DATA_FIELDS.md](docs/DATA_FIELDS.md)
- 隐私与本地存储：[PRIVACY.md](docs/PRIVACY.md)
- 安全边界和漏洞报告：[SECURITY.md](docs/SECURITY.md)
- 发布门禁：[RELEASE_GATES.md](docs/RELEASE_GATES.md)

公开可见不等于可以任意复制、再发布或处理。使用者仍需遵守平台规则、版权、隐私和适用法律。CrimsonFlux 与小红书官方无关。
