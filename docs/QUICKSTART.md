# CrimsonFlux 快速开始

## 先确认发布状态

公开版本必须有 [RELEASE_GATES.md](RELEASE_GATES.md) 中 G0 与 G1 的通过记录。G0 核对来源、Git 历史、依赖许可与归档内容；G1 核对固定 Python 签名、隔离的官方网页登录和凭证边界。本项目没有可由用户启用的演示/fixture 模式。

## 路径 A：Docker Compose

需要 Docker Engine/Desktop 与 Compose v2，不需要在宿主机安装 Python。

在仓库根目录执行：

```bash
docker compose up -d --build
```

打开 `http://127.0.0.1:8765`。容器无法直接打开宿主机的图形浏览器，因此 Docker 模式需要按网页中的 5 步指导手动导入登录状态；不会挂载或控制宿主浏览器资料。

启动后可通过 `/api/v1/health` 查看运行状态。真实 adapter 或登录自检未就绪时健康状态为 `degraded`，登录与采集 fail closed，不生成样例结果。

导出文件写到 `./exports/`；任务状态、加密登录态和本地密钥写到命名卷 `crimsonflux_state`。

```bash
docker compose down
```

上面的命令保留状态。若要同时清除登录态、任务和本地密钥：

```bash
docker compose down --volumes
```

若 Linux 上 `./exports` 不可写，可用当前 UID/GID 重新构建：

```bash
CRIMSONFLUX_CONTAINER_UID=$(id -u) CRIMSONFLUX_CONTAINER_GID=$(id -g) docker compose up -d --build
```

不要把 Compose 的宿主端口改成 `0.0.0.0`，也不要挂载主目录、浏览器资料或 Docker socket。

## 路径 B：原生源码

安装 Python 3.12.x；使用 Git clone 或下载 GitHub Source ZIP。然后执行：

```bash
python scripts/start.py
```

脚本只检查现有环境、创建仓库内 `.venv`、按 `requirements.lock` 安装带哈希依赖、初始化数据库并启动服务。它不安装系统软件，不请求管理员权限，也不修改 shell、代理或防火墙。

原生模式会从固定安装位置寻找 Chrome、Edge 或 Chromium。点击“打开官方网页登录”后，程序会使用一次性临时资料目录打开官方网页；你可在官方窗口完成扫码、确认或短信验证。验证成功后窗口自动关闭，临时资料被删除，日常浏览器 Profile 不会被读取。

只准备环境：

```bash
python scripts/start.py --prepare-only
```

然后可手动启动：

```bash
.venv/bin/uvicorn xhs_insight.api.app:create_app --factory --host 127.0.0.1 --port 8765
```

Windows 把 `.venv/bin/` 换成 `.venv\Scripts\`。

## CLI

CLI 只调用本机 API，不直接访问 SQLite 或读取 Cookie。保持 Web 服务运行，在第二个终端执行：

macOS / Linux：

```bash
.venv/bin/crimsonflux login
.venv/bin/crimsonflux collect keyword --keyword "露营装备" --limit 50 --preset basic
.venv/bin/crimsonflux collect user --url "https://www.xiaohongshu.com/user/profile/USER_ID" --all --preset full
.venv/bin/crimsonflux jobs list
.venv/bin/crimsonflux jobs show JOB_ID --watch
.venv/bin/crimsonflux jobs resume JOB_ID
.venv/bin/crimsonflux jobs cancel JOB_ID
.venv/bin/crimsonflux jobs confirm-details JOB_ID --preset basic
.venv/bin/crimsonflux jobs retry-details JOB_ID
.venv/bin/crimsonflux export JOB_ID --format all --output-dir ./exports/JOB_ID --yes
```

Windows PowerShell：

```powershell
.\.venv\Scripts\crimsonflux.exe login
.\.venv\Scripts\crimsonflux.exe collect keyword --keyword "露营装备" --limit 50 --preset basic
.\.venv\Scripts\crimsonflux.exe collect user --url "https://www.xiaohongshu.com/user/profile/USER_ID" --all --preset full
.\.venv\Scripts\crimsonflux.exe jobs show JOB_ID --watch
.\.venv\Scripts\crimsonflux.exe export JOB_ID --format all --output-dir .\exports\JOB_ID --yes
```

CLI 的 `login` 会打开隔离的官方网页登录窗口，完成后自动验证并关闭；Docker 或无图形界面环境可使用 `login --stdin`。不要把 Cookie 放在命令行参数、环境变量、`.env` 或 GitHub Actions secret 中。

若用户主页 URL 含 `xsec_token` 等访问参数，不要放进 `--url` 或 shell 历史；省略 URL 参数后按 CLI 隐藏输入提示粘贴。普通且不含敏感查询参数的完整主页 URL 可直接使用 `--url`。

## 创建任务

### 关键词

- 只输入一个关键词和最多采集条数，默认 50；
- 服务端上限由 `CRIMSONFLUX_MAX_KEYWORD_ITEMS` 控制，默认 1000；
- 按唯一 `note_id` 计数，广告、用户卡片和重复项不占额度；
- 数据源提前结束时导出实际数量并标记 `limit_satisfied=false`。

### 用户公开笔记

- 只接受完整的小红书用户主页 HTTPS URL；
- 只有接口明确返回 `has_more=false` 才标记 `enumeration_complete=true`；
- 默认安全上限 10,000，触发上限或分页停滞时标记部分完成；
- “全部”只指当前登录账号可见且接口实际返回的公开笔记。

### 详情字段

基础模式不逐条请求详情。任意详情字段组会产生最多一条笔记一次额外请求。用户全量任务先完成列表枚举，再展示实际发现数量与新版耗时估算；Web 需要二次确认，CLI 使用 `--yes` 时可跳过。

## 清除本地数据

Web 中使用“清除全部本地数据”，或执行：

```bash
.venv/bin/crimsonflux clear-data
```

该操作删除任务、导出、登录态并轮换主密钥。运行中或排队中的任务必须先取消。
