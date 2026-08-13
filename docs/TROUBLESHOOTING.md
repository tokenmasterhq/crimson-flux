# CrimsonFlux 排错指南

## `doctor.py` 报 Python 版本错误

原生路径只支持 Python 3.12.x。确认执行 `python --version` 得到的解释器版本；启动脚本不会自动修改或安装系统 Python。Docker 路径不依赖宿主 Python。

## 缺少或不同步的锁文件

`uv.lock` 与 `requirements.lock` 缺失或不同步属于发布阻断。不要改用不锁定的 `pip install -e .` 绕过。维护者应在受控环境更新 `uv.lock`，再导出带哈希的 `requirements.lock`：

```bash
uv lock
uv export --frozen --no-dev --extra bootstrap --no-emit-project --no-header --output-file requirements.lock
python scripts/check_locks.py
```

## `xhshow` 导入或签名自检失败

- 确认安装的是锁文件中的 `xhshow==0.2.0` 和 `pycryptodome==3.23.0`；
- 不要临时安装最新版、从任意 Git 分支安装或复制其他采集器的 signer；
- 原生模式可重新执行 `python scripts/start.py --prepare-only`；
- 若 golden self-test 仍失败，保持登录和采集 fail closed，并提交不含 Cookie、签名输入或平台响应的脱敏诊断。

## Docker 构建失败

先检查：

```bash
docker compose config
docker compose build --no-cache
```

Dockerfile 使用 Python 3.12 和根锁文件本地构建，不下载项目自定义成品镜像。代理或镜像站问题应在 Docker 自身配置中解决，不把凭证写进 Compose。

## `./exports` 权限不足

Linux 默认容器 UID/GID 为 1000。使用 [QUICKSTART.md](QUICKSTART.md) 中的 UID/GID 构建参数重新构建，或把 `./exports` 调整为当前用户可写；不要把容器改成 root。

## WorkBuddy 显示安装完成，但页面没有打开

WorkBuddy 只应负责克隆项目和执行 `python scripts/start.py --prepare-only`。正式服务不应依赖安装任务或工具命令一直保持运行。

安装完成后，请点击 WorkBuddy 生成的本地启动入口；如果没有入口，就打开一个新的普通系统终端，进入项目目录并运行：

```bash
python scripts/start.py
```

不需要复制安装任务中的命令环境，也不需要修改系统环境变量。启动成功后访问 `http://127.0.0.1:8765`。

## 页面无法打开

- 检查 `docker compose ps` 或前台原生日志；
- 确认使用 `http://127.0.0.1:8765`；
- 检查端口是否被占用，或用 `python scripts/start.py --port 8877`；
- 不要把服务绑定到局域网或公网地址。

## 登录窗口没有打开

- 自动登录只支持有图形桌面的原生模式；Docker、远程服务器和无 GUI Linux 会明确显示“不支持”，请使用页面中的手动导入备用入口；
- 如果项目由 WorkBuddy 安装，请确认服务是通过用户点击的本地入口，或在新的普通系统终端中启动，而不是依赖安装任务的后台命令；
- 目前只识别按操作系统固定路径安装的 Chrome、Edge 或 Chromium。应用不会接受自定义程序路径，也不会通过 PATH 启动未知浏览器；
- 若浏览器已安装但不在支持路径，提交操作系统、浏览器名称和版本即可，不要修改启动参数去复用默认 Profile；
- 查看 `/api/v1/health` 的登录 capability。服务从代理、跨域页面或非本机 Host 访问会被拒绝；
- 安全软件可能阻止本机回环调试连接。允许该次本地连接后重试，不要关闭浏览器沙箱、Web 安全或防火墙全局保护；
- 自动路径不可用不会阻止手动 Cookie 导入。

## 扫码后仍显示“等待登录”

请在新打开的独立窗口中完成官方网页登录和平台可能要求的短信验证，并保持窗口打开。CrimsonFlux 不会操作页面、代填短信或绕过验证；它只等待官方页面设置登录 Cookie。

完成后通常需要数秒读取并验证。若手动关闭窗口，会话将取消且不会保存 Cookie。超时、平台 429、风控或网络错误时请等待后重新开始，不要提高并发、轮换代理或添加危险浏览器参数。

只有固定 `/user/me` 确认 `guest=false` 且用户 ID 非空后，登录态才会加密保存。若官方网页显示已登录而工具仍失败，可使用手动导入备用入口，并提交不含 Cookie、CDP 地址、Profile 路径或平台响应的脱敏错误码。

自动登录使用的浏览器 Profile 位于操作系统当前用户的临时目录（Temp），不在数据库和密钥所在的状态目录。结束登录时，应用会关闭临时窗口并从正在使用的临时路径清理 Profile；这不表示磁盘物理擦除，异常断电、系统回收站或备份策略可能影响底层数据保留。

## 手动登录态导入失败

手动导入是显式备用入口，适用于 Docker、无 GUI 环境或自动窗口不可用的情况。确认 Cookie 来自官方网页当前请求并包含所需的 `a1` 与 `web_session`。Web 输入框使用密码样式；CLI 仅使用隐藏输入或 `login --stdin`。不要把 Cookie 放进聊天、公开 issue、命令行参数、环境变量或 `.env`。

## 任务卡在暂停状态

- `paused_auth`：重新扫码。同一账号可续跑；不同账号不能续跑旧任务。
- `paused_rate_limit`：遵守平台提示并等待，再由用户显式恢复。
- `paused_interrupted`：进程异常退出后由用户显式恢复。
- cursor 失效或 `pagination_stalled`：不要从第一页静默重启；保留部分导出并创建新任务。

## 请求受限或部分失败

停止任务并等待，不要反复重试、提高并发、使用代理轮换或尝试规避风控。已写入记录可按 partial/incomplete 状态导出；详情失败不会用额外搜索结果补足。

## 清除所有本地状态

Docker：

```bash
docker compose down --volumes
```

原生模式见 [PRIVACY.md](PRIVACY.md)。删除前先停止进程并保留仍需要的 CSV/JSONL。
