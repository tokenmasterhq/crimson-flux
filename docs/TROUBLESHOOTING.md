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

## 页面无法打开

- 检查 `docker compose ps` 或前台原生日志；
- 确认使用 `http://127.0.0.1:8765`；
- 检查端口是否被占用，或用 `python scripts/start.py --port 8877`；
- 不要把服务绑定到局域网或公网地址。

## 页面内二维码没有出现

- 页面内扫码使用固定纯 HTTP 登录接口，Docker、无 GUI Linux 和原生模式都不需要桌面浏览器；
- 查看 `/api/v1/health` 的登录运行时状态；若 signer 自检未通过，登录会 fail closed；
- 若一直停在“正在生成二维码”，取消会话后稍后重试，不要提高并发、轮换代理或持续刷新；
- 二维码接口返回 `401` 通常表示本地 Web 会话已失效，请刷新整个页面；`403` 表示 Origin 边界拒绝请求，不要通过代理或跨域页面访问本地服务；
- 不要添加浏览器自动化、动态代码执行或未锁定 signer 作为修复，这会触发 G1 阻断。

## 扫码后仍显示未登录

用小红书 App 扫描当前页面中的二维码，并在手机端完成确认。二维码是短期凭证，不要刷新、复制、分享或缓存。

CrimsonFlux 只有在状态接口返回成功、正式 session 与 visitor session 不同，并且 `/user/me` 确认 `guest=false` 后才保存登录态。二维码过期请重新创建；平台 429、风控或持续网络错误时应等待，不要增加并发或规避限制。

## 手动登录态导入失败

手动导入是显式备用入口。确认 Cookie 来自官方网页当前请求并包含所需的 `a1` 与 `web_session`。Web 输入框使用密码样式；CLI 仅使用隐藏输入或 `login --stdin`。不要把 Cookie 放进聊天、公开 issue、命令行参数、环境变量或 `.env`。

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
