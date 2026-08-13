# CrimsonFlux 隐私与本地数据

## 网络访问

CrimsonFlux 没有自建云端、模型服务、遥测或广告 SDK。真实采集会访问小红书相关 Web/API 域名；Docker 首次本地构建还会访问基础镜像和 Python 依赖仓库。

## 本地保存内容

状态目录可能保存：

- SQLite 任务、分页 cursor、列表字段和详情字段；
- 用于恢复会话的加密登录态；
- 本地生成的加密密钥；
- 错误码和不含秘密的任务元数据。

原生桌面环境选择自动登录时，CrimsonFlux 会启动一个一次性、可见的官方网页登录窗口，并在操作系统临时目录下的专用私有根中创建随机临时浏览器 Profile。该目录不进入持久状态目录；应用会校验随机所有权标记、创建时文件身份、直接父目录，并拒绝 symlink、junction 或 reparse point。它不会读取或复制你的默认浏览器 Profile。Windows 浏览器安装根只由系统 Known Folder API 返回，不读取 PATH 或安装目录环境变量。应用只通过回环随机 CDP 端口读取固定 `/user/me` URL 可用的平台域 Cookie，不读取页面正文、表单、浏览历史、localStorage、响应正文或其他网站 Cookie。

自动取得的 Cookie 只在内存中进入 `/user/me` 身份校验；校验成功后才加密保存。成功、取消、失败、超时、窗口关闭或服务退出时，应用会关闭 CDP 和临时浏览器，并只删除本会话重新验证归属的精确 Profile 路径。删除失败会阻止登录态保存并保留引用供重试；应用不会读取或清除宿主 safe-delete 设置，也不会用 shell、外部删除工具或扫描临时根来绕过宿主安全策略。本版本不自动回收异常断电留下的陈旧目录。Docker、无 GUI 环境或未找到固定 allowlist 浏览器时不启用自动登录。

Docker 将其放在命名卷 `crimsonflux_state`。原生模式默认位置：

- macOS：`~/Library/Application Support/CrimsonFlux`
- Windows：`%LOCALAPPDATA%\CrimsonFlux`
- Linux：`${XDG_DATA_HOME:-~/.local/share}/crimsonflux`

若本机已存在 v0.1 早期目录，CrimsonFlux 会继续使用原 `XHS Insight` / `xhs-insight` 路径，避免静默丢失加密登录态和未导出任务。新安装使用上述 CrimsonFlux 路径；迁移前请先退出登录并完成所需导出。

用户导出的 CSV/JSONL 位于显式输出目录；Docker 默认为仓库的 `./exports/`。

## 凭证处理

- Cookie 和签名材料不属于用户导出字段。
- 自动登录或手动导入取得的 Cookie 都必须通过固定 `/user/me` 确认 `guest=false` 且用户 ID 非空后才保存。平台响应中的 program/script 字段不得执行或保存；CDP endpoint、临时 Profile 路径与浏览器 target 信息也不得持久化或写入日志。
- 任务需要的私有 token 应加密存储，并在不再需要时删除。
- 本地密钥与加密状态位于同一用户控制范围，不能替代操作系统账户和磁盘保护。
- 不要分享状态卷、数据库、Cookie、`.env` 或未经检查的日志。

## 内容与个人信息

公开笔记仍可能包含昵称、作者 ID、正文、媒体 URL 和其他个人信息。字段是否公开不等于可以无限期保存或再次公开。仅采集完成当前目的所需字段，并在不再需要时删除。

应用不下载媒体；媒体 URL 可能过期，也可能包含可识别信息。导出前会移除已知认证和签名查询参数。

## 删除

Docker：

```bash
docker compose down --volumes
```

然后按需删除 `./exports/` 中的文件。

原生模式：先停止程序，再删除上述状态目录和自己选择的导出目录。删除前确认没有仍需保留的未导出任务。
