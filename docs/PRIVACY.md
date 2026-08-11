# CrimsonFlux 隐私与本地数据

## 网络访问

CrimsonFlux 没有自建云端、模型服务、遥测或广告 SDK。真实采集会访问小红书相关 Web/API 域名；Docker 首次本地构建还会访问基础镜像和 Python 依赖仓库。

## 本地保存内容

状态目录可能保存：

- SQLite 任务、分页 cursor、列表字段和详情字段；
- 用于恢复会话的加密登录态；
- 本地生成的加密密钥；
- 错误码和不含秘密的任务元数据。

扫码不启动浏览器或创建 Profile。服务通过固定 HTTP 接口取得 QR value，在本地内存生成二维码 PNG；QR value、qr_id、code 和 PNG 不写入 SQLite、文件或日志。扫码完成、取消、失败、超时或服务退出时会清空这些内存值。

Docker 将其放在命名卷 `crimsonflux_state`。原生模式默认位置：

- macOS：`~/Library/Application Support/CrimsonFlux`
- Windows：`%LOCALAPPDATA%\CrimsonFlux`
- Linux：`${XDG_DATA_HOME:-~/.local/share}/crimsonflux`

若本机已存在 v0.1 早期目录，CrimsonFlux 会继续使用原 `XHS Insight` / `xhs-insight` 路径，避免静默丢失加密登录态和未导出任务。新安装使用上述 CrimsonFlux 路径；迁移前请先退出登录并完成所需导出。

用户导出的 CSV/JSONL 位于显式输出目录；Docker 默认为仓库的 `./exports/`。

## 凭证处理

- Cookie 和签名材料不属于用户导出字段。
- 扫码成功后，服务必须用正式 session 替换匿名 visitor session，并通过固定 `/user/me` 确认 `guest=false` 后才保存 Cookie。平台响应中的 program/script 字段不得执行或保存；二维码由校验后的官方 QR URL 在本地生成，不保存原始响应体。
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
