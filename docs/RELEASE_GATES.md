# CrimsonFlux 发布门禁

真实采集版本公开前，G0 和 G1 都必须由发布负责人以可审计记录批准。环境变量、CI 绿灯或本文件中的文字本身都不构成批准。

## G0：来源、许可与历史洁净度

CrimsonFlux 原创代码使用 Apache License 2.0。运行时直接依赖 `xhshow==0.2.0`（MIT），其传递依赖固定为 `pycryptodome==3.23.0`（部分公有领域、部分 BSD 2-Clause）。准确来源、提交、制品哈希和许可文本见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

发布负责人必须确认：

- `pyproject.toml`、`uv.lock` 与 `requirements.lock` 对 `xhshow` 和 `pycryptodome` 的版本、来源与哈希一致；
- Source ZIP、Docker context、wheel、sdist、容器层和 Git 可达对象中均不存在 Spider_XHS 源码、subtree、submodule、压缩包、缓存或构建残留；
- 仓库从不依赖 `.gitignore`、`.dockerignore` 或 release allowlist 来隐藏未获授权源码；
- Apache-2.0、MIT、BSD 2-Clause/公有领域 notices 与所有其他运行依赖的许可义务已人工复核；
- `THIRD_PARTY_NOTICES.md` 明确记录实际 provenance，并且没有将本项目描述为严格 clean-room；
- 项目名称、README、包元数据、SBOM 和发行说明不暗示小红书官方或第三方项目背书。

由于早期开发人员曾研究过 Spider_XHS，实现过程不能诚实地宣称严格 clean-room。可验证的发布陈述仅限于：当前交付物不复制、不分发、也不在运行时依赖 Spider_XHS。若要建立法律意义上的 clean-room 证据，需要彼此隔离的规范团队和实现团队以及独立记录；本项目目前没有该证据。

首次公开发布必须使用不含旧源码对象的新 Git 历史（例如经审计的新仓库或 orphan 根提交），而不只是从工作树删除目录。G0 必须扫描：

```bash
git rev-list --objects --all
python scripts/scan_release.py --source .
python scripts/archive_source.py --release
python scripts/scan_release.py --archive dist/source
```

任何命中都使 G0 失败。不要通过重写规则误删用户未知分支后直接强推；发布负责人应先在隔离副本验证目标历史与最终归档。

## G1：固定 Python 签名与隔离可见浏览器登录

G1 证明产品只运行锁定、可审计的 Python 代码：

- 签名只通过 `xhshow==0.2.0` 的固定公开 API；禁止运行时下载、动态 import、备用 signer 或未锁定 patch；
- 平台响应中的 program/script 是不可信数据，不能进入 `eval`、`exec`、`compile`、subprocess、文件、数据库或日志；
- 浏览器登录只存在于规范模块；可执行文件、官方 URL 与 flags 固定，使用权限 `0700` 的随机临时 Profile，不读取默认 Profile；Windows executable 根只可来自 Known Folder API 与源码固定 suffix，禁止环境变量和 PATH；
- CDP 只绑定回环随机端口，只允许 `Target.getTargets`、`Target.attachToTarget` 与固定 `/user/me` URL scope 的 `Network.getCookies`；明确禁止 `Network.enable`、页面执行、响应正文、localStorage 和全局 Cookie 读取；
- 禁止 shell、自定义 executable/flags、`--no-sandbox`、`--disable-web-security` 及其他扩大权限的回退；
- 自动取得的 Cookie 必须经同一 `/user/me` 路径确认 `guest=false`、用户 ID 非空后才可加密保存；所有终止路径关闭进程/CDP并删除临时 Profile；
- 独立 security reviewer、真实低频扫码与采集 smoke、发布负责人共同批准。

详细验收见 [G1_SECURITY.md](G1_SECURITY.md)。机器 evidence 必须来自同一 commit，并覆盖 Windows、macOS、Linux 和构建镜像：

```bash
python scripts/verify_g1.py --output dist/g1/g1-native.json
python scripts/verify_g1.py --verify dist/g1/g1-native.json
```

Evidence 只证明编码门禁通过，不能替代人工复核。无法证明时必须 fail closed；可保留显式手动导入，但不得提供 fixture、伪登录、默认 Profile、任意浏览器自动化或 `allow-unsafe` 绕过。

## CI 与 GitHub Environment

公开 Release workflow 使用受保护的 `live-release` Environment，并配置 required reviewers：

- `G0_APPROVAL_REF`：来源、历史和许可证审批记录引用；
- `G1_APPROVAL_REF`：安全评审记录引用。

workflow 将 G1 审批引用映射为 `CRIMSONFLUX_RELEASE_G1_APPROVAL_REF`；G0 由同一受保护环境的历史、来源和许可扫描强制验收。随后运行：

```bash
python scripts/doctor.py --release
python scripts/check_locks.py
python scripts/verify_g1.py --output dist/g1/g1-native.json
python scripts/archive_source.py --release
python scripts/scan_release.py --archive dist/source
```

受保护 Environment 的 reviewer 对引用真实性负责。

## 其他发布条件

- CI、跨平台 source smoke、Compose smoke 全绿；
- 测试合成数据不含真实作者或可反查内容，且不能从产品入口启动；
- `uv.lock` 与带哈希的 `requirements.lock` 同步，Python 依赖清单和参考容器 SPDX SBOM 完成人工许可证复核；
- 最终源码 archive 通过秘密扫描，SBOM 中的 `NOASSERTION` 不得视为自动合规；
- Docker 宿主端口只绑定 `127.0.0.1`；
- 无 Cookie、Token、数据库、真实导出、`.env`、构建缓存或虚拟环境进入 archive；
- Source ZIP 不含 symlink、PEM 私钥、高置信 `xsec_token`/Cookie、动态代码执行原语或白名单外源码；
- Web、CLI 与容器使用同一 Python adapter 和签名路径；
- Release 明确标注 source preview、支持范围、平台接口易变风险以及与小红书官方无关。

## 回退

| 失败项 | 回退 |
|---|---|
| G0 未通过 | 不公开仓库、归档、容器或 Release；先建立无旧对象的新历史并补齐许可记录 |
| G1 未通过 | 健康状态为 `degraded`，真实登录/采集入口 fail closed，不提供替代 adapter |
| 隔离浏览器登录未通过 | 禁用自动登录并保留显式手动导入；不得回退到默认 Profile、危险 flags、页面执行或动态代码执行 |
| 单一平台 source 启动失败 | 不宣称支持该平台，继续内部修复 |
| 凭证泄露、SSRF 或高危依赖 | 停止 Release，撤回受影响资产并轮换测试凭证 |
| 平台接口不稳定 | 保留合法的部分导出并标记 incomplete，不增加绕过策略 |
