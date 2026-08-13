# CrimsonFlux（绯流）

一个在自己电脑上运行的公开内容整理工具：输入关键词或粘贴主页链接，完成后下载表格或 JSONL 文件。

## 最省事：交给 WorkBuddy

复制这个 GitHub 链接：

```text
https://github.com/tokenmasterhq/crimson-flux
```

把链接发给 WorkBuddy，再发送这句话：

```text
请把这个项目安装到本机。优先使用 Python 3.12 原生方式：克隆仓库后运行 `python scripts/start.py --prepare-only`，只完成安装准备。然后生成一个由我点击的独立本地启动入口，点击后启动服务并打开 http://127.0.0.1:8765；不要将正式服务作为 WorkBuddy 工具命令的后台或长期子进程。请告诉我如何停止和再次启动，也不要上传任何登录信息。如果只能使用 Docker，请先说明自动网页登录不可用，需要按网页提示手动导入登录状态。
```

安装完成后，点击 WorkBuddy 生成的本地启动入口，或在一个新的普通系统终端中启动项目。打开网页后，按三步提示操作：登录账号、选择要整理的内容、下载结果。

## 自己启动

已安装 Python 3.12（推荐，可自动打开官方网页登录窗口）：

```bash
python scripts/start.py
```

已安装 Docker（无法从容器直接弹出宿主网页登录窗口）：

```bash
docker compose up -d --build
```

然后打开 [http://127.0.0.1:8765](http://127.0.0.1:8765)。停止 Docker 服务时运行：

```bash
docker compose down
```

## 使用前请知道

- 登录信息会加密保存在本机；不要把 Cookie、二维码或账号凭证发到聊天、截图或公开 issue。
- 仅整理登录账号本来就能看到的公开内容，不绕过访问限制，也不保证结果始终完整。
- 请遵守平台规则、版权、隐私和适用法律；本项目与内容平台官方无关。

遇到问题请看 [快速开始](docs/QUICKSTART.md) 和 [排错指南](docs/TROUBLESHOOTING.md)。开发、许可与安全说明见 [项目文档](docs/)。
