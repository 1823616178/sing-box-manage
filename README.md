# singbox-manage

用于管理 sing-box 节点、系统代理/TUN 模式和 IP 栈的 Textual TUI/CLI，适用于 Linux/systemd 环境。

## 安装

需要 Python 3.12 或更高版本：

```bash
python -m venv .venv
.venv/bin/pip install -e .
```

## 使用

启动 TUI：

```bash
sudo .venv/bin/singbox-tui --config /etc/sing-box/config.json
```

切换 IP 栈：

```bash
sudo .venv/bin/singbox-tui --ip-stack ipv4
sudo .venv/bin/singbox-tui --ip-stack dual
```

工具会在实际配置文件旁创建 `config.json.singbox-tui-state.json`，用于保存暂时禁用的自定义 IPv4/IPv6 地址和排除路由，来回切换不会丢失配置。配置路径为符号链接时，保存、备份和状态文件都使用链接指向的实际路径。

保存会保留原文件的权限、属主和属组，在文件锁内重新读取最新配置，并先运行 `sing-box check` 再原子替换。没有变化时不创建配置备份，也不重载服务。切换操作保留配置原有的默认路由。

需要系统安装 `sing-box`；缺少命令或校验失败时中止保存。`--no-check` 可显式跳过校验，`--no-reload` 可只保存配置。TUN 设置变更使用服务重启，其他变更先尝试重载，失败时再重启。

## 开发

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
```

实现按职责分为 `config.py`（配置存储）、`network.py`（代理模式与 IP 栈）、`runtime.py`（服务控制与状态采集）、`tui.py`（界面）和 `cli.py`（命令行）。`app.py` 与根目录的 `singbox-tui.py` 保留为兼容启动入口。
