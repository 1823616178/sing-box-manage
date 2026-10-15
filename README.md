# singbox-manage

用于管理 sing-box 节点、系统代理/TUN 模式、节点并发测速、配置健康诊断和 IP 栈的 Textual 3D 赛博控制台（TUI/CLI），适用于 Linux/systemd 环境。

## 特性亮点

- **3D 全息动效中枢 (`HoloStage3D`)**：内置基于 Unicode Braille 子像素（2×4 点阵）与 Z-Buffer 深度着色的实时 3D 透视渲染引擎，支持 **3D 赛博超立方 (`tesseract`)**、**3D 全球节点星环 (`globe`)**、**3D 量子隧道流 (`helix`)** 三种全息模型实时旋转（按 `v` 键切换），并在节点切换或测速时自动触发 `HYPER` 加速与动态频谱脉冲。
- **多维节点矩阵与并发测速**：自动解析 `tuic`、`hysteria2`、`vless`、`naive`、`anytls` 等协议参数、传输层（`h3`/`ws`/`obfs`）、拥塞控制（`bbr`）与服务器端点；支持按 `p` 键并发测试全部节点 TCP 握手延迟，或按 `f` 键一键优选最快节点。
- **纯 TUN 与自定义路由表无损兼容**：完美兼容仅配置 `tun-in`（如 `tun0` + 自定义 `iproute2_table_index`）的新版配置，按需自动补充 `mixed-in` 入站，保留用户原有的 `strict_route: false` / `auto_redirect: false` 设置。
- **配置静态健康诊断 (`--doctor`)**：自动检测 `dns.strategy` 与 `tun.address` 双栈状态不一致、未引用的冗余 `rule_set`、明文 HTTP 规则链接等潜在问题。

## 安装

需要 Python 3.12 或更高版本：

```bash
python -m venv .venv
.venv/bin/pip install -e .
```

## 使用

启动 3D 交互式 TUI：

```bash
sudo .venv/bin/singbox-tui --config /etc/sing-box/config.json
```

命令行切换 IP 栈、静态诊断与并发测速：

```bash
sudo .venv/bin/singbox-tui --config /etc/sing-box/config.json --ip-stack ipv4
sudo .venv/bin/singbox-tui --config /etc/sing-box/config.json --ip-stack dual
.venv/bin/singbox-tui --config /etc/sing-box/config.json --doctor
.venv/bin/singbox-tui --config /etc/sing-box/config.json --ping
```

工具会在实际配置文件旁创建 `config.json.singbox-tui-state.json`，用于保存暂时禁用的自定义 IPv4/IPv6 地址和排除路由，来回切换不会丢失配置。配置路径为符号链接时，保存、备份和状态文件都使用链接指向的实际路径。

## 开发

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
```
