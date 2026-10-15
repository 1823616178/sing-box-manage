"""Interactive node and network configuration management with 3D cyber-cockpit UI."""

import math
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static
from textual.worker import get_current_worker

from .config import (
    ConfigHealthIssue,
    NodeInfo,
    SaveResult,
    describe_outbound_node,
    find_proxy_selector,
    format_save_note,
    index_inbounds,
    inspect_config_health,
    load_config,
    save_config,
    validate_config_structure,
)
from .network import (
    describe_ip_stack_state,
    format_ip_stack_mode,
    get_proxy_mode,
    get_sing_box_ip_stack,
    get_tun_interface_name,
    next_ip_stack_mode,
    save_ip_stack_config,
    set_proxy_mode,
    tun_settings_changed,
)
from .runtime import (
    format_latency_badge,
    get_dns_tun_status,
    get_public_ipv4,
    get_service_memory_usage,
    get_system_memory_usage,
    get_tun_link_status,
    measure_nodes_latency,
    reload_sing_box,
)

PUBLIC_IP_CACHE_TTL = 300.0
SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
WAVE_GLYPHS = "▁▂▃▄▅▆▇█"

# Braille sub-pixel bit mapping (2 cols x 4 rows per character cell)
_BRAILLE_MAP = (
    (0x01, 0x08),
    (0x02, 0x10),
    (0x04, 0x20),
    (0x40, 0x80),
)


class HoloStage3D(Static):
    """Real-time 3D perspective wireframe renderer using Unicode Braille sub-pixels."""

    MODES = ("tesseract", "globe", "helix")
    MODE_NAMES = {
        "tesseract": "3D 赛博超立方",
        "globe": "3D 全球节点星环",
        "helix": "3D 量子隧道流",
    }

    def __init__(self, id: str | None = None) -> None:
        super().__init__("", id=id)
        self.angle_x = 0.35
        self.angle_y = 0.55
        self.angle_z = 0.15
        self.tick_count = 0
        self.mode_index = 0
        self.boost = False
        self.alert_state = "ok"  # "ok" | "warning" | "error"
        self.active_node = "未选择"
        self.active_badge = "—"
        self.proxy_mode_label = "—"
        self.ip_stack_label = "—"
        self.node_count = 0
        self.best_latency_ms: int | None = None

    @property
    def current_mode(self) -> str:
        return self.MODES[self.mode_index % len(self.MODES)]

    def cycle_mode(self) -> str:
        self.mode_index = (self.mode_index + 1) % len(self.MODES)
        self.refresh_frame(advance=False)
        return self.MODE_NAMES[self.current_mode]

    def set_telemetry(
        self,
        *,
        active_node: str,
        active_badge: str,
        proxy_mode_label: str,
        ip_stack_label: str,
        node_count: int,
        alert_state: str = "ok",
        boost: bool = False,
        best_latency_ms: int | None = None,
    ) -> None:
        self.active_node = active_node or "未选择"
        self.active_badge = active_badge or "—"
        self.proxy_mode_label = proxy_mode_label
        self.ip_stack_label = ip_stack_label
        self.node_count = node_count
        self.alert_state = alert_state
        self.boost = boost
        if best_latency_ms is not None:
            self.best_latency_ms = best_latency_ms
        self.refresh_frame(advance=False)

    def _rotate_3d(
        self,
        x: float,
        y: float,
        z: float,
        ax: float,
        ay: float,
        az: float,
    ) -> tuple[float, float, float]:
        # Rotate around X
        cos_x, sin_x = math.cos(ax), math.sin(ax)
        y, z = y * cos_x - z * sin_x, y * sin_x + z * cos_x
        # Rotate around Y
        cos_y, sin_y = math.cos(ay), math.sin(ay)
        x, z = x * cos_y + z * sin_y, -x * sin_y + z * cos_y
        # Rotate around Z
        cos_z, sin_z = math.cos(az), math.sin(az)
        x, y = x * cos_z - y * sin_z, x * sin_z + y * cos_z
        return x, y, z

    def _project(
        self,
        x: float,
        y: float,
        z: float,
        px_w: int,
        px_h: int,
    ) -> tuple[int, int, float]:
        fov = 3.6
        dist = 4.2
        scale = fov / max(0.8, dist + z)
        sx = int(px_w * 0.5 + x * scale * (px_w * 0.30))
        sy = int(px_h * 0.5 + y * scale * (px_h * 0.34))
        return sx, sy, z

    @staticmethod
    def _draw_line(
        canvas: list[list[int]],
        zbuf: list[list[float]],
        x0: int,
        y0: int,
        z0: float,
        x1: int,
        y1: int,
        z1: float,
        layer: int = 1,
    ) -> None:
        h = len(canvas) * 4
        w = len(canvas[0]) * 2 if canvas else 0
        dx = abs(x1 - x0)
        dy = -abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx + dy
        steps = max(abs(x1 - x0), abs(y1 - y0), 1)
        step = 0
        while True:
            if 0 <= x0 < w and 0 <= y0 < h:
                cx, cy = x0 // 2, y0 // 4
                bit = _BRAILLE_MAP[y0 % 4][x0 % 2]
                canvas[cy][cx] |= bit
                t = step / steps
                z_val = z0 * (1.0 - t) + z1 * t - (0.35 if layer > 1 else 0.0)
                if z_val < zbuf[cy][cx]:
                    zbuf[cy][cx] = z_val
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 >= dy:
                err += dy
                x0 += sx
            if e2 <= dx:
                err += dx
                y0 += sy
            step += 1

    def _build_geometry(self) -> tuple[list[tuple[float, float, float]], list[tuple[int, int, int]]]:
        mode = self.current_mode
        vertices: list[tuple[float, float, float]] = []
        edges: list[tuple[int, int, int]] = []  # (i, j, layer)

        if mode == "tesseract":
            # Outer cube (0..7)
            for ix in (-1.0, 1.0):
                for iy in (-1.0, 1.0):
                    for iz in (-1.0, 1.0):
                        vertices.append((ix, iy, iz))
            for i in range(8):
                for j in range(i + 1, 8):
                    diff = (
                        (vertices[i][0] != vertices[j][0])
                        + (vertices[i][1] != vertices[j][1])
                        + (vertices[i][2] != vertices[j][2])
                    )
                    if diff == 1:
                        edges.append((i, j, 1))
            # Inner pulsing octahedron core (8..13)
            pulse = 0.52 + 0.12 * math.sin(self.tick_count * 0.22)
            oct_pts = [
                (pulse, 0.0, 0.0),
                (-pulse, 0.0, 0.0),
                (0.0, pulse, 0.0),
                (0.0, -pulse, 0.0),
                (0.0, 0.0, pulse),
                (0.0, 0.0, -pulse),
            ]
            base = len(vertices)
            vertices.extend(oct_pts)
            oct_edges = [
                (0, 2), (0, 3), (0, 4), (0, 5),
                (1, 2), (1, 3), (1, 4), (1, 5),
                (2, 4), (4, 3), (3, 5), (5, 2),
            ]
            for u, v in oct_edges:
                edges.append((base + u, base + v, 2))

        elif mode == "globe":
            # 3D latitude/longitude wireframe sphere + orbital satellite ring
            ring_n = 10
            for lat in (-0.55, 0.0, 0.55):
                r = math.sqrt(max(0.0, 1.0 - lat * lat))
                start = len(vertices)
                for k in range(ring_n):
                    theta = 2 * math.pi * k / ring_n
                    vertices.append((r * math.cos(theta), lat, r * math.sin(theta)))
                for k in range(ring_n):
                    edges.append((start + k, start + (k + 1) % ring_n, 1))
            # Two meridian rings
            for phi in (0.0, math.pi / 2):
                start = len(vertices)
                for k in range(ring_n):
                    theta = 2 * math.pi * k / ring_n
                    vertices.append(
                        (
                            math.cos(theta) * math.cos(phi),
                            math.sin(theta),
                            math.cos(theta) * math.sin(phi),
                        )
                    )
                for k in range(ring_n):
                    edges.append((start + k, start + (k + 1) % ring_n, 1))
            # Inclined outer orbital ring
            orbit_n = 12
            start = len(vertices)
            for k in range(orbit_n):
                theta = 2 * math.pi * k / orbit_n + self.tick_count * 0.08
                ox = 1.32 * math.cos(theta)
                oy = 0.38 * math.sin(theta)
                oz = 1.32 * math.sin(theta)
                vertices.append((ox, oy, oz))
            for k in range(orbit_n):
                edges.append((start + k, start + (k + 1) % orbit_n, 2))

        else:  # helix
            strands = 10
            for k in range(strands):
                t = -1.1 + 2.2 * k / (strands - 1)
                phase = t * 2.4 + self.tick_count * 0.18
                vertices.append((0.88 * math.cos(phase), t, 0.88 * math.sin(phase)))
                vertices.append((-0.88 * math.cos(phase), t, -0.88 * math.sin(phase)))
                idx = k * 2
                edges.append((idx, idx + 1, 2))
                if k > 0:
                    edges.append((idx - 2, idx, 1))
                    edges.append((idx - 1, idx + 1, 1))

        return vertices, edges

    def render_3d_frame(self, cols: int = 28, rows: int = 6) -> Text:
        px_w, px_h = cols * 2, rows * 4
        canvas = [[0 for _ in range(cols)] for _ in range(rows)]
        zbuf = [[99.0 for _ in range(cols)] for _ in range(rows)]

        vertices, edges = self._build_geometry()
        projected: list[tuple[int, int, float]] = []
        for vx, vy, vz in vertices:
            rx, ry, rz = self._rotate_3d(vx, vy, vz, self.angle_x, self.angle_y, self.angle_z)
            projected.append(self._project(rx, ry, rz, px_w, px_h))

        for u, v, layer in edges:
            x0, y0, z0 = projected[u]
            x1, y1, z1 = projected[v]
            self._draw_line(canvas, zbuf, x0, y0, z0, x1, y1, z1, layer=layer)

        # Palette selection based on status and boost
        if self.alert_state == "error":
            near_style, mid_style, far_style = "bold bright_red", "red", "dim red"
        elif self.boost:
            near_style, mid_style, far_style = "bold bright_yellow", "bold bright_cyan", "cyan"
        elif self.alert_state == "warning":
            near_style, mid_style, far_style = "bold yellow", "bright_cyan", "dim cyan"
        else:
            near_style, mid_style, far_style = "bold bright_cyan", "dodger_blue1", "dim cyan"

        # Build side-by-side 3D Canvas + Live Cyber Telemetry HUD
        out = Text()
        wave_chars = []
        for i in range(12):
            amp = math.sin(self.tick_count * (0.45 if self.boost else 0.2) + i * 0.55)
            idx = int((amp + 1.0) * 0.5 * (len(WAVE_GLYPHS) - 1))
            wave_chars.append(WAVE_GLYPHS[max(0, min(len(WAVE_GLYPHS) - 1, idx))])
        wave_str = "".join(wave_chars)

        deg_x = int(math.degrees(self.angle_x) % 360)
        deg_y = int(math.degrees(self.angle_y) % 360)
        deg_z = int(math.degrees(self.angle_z) % 360)
        mode_title = self.MODE_NAMES[self.current_mode]
        speed_tag = "⚡HYPER" if self.boost else ("🚨ALERT" if self.alert_state == "error" else "🟢SYNC")
        best_ping = f"{self.best_latency_ms}ms" if self.best_latency_ms is not None else "待测速"

        hud_lines = [
            ("bold bright_magenta", f"❖ {mode_title} [{speed_tag}]"),
            ("bright_cyan", f"🚀 节点: {self.active_node} ({self.active_badge})"),
            ("cyan", f"🌐 模式: {self.proxy_mode_label} | 栈: {self.ip_stack_label}"),
            ("bright_green", f"📡 拓扑: {self.node_count} 节点 | 最快: {best_ping}"),
            ("dim cyan", f"🧭 姿态: X:{deg_x:03d}° Y:{deg_y:03d}° Z:{deg_z:03d}°"),
            ("bright_yellow" if self.boost else "bright_blue", f"📶 频谱: {wave_str} (按 v 切换3D)"),
        ]

        for r in range(rows):
            out.append(" ▕", style="dim cyan")
            for c in range(cols):
                mask = canvas[r][c]
                if mask == 0:
                    # Subtle starfield background dots
                    if (r * 17 + c * 31 + self.tick_count) % 53 == 0:
                        out.append("·", style="dim blue")
                    else:
                        out.append(" ")
                else:
                    ch = chr(0x2800 + mask)
                    z = zbuf[r][c]
                    style = near_style if z < -0.25 else (mid_style if z < 0.45 else far_style)
                    out.append(ch, style=style)
            out.append("▏ ", style="dim cyan")
            if r < len(hud_lines):
                hud_style, hud_text = hud_lines[r]
                out.append(hud_text, style=hud_style)
            if r < rows - 1:
                out.append("\n")

        return out

    def refresh_frame(self, advance: bool = True) -> None:
        if advance:
            step = 0.22 if self.boost else 0.075
            self.angle_x += step * 0.7
            self.angle_y += step * 1.1
            self.angle_z += step * 0.45
            self.tick_count += 1
        self.update(self.render_3d_frame())


class ConfirmScreen(ModalScreen[bool]):
    """二次确认弹窗，dismiss 时返回 True（确认）或 False（取消）。"""

    BINDINGS = [
        ("escape", "cancel", "取消"),
        ("n", "cancel", "取消"),
        ("y", "confirm", "确认"),
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static("⚠️ 操作确认", classes="section-title")
            yield Static(self._message, id="confirm-message")
            with Horizontal(id="confirm-buttons"):
                yield Button("确认 (Y)", id="confirm-yes", variant="error")
                yield Button("取消 (N/Esc)", id="confirm-no", variant="primary")

    def on_mount(self) -> None:
        # 默认聚焦“取消”，防止误触回车直接重启服务
        self.query_one("#confirm-no", Button).focus()

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")


class HelpScreen(ModalScreen[None]):
    """快捷键帮助弹窗。"""

    BINDINGS = [
        ("escape", "close_help", "关闭"),
        ("q", "close_help", "关闭"),
        ("question_mark", "close_help", "关闭"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Static("⌨️ 快捷键与功能指南", classes="section-title")
            yield Static(
                "↑ / ↓        上下选择代理节点\n"
                "Enter / 空格 切换到当前高亮节点\n"
                "/            聚焦节点搜索框（支持名称/协议/域名过滤）\n"
                "Esc          清空搜索框并返回节点列表 / 关闭弹窗\n"
                "p            并发测试所有节点 TCP 握手延迟\n"
                "f            一键切换到当前延迟最低的可用节点\n"
                "v            切换 3D 全息视图模式（超立方/星环/量子流）\n"
                "r            刷新运行状态与公网出口 IP\n"
                "?            显示/关闭本帮助弹窗\n"
                "q            退出程序",
                id="help-text",
            )
            with Horizontal(id="help-buttons"):
                yield Button("关闭 (Esc/Q)", id="help-close", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#help-close", Button).focus()

    def action_close_help(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)


class SingBoxTUI(App):
    TITLE = "sing-box 赛博节点控制台"
    SUB_TITLE = "3D Holo-Cockpit & Network Manager"

    CSS = """
    Screen, ConfirmScreen, HelpScreen {
        align: center middle;
    }
    #main {
        width: 1fr;
        max-width: 112;
        height: auto;
        max-height: 100%;
        overflow-y: auto;
        border: heavy $accent;
        background: $surface;
        padding: 0 2 1 2;
    }
    #title {
        text-align: center;
        text-style: bold;
        color: $accent;
    }
    #subtitle {
        text-align: center;
        color: $text-muted;
        margin-bottom: 1;
    }
    #holo-panel {
        height: auto;
        border: round $primary;
        background: $boost;
        padding: 0 1;
        margin-bottom: 1;
    }
    #status-panel {
        height: auto;
        border: round $primary;
        padding: 0 1;
        margin-bottom: 1;
    }
    #runtime-info {
        text-align: center;
        color: $text;
    }
    #runtime-info.warning {
        color: $warning;
    }
    #runtime-info.error {
        color: $error;
        text-style: bold;
    }
    #network-info {
        text-align: center;
        color: $text-muted;
    }
    #network-info.error {
        color: $error;
        text-style: bold;
    }
    #network-info.warning {
        color: $warning;
        text-style: bold;
    }
    #health-info {
        text-align: center;
        color: $warning;
    }
    #node-section {
        height: auto;
        border: round $secondary;
        padding: 0 1;
        margin-bottom: 1;
    }
    #node-toolbar {
        height: auto;
        margin-bottom: 1;
    }
    #node-filter {
        width: 1fr;
        margin-bottom: 0;
    }
    DataTable {
        height: 10;
        min-height: 6;
        max-height: 14;
    }
    #mode-section {
        height: auto;
        border: round $primary;
        padding: 0 1;
        margin-bottom: 1;
    }
    .section-title {
        text-style: bold;
        color: $secondary;
        margin-bottom: 0;
    }
    #mode-section Horizontal {
        height: auto;
        margin-top: 0;
    }
    #mode-section Button {
        width: 1fr;
        margin: 0 1;
    }
    #node-toolbar Button {
        width: auto;
        min-width: 14;
        margin-left: 1;
    }
    #status {
        text-align: center;
        color: $success;
        text-style: bold;
        margin-top: 0;
    }
    #status.pending {
        color: $warning;
    }
    #status.error {
        color: $error;
    }
    #confirm-dialog {
        width: 64;
        height: auto;
        border: heavy $warning;
        background: $surface;
        padding: 1 2;
    }
    #confirm-message {
        text-align: center;
        margin: 1 0;
    }
    #confirm-buttons, #help-buttons {
        height: auto;
        align: center middle;
    }
    #help-dialog {
        width: 62;
        height: auto;
        border: heavy $primary;
        background: $surface;
        padding: 1 2;
    }
    #help-text {
        margin: 1 0;
    }
    """

    BINDINGS = [
        ("q", "quit", "退出"),
        ("r", "refresh", "刷新状态"),
        ("space", "select_highlighted_node", "切换节点"),
        ("p", "ping_nodes", "节点测速"),
        ("f", "select_fastest_node", "优选最快"),
        ("v", "cycle_3d_view", "3D视图"),
        ("/", "focus_filter", "搜索节点"),
        ("?", "show_help", "帮助"),
    ]

    def __init__(
        self,
        config_path: Path,
        service_name: str,
        selector_tag: str,
        mixed_tag: str,
        tun_tag: str,
        backup_keep: int,
        reload_enabled: bool,
        validate_config: bool,
    ) -> None:
        super().__init__()
        self.config_path = config_path.expanduser()
        self.service_name = service_name
        self.selector_tag = selector_tag
        self.mixed_tag = mixed_tag
        self.tun_tag = tun_tag
        self.backup_keep = backup_keep
        self.reload_enabled = reload_enabled
        self.validate_config = validate_config
        self.config: dict[str, Any] | None = None
        self.selector: dict[str, Any] | None = None
        self.inbounds: dict[str, dict[str, Any]] = {}
        self.node_infos: dict[str, NodeInfo] = {}
        self.node_latencies: dict[str, int | None] = {}
        self._latency_tested = False
        self.health_issues: list[ConfigHealthIssue] = []
        self.current_node = ""
        self.proxy_mode = ""
        self.nodes: list[str] = []
        self.visible_nodes: list[str] = []
        self._node_filter = ""
        self._busy = False
        self._pinging = False
        self._public_ip: str | None = None
        self._public_ip_at = 0.0
        self._runtime_generation = 0
        self._network_state = "ok"
        self._columns_initialized = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="main"):
            yield Static("✦ SING-BOX HOLO-COCKPIT 节点与网络中枢 ✦", id="title")
            yield Static(
                "↑↓ 选节点 | Enter/空格 切换 | p 测速 | f 优选最快 | v 切换3D | / 搜索 | r 刷新 | ? 帮助",
                id="subtitle",
            )
            with Vertical(id="holo-panel"):
                yield HoloStage3D(id="holo-stage")

            with Vertical(id="status-panel"):
                yield Static("🖥️ 实时遥测与链路状态", classes="section-title")
                yield Static("正在获取运行状态…", id="runtime-info")
                yield Static("", id="network-info")
                yield Static("", id="health-info")

            with Vertical(id="node-section"):
                yield Static("📡 代理节点矩阵", id="node-section-title", classes="section-title")
                with Horizontal(id="node-toolbar"):
                    yield Input(
                        placeholder="🔍 输入名称 / 协议(tuic,vless,hy2) / 域名过滤节点… (回车跳入列表, Esc清空)",
                        id="node-filter",
                    )
                    yield Button("⚡ 节点测速 (p)", id="btn-ping-nodes", variant="primary")
                    yield Button("🚀 优选最快 (f)", id="btn-fastest-node", variant="success")
                    yield Button("🎲 3D视图 (v)", id="btn-3d-view", variant="default")
                table: DataTable[Any] = DataTable(id="node-table", zebra_stripes=True)
                table.cursor_type = "row"
                yield table

            with Vertical(id="mode-section"):
                yield Static("🌐 代理模式与 TUN IP 协议栈", classes="section-title")
                with Horizontal():
                    yield Button("系统代理 (mixed)", id="btn-system")
                    yield Button("TUN 模式", id="btn-tun")
                    yield Button("切换 IPv4/IPv6", id="btn-cycle-ip-stack")
                with Horizontal():
                    yield Button("IPv4 only", id="btn-ipv4")
                    yield Button("IPv6 only", id="btn-ipv6")
                    yield Button("IPv4+IPv6", id="btn-dual-stack")

            yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_data()
        self.update_node_table()
        self.update_mode_buttons()
        self._sync_holo_telemetry()
        self.refresh_runtime_info()
        # 启动 3D 动效帧定时器（约 12 FPS）
        self.set_interval(0.085, self._tick_animation)

    def _tick_animation(self) -> None:
        # 弹窗打开时降低后台刷新干扰
        if isinstance(self.screen, ModalScreen):
            return
        for stage in self.query(HoloStage3D):
            stage.boost = self._busy or self._pinging
            stage.refresh_frame(advance=True)

    # ------------------------------------------------------------------
    # 数据加载与静态健康分析
    # ------------------------------------------------------------------

    def _reset_state(self) -> None:
        self.config = None
        self.selector = None
        self.inbounds = {}
        self.node_infos = {}
        self.health_issues = []
        self.nodes = []
        self.visible_nodes = []
        self.current_node = ""
        self.proxy_mode = "unknown"

    def _ingest_config(self, loaded: dict[str, Any]) -> None:
        self.config = loaded
        self.selector = find_proxy_selector(loaded, self.selector_tag)
        self.inbounds = index_inbounds(loaded)

        if self.selector:
            selector_nodes = self.selector.get("outbounds", [])
            self.nodes = [str(n) for n in selector_nodes] if isinstance(selector_nodes, list) else []
            self.current_node = str(self.selector.get("default", ""))
        else:
            self.nodes = []
            self.current_node = ""

        self.node_infos = {tag: describe_outbound_node(loaded, tag) for tag in self.nodes}
        self.proxy_mode = get_proxy_mode(loaded, self.mixed_tag, self.tun_tag)
        self.health_issues = inspect_config_health(
            loaded,
            selector_tag=self.selector_tag,
            mixed_tag=self.mixed_tag,
            tun_tag=self.tun_tag,
        )
        self._render_health_issues()
        self._sync_holo_telemetry()

    def _render_health_issues(self) -> None:
        health_widget = self.query_one("#health-info", Static)
        warnings = [i for i in self.health_issues if i.level in ("error", "warning")]
        if not warnings:
            infos = [i for i in self.health_issues if i.level == "info"]
            if infos:
                health_widget.update(f"💡 诊断提示: {infos[0].message}")
            else:
                health_widget.update("")
            return
        top = warnings[0]
        prefix = "❌ 配置错误" if top.level == "error" else "⚠️ 配置诊断"
        extra = f" (共 {len(warnings)} 项)" if len(warnings) > 1 else ""
        health_widget.update(f"{prefix}{extra}: {top.message}")

    def _sync_holo_telemetry(self) -> None:
        stages = list(self.query(HoloStage3D))
        if not stages:
            return
        info = self.node_infos.get(self.current_node)
        active_badge = info.badge if info else "—"
        mode_map = {
            "system": "系统代理 (mixed)",
            "tun": "TUN 透明代理",
            "mixed+tun": "混合双开 (mixed+TUN)",
        }
        mode_label = mode_map.get(self.proxy_mode, "未启用")
        stack_label = describe_ip_stack_state(self.config, self.tun_tag)
        reachable = [ms for ms in self.node_latencies.values() if ms is not None]
        best_ms = min(reachable) if reachable else None
        for stage in stages:
            stage.set_telemetry(
                active_node=self.current_node or "未选择",
                active_badge=active_badge,
                proxy_mode_label=mode_label,
                ip_stack_label=stack_label,
                node_count=len(self.nodes),
                alert_state=self._network_state,
                boost=self._busy or self._pinging,
                best_latency_ms=best_ms,
            )

    def refresh_data(self) -> bool:
        try:
            loaded = load_config(self.config_path)
            validate_config_structure(loaded)
        except Exception as e:
            self._reset_state()
            self.show_status(f"读取配置失败: {e}", error=True)
            return False

        self._ingest_config(loaded)
        return True

    # ------------------------------------------------------------------
    # 界面更新
    # ------------------------------------------------------------------

    def _matches_filter(self, tag: str, keyword: str) -> bool:
        if not keyword:
            return True
        if keyword in tag.lower():
            return True
        info = self.node_infos.get(tag)
        if not info:
            return False
        haystack = f"{info.protocol} {info.badge} {info.server} {info.server_port or ''}".lower()
        return keyword in haystack

    def update_node_table(self, focus: bool = True) -> None:
        table = self.query_one("#node-table", DataTable)
        prev_cursor = table.cursor_row if table.cursor_row is not None else 0

        if not self._columns_initialized:
            table.clear(columns=True)
            table.add_columns("状态", "节点名称", "协议 / 特性", "服务器端点", "实时延迟")
            self._columns_initialized = True
        else:
            table.clear(columns=False)

        keyword = self._node_filter.lower()
        self.visible_nodes = [node for node in self.nodes if self._matches_filter(node, keyword)]

        # 更新区块标题（显示当前节点与过滤计数）
        title_widget = self.query_one("#node-section-title", Static)
        current_label = self.current_node or "无"
        title_widget.update(
            f"📡 代理节点矩阵 (当前: {current_label} | 显示 {len(self.visible_nodes)}/{len(self.nodes)})"
        )

        if not self.nodes:
            table.add_row("!", f"未找到 {self.selector_tag} selector 或节点列表为空", "—", "—", "—")
        elif not self.visible_nodes:
            table.add_row("!", f"没有匹配 [{self._node_filter}] 的节点", "—", "—", "—")
        else:
            target_row = min(prev_cursor, len(self.visible_nodes) - 1)
            for idx, node in enumerate(self.visible_nodes):
                is_current = node == self.current_node
                marker = "✅" if is_current else "  "
                info = self.node_infos.get(node, NodeInfo(tag=node))
                latency = self.node_latencies.get(node)
                latency_text = format_latency_badge(latency, tested=self._latency_tested)
                table.add_row(
                    marker,
                    node,
                    info.badge,
                    info.endpoint,
                    latency_text,
                    key=str(idx),
                )
                if is_current and prev_cursor == 0:
                    target_row = idx
            table.move_cursor(row=target_row)

        if focus:
            table.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "node-filter":
            return
        self._node_filter = event.value.strip()
        # 过滤时不抢焦点，让用户可以连续输入
        self.update_node_table(focus=False)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "node-filter":
            self.query_one("#node-table", DataTable).focus()

    def on_key(self, event: events.Key) -> None:
        # 搜索框内按 Escape 清空并返回列表，按 Down 直接进入列表选节点
        if self.focused is not None and getattr(self.focused, "id", None) == "node-filter":
            filter_input = self.query_one("#node-filter", Input)
            if event.key == "escape":
                filter_input.value = ""
                self._node_filter = ""
                self.update_node_table(focus=True)
                event.stop()
            elif event.key == "down":
                self.query_one("#node-table", DataTable).focus()
                event.stop()

    def update_mode_buttons(self) -> None:
        btn_sys = self.query_one("#btn-system", Button)
        btn_tun = self.query_one("#btn-tun", Button)
        has_mixed = self.mixed_tag in self.inbounds
        sys_suffix = "" if has_mixed else " [自动补充]"

        ip_stack_buttons = {
            "ipv4": self.query_one("#btn-ipv4", Button),
            "ipv6": self.query_one("#btn-ipv6", Button),
            "dual": self.query_one("#btn-dual-stack", Button),
        }
        if self.proxy_mode == "system":
            btn_sys.label = f"✅ 系统代理 (mixed){sys_suffix}"
            btn_tun.label = "TUN 模式"
            btn_sys.variant = "success"
            btn_tun.variant = "primary"
        elif self.proxy_mode == "tun":
            btn_sys.label = f"系统代理 (mixed){sys_suffix}"
            btn_tun.label = "✅ TUN 模式"
            btn_sys.variant = "primary"
            btn_tun.variant = "success"
        elif self.proxy_mode == "mixed+tun":
            btn_sys.label = f"✅ 系统代理 (mixed){sys_suffix}"
            btn_tun.label = "✅ TUN 模式"
            btn_sys.variant = "warning"
            btn_tun.variant = "warning"
        else:
            btn_sys.label = f"系统代理 (mixed){sys_suffix}"
            btn_tun.label = "TUN 模式"
            btn_sys.variant = "primary"
            btn_tun.variant = "primary"

        current_ip_stack = get_sing_box_ip_stack(self.config, self.tun_tag)
        stack_detail = describe_ip_stack_state(self.config, self.tun_tag)
        cycle_button = self.query_one("#btn-cycle-ip-stack", Button)
        cycle_button.label = f"切换 IPv4/IPv6 ({stack_detail})"
        cycle_button.variant = "warning" if current_ip_stack == "unknown" else "primary"

        for mode, button in ip_stack_buttons.items():
            label = format_ip_stack_mode(mode)
            if mode == current_ip_stack:
                button.label = f"✅ {label}"
                button.variant = "success"
            else:
                button.label = label
                button.variant = "primary"

    def show_status(self, msg: str, error: bool = False, pending: bool = False) -> None:
        status = self.query_one("#status", Static)
        status.update(Text(str(msg)))
        status.remove_class("error", "pending")
        if error:
            status.add_class("error")
        elif pending:
            status.add_class("pending")

    def _set_action_buttons_disabled(self, disabled: bool) -> None:
        for button in self.query(Button):
            button.disabled = disabled

    # ------------------------------------------------------------------
    # 运行状态与节点并发测速（全部放入后台线程 Worker）
    # ------------------------------------------------------------------

    @staticmethod
    def _format_memory_bar(memory_str: str) -> str:
        match = re.search(r"\((\d+)%\)", memory_str)
        if not match:
            return memory_str
        pct = max(0, min(100, int(match.group(1))))
        filled = round(pct / 100 * 8)
        bar = "█" * filled + "░" * (8 - filled)
        return f"{memory_str} [{bar}]"

    def refresh_runtime_info(self, force_ip: bool = False):
        """Capture state on the UI thread and only publish the latest refresh."""

        self._runtime_generation += 1
        now = time.monotonic()
        cached_ip = None
        if not force_ip and self._public_ip is not None and now - self._public_ip_at < PUBLIC_IP_CACHE_TTL:
            cached_ip = self._public_ip
        config = self.config
        interface_name = get_tun_interface_name(config, self.tun_tag)
        ip_stack_status = describe_ip_stack_state(config, self.tun_tag)
        return self._runtime_info_worker(
            self._runtime_generation,
            interface_name,
            ip_stack_status,
            self.proxy_mode,
            cached_ip,
            self._public_ip_at,
        )

    @work(thread=True, exclusive=True, group="runtime-info")
    def _runtime_info_worker(
        self,
        generation: int,
        interface_name: str,
        ip_stack_status: str,
        proxy_mode: str,
        cached_ip: str | None,
        cached_ip_at: float,
    ) -> None:
        public_ip = cached_ip if cached_ip is not None else get_public_ipv4()
        public_ip_at = cached_ip_at if cached_ip is not None else time.monotonic()
        system_memory = self._format_memory_bar(get_system_memory_usage())
        service_memory = get_service_memory_usage(self.service_name)
        tun_status = get_tun_link_status(interface_name)
        dns_status = get_dns_tun_status(interface_name)
        runtime_text = f"🌍 出口 IPv4: {public_ip} | 🧠 系统内存: {system_memory} | ⚙️ sing-box: {service_memory}"
        network_text = f"🔌 TUN: {tun_status} ({interface_name}) | 🛡️ DNS 走 TUN: {dns_status} | 🧬 IP 栈: {ip_stack_status}"
        # TUN 模式下链路 DOWN 是故障，DNS 未走 TUN 或 IP 栈不一致是告警
        if proxy_mode == "tun" and tun_status != "UP":
            network_state = "error"
        elif (proxy_mode == "tun" and dns_status == "否") or "未知" in ip_stack_status:
            network_state = "warning"
        else:
            network_state = "ok"

        runtime_state = "ok"
        if service_memory == "未运行":
            runtime_state = "error"
        elif public_ip in ("获取失败", "未找到 curl"):
            runtime_state = "warning"

        if not get_current_worker().is_cancelled:
            self.call_from_thread(
                self._render_runtime_info,
                generation,
                public_ip,
                public_ip_at,
                runtime_text,
                network_text,
                network_state,
                runtime_state,
            )

    def _render_runtime_info(
        self,
        generation: int,
        public_ip: str,
        public_ip_at: float,
        runtime_text: str,
        network_text: str,
        network_state: str,
        runtime_state: str = "ok",
    ) -> None:
        if generation != self._runtime_generation:
            return
        self._public_ip = public_ip
        self._public_ip_at = public_ip_at
        self._network_state = network_state

        runtime_widget = self.query_one("#runtime-info", Static)
        runtime_widget.update(runtime_text)
        runtime_widget.remove_class("error", "warning")
        if runtime_state in ("error", "warning"):
            runtime_widget.add_class(runtime_state)

        network_widget = self.query_one("#network-info", Static)
        network_widget.update(network_text)
        network_widget.remove_class("error", "warning")
        if network_state in ("error", "warning"):
            network_widget.add_class(network_state)

        self._sync_holo_telemetry()

    def action_ping_nodes(self, auto_select_fastest: bool = False) -> None:
        if self._pinging:
            self.show_status("正在执行节点延迟测速，请稍候…", pending=True)
            return
        if not self.nodes:
            self.show_status("当前没有可测速的节点", error=True)
            return
        self._pinging = True
        self._sync_holo_telemetry()
        self.show_status(f"⚡ 正在并发探测 {len(self.nodes)} 个节点的 TCP 握手延迟…", pending=True)
        endpoints = [
            (tag, self.node_infos[tag].server, self.node_infos[tag].server_port)
            for tag in self.nodes
            if tag in self.node_infos
        ]
        self._ping_nodes_worker(endpoints, auto_select_fastest)

    @work(thread=True, exclusive=True, group="node-ping")
    def _ping_nodes_worker(
        self,
        endpoints: list[tuple[str, str, int | None]],
        auto_select_fastest: bool,
    ) -> None:
        results = measure_nodes_latency(endpoints, timeout=2.0)
        if not get_current_worker().is_cancelled:
            self.call_from_thread(self._finish_ping_nodes, results, auto_select_fastest)

    def _finish_ping_nodes(
        self,
        results: dict[str, int | None],
        auto_select_fastest: bool,
    ) -> None:
        self._pinging = False
        self._latency_tested = True
        self.node_latencies = results
        self.update_node_table(focus=False)
        self._sync_holo_telemetry()

        reachable = [(tag, ms) for tag, ms in results.items() if ms is not None]
        if not reachable:
            self.show_status("测速完成：所有节点均超时或不可达", error=True)
            return

        fastest_tag, fastest_ms = min(reachable, key=lambda item: item[1])
        if auto_select_fastest:
            if fastest_tag in self.visible_nodes:
                idx = self.visible_nodes.index(fastest_tag)
                self._select_node_by_index(idx)
            else:
                self._select_node_by_tag(fastest_tag)
            return

        self.show_status(
            f"⚡ 测速完成：可达 {len(reachable)}/{len(results)} 个节点，最快 [{fastest_tag}] ({fastest_ms}ms)"
        )

    def action_select_fastest_node(self) -> None:
        reachable = [(tag, ms) for tag, ms in self.node_latencies.items() if ms is not None]
        if not reachable:
            self.action_ping_nodes(auto_select_fastest=True)
            return
        fastest_tag, _ = min(reachable, key=lambda item: item[1])
        self._select_node_by_tag(fastest_tag)

    def action_cycle_3d_view(self) -> None:
        for stage in self.query(HoloStage3D):
            mode_name = stage.cycle_mode()
            self.show_status(f"🎲 已切换全息视图为: {mode_name}")

    # ------------------------------------------------------------------
    # 动作与事件处理
    # ------------------------------------------------------------------

    def action_refresh(self) -> None:
        ok = self.refresh_data()
        self.update_node_table()
        self.update_mode_buttons()
        self.refresh_runtime_info(force_ip=True)
        if ok:
            self.show_status("🔄 状态与公网 IP 已刷新")

    def action_select_highlighted_node(self) -> None:
        table = self.query_one("#node-table", DataTable)
        # 仅当焦点在节点表格（或无特定输入/按钮焦点）时响应空格切换，防止在按钮上按空格误触
        if self.focused is not None and self.focused is not table:
            return
        if table.cursor_row is not None:
            self._select_node_by_index(table.cursor_row)

    def action_focus_filter(self) -> None:
        self.query_one("#node-filter", Input).focus()

    def action_show_help(self) -> None:
        if not isinstance(self.screen, HelpScreen):
            self.push_screen(HelpScreen())

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not self.selector:
            return
        row_key = getattr(event.row_key, "value", event.row_key)
        try:
            idx = int(str(row_key))
        except (ValueError, TypeError):
            return
        self._select_node_by_index(idx)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-system":
            self.set_mode("system")
        elif btn_id == "btn-tun":
            self.set_mode("tun")
        elif btn_id == "btn-cycle-ip-stack":
            self.cycle_ip_stack()
        elif btn_id == "btn-ipv4":
            self.set_ip_stack("ipv4")
        elif btn_id == "btn-ipv6":
            self.set_ip_stack("ipv6")
        elif btn_id == "btn-dual-stack":
            self.set_ip_stack("dual")
        elif btn_id == "btn-ping-nodes":
            self.action_ping_nodes(auto_select_fastest=False)
        elif btn_id == "btn-fastest-node":
            self.action_select_fastest_node()
        elif btn_id == "btn-3d-view":
            self.action_cycle_3d_view()

    def _select_node_by_index(self, idx: int) -> None:
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return
        if not self.selector or not (0 <= idx < len(self.visible_nodes)):
            return
        selected = self.visible_nodes[idx]
        self._select_node_by_tag(selected)

    def _select_node_by_tag(self, selected: str) -> None:
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return

        def mutate(data: dict[str, Any]) -> None:
            selector = find_proxy_selector(data, self.selector_tag)
            if not selector:
                raise ValueError(f"配置中未找到 tag={self.selector_tag} 的 selector")
            if selected not in selector.get("outbounds", []):
                raise ValueError(f"节点 [{selected}] 已不在 selector 中，请刷新状态")
            selector["default"] = selected

        self._apply_config_change(mutate, f"切换节点 [{selected}]")

    def get_next_ip_stack_mode(self, current_mode: str) -> str:
        return next_ip_stack_mode(current_mode)

    def cycle_ip_stack(self) -> None:
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return
        self.set_ip_stack(next_ip_stack_mode(get_sing_box_ip_stack(self.config, self.tun_tag)))

    def set_ip_stack(self, mode: str) -> None:
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return
        label = format_ip_stack_mode(mode)
        if mode == get_sing_box_ip_stack(self.config, self.tun_tag):
            self.show_status(f"IP 栈已经是 {label}")
            return

        def save_operation() -> SaveResult:
            return save_ip_stack_config(
                self.config_path,
                self.tun_tag,
                mode,
                validate=self.validate_config,
                backup_keep=self.backup_keep,
            )

        def on_confirm(confirmed: bool | None) -> None:
            if confirmed:
                self._apply_save_operation(
                    save_operation,
                    f"切换 IP 栈为 {label}",
                    "切换 IP 栈失败",
                )

        # IP 栈切换会重启 sing-box 服务，先二次确认
        self.push_screen(
            ConfirmScreen(f"切换 IP 栈为 {label} 将重启 sing-box 服务，确定继续吗？"),
            on_confirm,
        )

    def set_mode(self, mode: str) -> None:
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return
        label = "系统代理" if mode == "system" else "TUN 模式"

        def mutate(data: dict[str, Any]) -> None:
            set_proxy_mode(
                data,
                mode,
                self.mixed_tag,
                self.tun_tag,
                auto_create_mixed=True,
                preserve_custom_tun_flags=True,
            )

        self._apply_config_change(mutate, f"切换代理模式为 {label}")

    # ------------------------------------------------------------------
    # 保存 → 重载 → 更新界面 的统一流程（线程 worker 中执行）
    # ------------------------------------------------------------------

    def _apply_config_change(
        self,
        mutate: Callable[[dict], None],
        success_label: str,
        failure_prefix: str = "保存配置失败",
    ) -> None:
        def save_operation() -> SaveResult:
            return save_config(
                self.config_path,
                mutate,
                validate=self.validate_config,
                backup_keep=self.backup_keep,
            )

        self._apply_save_operation(save_operation, success_label, failure_prefix)

    def _apply_save_operation(
        self,
        save_operation: Callable[[], SaveResult],
        success_label: str,
        failure_prefix: str,
    ) -> None:
        if self._busy:
            self.show_status("上一个操作尚未完成，请稍候", error=True)
            return
        self._busy = True
        self._set_action_buttons_disabled(True)
        self._sync_holo_telemetry()
        self.show_status(f"⏳ 正在应用: {success_label}…", pending=True)
        self._config_change_worker(save_operation, success_label, failure_prefix)

    @work(thread=True, group="config-change")
    def _config_change_worker(
        self,
        save_operation: Callable[[], SaveResult],
        success_label: str,
        failure_prefix: str,
    ) -> None:
        try:
            save_result = save_operation()
        except Exception as e:
            self.call_from_thread(self._finish_busy_error, f"{failure_prefix}: {e}")
            return

        if not save_result.changed:
            self.call_from_thread(self._finish_config_change, save_result, f"配置无需修改: {success_label}", False)
            return

        if not self.reload_enabled:
            self.call_from_thread(
                self._finish_config_change,
                save_result,
                f"已保存 {success_label}，未重载服务",
                False,
            )
            return

        # TUN 设置变更需要重建 TUN 接口，避免 reload 后新配置不生效
        force_restart = tun_settings_changed(save_result.previous_config, save_result.config, self.tun_tag)
        try:
            ok, msg = reload_sing_box(self.service_name, force_restart=force_restart)
        except Exception as error:
            ok, msg = False, str(error)
        if ok:
            self.call_from_thread(
                self._finish_config_change,
                save_result,
                f"✅ {success_label}，{msg}",
                False,
            )
        else:
            self.call_from_thread(
                self._finish_config_change,
                save_result,
                f"配置已保存但服务重载失败: {msg}",
                True,
            )

    def _finish_config_change(self, save_result: SaveResult, message: str, error: bool) -> None:
        self._busy = False
        self._set_action_buttons_disabled(False)
        self._ingest_config(save_result.config)
        self.update_node_table(focus=False)
        self.update_mode_buttons()
        self._sync_holo_telemetry()
        self.refresh_runtime_info()
        note = format_save_note(save_result, short=True)
        self.show_status(f"{message}。{note}" if note else message, error=error)

    def _finish_busy_error(self, message: str) -> None:
        self._busy = False
        self._set_action_buttons_disabled(False)
        self._sync_holo_telemetry()
        self.show_status(message, error=True)
