"""Interactive node and network configuration management."""

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Static
from textual.worker import get_current_worker

from .config import (
    SaveResult,
    find_proxy_selector,
    format_save_note,
    index_inbounds,
    load_config,
    save_config,
    validate_config_structure,
)
from .network import (
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
    get_dns_tun_status,
    get_public_ipv4,
    get_service_memory_usage,
    get_system_memory_usage,
    get_tun_link_status,
    reload_sing_box,
)

PUBLIC_IP_CACHE_TTL = 300.0


class SingBoxTUI(App):
    CSS = """
    Screen { align: center middle; }
    #main { width: 1fr; max-width: 96; height: auto; border: solid green; padding: 1 2; }
    #title { text-align: center; text-style: bold; color: $primary; }
    #subtitle { text-align: center; margin-bottom: 1; }
    #node-section { height: auto; margin-bottom: 1; }
    #mode-section { height: auto; margin-bottom: 1; }
    #status { text-align: center; color: $success; margin-top: 1; }
    #status.error { color: $error; }
    #runtime-info { text-align: center; color: $text-muted; margin-bottom: 1; }
    #network-info { text-align: center; color: $text-muted; margin-bottom: 1; }
    DataTable { height: 10; }
    .section-title { text-style: bold; color: $secondary; margin-bottom: 1; }
    #mode-section Horizontal { height: auto; }
    Button { margin: 0 1; }
    """

    BINDINGS = [
        ("q", "quit", "退出"),
        ("r", "refresh", "刷新状态"),
        ("space", "select_highlighted_node", "切换节点"),
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
        self.current_node = ""
        self.proxy_mode = ""
        self.nodes: list[str] = []
        self._busy = False
        self._public_ip: str | None = None
        self._public_ip_at = 0.0
        self._runtime_generation = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="main"):
            yield Static("sing-box 节点切换工具", id="title")
            yield Static(
                "使用 ↑↓ 选择节点，回车/空格切换 | Tab切换区域 | r刷新 | q退出",
                id="subtitle",
            )
            yield Static("正在获取运行状态…", id="runtime-info")
            yield Static("", id="network-info")

            with Vertical(id="node-section"):
                yield Static("📡 代理节点", classes="section-title")
                table: DataTable[Any] = DataTable(id="node-table")
                table.cursor_type = "row"
                yield table

            with Vertical(id="mode-section"):
                yield Static("🌐 代理模式", classes="section-title")
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

    def on_mount(self):
        self.refresh_data()
        self.update_node_table()
        self.update_mode_buttons()
        self.refresh_runtime_info()

    # ------------------------------------------------------------------
    # 数据加载
    # ------------------------------------------------------------------

    def _reset_state(self):
        self.config = None
        self.selector = None
        self.inbounds = {}
        self.nodes = []
        self.current_node = ""
        self.proxy_mode = "unknown"

    def _ingest_config(self, loaded: dict):
        self.config = loaded
        self.selector = find_proxy_selector(loaded, self.selector_tag)
        self.inbounds = index_inbounds(loaded)

        if self.selector:
            selector_nodes = self.selector.get("outbounds", [])
            self.nodes = selector_nodes if isinstance(selector_nodes, list) else []
            self.current_node = self.selector.get("default", "")
        else:
            self.nodes = []
            self.current_node = ""

        self.proxy_mode = get_proxy_mode(loaded, self.mixed_tag, self.tun_tag)

    def refresh_data(self):
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

    def update_node_table(self):
        table = self.query_one("#node-table", DataTable)
        table.clear(columns=True)
        table.add_columns("状态", "节点名称")
        if not self.nodes:
            table.add_row("!", f"未找到 {self.selector_tag} selector 或节点列表为空")
            return
        for idx, node in enumerate(self.nodes):
            marker = "✅" if node == self.current_node else "  "
            table.add_row(marker, node, key=str(idx))
        table.focus()

    def update_mode_buttons(self):
        btn_sys = self.query_one("#btn-system", Button)
        btn_tun = self.query_one("#btn-tun", Button)
        ip_stack_buttons = {
            "ipv4": self.query_one("#btn-ipv4", Button),
            "ipv6": self.query_one("#btn-ipv6", Button),
            "dual": self.query_one("#btn-dual-stack", Button),
        }
        if self.proxy_mode == "system":
            btn_sys.label = "✅ 系统代理 (mixed)"
            btn_tun.label = "TUN 模式"
            btn_sys.variant = "success"
            btn_tun.variant = "primary"
        elif self.proxy_mode == "tun":
            btn_sys.label = "系统代理 (mixed)"
            btn_tun.label = "✅ TUN 模式"
            btn_sys.variant = "primary"
            btn_tun.variant = "success"
        elif self.proxy_mode == "mixed+tun":
            btn_sys.label = "✅ 系统代理 (mixed)"
            btn_tun.label = "✅ TUN 模式"
            btn_sys.variant = "warning"
            btn_tun.variant = "warning"
        else:
            btn_sys.label = "系统代理 (mixed)"
            btn_tun.label = "TUN 模式"
            btn_sys.variant = "primary"
            btn_tun.variant = "primary"

        current_ip_stack = get_sing_box_ip_stack(self.config, self.tun_tag)
        cycle_button = self.query_one("#btn-cycle-ip-stack", Button)
        cycle_button.label = f"切换 IPv4/IPv6 ({format_ip_stack_mode(current_ip_stack)})"
        cycle_button.variant = "warning" if current_ip_stack == "unknown" else "primary"

        for mode, button in ip_stack_buttons.items():
            label = format_ip_stack_mode(mode)
            if mode == current_ip_stack:
                button.label = f"✅ {label}"
                button.variant = "success"
            else:
                button.label = label
                button.variant = "primary"

    def show_status(self, msg: str, error: bool = False):
        status = self.query_one("#status", Static)
        status.update(Text(str(msg)))
        if error:
            status.add_class("error")
        else:
            status.remove_class("error")

    def _set_action_buttons_disabled(self, disabled: bool) -> None:
        for button in self.query(Button):
            button.disabled = disabled

    # ------------------------------------------------------------------
    # 运行状态（子进程调用全部放到线程 worker，避免阻塞界面）
    # ------------------------------------------------------------------

    def refresh_runtime_info(self, force_ip: bool = False):
        """Capture state on the UI thread and only publish the latest refresh."""

        self._runtime_generation += 1
        now = time.monotonic()
        cached_ip = None
        if not force_ip and self._public_ip is not None and now - self._public_ip_at < PUBLIC_IP_CACHE_TTL:
            cached_ip = self._public_ip
        # 只把 worker 真正需要的 TUN 快照传过去，避免深拷贝整个配置
        config = self.config
        interface_name = get_tun_interface_name(config, self.tun_tag)
        ip_stack_mode = get_sing_box_ip_stack(config, self.tun_tag)
        return self._runtime_info_worker(
            self._runtime_generation,
            interface_name,
            ip_stack_mode,
            cached_ip,
            self._public_ip_at,
        )

    @work(thread=True, exclusive=True, group="runtime-info")
    def _runtime_info_worker(
        self,
        generation: int,
        interface_name: str,
        ip_stack_mode: str,
        cached_ip: str | None,
        cached_ip_at: float,
    ):
        public_ip = cached_ip if cached_ip is not None else get_public_ipv4()
        public_ip_at = cached_ip_at if cached_ip is not None else time.monotonic()
        system_memory = get_system_memory_usage()
        service_memory = get_service_memory_usage(self.service_name)
        tun_status = get_tun_link_status(interface_name)
        dns_status = get_dns_tun_status(interface_name)
        ip_stack_status = format_ip_stack_mode(ip_stack_mode)
        runtime_text = f"出口 IPv4: {public_ip} | 系统内存: {system_memory} | sing-box 内存: {service_memory}"
        network_text = f"TUN: {tun_status} ({interface_name}) | DNS 走 TUN: {dns_status} | IP 栈: {ip_stack_status}"
        if not get_current_worker().is_cancelled:
            self.call_from_thread(
                self._render_runtime_info,
                generation,
                public_ip,
                public_ip_at,
                runtime_text,
                network_text,
            )

    def _render_runtime_info(
        self,
        generation: int,
        public_ip: str,
        public_ip_at: float,
        runtime_text: str,
        network_text: str,
    ):
        if generation != self._runtime_generation:
            return
        self._public_ip = public_ip
        self._public_ip_at = public_ip_at
        self.query_one("#runtime-info", Static).update(runtime_text)
        self.query_one("#network-info", Static).update(network_text)

    # ------------------------------------------------------------------
    # 动作
    # ------------------------------------------------------------------

    def action_refresh(self):
        ok = self.refresh_data()
        self.update_node_table()
        self.update_mode_buttons()
        self.refresh_runtime_info(force_ip=True)
        if ok:
            self.show_status("状态已刷新")

    def action_select_highlighted_node(self):
        table = self.query_one("#node-table", DataTable)
        if table.cursor_row is not None:
            self._select_node_by_index(table.cursor_row)

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if not self.selector:
            return
        row_key = getattr(event.row_key, "value", event.row_key)
        try:
            idx = int(str(row_key))
        except (ValueError, TypeError):
            return
        self._select_node_by_index(idx)

    def on_button_pressed(self, event: Button.Pressed):
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

    def _select_node_by_index(self, idx: int):
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return
        if not self.selector or not (0 <= idx < len(self.nodes)):
            return
        selected = self.nodes[idx]

        def mutate(data):
            selector = find_proxy_selector(data, self.selector_tag)
            if not selector:
                raise ValueError(f"配置中未找到 tag={self.selector_tag} 的 selector")
            if selected not in selector.get("outbounds", []):
                raise ValueError(f"节点 [{selected}] 已不在 selector 中，请刷新状态")
            selector["default"] = selected

        self._apply_config_change(mutate, f"切换节点 [{selected}]")

    def get_next_ip_stack_mode(self, current_mode: str):
        return next_ip_stack_mode(current_mode)

    def cycle_ip_stack(self):
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return
        self.set_ip_stack(next_ip_stack_mode(get_sing_box_ip_stack(self.config, self.tun_tag)))

    def set_ip_stack(self, mode: str):
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return
        label = format_ip_stack_mode(mode)

        def save_operation() -> SaveResult:
            return save_ip_stack_config(
                self.config_path,
                self.tun_tag,
                mode,
                validate=self.validate_config,
                backup_keep=self.backup_keep,
            )

        self._apply_save_operation(
            save_operation,
            f"切换 IP 栈为 {label}",
            "切换 IP 栈失败",
        )

    def set_mode(self, mode: str):
        if not self.config:
            self.show_status("配置尚未成功加载", error=True)
            return
        label = "系统代理" if mode == "system" else "TUN 模式"

        def mutate(data):
            set_proxy_mode(data, mode, self.mixed_tag, self.tun_tag)

        self._apply_config_change(mutate, f"切换代理模式为 {label}")

    # ------------------------------------------------------------------
    # 保存 → 重载 → 更新界面 的统一流程（线程 worker 中执行）
    # ------------------------------------------------------------------

    def _apply_config_change(
        self,
        mutate: Callable[[dict], None],
        success_label: str,
        failure_prefix: str = "保存配置失败",
    ):
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
        self.show_status(f"正在应用: {success_label}…")
        self._config_change_worker(save_operation, success_label, failure_prefix)

    @work(thread=True, group="config-change")
    def _config_change_worker(
        self,
        save_operation: Callable[[], SaveResult],
        success_label: str,
        failure_prefix: str,
    ):
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

    def _finish_config_change(self, save_result: SaveResult, message: str, error: bool):
        self._busy = False
        self._set_action_buttons_disabled(False)
        self._ingest_config(save_result.config)
        self.update_node_table()
        self.update_mode_buttons()
        self.refresh_runtime_info()
        note = format_save_note(save_result)
        self.show_status(f"{message}。{note}" if note else message, error=error)

    def _finish_busy_error(self, message: str):
        self._busy = False
        self._set_action_buttons_disabled(False)
        self.show_status(message, error=True)
