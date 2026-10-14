"""Command-line options and application entry point."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .config import (
    DEFAULT_BACKUP_KEEP,
    DEFAULT_CONFIG_PATH,
    DEFAULT_MIXED_TAG,
    DEFAULT_SELECTOR_TAG,
    DEFAULT_SERVICE_NAME,
    DEFAULT_TUN_TAG,
    format_save_note,
)
from .network import format_ip_stack_mode, save_ip_stack_config
from .runtime import reload_sing_box
from .tui import SingBoxTUI


def run_set_ip_stack_command(
    config_path: Path,
    service_name: str,
    tun_tag: str,
    mode: str,
    reload_enabled: bool,
    validate_config: bool,
    backup_keep: int,
) -> int:
    label = format_ip_stack_mode(mode)
    save_result = save_ip_stack_config(
        config_path,
        tun_tag,
        mode,
        validate=validate_config,
        backup_keep=backup_keep,
    )

    if not save_result.changed:
        print(f"sing-box IP 栈已经是 {label}")
        return 0

    note = format_save_note(save_result)
    if not reload_enabled:
        print(f"已保存 IP 栈配置: {label}，未重载服务。{note}")
        return 0

    # 切换 IP 栈会改变 TUN address/dns.strategy，必须 restart 才能重建 TUN 接口
    ok, msg = reload_sing_box(service_name, force_restart=True)
    if ok:
        print(f"已切换 sing-box IP 栈到 {label}，{msg}。{note}")
        return 0
    print(f"IP 栈配置已保存但服务重载失败: {msg}。{note}", file=sys.stderr)
    return 1


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="sing-box 节点切换 TUI 工具")
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"sing-box 配置文件路径，默认 {DEFAULT_CONFIG_PATH}",
    )
    parser.add_argument(
        "--service",
        default=DEFAULT_SERVICE_NAME,
        help=f"systemd 服务名，默认 {DEFAULT_SERVICE_NAME}",
    )
    parser.add_argument(
        "--selector-tag",
        default=DEFAULT_SELECTOR_TAG,
        help=f"selector 出站 tag，默认 {DEFAULT_SELECTOR_TAG}",
    )
    parser.add_argument(
        "--mixed-tag",
        default=DEFAULT_MIXED_TAG,
        help=f"mixed 入站 tag，默认 {DEFAULT_MIXED_TAG}",
    )
    parser.add_argument(
        "--tun-tag",
        default=DEFAULT_TUN_TAG,
        help=f"TUN 入站 tag，默认 {DEFAULT_TUN_TAG}",
    )
    parser.add_argument(
        "--backup-keep",
        type=int,
        default=DEFAULT_BACKUP_KEEP,
        help=f"保留最近 N 个配置备份，默认 {DEFAULT_BACKUP_KEEP}，设为 -1 表示不清理",
    )
    parser.add_argument(
        "--disable-ipv6",
        action="store_true",
        help="兼容旧参数：等同于 --ip-stack ipv4",
    )
    parser.add_argument(
        "--ip-stack",
        choices=("ipv4", "ipv6", "dual"),
        help="切换 sing-box TUN IP 栈：ipv4=IPv4 only，ipv6=IPv6 only，dual=IPv4+IPv6",
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="只保存配置，不调用 systemctl reload/restart",
    )
    parser.add_argument(
        "--no-check",
        action="store_true",
        help="保存前不执行 sing-box check",
    )
    return parser.parse_args(argv)


def validate_cli_request(
    args: argparse.Namespace,
    config_path: Path,
) -> tuple[str | None, str | None]:
    """Validate cross-option constraints and resolve the requested IP mode."""

    if args.backup_keep < -1:
        return None, "--backup-keep 必须大于等于 -1"
    if not config_path.exists():
        return None, f"配置文件不存在: {config_path}"

    ip_stack_mode = args.ip_stack
    if args.disable_ipv6:
        if ip_stack_mode and ip_stack_mode != "ipv4":
            return None, "--disable-ipv6 只能与 --ip-stack ipv4 一起使用"
        ip_stack_mode = "ipv4"

    return ip_stack_mode, None


def execute_ip_stack_cli(
    args: argparse.Namespace,
    config_path: Path,
    mode: str,
) -> int:
    """Execute the non-interactive IP-stack operation."""

    try:
        return run_set_ip_stack_command(
            config_path=config_path,
            service_name=args.service,
            tun_tag=args.tun_tag,
            mode=mode,
            reload_enabled=not args.no_reload,
            validate_config=not args.no_check,
            backup_keep=args.backup_keep,
        )
    except Exception as error:
        print(f"切换 IP 栈失败: {error}", file=sys.stderr)
        return 1


def launch_tui(args: argparse.Namespace, config_path: Path) -> None:
    """Construct and run the interactive application."""

    app = SingBoxTUI(
        config_path=config_path,
        service_name=args.service,
        selector_tag=args.selector_tag,
        mixed_tag=args.mixed_tag,
        tun_tag=args.tun_tag,
        backup_keep=args.backup_keep,
        reload_enabled=not args.no_reload,
        validate_config=not args.no_check,
    )
    app.run()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line operation or launch the Textual application."""

    args = parse_args(argv)
    config_path = args.config.expanduser()
    ip_stack_mode, error = validate_cli_request(args, config_path)
    if error:
        print(error, file=sys.stderr)
        return 1

    if ip_stack_mode:
        return execute_ip_stack_cli(args, config_path, ip_stack_mode)

    launch_tui(args, config_path)
    return 0
