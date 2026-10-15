"""Proxy modes and persistent TUN IP-family settings."""

import ipaddress
import json
from collections.abc import Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_BACKUP_KEEP,
    SaveResult,
    cleanup_backups,
    dump_json_atomic,
    index_inbounds,
    load_config,
    locked_paths,
    resolve_config_path,
    validate_config_structure,
    write_json_atomic,
)

DEFAULT_TUN_IPV4_ADDRESS = "172.19.0.1/30"
DEFAULT_TUN_IPV6_ADDRESS = "fdfe:dcba:9876::1/126"
DEFAULT_MIXED_LISTEN = "127.0.0.1"
DEFAULT_MIXED_PORT = 2080
IP_STACK_LABELS = {
    "ipv4": "IPv4 only",
    "ipv6": "IPv6 only",
    "dual": "IPv4+IPv6",
    "unknown": "未知",
}


def list_value(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    raise ValueError("地址字段必须是字符串或字符串数组")


def is_ipv6_address(value: object) -> bool:
    """Return whether an address or network value is IPv6.

    Invalid strings are rejected instead of being guessed from the presence of a
    colon, so a missing ``sing-box`` binary cannot silently bypass validation.
    """

    text = str(value).strip()
    try:
        return ipaddress.ip_interface(text).version == 6
    except ValueError:
        try:
            return ipaddress.ip_network(text, strict=False).version == 6
        except ValueError as error:
            raise ValueError(f"无效的 IP 地址或网段: {value}") from error


def split_ip_values(value):
    ipv4 = []
    ipv6 = []
    for item in list_value(value):
        if is_ipv6_address(item):
            ipv6.append(item)
        else:
            ipv4.append(item)
    return ipv4, ipv6


def unique_values(values: Sequence[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        key = str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def get_tun_inbound(config: dict[str, Any], tun_tag: str) -> dict[str, Any]:
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise ValueError("inbounds 字段必须是数组")

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if inbound.get("type") == "tun" and inbound.get("tag") == tun_tag:
            return inbound
    raise ValueError(f"配置中未找到 tag={tun_tag} 的 TUN 入站")


def tun_settings_changed(
    old_config: dict | None,
    new_config: dict | None,
    tun_tag: str,
) -> bool:
    """判断两次配置之间 TUN 入站设置或 DNS IP 策略是否发生变化。

    TUN 设置变更（如 address、auto_route、strict_route 等）通常需要
    重启 sing-box 才能重新创建 TUN 接口并应用新的路由/重定向规则，
    单纯的 reload 可能无法让新配置生效。
    """
    if not isinstance(old_config, dict) or not isinstance(new_config, dict):
        return True
    try:
        old_tun = get_tun_inbound(old_config, tun_tag)
    except ValueError:
        old_tun = None
    try:
        new_tun = get_tun_inbound(new_config, tun_tag)
    except ValueError:
        new_tun = None
    return bool(old_tun != new_tun)


def set_dns_ip_strategy(data: dict[str, Any], mode: str) -> None:
    """Apply the DNS strategy associated with an IP-stack mode."""

    dns = data.get("dns")
    if dns is None:
        dns = {}
        data["dns"] = dns
    if not isinstance(dns, dict):
        raise ValueError("dns 字段必须是 JSON 对象")
    if mode in {"ipv4", "ipv6"}:
        dns["strategy"] = f"{mode}_only"
    elif dns.get("strategy") in {"ipv4_only", "ipv6_only"}:
        dns.pop("strategy", None)


def preserve_ip_family_values(
    preserved_values: dict[str, list[Any]],
    prefix: str,
    ipv4_values: list[Any],
    ipv6_values: list[Any],
) -> tuple[list[Any], list[Any]]:
    """Remember non-empty address families and return the best saved values."""

    if ipv4_values:
        preserved_values[f"{prefix}_ipv4"] = ipv4_values
    if ipv6_values:
        preserved_values[f"{prefix}_ipv6"] = ipv6_values
    return (
        preserved_values.get(f"{prefix}_ipv4", []),
        preserved_values.get(f"{prefix}_ipv6", []),
    )


def select_ip_family_values(
    mode: str,
    ipv4_values: list[Any],
    ipv6_values: list[Any],
) -> list[Any]:
    """Select one or both families from already resolved value lists."""

    if mode == "ipv4":
        return ipv4_values
    if mode == "ipv6":
        return ipv6_values
    return unique_values(ipv4_values + ipv6_values)


def update_tun_addresses(
    tun: dict[str, Any],
    mode: str,
    preserved_values: dict[str, list[Any]],
) -> None:
    """Update active TUN interface addresses while retaining custom values."""

    current_ipv4, current_ipv6 = split_ip_values(tun.get("address"))
    saved_ipv4, saved_ipv6 = preserve_ip_family_values(preserved_values, "address", current_ipv4, current_ipv6)
    ipv4_values = current_ipv4 or saved_ipv4 or [DEFAULT_TUN_IPV4_ADDRESS]
    ipv6_values = current_ipv6 or saved_ipv6 or [DEFAULT_TUN_IPV6_ADDRESS]
    tun["address"] = select_ip_family_values(mode, ipv4_values, ipv6_values)


def update_tun_excluded_routes(
    tun: dict[str, Any],
    mode: str,
    preserved_values: dict[str, list[Any]],
) -> None:
    """Update active excluded routes while retaining the inactive family."""

    if "route_exclude_address" not in tun:
        return
    current_ipv4, current_ipv6 = split_ip_values(tun.get("route_exclude_address"))
    saved_ipv4, saved_ipv6 = preserve_ip_family_values(
        preserved_values,
        "route_exclude_address",
        current_ipv4,
        current_ipv6,
    )
    tun["route_exclude_address"] = select_ip_family_values(
        mode,
        current_ipv4 or saved_ipv4,
        current_ipv6 or saved_ipv6,
    )


def set_sing_box_ip_stack(
    data: dict,
    tun_tag: str,
    mode: str,
    preserved_values: dict[str, list[Any]] | None = None,
):
    """Set the active IP family while preserving inactive custom values."""

    if mode not in ("ipv4", "ipv6", "dual"):
        raise ValueError("IP 栈模式必须是 ipv4、ipv6 或 dual")

    if preserved_values is None:
        preserved_values = {}

    validate_config_structure(data)

    set_dns_ip_strategy(data, mode)
    tun = get_tun_inbound(data, tun_tag)
    update_tun_addresses(tun, mode, preserved_values)
    update_tun_excluded_routes(tun, mode, preserved_values)

    return data


def ip_stack_state_path(config_path: Path) -> Path:
    """Return the sidecar used to preserve inactive TUN address families."""

    config_path = resolve_config_path(config_path)
    return config_path.with_name(f"{config_path.name}.singbox-tui-state.json")


def load_ip_stack_state(config_path: Path) -> dict[str, Any]:
    """Load preserved IP-stack values, tolerating a missing sidecar."""

    state_path = ip_stack_state_path(config_path)
    if not state_path.exists():
        return {"version": 1, "tun": {}}
    try:
        state = load_config(state_path)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"无法读取 IP 栈状态文件 {state_path}: {error}") from error
    if not isinstance(state, dict) or not isinstance(state.get("tun", {}), dict):
        raise ValueError(f"IP 栈状态文件格式无效: {state_path}")
    state.setdefault("version", 1)
    state.setdefault("tun", {})
    return state


def save_ip_stack_config(
    config_path: Path,
    tun_tag: str,
    mode: str,
    *,
    validate: bool = True,
    backup_keep: int = DEFAULT_BACKUP_KEEP,
) -> SaveResult:
    """Save an IP-stack change without losing inactive custom values."""

    config_path = resolve_config_path(config_path)
    state_path = ip_stack_state_path(config_path)
    with locked_paths([config_path, state_path]):
        data = load_config(config_path)
        validate_config_structure(data)
        previous_config = deepcopy(data)
        state = load_ip_stack_state(config_path)
        previous_state = deepcopy(state)
        tun_states = state.setdefault("tun", {})
        tun_state = tun_states.setdefault(tun_tag, {})
        if not isinstance(tun_state, dict):
            raise ValueError(f"IP 栈状态中 {tun_tag} 字段必须是 JSON 对象")
        set_sing_box_ip_stack(
            data,
            tun_tag,
            mode,
            preserved_values=tun_state,
        )
        validate_config_structure(data)

        # Write preservation metadata first. If config validation subsequently
        # fails, keeping extra state is harmless and avoids ever losing values.
        if state != previous_state:
            write_json_atomic(state, state_path)
        if data == previous_config:
            return SaveResult(data, None, changed=False, previous_config=previous_config)
        backup_path, validation_message = dump_json_atomic(data, config_path, validate)
        cleaned_backups = cleanup_backups(config_path, backup_keep)
    return SaveResult(
        config=data,
        backup_path=backup_path,
        validation_message=validation_message,
        cleaned_backups=cleaned_backups,
        previous_config=previous_config,
    )


def get_sing_box_ip_stack(config: dict[str, Any] | None, tun_tag: str) -> str:
    if not isinstance(config, dict):
        return "unknown"
    try:
        tun = get_tun_inbound(config, tun_tag)
    except ValueError:
        return "unknown"
    dns = config.get("dns", {})
    dns_strategy = dns.get("strategy") if isinstance(dns, dict) else None
    try:
        ipv4_address, ipv6_address = split_ip_values(tun.get("address"))
    except ValueError:
        return "unknown"
    if dns_strategy == "ipv4_only":
        return "ipv4" if ipv4_address and not ipv6_address else "unknown"
    if dns_strategy == "ipv6_only":
        return "ipv6" if ipv6_address and not ipv4_address else "unknown"
    if ipv4_address and ipv6_address:
        return "dual"
    if ipv4_address:
        return "ipv4"
    if ipv6_address:
        return "ipv6"
    return "unknown"


def describe_ip_stack_state(config: dict[str, Any] | None, tun_tag: str) -> str:
    """Return a user-friendly IP stack label including mismatch diagnostics."""

    mode = get_sing_box_ip_stack(config, tun_tag)
    if mode != "unknown" or not isinstance(config, dict):
        return format_ip_stack_mode(mode)
    try:
        tun = get_tun_inbound(config, tun_tag)
        ipv4_address, ipv6_address = split_ip_values(tun.get("address"))
    except ValueError:
        return format_ip_stack_mode("unknown")

    dns = config.get("dns", {})
    dns_strategy = dns.get("strategy") if isinstance(dns, dict) else None
    if dns_strategy == "ipv4_only" and ipv4_address and ipv6_address:
        return "未知 (DNS仅v4/TUN双栈)"
    if dns_strategy == "ipv6_only" and ipv4_address and ipv6_address:
        return "未知 (DNS仅v6/TUN双栈)"
    return format_ip_stack_mode("unknown")


def next_ip_stack_mode(current_mode: str) -> str:
    order = ("ipv4", "ipv6", "dual")
    if current_mode not in order:
        return "ipv4"
    return order[(order.index(current_mode) + 1) % len(order)]


def format_ip_stack_mode(mode: str) -> str:
    return IP_STACK_LABELS.get(mode, IP_STACK_LABELS["unknown"])


def set_proxy_mode(
    data: dict[str, Any],
    mode: str,
    mixed_tag: str,
    tun_tag: str,
    *,
    auto_create_mixed: bool = False,
    preserve_custom_tun_flags: bool = False,
) -> dict[str, Any]:
    if mode not in ("system", "tun"):
        raise ValueError(f"未知模式: {mode}")

    inbounds = index_inbounds(data)
    mixed = inbounds.get(mixed_tag)
    tun = inbounds.get(tun_tag)

    if not tun:
        raise ValueError(f"配置中缺少 {mixed_tag} 或 {tun_tag}")

    if not mixed:
        if not auto_create_mixed:
            raise ValueError(f"配置中缺少 {mixed_tag} 或 {tun_tag}")
        mixed = {
            "type": "mixed",
            "tag": mixed_tag,
            "listen": DEFAULT_MIXED_LISTEN,
            "listen_port": DEFAULT_MIXED_PORT,
            "set_system_proxy": False,
        }
        inbound_list = data.setdefault("inbounds", [])
        if isinstance(inbound_list, list):
            inbound_list.insert(0, mixed)

    enable_tun = mode == "tun"
    mixed["set_system_proxy"] = not enable_tun

    # Custom iproute2 routing setups (like iproute2_table_index / iproute2_rule_index)
    # often intentionally set strict_route=False and auto_redirect=False.
    has_custom_iproute2 = "iproute2_table_index" in tun or "iproute2_rule_index" in tun
    tun["auto_route"] = enable_tun
    if not (preserve_custom_tun_flags and has_custom_iproute2):
        tun["strict_route"] = enable_tun
        if "auto_redirect" in tun:
            tun["auto_redirect"] = enable_tun
    elif not enable_tun:
        tun["strict_route"] = False
        if "auto_redirect" in tun:
            tun["auto_redirect"] = False

    return data


def get_proxy_mode(config: dict[str, Any], mixed_tag: str, tun_tag: str) -> str:
    inbounds = index_inbounds(config)
    mixed_enabled = bool(inbounds.get(mixed_tag, {}).get("set_system_proxy"))
    tun_enabled = bool(inbounds.get(tun_tag, {}).get("auto_route"))
    if mixed_enabled and tun_enabled:
        return "mixed+tun"
    if mixed_enabled:
        return "system"
    if tun_enabled:
        return "tun"
    return "unknown"


def get_tun_interface_name(config: dict[str, Any] | None, tun_tag: str) -> str:
    if not isinstance(config, dict):
        return "sing-tun"
    try:
        tun = get_tun_inbound(config, tun_tag)
    except ValueError:
        return "sing-tun"
    return str(tun.get("interface_name") or "sing-tun")
