"""Validated, locked and atomic configuration storage."""

import fcntl
import json
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager, suppress
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path("/etc/sing-box/config.json")
DEFAULT_SERVICE_NAME = "sing-box"
DEFAULT_SELECTOR_TAG = "proxy"
DEFAULT_MIXED_TAG = "mixed-in"
DEFAULT_TUN_TAG = "tun-in"
DEFAULT_BACKUP_KEEP = 10
CONFIG_CHECK_TIMEOUT = 30


@dataclass
class SaveResult:
    config: dict[str, Any]
    backup_path: Path | None
    validation_message: str | None = None
    cleaned_backups: list[Path] = field(default_factory=list)
    changed: bool = True
    previous_config: dict[str, Any] | None = None


@dataclass(frozen=True)
class NodeInfo:
    """Structured metadata extracted from an outbound definition."""

    tag: str
    protocol: str = "unknown"
    server: str = ""
    server_port: int | None = None
    tls_enabled: bool = False
    server_name: str = ""
    transport_type: str = ""
    congestion_control: str = ""
    detour: str = ""

    @property
    def endpoint(self) -> str:
        if not self.server:
            return "本地/内置"
        if self.server_port:
            return f"{self.server}:{self.server_port}"
        return self.server

    @property
    def badge(self) -> str:
        proto = self.protocol.upper()
        extras: list[str] = []
        if self.transport_type:
            extras.append(self.transport_type)
        if self.congestion_control:
            extras.append(self.congestion_control)
        if self.tls_enabled:
            extras.append("tls")
        if extras:
            return f"{proto} · {'+'.join(extras)}"
        return proto


@dataclass(frozen=True)
class ConfigHealthIssue:
    """Diagnostic item discovered when inspecting a sing-box configuration."""

    level: str  # "warning" | "info" | "error"
    code: str
    message: str


def resolve_config_path(path: Path) -> Path:
    """Use the same real destination for reads, locks, backups and writes."""

    return path.expanduser().resolve()


def load_config(config_path: Path) -> dict[str, Any]:
    with open(config_path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("配置文件根节点必须是 JSON 对象")
    return data


def validate_config_structure(data: object) -> None:
    if not isinstance(data, dict):
        raise ValueError("配置文件根节点必须是 JSON 对象")

    for key in ("route", "dns", "log", "experimental"):
        if key in data and not isinstance(data[key], dict):
            raise ValueError(f"{key} 字段必须是 JSON 对象")

    for key in ("inbounds", "outbounds", "http_clients", "endpoints"):
        if key in data and not isinstance(data[key], list):
            raise ValueError(f"{key} 字段必须是数组")
        for idx, item in enumerate(data.get(key, [])):
            if not isinstance(item, dict):
                raise ValueError(f"{key}[{idx}] 必须是 JSON 对象")

    dns = data.get("dns")
    if isinstance(dns, dict):
        for subkey in ("servers", "rules"):
            if subkey in dns and not isinstance(dns[subkey], list):
                raise ValueError(f"dns.{subkey} 字段必须是数组")

    route = data.get("route")
    if isinstance(route, dict):
        for subkey in ("rules", "rule_set"):
            if subkey in route and not isinstance(route[subkey], list):
                raise ValueError(f"route.{subkey} 字段必须是数组")


def fsync_directory(path: Path) -> None:
    """Persist directory metadata after an atomic replacement."""

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def preserve_file_metadata(path: Path, original_stat: os.stat_result | None) -> None:
    """Preserve ownership and permissions, aborting if that is not possible."""

    if original_stat is None:
        return
    current_stat = path.stat()
    if (current_stat.st_uid, current_stat.st_gid) != (original_stat.st_uid, original_stat.st_gid):
        os.chown(path, original_stat.st_uid, original_stat.st_gid)
    # chown may clear permission bits, so restore the mode afterwards.
    os.chmod(path, stat.S_IMODE(original_stat.st_mode))


def fsync_file(path: Path) -> None:
    with path.open("rb") as file:
        os.fsync(file.fileno())


@contextmanager
def _staged_json_write(data: dict[str, Any], path: Path) -> Iterator[Path]:
    """将 JSON 写入 path 同目录的临时文件并 yield 其路径。

    调用方在 yield 期间完成校验，再把临时文件原子替换到目标位置；
    临时文件在任何情况下都会被清理（替换成功后原路径已不存在，清理自动跳过）。
    """

    path = resolve_config_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_stat = path.stat() if path.exists() else None
    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            staged = Path(temporary.name)
            json.dump(data, temporary, indent=2, ensure_ascii=False)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        assert staged is not None
        preserve_file_metadata(staged, existing_stat)
        fsync_file(staged)
        yield staged
    finally:
        if staged is not None and staged.exists():
            staged.unlink()


def write_json_atomic(data: dict[str, Any], path: Path) -> None:
    """Write JSON atomically without creating a backup."""

    path = resolve_config_path(path)
    with _staged_json_write(data, path) as staged:
        os.replace(staged, path)
        fsync_directory(path.parent)


def find_proxy_selector(config: dict[str, Any], selector_tag: str) -> dict[str, Any] | None:
    for outbound in config.get("outbounds", []):
        if not isinstance(outbound, dict):
            continue
        if outbound.get("type") == "selector" and outbound.get("tag") == selector_tag:
            return outbound
    return None


def index_inbounds(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    inbounds: dict[str, dict[str, Any]] = {}
    for inbound in config.get("inbounds", []):
        if isinstance(inbound, dict) and isinstance(tag := inbound.get("tag"), str) and tag:
            inbounds[tag] = inbound
    return inbounds


def index_outbounds(config: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Index all outbounds by tag for fast lookup."""

    if not isinstance(config, dict):
        return {}
    outbounds: dict[str, dict[str, Any]] = {}
    for outbound in config.get("outbounds", []):
        if isinstance(outbound, dict) and isinstance(tag := outbound.get("tag"), str) and tag:
            outbounds[tag] = outbound
    return outbounds


def describe_outbound_node(config: dict[str, Any] | None, node_tag: str) -> NodeInfo:
    """Extract rich protocol, endpoint and transport details for a node tag."""

    outbound = index_outbounds(config).get(node_tag)
    if not isinstance(outbound, dict):
        return NodeInfo(tag=node_tag)

    protocol = str(outbound.get("type") or "unknown")
    server = str(outbound.get("server") or "").strip()
    raw_port = outbound.get("server_port")
    server_port = int(raw_port) if isinstance(raw_port, int) and not isinstance(raw_port, bool) else None

    tls = outbound.get("tls")
    tls_enabled = bool(isinstance(tls, dict) and tls.get("enabled"))
    server_name = str(tls.get("server_name") or "").strip() if isinstance(tls, dict) else ""

    transport = outbound.get("transport")
    transport_type = ""
    if isinstance(transport, dict) and transport.get("type"):
        transport_type = str(transport.get("type"))
    elif isinstance(outbound.get("obfs"), dict) and outbound["obfs"].get("type"):
        transport_type = f"obfs:{outbound['obfs']['type']}"
    elif isinstance(tls, dict) and isinstance(tls.get("alpn"), list) and tls["alpn"]:
        transport_type = "/".join(str(x) for x in tls["alpn"])

    congestion = str(outbound.get("congestion_control") or "").strip()
    detour = str(outbound.get("detour") or "").strip()

    return NodeInfo(
        tag=node_tag,
        protocol=protocol,
        server=server,
        server_port=server_port,
        tls_enabled=tls_enabled,
        server_name=server_name,
        transport_type=transport_type,
        congestion_control=congestion,
        detour=detour,
    )


def _collect_referenced_rule_sets(rules: list[Any]) -> set[str]:
    referenced: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rs = rule.get("rule_set")
        if isinstance(rs, str) and rs:
            referenced.add(rs)
        elif isinstance(rs, list):
            referenced.update(str(item) for item in rs if isinstance(item, str) and item)
    return referenced


def inspect_config_health(
    config: dict[str, Any] | None,
    selector_tag: str = DEFAULT_SELECTOR_TAG,
    mixed_tag: str = DEFAULT_MIXED_TAG,
    tun_tag: str = DEFAULT_TUN_TAG,
) -> list[ConfigHealthIssue]:
    """Perform static diagnostics on a sing-box configuration."""

    if not isinstance(config, dict):
        return [ConfigHealthIssue("error", "invalid_root", "配置未加载或根节点无效")]

    issues: list[ConfigHealthIssue] = []
    inbounds = index_inbounds(config)
    outbounds = index_outbounds(config)

    selector = find_proxy_selector(config, selector_tag)
    if not selector:
        issues.append(
            ConfigHealthIssue("error", "missing_selector", f"未找到 tag={selector_tag} 的 selector 出站")
        )
    else:
        candidates = [str(x) for x in selector.get("outbounds", []) if isinstance(x, str)]
        default_node = selector.get("default")
        if isinstance(default_node, str) and default_node and default_node not in candidates:
            issues.append(
                ConfigHealthIssue(
                    "warning",
                    "invalid_default_node",
                    f"selector 默认节点 [{default_node}] 不在候选列表中",
                )
            )
        missing_targets = [tag for tag in candidates if tag not in outbounds]
        if missing_targets:
            issues.append(
                ConfigHealthIssue(
                    "error",
                    "missing_outbound_targets",
                    f"selector 引用了未定义的出站节点: {', '.join(missing_targets)}",
                )
            )

    if tun_tag not in inbounds:
        issues.append(ConfigHealthIssue("warning", "missing_tun", f"未配置 tag={tun_tag} 的 TUN 入站"))
    if mixed_tag not in inbounds:
        issues.append(
            ConfigHealthIssue(
                "info",
                "pure_tun_mode",
                f"当前为纯 TUN 配置（未定义 {mixed_tag}），切换到系统代理时将自动按需补充",
            )
        )

    # Check DNS strategy vs TUN address family consistency
    dns = config.get("dns", {})
    dns_strategy = dns.get("strategy") if isinstance(dns, dict) else None
    tun = inbounds.get(tun_tag)
    if isinstance(tun, dict):
        raw_addr = tun.get("address", [])
        addrs = [raw_addr] if isinstance(raw_addr, str) else (raw_addr if isinstance(raw_addr, list) else [])
        has_v4 = any("." in str(a) for a in addrs)
        has_v6 = any(":" in str(a) for a in addrs)
        if dns_strategy == "ipv4_only" and has_v6:
            issues.append(
                ConfigHealthIssue(
                    "warning",
                    "dns_tun_stack_mismatch",
                    "DNS 策略为 ipv4_only，但 TUN 仍分配了 IPv6 地址（可能导致 IPv6 流量泄漏或状态显示未知）",
                )
            )
        elif dns_strategy == "ipv6_only" and has_v4:
            issues.append(
                ConfigHealthIssue(
                    "warning",
                    "dns_tun_stack_mismatch",
                    "DNS 策略为 ipv6_only，但 TUN 仍分配了 IPv4 地址",
                )
            )

    # Check unused or plaintext HTTP rule_sets
    route = config.get("route", {})
    if isinstance(route, dict):
        rule_sets = route.get("rule_set", [])
        if isinstance(rule_sets, list) and rule_sets:
            used_rs = _collect_referenced_rule_sets(
                (route.get("rules") if isinstance(route.get("rules"), list) else [])
                + (dns.get("rules") if isinstance(dns, dict) and isinstance(dns.get("rules"), list) else [])
            )
            defined_tags = [
                str(rs.get("tag"))
                for rs in rule_sets
                if isinstance(rs, dict) and isinstance(rs.get("tag"), str)
            ]
            unused_tags = [tag for tag in defined_tags if tag not in used_rs]
            if unused_tags:
                issues.append(
                    ConfigHealthIssue(
                        "info",
                        "unused_rule_sets",
                        f"存在未被引用的冗余规则集: {', '.join(unused_tags)}",
                    )
                )
            http_urls = [
                str(rs.get("tag"))
                for rs in rule_sets
                if isinstance(rs, dict) and str(rs.get("url", "")).startswith("http://")
            ]
            if http_urls:
                issues.append(
                    ConfigHealthIssue(
                        "info",
                        "plaintext_ruleset_url",
                        f"{len(http_urls)} 个远程规则集使用明文 HTTP 链接",
                    )
                )

    return issues


def run_sing_box_check(
    config_path: Path,
    timeout: int = CONFIG_CHECK_TIMEOUT,
) -> tuple[bool, str]:
    """Validate a configuration with a bounded ``sing-box check`` process."""

    sing_box = shutil.which("sing-box")
    if not sing_box:
        return False, "未找到 sing-box 命令；请安装 sing-box，或使用 --no-check 显式跳过配置校验"

    try:
        result = subprocess.run(
            [sing_box, "check", "-c", str(config_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"sing-box check 超时（{timeout} 秒）"
    except OSError as error:
        return False, f"无法执行 sing-box check: {format_exception(error)}"
    if result.returncode == 0:
        return True, "sing-box check 校验通过"
    output = (result.stderr or result.stdout or "unknown error").strip()
    return False, output


def dump_json_atomic(data: dict[str, Any], config_path: Path, validate: bool) -> tuple[Path | None, str | None]:
    config_path = resolve_config_path(config_path)
    with _staged_json_write(data, config_path) as staged:
        validation_message = None
        if validate:
            ok, validation_message = run_sing_box_check(staged)
            if not ok:
                raise RuntimeError(f"配置校验失败: {validation_message}")

        # 校验通过后再备份，避免校验失败时留下无意义的备份文件
        backup_path = backup_config(config_path)
        os.replace(staged, config_path)
        fsync_directory(config_path.parent)
        return backup_path, validation_message


@contextmanager
def locked_paths(paths: Sequence[Path]) -> Iterator[None]:
    """Lock multiple paths in stable order to avoid updater deadlocks."""

    unique_paths = sorted({resolve_config_path(path) for path in paths})
    with ExitStack() as stack:
        lock_files = []
        for path in unique_paths:
            lock_path = path.with_name(f"{path.name}.lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_file = stack.enter_context(open(lock_path, "a+", encoding="utf-8"))
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            lock_files.append(lock_file)
        try:
            yield
        finally:
            for lock_file in reversed(lock_files):
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


@contextmanager
def locked_config(config_path: Path) -> Iterator[None]:
    """Lock a configuration path for a complete read-modify-write cycle."""

    with locked_paths([config_path]):
        yield


def backup_config(config_path: Path) -> Path | None:
    config_path = resolve_config_path(config_path)
    if not config_path.exists():
        return None
    original_stat = config_path.stat()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup_path = config_path.with_name(f"{config_path.name}.bak-{timestamp}")
    try:
        shutil.copy2(config_path, backup_path)
        preserve_file_metadata(backup_path, original_stat)
        fsync_file(backup_path)
        fsync_directory(backup_path.parent)
    except OSError:
        with suppress(OSError):
            backup_path.unlink()
        raise
    return backup_path


def cleanup_backups(config_path: Path, keep: int) -> list[Path]:
    config_path = resolve_config_path(config_path)
    if keep < 0:
        return []

    backups = sorted(
        config_path.parent.glob(f"{config_path.name}.bak-*"),
        key=lambda path: (path.stat().st_mtime, path.name),
        reverse=True,
    )
    removed = []
    for backup in backups[keep:]:
        try:
            backup.unlink()
            removed.append(backup)
        except OSError:
            continue
    return removed


def save_config(
    config_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    validate: bool = True,
    backup_keep: int = DEFAULT_BACKUP_KEEP,
) -> SaveResult:
    """在文件锁内重新读取配置、应用 mutate 后原子写回。

    整个读-改-写窗口都在锁内完成，遵循相同锁协议的多个实例不会互相覆盖。
    返回的 SaveResult.config 是写回磁盘的最新配置。
    """
    config_path = resolve_config_path(config_path)
    with locked_config(config_path):
        data = load_config(config_path)
        validate_config_structure(data)
        previous_config = deepcopy(data)
        mutate(data)
        validate_config_structure(data)
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


def format_save_note(save_result: SaveResult, *, short: bool = False) -> str:
    notes = []
    if save_result.backup_path:
        backup_display = save_result.backup_path.name if short else str(save_result.backup_path)
        notes.append(f"备份: {backup_display}")
    if save_result.validation_message:
        notes.append(save_result.validation_message)
    if save_result.cleaned_backups:
        notes.append(f"清理旧备份: {len(save_result.cleaned_backups)} 个")
    return " | ".join(notes)


def format_exception(error: Exception) -> str:
    message = str(error).strip()
    if message:
        return message
    return error.__class__.__name__
