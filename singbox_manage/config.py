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

    for key in ("route", "dns"):
        if key in data and not isinstance(data[key], dict):
            raise ValueError(f"{key} 字段必须是 JSON 对象")

    for key in ("inbounds", "outbounds"):
        if key in data and not isinstance(data[key], list):
            raise ValueError(f"{key} 字段必须是数组")
        for idx, item in enumerate(data.get(key, [])):
            if not isinstance(item, dict):
                raise ValueError(f"{key}[{idx}] 必须是 JSON 对象")


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


def format_save_note(save_result: SaveResult) -> str:
    notes = []
    if save_result.backup_path:
        notes.append(f"备份: {save_result.backup_path}")
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
