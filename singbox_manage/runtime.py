"""Bounded system commands and runtime diagnostics."""

import ipaddress
import os
import shutil
import subprocess
from pathlib import Path

from .config import format_exception


def reload_sing_box(service_name: str, force_restart: bool = False) -> tuple[bool, str]:
    def run_systemctl(action: str):
        return subprocess.run(
            ["systemctl", action, service_name],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )

    if force_restart:
        # TUN 设置变更需要重建 TUN 接口，直接 restart
        try:
            run_systemctl("restart")
            return True, f"{service_name} 服务已重启"
        except subprocess.TimeoutExpired:
            return False, "重启超时"
        except subprocess.CalledProcessError as e:
            return False, f"重启失败: {e.stderr or e.stdout or 'unknown error'}"
        except OSError as error:
            return False, f"无法执行 systemctl restart: {format_exception(error)}"

    try:
        run_systemctl("reload")
        return True, f"{service_name} 服务已重载"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # reload 失败时尝试 restart
        try:
            run_systemctl("restart")
            return True, f"{service_name} 服务已重启"
        except subprocess.TimeoutExpired:
            return False, "重载/重启超时"
        except subprocess.CalledProcessError as e2:
            return False, f"重载/重启失败: {e2.stderr or e2.stdout or 'unknown error'}"
        except OSError as error:
            return False, f"无法执行 systemctl restart: {format_exception(error)}"
    except OSError as error:
        return False, f"无法执行 systemctl reload: {format_exception(error)}"


def run_output(command: list[str], timeout: int = 5, env: dict[str, str] | None = None) -> str | None:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, **env} if env else None,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def get_public_ipv4() -> str:
    curl = shutil.which("curl")
    if not curl:
        return "未找到 curl"

    for url in ("https://ipinfo.io/ip", "https://api.ipify.org"):
        output = run_output(
            [curl, "-4", "-fsS", "--max-time", "5", url],
            timeout=6,
        )
        if output:
            value = output.splitlines()[0].strip()
            try:
                return str(ipaddress.IPv4Address(value))
            except ipaddress.AddressValueError:
                continue
    return "获取失败"


def format_bytes(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def get_system_memory_usage() -> str:
    values = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                name, rest = line.split(":", 1)
                amount = rest.strip().split()[0]
                values[name] = int(amount) * 1024
    except (OSError, ValueError, IndexError):
        return "未知"

    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return "未知"

    used = total - available
    percent = used / total * 100
    return f"{format_bytes(used)} / {format_bytes(total)} ({percent:.0f}%)"


def get_service_memory_usage(service_name: str) -> str:
    pid_text = run_output(
        ["systemctl", "show", service_name, "--property=MainPID", "--value"],
        timeout=3,
    )
    if not pid_text or not pid_text.isdigit() or pid_text == "0":
        return "未运行"

    status_path = Path("/proc") / pid_text / "status"
    try:
        with open(status_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kib = int(line.split()[1])
                    return format_bytes(rss_kib * 1024)
    except (OSError, ValueError, IndexError):
        return "未知"
    return "未知"


def get_tun_link_status(interface_name: str) -> str:
    output = run_output(["ip", "link", "show", "dev", interface_name], timeout=3)
    if not output:
        return "DOWN"
    first_line = output.splitlines()[0]
    flags = first_line.split(":", 2)[2] if first_line.count(":") >= 2 else first_line
    return "UP" if "UP" in flags.split(">")[0] else "DOWN"


def get_dns_tun_status(interface_name: str) -> str:
    # LC_ALL=C 固定输出为英文，避免非英文 locale 下解析失败
    output = run_output(["resolvectl", "status"], timeout=3, env={"LC_ALL": "C"})
    if not output:
        return "未知"

    lines = output.splitlines()
    section = []
    capture = False
    for line in lines:
        if line.startswith("Link "):
            capture = f"({interface_name})" in line
            if capture:
                section = [line]
            continue
        if capture:
            section.append(line)

    if not section:
        return "否"
    text = "\n".join(section)
    if "DNS Domain: ~." in text and "DNS Servers:" in text:
        return "是"
    return "否"
