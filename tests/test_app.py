"""Configuration, network, CLI and TUI regression tests."""

import asyncio
import json
import os
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path

import pytest

from singbox_manage import cli, network, runtime, tui
from singbox_manage import config as store


def base_config():
    return {
        "dns": {},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "set_system_proxy": True},
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": False,
                "strict_route": False,
                "auto_redirect": False,
            },
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["node-a", "node-b"],
                "default": "node-a",
            },
        ],
        "route": {"final": "proxy"},
    }


def write_config(tmp_path: Path, config: dict) -> Path:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path


def test_format_bytes():
    assert runtime.format_bytes(0) == "0 B"
    assert runtime.format_bytes(512) == "512 B"
    assert runtime.format_bytes(2048) == "2.0 KiB"
    assert runtime.format_bytes(5 * 1024**3) == "5.0 GiB"
    assert runtime.format_bytes(3 * 1024**4) == "3.0 TiB"
    assert runtime.format_bytes(5000 * 1024**4) == "5000.0 TiB"


def test_list_value():
    assert network.list_value(None) == []
    assert network.list_value("a") == ["a"]
    assert network.list_value(["a", "b"]) == ["a", "b"]
    with pytest.raises(ValueError):
        network.list_value(42)


def test_split_ip_values():
    ipv4, ipv6 = network.split_ip_values(["1.2.3.4/32", "::1/128", "10.0.0.0/8"])
    assert ipv4 == ["1.2.3.4/32", "10.0.0.0/8"]
    assert ipv6 == ["::1/128"]


def test_unique_values():
    assert network.unique_values(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


def test_next_ip_stack_mode():
    assert network.next_ip_stack_mode("ipv4") == "ipv6"
    assert network.next_ip_stack_mode("ipv6") == "dual"
    assert network.next_ip_stack_mode("dual") == "ipv4"
    assert network.next_ip_stack_mode("unknown") == "ipv4"


def test_set_ip_stack_ipv4():
    config = base_config()
    config["dns"]["strategy"] = "prefer_ipv6"
    config["inbounds"][1]["route_exclude_address"] = ["10.0.0.0/8", "fd00::/8"]
    network.set_sing_box_ip_stack(config, "tun-in", "ipv4")
    assert config["dns"]["strategy"] == "ipv4_only"
    assert config["inbounds"][1]["address"] == ["172.19.0.1/30"]
    assert config["inbounds"][1]["route_exclude_address"] == ["10.0.0.0/8"]


def test_set_ip_stack_ipv6_uses_default_when_missing():
    config = base_config()
    config["inbounds"][1]["address"] = ["172.19.0.1/30"]
    network.set_sing_box_ip_stack(config, "tun-in", "ipv6")
    assert config["dns"]["strategy"] == "ipv6_only"
    assert config["inbounds"][1]["address"] == [network.DEFAULT_TUN_IPV6_ADDRESS]


def test_set_ip_stack_dual_clears_strategy():
    config = base_config()
    config["dns"]["strategy"] = "ipv4_only"
    config["inbounds"][1]["address"] = ["172.19.0.1/30"]
    network.set_sing_box_ip_stack(config, "tun-in", "dual")
    assert "strategy" not in config["dns"]
    assert config["inbounds"][1]["address"] == [
        "172.19.0.1/30",
        network.DEFAULT_TUN_IPV6_ADDRESS,
    ]


def test_set_ip_stack_rejects_bad_mode():
    with pytest.raises(ValueError):
        network.set_sing_box_ip_stack(base_config(), "tun-in", "both")


def test_get_ip_stack():
    config = base_config()
    assert network.get_sing_box_ip_stack(config, "tun-in") == "dual"
    config["dns"]["strategy"] = "ipv4_only"
    assert network.get_sing_box_ip_stack(config, "tun-in") == "unknown"
    config["inbounds"][1]["address"] = ["172.19.0.1/30"]
    assert network.get_sing_box_ip_stack(config, "tun-in") == "ipv4"
    config["dns"]["strategy"] = "ipv6_only"
    assert network.get_sing_box_ip_stack(config, "tun-in") == "unknown"
    config["inbounds"][1]["address"] = ["fdfe:dcba:9876::1/126"]
    assert network.get_sing_box_ip_stack(config, "tun-in") == "ipv6"
    assert network.get_sing_box_ip_stack(None, "tun-in") == "unknown"
    assert network.get_sing_box_ip_stack({}, "tun-in") == "unknown"


def test_set_proxy_mode():
    config = base_config()
    network.set_proxy_mode(config, "tun", "mixed-in", "tun-in")
    tun = config["inbounds"][1]
    assert config["inbounds"][0]["set_system_proxy"] is False
    assert tun["auto_route"] is True
    assert tun["strict_route"] is True
    assert tun["auto_redirect"] is True
    assert network.get_proxy_mode(config, "mixed-in", "tun-in") == "tun"

    network.set_proxy_mode(config, "system", "mixed-in", "tun-in")
    assert config["inbounds"][0]["set_system_proxy"] is True
    assert tun["auto_route"] is False
    assert network.get_proxy_mode(config, "mixed-in", "tun-in") == "system"

    with pytest.raises(ValueError):
        network.set_proxy_mode(config, "off", "mixed-in", "tun-in")
    with pytest.raises(ValueError):
        network.set_proxy_mode(config, "tun", "nope", "tun-in")


def test_save_config_applies_mutation(tmp_path):
    config_path = write_config(tmp_path, base_config())

    def mutate(data):
        store.find_proxy_selector(data, "proxy")["default"] = "node-b"

    result = store.save_config(config_path, mutate, validate=False)
    on_disk = json.loads(config_path.read_text(encoding="utf-8"))
    assert on_disk["outbounds"][0]["default"] == "node-b"
    assert result.config == on_disk
    assert result.backup_path is not None and result.backup_path.exists()


def test_save_config_preserves_external_changes(tmp_path):
    """外部脚本先改了配置，本工具保存时不应把它覆盖掉。"""
    config_path = write_config(tmp_path, base_config())

    external = base_config()
    external["log"] = {"level": "warn"}
    write_config(tmp_path, external)

    def mutate(data):
        store.find_proxy_selector(data, "proxy")["default"] = "node-b"

    result = store.save_config(config_path, mutate, validate=False)
    assert result.config["log"] == {"level": "warn"}
    assert result.config["outbounds"][0]["default"] == "node-b"


def test_save_config_no_backup_on_validation_failure(tmp_path, monkeypatch):
    config_path = write_config(tmp_path, {"outbounds": [{"type": "no-such-type", "tag": "x"}]})

    def mutate(data):
        data["route"] = {}

    monkeypatch.setattr(store, "run_sing_box_check", lambda path: (False, "invalid"))
    with pytest.raises(RuntimeError):
        store.save_config(config_path, mutate, validate=True)
    assert list(tmp_path.glob("config.json.bak-*")) == []


def test_cleanup_backups(tmp_path):
    config_path = write_config(tmp_path, base_config())
    for _i in range(5):
        backup = store.backup_config(config_path)
        assert backup is not None
    removed = store.cleanup_backups(config_path, keep=2)
    assert len(removed) == 3
    assert len(list(tmp_path.glob("config.json.bak-*"))) == 2
    assert store.cleanup_backups(config_path, keep=-1) == []


def test_tun_settings_changed_detects_address_change():
    old = base_config()
    new = base_config()
    new["inbounds"][1]["address"] = ["10.0.0.1/30", "fdfe:dcba:9876::1/126"]
    assert network.tun_settings_changed(old, new, "tun-in") is True


def test_tun_settings_changed_detects_auto_route_change():
    old = base_config()
    new = base_config()
    new["inbounds"][1]["auto_route"] = True
    assert network.tun_settings_changed(old, new, "tun-in") is True


def test_tun_settings_changed_unchanged():
    old = base_config()
    new = base_config()
    new["outbounds"][0]["default"] = "node-b"
    assert network.tun_settings_changed(old, new, "tun-in") is False


def test_tun_settings_changed_missing_tun():
    old = base_config()
    new = base_config()
    new["inbounds"] = [ib for ib in new["inbounds"] if ib.get("tag") != "tun-in"]
    assert network.tun_settings_changed(old, new, "tun-in") is True


def test_reload_sing_box_force_restart(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)

        class R:
            returncode = 0
            stdout = ""
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    ok, msg = runtime.reload_sing_box("sing-box", force_restart=True)
    assert ok is True
    assert "重启" in msg
    assert calls == [["systemctl", "restart", "sing-box"]]


def test_ip_stack_round_trip_preserves_custom_values(tmp_path):
    config = base_config()
    tun = config["inbounds"][1]
    tun["address"] = ["10.8.0.1/30", "fd00:1234::1/126"]
    tun["route_exclude_address"] = ["192.168.0.0/16", "fd12::/16"]
    config_path = write_config(tmp_path, config)

    network.save_ip_stack_config(config_path, "tun-in", "ipv4", validate=False)
    network.save_ip_stack_config(config_path, "tun-in", "dual", validate=False)

    restored = json.loads(config_path.read_text(encoding="utf-8"))["inbounds"][1]
    assert restored["address"] == ["10.8.0.1/30", "fd00:1234::1/126"]
    assert restored["route_exclude_address"] == [
        "192.168.0.0/16",
        "fd12::/16",
    ]
    assert network.ip_stack_state_path(config_path).exists()


def test_set_ip_stack_rejects_invalid_address():
    config = base_config()
    config["inbounds"][1]["address"] = ["not-an-ip"]
    with pytest.raises(ValueError, match="无效的 IP"):
        network.set_sing_box_ip_stack(config, "tun-in", "ipv4")


def test_run_sing_box_check_times_out(monkeypatch, tmp_path):
    monkeypatch.setattr(store.shutil, "which", lambda command: "/usr/bin/sing-box")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(runtime.subprocess, "run", timeout)
    ok, message = store.run_sing_box_check(tmp_path / "config.json", timeout=2)
    assert not ok
    assert "2 秒" in message


@pytest.mark.skipif(shutil.which("sing-box") is None, reason="需要 sing-box")
def test_real_sing_box_check_rejects_invalid_configuration(tmp_path):
    config_path = tmp_path / "invalid.json"
    config_path.write_text(
        json.dumps({"outbounds": [{"type": "definitely-invalid", "tag": "x"}]}),
        encoding="utf-8",
    )
    ok, message = store.run_sing_box_check(config_path)
    assert not ok
    assert message


def test_reload_sing_box_falls_back_from_reload_to_restart(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "reload":
            raise subprocess.CalledProcessError(1, args, stderr="unsupported")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    ok, message = runtime.reload_sing_box("sing-box")
    assert ok
    assert "重启" in message
    assert [call[1] for call in calls] == ["reload", "restart"]


def test_save_config_serializes_real_concurrent_updates(tmp_path):
    config_path = write_config(tmp_path, base_config())

    def first_mutation(data):
        data["first"] = True
        time.sleep(0.05)

    def second_mutation(data):
        data["second"] = True

    first = threading.Thread(
        target=store.save_config,
        args=(config_path, first_mutation),
        kwargs={"validate": False},
    )
    second = threading.Thread(
        target=store.save_config,
        args=(config_path, second_mutation),
        kwargs={"validate": False},
    )
    first.start()
    time.sleep(0.01)
    second.start()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive() and not second.is_alive()
    saved = json.loads(config_path.read_text(encoding="utf-8"))
    assert saved["first"] is True
    assert saved["second"] is True


def test_tui_mounts_with_loaded_configuration(tmp_path, monkeypatch):
    config_path = write_config(tmp_path, base_config())
    monkeypatch.setattr(tui, "get_public_ipv4", lambda: "203.0.113.1")
    monkeypatch.setattr(tui, "get_system_memory_usage", lambda: "1 GiB")
    monkeypatch.setattr(tui, "get_service_memory_usage", lambda service: "10 MiB")
    monkeypatch.setattr(tui, "get_tun_link_status", lambda interface: "UP")
    monkeypatch.setattr(tui, "get_dns_tun_status", lambda interface: "是")
    app = tui.SingBoxTUI(
        config_path=config_path,
        service_name="sing-box",
        selector_tag="proxy",
        mixed_tag="mixed-in",
        tun_tag="tun-in",
        backup_keep=2,
        reload_enabled=False,
        validate_config=False,
    )

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            table = app.query_one("#node-table", tui.DataTable)
            assert table.row_count == 2
            assert "203.0.113.1" in str(app.query_one("#runtime-info", tui.Static).render())

    asyncio.run(exercise())


@pytest.mark.parametrize("route", [None, {}, {"final": ""}, {"final": "node-a"}])
def test_save_preserves_default_route(tmp_path, route):
    data = base_config()
    if route is None:
        data.pop("route")
    else:
        data["route"] = route
    path = write_config(tmp_path, data)
    store.save_config(path, lambda loaded: loaded.update({"log": {"level": "debug"}}), validate=False)
    saved = store.load_config(path)
    assert saved.get("route") == route
    assert ("route" in saved) == (route is not None)
    network.save_ip_stack_config(path, "tun-in", "ipv4", validate=False)
    assert store.load_config(path).get("route") == route


def test_save_follows_symlink_and_uses_target_backups(tmp_path):
    target_dir = tmp_path / "actual"
    target_dir.mkdir()
    target = write_config(target_dir, base_config())
    link = tmp_path / "config-link.json"
    link.symlink_to(target.relative_to(tmp_path))
    result = store.save_config(link, lambda data: data.update({"log": {"level": "debug"}}), validate=False)
    assert link.is_symlink()
    assert store.load_config(target)["log"]["level"] == "debug"
    assert result.backup_path.parent == target_dir
    assert (target_dir / "config.json.lock").exists()
    assert not link.with_name(link.name + ".lock").exists()


def test_ip_stack_state_is_shared_between_symlink_and_target(tmp_path):
    target_dir = tmp_path / "actual"
    target_dir.mkdir()
    data = base_config()
    data["inbounds"][1]["address"] = ["10.8.0.1/30", "fd00:1234::1/126"]
    target = write_config(target_dir, data)
    link = tmp_path / "config-link.json"
    link.symlink_to(target)
    network.save_ip_stack_config(link, "tun-in", "ipv4", validate=False)
    network.save_ip_stack_config(target, "tun-in", "dual", validate=False)
    assert link.is_symlink()
    assert store.load_config(target)["inbounds"][1]["address"] == data["inbounds"][1]["address"]
    assert network.ip_stack_state_path(link) == network.ip_stack_state_path(target)
    assert not (tmp_path / "config-link.json.singbox-tui-state.json").exists()


def test_symlink_and_target_updates_share_the_same_lock(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    target = write_config(tmp_path, base_config())
    link = tmp_path / "alias.json"
    link.symlink_to(target)
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first(data):
        first_entered.set()
        assert release_first.wait(timeout=3)
        data["first"] = True

    def second(data):
        second_entered.set()
        data["second"] = True

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_result = executor.submit(store.save_config, link, first, validate=False)
        try:
            assert first_entered.wait(timeout=3)
            second_result = executor.submit(store.save_config, target, second, validate=False)
            assert not second_entered.wait(timeout=0.1)
        finally:
            release_first.set()
        first_result.result(timeout=3)
        second_result.result(timeout=3)
    saved = store.load_config(target)
    assert saved["first"] and saved["second"]
    assert link.is_symlink()


def test_atomic_sidecar_write_preserves_symlink(tmp_path):
    target = tmp_path / "state.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "state-link.json"
    link.symlink_to(target)
    store.write_json_atomic({"version": 1}, link)
    assert link.is_symlink()
    assert store.load_config(target) == {"version": 1}


def test_save_and_backup_preserve_file_permissions(tmp_path):
    path = write_config(tmp_path, base_config())
    path.chmod(0o640)
    original_stat = path.stat()
    result = store.save_config(path, lambda data: data.update({"log": {"level": "debug"}}), validate=False)
    for file in (path, result.backup_path):
        metadata = file.stat()
        assert stat.S_IMODE(metadata.st_mode) == 0o640
        assert (metadata.st_uid, metadata.st_gid) == (original_stat.st_uid, original_stat.st_gid)


@pytest.mark.skipif(os.geteuid() != 0, reason="需要 root 才能设置其他用户的属主")
def test_save_and_backup_preserve_non_root_ownership(tmp_path):
    path = write_config(tmp_path, base_config())
    os.chown(path, 65534, 65534)
    path.chmod(0o640)
    result = store.save_config(path, lambda data: data.update({"log": {"level": "debug"}}), validate=False)
    for file in (path, result.backup_path):
        metadata = file.stat()
        assert (metadata.st_uid, metadata.st_gid) == (65534, 65534)
        assert stat.S_IMODE(metadata.st_mode) == 0o640


def test_metadata_failure_keeps_original_file_and_cleans_temporary(tmp_path, monkeypatch):
    path = write_config(tmp_path, base_config())
    original = path.read_bytes()

    def denied(*args):
        raise PermissionError("metadata permission denied")

    monkeypatch.setattr(store, "preserve_file_metadata", denied)
    with pytest.raises(PermissionError, match="metadata permission denied"):
        store.save_config(path, lambda data: data.update({"log": {"level": "debug"}}), validate=False)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp"))
    assert not list(tmp_path.glob("*.bak-*"))


def test_noop_save_keeps_file_and_backups_unchanged(tmp_path):
    path = write_config(tmp_path, base_config())
    original_stat = path.stat()
    result = store.save_config(path, lambda data: None, validate=False)
    assert not result.changed
    assert result.backup_path is None
    assert path.stat().st_ino == original_stat.st_ino
    assert path.stat().st_mtime_ns == original_stat.st_mtime_ns
    assert not list(tmp_path.glob("*.bak-*"))


def test_missing_sing_box_requires_explicit_no_check(tmp_path, monkeypatch):
    path = write_config(tmp_path, base_config())
    original = path.read_bytes()
    monkeypatch.setattr(store.shutil, "which", lambda command: None)
    with pytest.raises(RuntimeError, match="--no-check"):
        store.save_config(path, lambda data: data.update({"log": {"level": "debug"}}))
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.bak-*"))
    result = store.save_config(path, lambda data: data.update({"log": {"level": "debug"}}), validate=False)
    assert result.changed


@pytest.mark.parametrize("mode", ["ipv4", "ipv6"])
def test_cli_repairs_dns_strategy_and_tun_address_mismatch(tmp_path, mode):
    data = base_config()
    data["dns"]["strategy"] = mode + "_only"
    data.pop("route")
    path = write_config(tmp_path, data)
    assert cli.main(["--config", str(path), "--ip-stack", mode, "--no-check", "--no-reload"]) == 0
    saved = store.load_config(path)
    addresses = saved["inbounds"][1]["address"]
    assert all(network.is_ipv6_address(address) == (mode == "ipv6") for address in addresses)
    assert "route" not in saved


def test_cli_repeated_ip_stack_change_does_not_restart(tmp_path, monkeypatch):
    path = write_config(tmp_path, base_config())
    reload_calls = []
    monkeypatch.setattr(cli, "reload_sing_box", lambda *args, **kwargs: (reload_calls.append(kwargs) or True, "已重启"))
    args = ["--config", str(path), "--ip-stack", "ipv4", "--no-check"]
    assert cli.main(args) == 0
    assert cli.main(args) == 0
    assert reload_calls == [{"force_restart": True}]
    assert len(list(tmp_path.glob("*.bak-*"))) == 1


def test_cli_reports_reload_failure_after_saving(tmp_path, monkeypatch, capsys):
    path = write_config(tmp_path, base_config())
    monkeypatch.setattr(cli, "reload_sing_box", lambda *a, **kw: (False, "systemctl absent"))
    assert cli.main(["--config", str(path), "--ip-stack", "ipv4", "--no-check"]) == 1
    assert network.get_sing_box_ip_stack(store.load_config(path), "tun-in") == "ipv4"
    assert "配置已保存" in capsys.readouterr().err


@pytest.mark.parametrize("option", ["--update-certs", "--dry-run", "--accept-cert-sha256"])
def test_certificate_cli_options_have_been_removed(option, capsys):
    with pytest.raises(SystemExit) as error:
        cli.parse_args([option])
    assert error.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


@pytest.mark.parametrize("args", [["--backup-keep", "-2"], ["--disable-ipv6", "--ip-stack", "ipv6"]])
def test_cli_rejects_conflicting_options(tmp_path, args, capsys):
    path = write_config(tmp_path, base_config())
    assert cli.main(["--config", str(path), *args]) == 1
    assert capsys.readouterr().err


@pytest.mark.parametrize("force_restart", [False, True])
def test_missing_systemctl_is_reported_without_raising(monkeypatch, force_restart):
    def absent(*args, **kwargs):
        raise FileNotFoundError("systemctl absent")

    monkeypatch.setattr(runtime.subprocess, "run", absent)
    ok, message = runtime.reload_sing_box("sing-box", force_restart=force_restart)
    assert not ok
    assert "systemctl absent" in message


def test_reload_fallback_reports_os_error(monkeypatch):
    def run(args, **kwargs):
        if args[1] == "reload":
            raise subprocess.CalledProcessError(1, args, stderr="unsupported")
        raise PermissionError("restart denied")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    ok, message = runtime.reload_sing_box("sing-box")
    assert not ok
    assert "restart denied" in message


def test_public_ip_rejects_invalid_service_response(monkeypatch):
    responses = iter(["<html>error</html>", "203.0.113.2"])
    monkeypatch.setattr(runtime.shutil, "which", lambda command: "/usr/bin/curl")
    monkeypatch.setattr(runtime, "run_output", lambda *args, **kwargs: next(responses))
    assert runtime.get_public_ipv4() == "203.0.113.2"


@pytest.mark.skipif(shutil.which("sing-box") is None, reason="需要 sing-box")
def test_ip_stack_changes_pass_real_sing_box_check(tmp_path):
    data = {
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["10.0.0.1/30", "fd00::1/126"], "auto_route": False}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    path = write_config(tmp_path, data)
    assert store.run_sing_box_check(path)[0]
    for mode in ("ipv4", "ipv6", "dual"):
        result = network.save_ip_stack_config(path, "tun-in", mode, validate=True)
        assert result.changed
        assert store.run_sing_box_check(path)[0]
        assert "route" not in result.config


def make_tui(tmp_path, monkeypatch):
    path = write_config(tmp_path, base_config())
    monkeypatch.setattr(tui, "get_public_ipv4", lambda: "203.0.113.1")
    monkeypatch.setattr(tui, "get_system_memory_usage", lambda: "1 GiB")
    monkeypatch.setattr(tui, "get_service_memory_usage", lambda service: "10 MiB")
    monkeypatch.setattr(tui, "get_tun_link_status", lambda interface: "UP")
    monkeypatch.setattr(tui, "get_dns_tun_status", lambda interface: "是")
    return tui.SingBoxTUI(path, "sing-box", "proxy", "mixed-in", "tun-in", 2, False, False)


async def wait_until(predicate):
    async def wait():
        while not predicate():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(wait(), timeout=3)


def test_tui_old_runtime_refresh_cannot_overwrite_new_result(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)
    started = threading.Event()
    release = threading.Event()
    old_finished = threading.Event()
    calls = 0

    def public_ip():
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            assert release.wait(timeout=3)
            old_finished.set()
            return "203.0.113.10"
        return "203.0.113.20"

    monkeypatch.setattr(tui, "get_public_ipv4", public_ip)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            try:
                assert await asyncio.to_thread(started.wait, 2)
                app.refresh_runtime_info(force_ip=True)
                await wait_until(lambda: app._public_ip == "203.0.113.20")
            finally:
                release.set()
            assert await asyncio.to_thread(old_finished.wait, 2)
            await pilot.pause()
            assert app._public_ip == "203.0.113.20"
            assert "203.0.113.20" in str(app.query_one("#runtime-info", tui.Static).render())

    asyncio.run(exercise())


def test_tui_saves_node_and_ip_stack_changes_without_certificate_controls(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert not app.query("#btn-update-certs")
            app._select_node_by_index(1)
            await wait_until(lambda: not app._busy)
            assert app.current_node == "node-b"
            await pilot.click("#btn-ipv4")
            await pilot.pause()
            await pilot.click("#confirm-yes")
            await wait_until(lambda: not app._busy)
            assert network.get_sing_box_ip_stack(store.load_config(app.config_path), "tun-in") == "ipv4"
            await pilot.click("#btn-tun")
            await wait_until(lambda: not app._busy)
            assert app.proxy_mode == "tun"

    asyncio.run(exercise())


def test_tui_repairs_ip_stack_inconsistent_with_dns(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)
    data = store.load_config(app.config_path)
    data["dns"]["strategy"] = "ipv4_only"
    write_config(tmp_path, data)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#btn-ipv4")
            await pilot.pause()
            await pilot.click("#confirm-yes")
            await wait_until(lambda: not app._busy)
            assert store.load_config(app.config_path)["inbounds"][1]["address"] == ["172.19.0.1/30"]

    asyncio.run(exercise())


def test_tui_ip_stack_cancel_keeps_config(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#btn-ipv4")
            await pilot.pause()
            assert isinstance(app.screen, tui.ConfirmScreen)
            await pilot.click("#confirm-no")
            await pilot.pause()
            assert not isinstance(app.screen, tui.ConfirmScreen)
            assert not app._busy
            assert network.get_sing_box_ip_stack(store.load_config(app.config_path), "tun-in") == "dual"

    asyncio.run(exercise())


def test_tui_node_filter_narrows_table_and_selects_filtered(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            table = app.query_one("#node-table", tui.DataTable)
            assert table.row_count == 2
            await pilot.click("#node-filter")
            await pilot.press("b")
            await pilot.pause()
            assert table.row_count == 1
            assert app.visible_nodes == ["node-b"]
            # 过滤后的序号映射到正确的节点
            app._select_node_by_index(0)
            await wait_until(lambda: not app._busy)
            assert app.current_node == "node-b"

    asyncio.run(exercise())


def test_tui_help_screen_opens_and_closes(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_help()
            await pilot.pause()
            assert isinstance(app.screen, tui.HelpScreen)
            await pilot.click("#help-close")
            await pilot.pause()
            assert not isinstance(app.screen, tui.HelpScreen)

    asyncio.run(exercise())


def test_tui_focus_filter_action_focuses_input(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_focus_filter()
            await pilot.pause()
            assert app.focused is app.query_one("#node-filter", tui.Input)

    asyncio.run(exercise())


def test_tui_reload_exception_clears_busy_and_keeps_saved_state(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)
    app.reload_enabled = True

    def fail_reload(*args, **kwargs):
        raise FileNotFoundError("systemctl absent")

    monkeypatch.setattr(tui, "reload_sing_box", fail_reload)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app._select_node_by_index(1)
            await wait_until(lambda: not app._busy)
            assert app.current_node == "node-b"
            status = app.query_one("#status", tui.Static)
            assert status.has_class("error")
            assert "配置已保存" in str(status.render())

    asyncio.run(exercise())


def test_tui_removed_node_is_not_written_from_stale_cache(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            data = store.load_config(app.config_path)
            data["outbounds"][0]["outbounds"] = ["node-a"]
            write_config(tmp_path, data)
            app._select_node_by_index(1)
            await wait_until(lambda: not app._busy)
            assert store.load_config(app.config_path)["outbounds"][0]["default"] == "node-a"
            assert "已不在 selector" in str(app.query_one("#status", tui.Static).render())

    asyncio.run(exercise())


def test_tui_restart_decision_uses_latest_config_inside_lock(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)
    app.reload_enabled = True
    reload_calls = []
    monkeypatch.setattr(tui, "reload_sing_box", lambda *args, **kwargs: (reload_calls.append(kwargs) or True, "已重载"))

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            data = store.load_config(app.config_path)
            data["inbounds"][1]["auto_route"] = True
            write_config(tmp_path, data)
            app._select_node_by_index(1)
            await wait_until(lambda: not app._busy)
            assert reload_calls == [{"force_restart": False}]
            assert app.current_node == "node-b"

    asyncio.run(exercise())


def test_tui_reapplies_cached_node_and_mode_to_latest_config(tmp_path, monkeypatch):
    app = make_tui(tmp_path, monkeypatch)

    async def exercise():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            data = store.load_config(app.config_path)
            data["outbounds"][0]["default"] = "node-b"
            network.set_proxy_mode(data, "tun", "mixed-in", "tun-in")
            write_config(tmp_path, data)
            # The UI still shows node-a/system; requesting either must read disk.
            app._select_node_by_index(0)
            await wait_until(lambda: not app._busy)
            assert store.load_config(app.config_path)["outbounds"][0]["default"] == "node-a"
            await pilot.click("#btn-system")
            await wait_until(lambda: not app._busy)
            assert network.get_proxy_mode(store.load_config(app.config_path), "mixed-in", "tun-in") == "system"

    asyncio.run(exercise())
