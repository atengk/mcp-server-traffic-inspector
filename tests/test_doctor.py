"""运行环境健康自检探针 (--check / --doctor) 与跨平台组件寻址测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.doctor import (
    _probe_binary_version,
    resolve_tshark_path,
    run_doctor,
)


def test_resolve_tshark_path_prioritizes_explicit_then_path_then_windows_defaults(
    tmp_path: Path,
) -> None:
    """tshark 寻址应严格遵循：显式路径 > 系统 PATH > Windows 默认安装目录。"""
    explicit_bin = tmp_path / "custom_tshark.exe"
    explicit_bin.write_bytes(b"fake-bin")
    path_bin = tmp_path / "path_tshark.exe"
    path_bin.write_bytes(b"fake-bin")
    win_default_bin = tmp_path / "Wireshark" / "tshark.exe"
    win_default_bin.parent.mkdir(parents=True)
    win_default_bin.write_bytes(b"fake-bin")

    # 1. 显式路径最高优先级
    resolved_explicit = resolve_tshark_path(
        explicit_path=str(explicit_bin),
        which_fn=lambda _: str(path_bin),
        candidate_paths=[win_default_bin],
    )
    assert resolved_explicit == explicit_bin.resolve()

    # 2. 未指定显式路径时优先使用 PATH
    resolved_from_path = resolve_tshark_path(
        explicit_path=None,
        which_fn=lambda _: str(path_bin),
        candidate_paths=[win_default_bin],
    )
    assert resolved_from_path == path_bin.resolve()

    # 3. PATH 未命中时回退至默认安装路径候选列表
    resolved_fallback = resolve_tshark_path(
        explicit_path=None,
        which_fn=lambda _: None,
        candidate_paths=[win_default_bin],
    )
    assert resolved_fallback == win_default_bin.resolve()


def test_run_doctor_returns_ready_zero_when_core_components_healthy(
    tmp_path: Path,
) -> None:
    """核心组件（Python、mitmdump、SQLite WAL）就绪时，run_doctor 应返回 exit_code 0。"""
    db_file = tmp_path / "doctor_probe.db"
    cfg = parse_config(argv=["--check", "--db-path", str(db_file)], env={})

    report = run_doctor(cfg)
    payload = report.to_dict()

    assert report.ready is True
    assert report.exit_code == 0
    assert payload["ready"] is True
    assert payload["checks"]["python_runtime"]["status"] == "ok"
    assert payload["checks"]["mitmdump"]["status"] == "ok"
    assert payload["checks"]["sqlite_wal"]["status"] == "ok"
    assert payload["checks"]["sqlite_wal"]["journal_mode"] == "wal"
    assert "tshark" in payload["checks"]
    assert "ca_certificate" in payload["checks"]


def test_run_doctor_fails_when_explicit_tshark_path_missing(tmp_path: Path) -> None:
    """当用户显式传入不存在的 --tshark-path 时，自检应标记异常并返回非 0 退出码。"""
    missing_tshark = tmp_path / "nonexistent_tshark"
    cfg = parse_config(
        argv=["--check", "--tshark-path", str(missing_tshark)],
        env={},
    )

    report = run_doctor(cfg)

    assert report.ready is False
    assert report.exit_code == 1
    assert report.checks["tshark"].status == "error"


def test_probe_binary_version_handles_utf8_and_unicode_decode_error(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """_probe_binary_version 应能正常提取 UTF-8 版本信息并在解码错误时返回 None。"""
    dummy_bin = tmp_path / "probe.exe"
    dummy_bin.write_bytes(b"bin")

    # 1. 模拟含 UTF-8 非 ASCII 字符的版本输出
    class FakeCompleted:
        stdout = "TShark (Wireshark) 4.2.0 (v4.2.0-0-g12345 本地构建版)\n"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: FakeCompleted())
    version = _probe_binary_version(dummy_bin)
    assert version is not None
    assert "4.2.0" in version
    assert "本地构建版" in version

    # 2. 模拟抛出 UnicodeDecodeError 异常时应被捕获并返回 None
    def mock_raising_decode_error(*args, **kwargs):
        raise UnicodeDecodeError("gbk", b"\xac", 57, 58, "illegal multibyte sequence")

    monkeypatch.setattr(subprocess, "run", mock_raising_decode_error)
    assert _probe_binary_version(dummy_bin) is None
