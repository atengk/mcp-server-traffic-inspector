"""报文时空切片 (PcapSlicer) 与伴随元数据 (CaptureSidecar) 单元测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path

from mcp_server_traffic_inspector.pcap_slicer import (
    CaptureSidecar,
    build_slice_display_filter,
    slice_pcap_file,
)
from mcp_server_traffic_inspector.process_tracker import (
    ProcessFamily,
    ProcessInfo,
    SocketEntry,
    SocketTimeline,
)


def test_build_slice_display_filter_generates_valid_wireshark_syntax() -> None:
    """build_slice_display_filter 应基于端口集合生成正确的 Wireshark Display Filter。"""
    # 1. 多个端口
    filter_expr = build_slice_display_filter({80, 443, 52341})
    assert "tcp.port in {80, 443, 52341}" in filter_expr
    assert "udp.port in {80, 443, 52341}" in filter_expr

    # 2. 单个端口
    filter_single = build_slice_display_filter({8080})
    assert "tcp.port in {8080}" in filter_single

    # 3. 空端口集合
    assert build_slice_display_filter(set()) == ""


def test_capture_sidecar_save_and_load_lifecycle(tmp_path: Path) -> None:
    """CaptureSidecar 应能保存与加载同名 .pcap.meta.json 伴随元数据文件。"""
    pcap_file = tmp_path / "test_session.pcap"
    pcap_file.write_bytes(b"FAKE_PCAP_DATA")

    family = ProcessFamily(
        root_pid=1000,
        all_pids={1000, 1001},
        members=[
            ProcessInfo(pid=1000, ppid=1, name="Weixin.exe", exe_path="C:\\Weixin\\Weixin.exe"),
            ProcessInfo(
                pid=1001,
                ppid=1000,
                name="WeChatAppEx.exe",
                exe_path="C:\\Weixin\\WeChatAppEx.exe",
            ),
        ],
    )

    timeline = SocketTimeline()
    timeline.record_snapshot(
        timestamp=1000.0,
        entries=[
            SocketEntry(
                proto="TCP",
                local_ip="127.0.0.1",
                local_port=52341,
                remote_ip="101.91.1.1",
                remote_port=443,
                pid=1000,
            ),
        ],
    )

    # 1. 落盘 Sidecar
    meta_path = CaptureSidecar.save(
        pcap_path=pcap_file,
        process_family=family,
        timeline=timeline,
        extra={"session_name": "weixin_audit"},
    )

    assert meta_path.is_file()
    assert meta_path.name == "test_session.pcap.meta.json"

    # 2. 读取并校验
    loaded = CaptureSidecar.load(pcap_file)
    assert loaded is not None
    assert loaded["process_family"]["root_pid"] == 1000
    assert loaded["process_family"]["all_pids"] == [1000, 1001]
    assert loaded["extra"]["session_name"] == "weixin_audit"
    assert len(loaded["server_topology"]) == 1
    assert loaded["server_topology"][0]["server_ip"] == "101.91.1.1"

    # 3. 不存在时返回 None
    missing_pcap = tmp_path / "non_existent.pcap"
    assert CaptureSidecar.load(missing_pcap) is None


def test_slice_pcap_file_executes_tshark_and_cleans_raw_if_requested(tmp_path: Path) -> None:
    """slice_pcap_file 应调用 tshark 切片并在 keep_raw_pcap=False 时清理原始文件。"""
    raw_pcap = tmp_path / "capture_raw.pcap"
    raw_pcap.write_bytes(b"RAW_DATA_123")
    target_pcap = tmp_path / "capture_sliced.pcap"

    executed_cmds: list[list[str]] = []

    def mock_runner(cmd: list[str]) -> str:
        executed_cmds.append(cmd)
        # 模拟 tshark -w 写入目标切片文件
        target_pcap.write_bytes(b"SLICED_DATA_456")
        return ""

    # 执行切片，keep_raw_pcap=False
    res = slice_pcap_file(
        raw_pcap_path=raw_pcap,
        target_pcap_path=target_pcap,
        display_filter="tcp.port in {52341}",
        tshark_bin="tshark",
        runner=mock_runner,
        keep_raw_pcap=False,
    )

    assert res["status"] == "sliced"
    assert res["output_file"] == str(target_pcap.resolve())
    assert target_pcap.is_file()
    # 原始全量文件已被自动清理
    assert not raw_pcap.exists()
    assert len(executed_cmds) == 1
    assert "-Y" in executed_cmds[0]
    assert "tcp.port in {52341}" in executed_cmds[0]
