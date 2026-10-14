"""TCP 会话流枚举 (list_tcp_streams) 与交互回合重组跟踪 (follow_tcp_stream) 单元测试。

@author Ateng
@since 2026-10-14
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.pcap import (
    PcapCaptureManager,
    parse_tcp_stream_turns_output,
    parse_tcp_streams_output,
)
from mcp_server_traffic_inspector.server import create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


def test_parse_tcp_streams_output_aggregates_endpoints_and_sni() -> None:
    """parse_tcp_streams_output 应正确汇总 stream_id、端点、包数、字节数及 SNI 域名。"""
    tsv_lines = [
        # Stream 0: Packet 1 (SYN)
        "0\t192.168.1.50\t93.184.216.34\t\t\t54321\t443\tTCP\t0\t\t",
        # Stream 0: Packet 2 (TLS Client Hello with SNI)
        "0\t192.168.1.50\t93.184.216.34\t\t\t54321\t443\tTLSv1.3\t517\texample.com\t",
        # Stream 0: Packet 3 (TLS Server Hello)
        "0\t93.184.216.34\t192.168.1.50\t\t\t443\t54321\tTLSv1.3\t1420\t\t",
        # Stream 1: HTTP GET
        "1\t10.0.0.2\t10.0.0.1\t\t\t60123\t80\tHTTP\t120\t\tapi.local",
    ]

    streams = parse_tcp_streams_output(tsv_lines, limit=10)
    assert len(streams) == 2

    s0 = streams[0]
    assert s0["stream_id"] == 0
    assert s0["client"] == "192.168.1.50:54321"
    assert s0["server"] == "93.184.216.34:443"
    assert s0["packet_count"] == 3
    assert s0["payload_bytes"] == 517 + 1420
    assert s0["protocol"] == "TLSv1.3"
    assert s0["sni_or_host"] == "example.com"

    s1 = streams[1]
    assert s1["stream_id"] == 1
    assert s1["client"] == "10.0.0.2:60123"
    assert s1["server"] == "10.0.0.1:80"
    assert s1["packet_count"] == 1
    assert s1["payload_bytes"] == 120
    assert s1["protocol"] == "HTTP"
    assert s1["sni_or_host"] == "api.local"


def test_parse_tcp_stream_turns_output_groups_consecutive_direction_turns() -> None:
    """parse_tcp_stream_turns_output 应将同方向连续报文合并为单次回合 (Turns)。"""
    # 模拟文本通信：客户端连续发两段 HTTP 请求，服务端返回一段响应
    get_part1 = b"GET /index.html ".hex()
    get_part2 = b"HTTP/1.1\r\nHost: example.com\r\n\r\n".hex()
    resp_part = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".hex()

    tsv_lines = [
        f"1\t1700000000.100\t192.168.1.10\t93.184.216.34\t\t\t50000\t80\t{get_part1}",
        f"2\t1700000000.120\t192.168.1.10\t93.184.216.34\t\t\t50000\t80\t{get_part2}",
        f"3\t1700000000.150\t93.184.216.34\t192.168.1.10\t\t\t80\t50000\t{resp_part}",
    ]

    res = parse_tcp_stream_turns_output(tsv_lines, stream_id=0, format="turns")
    assert res["stream_id"] == 0
    assert res["client"] == "192.168.1.10:50000"
    assert res["server"] == "93.184.216.34:80"
    assert res["total_turns"] == 2

    # Turn 1: Client -> Server (合并两包)
    t1 = res["turns"][0]
    assert t1["turn_index"] == 1
    assert t1["direction"] == "client_to_server"
    assert t1["packet_count"] == 2
    assert t1["is_binary"] is False
    assert "GET /index.html HTTP/1.1" in t1["payload_preview"]
    assert t1["start_time"] == 1700000000.100
    assert t1["end_time"] == 1700000000.120

    # Turn 2: Server -> Client
    t2 = res["turns"][1]
    assert t2["turn_index"] == 2
    assert t2["direction"] == "server_to_client"
    assert t2["packet_count"] == 1
    assert t2["is_binary"] is False
    assert "HTTP/1.1 200 OK" in t2["payload_preview"]


def test_parse_tcp_stream_turns_output_handles_binary_and_hex_format() -> None:
    """parse_tcp_stream_turns_output 应正确识别二进制载荷并支持 hex 与 raw 格式。"""
    bin_payload = b"\x16\x03\x01\x00\xa5\x00\x00\x00".hex()
    tsv_lines = [
        f"1\t1700000000.000\t10.0.0.1\t10.0.0.2\t\t\t44444\t443\t{bin_payload}",
    ]

    res = parse_tcp_stream_turns_output(tsv_lines, stream_id=5, format="hex")
    assert res["total_turns"] == 1
    t0 = res["turns"][0]
    assert t0["is_binary"] is True
    assert "<binary payload" in t0["payload_preview"] or "<binary data" in t0["payload_preview"]
    assert "payload_hex" in t0
    assert t0["payload_hex"] == bin_payload


def test_normalize_interface_handles_friendly_name_and_index() -> None:
    """_normalize_interface 应支持通过友好名、描述或索引匹配解析出底层网卡设备名。"""
    fake_output = (
        "1. \\Device\\NPF_{GUID_ETH} (以太网 2)\n"
        "2. \\Device\\NPF_{GUID_WLAN} (WLAN)\n"
        "3. eth0 (Primary)\n"
    )
    manager = PcapCaptureManager(
        command_runner=lambda cmd: fake_output if "-D" in cmd else "",
    )

    # 1. 纯数字索引
    assert manager._normalize_interface(2) == "2"
    assert manager._normalize_interface("2") == "2"

    # 2. 友好别名或描述
    assert manager._normalize_interface("WLAN") == "\\Device\\NPF_{GUID_WLAN}"
    assert manager._normalize_interface("以太网 2") == "\\Device\\NPF_{GUID_ETH}"
    assert manager._normalize_interface("Primary") == "eth0"

    # 3. 直接传入设备名或未匹配名称
    assert manager._normalize_interface("\\Device\\NPF_{GUID_ETH}") == "\\Device\\NPF_{GUID_ETH}"
    assert manager._normalize_interface("unknown_dev") == "unknown_dev"


@pytest.mark.asyncio
async def test_tcp_stream_tools_via_mcp_server(tmp_path: Path) -> None:
    """FastMCP 应能正常暴露并调用 list_tcp_streams 与 follow_tcp_stream。"""
    config = parse_config([])
    bus = StorageBus(db_path=tmp_path / "stream_test.db", bodies_dir=tmp_path / "bodies")
    bus.initialize()

    fake_pcap = tmp_path / "test.pcap"
    fake_pcap.write_bytes(b"dummy")

    def fake_runner(cmd: list[str]) -> str:
        cmd_str = " ".join(cmd)
        if "tcp.stream eq" in cmd_str:
            return f"1\t1700000000.0\t192.168.1.1\t192.168.1.2\t\t\t12345\t80\t{b'PING'.hex()}\n"
        if "-Y tcp" in cmd_str:
            return "0\t192.168.1.1\t192.168.1.2\t\t\t12345\t80\tTCP\t4\t\t\n"
        return ""

    pcap_mgr = PcapCaptureManager(
        tshark_path=str(tmp_path / "tshark.exe"),
        command_runner=fake_runner,
    )
    (tmp_path / "tshark.exe").write_bytes(b"mock")

    server = create_mcp_server(config=config, storage=bus, pcap_manager=pcap_mgr)

    # 1. 调用 list_tcp_streams
    _, streams_res = await server.call_tool("list_tcp_streams", {"file_path": str(fake_pcap)})
    streams = (
        streams_res["result"]
        if isinstance(streams_res, dict) and "result" in streams_res
        else streams_res
    )
    assert len(streams) == 1
    assert streams[0]["stream_id"] == 0
    assert streams[0]["client"] == "192.168.1.1:12345"

    # 2. 调用 follow_tcp_stream
    _, follow_res = await server.call_tool(
        "follow_tcp_stream",
        {"file_path": str(fake_pcap), "stream_id": 0},
    )
    follow_data = (
        follow_res["result"]
        if isinstance(follow_res, dict) and "result" in follow_res
        else follow_res
    )
    assert follow_data["stream_id"] == 0
    assert follow_data["total_turns"] == 1
    assert "PING" in follow_data["turns"][0]["payload_preview"]
