"""PcapCapture 网卡列表解析与离线 PCAP 深度协议分析测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_server_traffic_inspector.pcap import (
    PcapCaptureManager,
    parse_interface_list,
    parse_tshark_fields_output,
)


def test_parse_interface_list_handles_windows_and_linux_formats() -> None:
    """parse_interface_list 应支持解析 Windows NPF GUID 与 Linux 标准网卡名称。"""
    raw_output = (
        "1. \\Device\\NPF_{1234-ABCD} (Ethernet 2)\n"
        "2. eth0 (Primary Network)\n"
        "3. lo (Loopback Interface)\n"
        "4. \\Device\\NPF_Loopback\n"
    )

    interfaces = parse_interface_list(raw_output)

    assert len(interfaces) == 4
    assert interfaces[0] == {
        "index": 1,
        "name": "\\Device\\NPF_{1234-ABCD}",
        "description": "Ethernet 2",
        "friendly_name": "Ethernet 2",
    }
    assert interfaces[1] == {
        "index": 2,
        "name": "eth0",
        "description": "Primary Network",
        "friendly_name": "Primary Network",
    }
    assert interfaces[2] == {
        "index": 3,
        "name": "lo",
        "description": "Loopback Interface",
        "friendly_name": "Loopback Interface",
    }
    assert interfaces[3] == {
        "index": 4,
        "name": "\\Device\\NPF_Loopback",
        "description": "\\Device\\NPF_Loopback",
        "friendly_name": "\\Device\\NPF_Loopback",
    }

    assert parse_interface_list("") == []


def test_parse_tshark_fields_output_computes_tcp_and_dns_metrics() -> None:
    """从 tshark -T fields 输出行提取协议分布、TCP 重传率、RTT 极值与 DNS 指标。"""
    # 模拟 tshark -T fields 输出行结构：
    # frame.number \t frame.protocols \t tcp.retrans \t tcp.ack_rtt \t
    # dns.response \t dns.rcode \t dns.time
    tsv_lines = [
        # Packet 1: TCP SYN
        "1\teth:ethertype:ip:tcp\t\t\t\t\t",
        # Packet 2: TCP ACK with RTT 0.015s (15.0ms)
        "2\teth:ethertype:ip:tcp\t\t0.015\t\t\t",
        # Packet 3: TCP Retransmission with RTT 0.045s (45.0ms)
        "3\teth:ethertype:ip:tcp\t1\t0.045\t\t\t",
        # Packet 4: DNS Query
        "4\teth:ethertype:ip:udp:dns\t\t\t0\t\t",
        # Packet 5: DNS Response with time 0.020s (20.0ms), rcode 0 (Success)
        "5\teth:ethertype:ip:udp:dns\t\t\t1\t0\t0.020",
        # Packet 6: TLS Client Hello
        "6\teth:ethertype:ip:tcp:tls\t\t0.010\t\t\t",
    ]

    analysis = parse_tshark_fields_output(
        tsv_lines=tsv_lines,
        file_path="/tmp/sample.pcap",
        total_packets=6,
    )

    assert analysis["total_packets"] == 6
    assert analysis["analyzed_packets"] == 6

    # 1. 协议分布
    proto_dist = analysis["protocol_distribution"]
    assert proto_dist.get("TCP") == 4
    assert proto_dist.get("DNS") == 2
    assert proto_dist.get("TLS") == 1

    # 2. TCP 重传率与 RTT 指标
    tcp = analysis["tcp_analysis"]
    assert tcp["total_tcp_packets"] == 4
    assert tcp["retransmission_packets"] == 1
    assert tcp["retransmission_rate_pct"] == 25.0
    assert tcp["rtt_ms"]["min"] == 10.0
    assert tcp["rtt_ms"]["max"] == 45.0
    assert tcp["rtt_ms"]["avg"] == 23.33

    # 3. DNS 指标
    dns = analysis["dns_analysis"]
    assert dns["query_count"] == 1
    assert dns["response_count"] == 1
    assert dns["failed_count"] == 0
    assert dns["avg_duration_ms"] == 20.0


def test_analyze_pcap_validates_file_existence(tmp_path: Path) -> None:
    """分析不存在的 PCAP 文件时应抛出明确的 ValueError。"""
    manager = PcapCaptureManager(tshark_path=str(tmp_path / "fake_tshark"))
    missing_file = tmp_path / "missing.pcap"

    with pytest.raises(ValueError, match="PCAP 文件不存在"):
        manager.analyze_pcap(file_path=str(missing_file))
