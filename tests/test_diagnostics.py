"""HTTP 流量聚合统计与全栈 SessionDiagnosis 智能根因诊断测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.diagnostics import NetworkDiagnostics
from mcp_server_traffic_inspector.pcap import PcapCaptureManager
from mcp_server_traffic_inspector.server import create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


def test_analyze_http_traffic_aggregates_top_metrics(tmp_path: Path) -> None:
    """analyze_http_traffic 应聚合慢请求 Top 5、状态码分布、高频端点 Top 10 与大载荷 Top 3。"""
    bus = StorageBus(
        db_path=tmp_path / "diag.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    # 录制测试流：200 正常流、502 错误流、慢请求流
    bus.record_http_flow(
        flow_id="f-1",
        session_id="sess-diag",
        timestamp=1700003001.0,
        method="GET",
        scheme="https",
        host="api.test.com",
        port=443,
        path="/v1/users",
        status_code=200,
        duration_ms=40.0,
        request_body=b"req1",
        response_body=b"response-1",
    )
    bus.record_http_flow(
        flow_id="f-2",
        session_id="sess-diag",
        timestamp=1700003002.0,
        method="GET",
        scheme="https",
        host="api.test.com",
        port=443,
        path="/v1/users",
        status_code=200,
        duration_ms=50.0,
        request_body=b"req2",
        response_body=b"response-2",
    )
    bus.record_http_flow(
        flow_id="f-3",
        session_id="sess-diag",
        timestamp=1700003003.0,
        method="POST",
        scheme="https",
        host="api.test.com",
        port=443,
        path="/v1/checkout",
        status_code=502,
        duration_ms=2500.0,
        request_body=b"req3",
        response_body=b"bad gateway error payload",
        has_error=True,
    )

    bus.record_http_flow(
        flow_id="f-4",
        session_id="sess-diag",
        timestamp=1700003004.0,
        method="GET",
        scheme="https",
        host="api.test.com",
        port=443,
        path="/v1/broken-conn",
        status_code=None,
        duration_ms=10.0,
        request_body=b"",
        response_body=b"",
        has_error=True,
    )

    diagnostics = NetworkDiagnostics(storage=bus)
    stats = diagnostics.analyze_http_traffic(session_id="sess-diag")

    assert stats["session_id"] == "sess-diag"
    assert stats["total_flows"] == 4
    assert stats["status_distribution"]["2xx"] == 2
    assert stats["status_distribution"]["5xx"] == 1
    assert stats["status_distribution"]["error"] == 1
    assert stats["status_distribution_pct"]["2xx"] == 50.0
    assert stats["status_distribution_pct"]["5xx"] == 25.0
    assert stats["status_distribution_pct"]["error"] == 25.0

    # 慢请求 Top 5
    assert len(stats["slow_requests_top_5"]) == 4
    assert stats["slow_requests_top_5"][0]["id"] == "f-3"
    assert stats["slow_requests_top_5"][0]["duration_ms"] == 2500.0

    # 高频端点 Top 10
    top_endpoints = stats["top_endpoints_top_10"]
    assert len(top_endpoints) == 3
    users_endpoint = next(e for e in top_endpoints if e["path"] == "/v1/users")
    assert users_endpoint["count"] == 2

    # 流量总计与大载荷 Top 3
    assert stats["total_bytes_sent"] > 0
    assert stats["total_bytes_received"] > 0
    assert len(stats["largest_payloads_top_3"]) == 3


def test_analyze_http_traffic_defaults_to_latest_session(tmp_path: Path) -> None:
    """analyze_http_traffic 未指定 session_id 时应自动定位至最近一次会话。"""
    bus = StorageBus(
        db_path=tmp_path / "diag_default.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    # 先写入较早会话
    bus.record_http_flow(
        flow_id="f-old",
        session_id="sess-old",
        timestamp=1700001000.0,
        method="GET",
        scheme="https",
        host="old.test.com",
        port=443,
        path="/old",
        status_code=200,
        duration_ms=20.0,
    )
    # 后写入最新会话
    bus.record_http_flow(
        flow_id="f-new",
        session_id="sess-new",
        timestamp=1700009000.0,
        method="GET",
        scheme="https",
        host="new.test.com",
        port=443,
        path="/new",
        status_code=404,
        duration_ms=30.0,
    )

    diagnostics = NetworkDiagnostics(storage=bus)
    stats = diagnostics.analyze_http_traffic(session_id=None)

    assert stats["session_id"] == "sess-new"
    assert stats["total_flows"] == 1
    assert stats["status_distribution"]["4xx"] == 1
    assert stats["status_distribution_pct"]["4xx"] == 100.0


def test_diagnose_http_session_detects_5xx_and_slow_requests(tmp_path: Path) -> None:
    """diagnose_network_session(http) 应识别出 5xx 高错误率与慢接口异常并生成排障建议。"""
    bus = StorageBus(
        db_path=tmp_path / "diag_http.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    # 构造 1 条慢且报错的 504 网关超时请求
    bus.record_http_flow(
        flow_id="f-slow-504",
        session_id="sess-broken",
        timestamp=1700003010.0,
        method="POST",
        scheme="https",
        host="payment.service.com",
        port=443,
        path="/charge",
        status_code=504,
        duration_ms=3500.0,
        request_body=b"pay",
        response_body=b"Gateway Timeout",
        has_error=True,
    )

    diagnostics = NetworkDiagnostics(storage=bus)
    report = diagnostics.diagnose_network_session(
        session_type="http",
        target="sess-broken",
    )

    assert report["session_type"] == "http"
    assert report["health_status"] in {"degraded", "critical"}
    assert report["health_score"] < 80
    assert len(report["anomalies"]) >= 1

    anomaly_types = {a["type"] for a in report["anomalies"]}
    assert "server_errors" in anomaly_types or "slow_requests" in anomaly_types
    assert len(report["recommendations"]) >= 1


def test_diagnose_pcap_session_detects_retransmission_and_dns_delay(
    tmp_path: Path,
) -> None:
    """diagnose_network_session(pcap) 应检测高 TCP 重传率与 DNS 解析异常。"""
    sample_pcap = tmp_path / "bad_link.pcap"
    sample_pcap.write_bytes(b"dummy-pcap")

    # 模拟高重传与高 RTT tshark 字段输出
    def runner_mock(cmd: list[str]) -> str:
        lines = [
            # 10 个 TCP 包中有 3 个重传 (30% 重传率)
            "1\teth:ip:tcp\t1\t0.350\t\t\t",
            "2\teth:ip:tcp\t1\t0.420\t\t\t",
            "3\teth:ip:tcp\t1\t0.380\t\t\t",
            "4\teth:ip:tcp\t\t0.250\t\t\t",
            "5\teth:ip:tcp\t\t0.150\t\t\t",
            # 1 个 DNS 失败
            "6\teth:ip:udp:dns\t\t\t1\t3\t0.210",
        ]
        return "\n".join(lines)

    fake_tshark = tmp_path / "tshark"
    fake_tshark.write_bytes(b"bin")

    pcap_mgr = PcapCaptureManager(
        tshark_path=str(fake_tshark),
        command_runner=runner_mock,
    )
    diagnostics = NetworkDiagnostics(
        storage=StorageBus(tmp_path / "empty.db", tmp_path / "b"),
        pcap_manager=pcap_mgr,
    )

    report = diagnostics.diagnose_network_session(
        session_type="pcap",
        target=str(sample_pcap),
    )

    assert report["session_type"] == "pcap"
    assert report["health_status"] in {"degraded", "critical"}
    assert report["health_score"] < 70
    assert any("tcp_retransmission" in a["type"] for a in report["anomalies"])
    assert any("dns" in a["type"] for a in report["anomalies"])


async def test_mcp_server_exposes_diagnostics_tools(tmp_path: Path) -> None:
    """FastMCP 服务应注册并正常调用 analyze_http_traffic 与 diagnose_network_session。"""
    db_file = tmp_path / "diag_tools.db"
    cfg = parse_config(argv=["--db-path", str(db_file)], env={})
    bus = StorageBus.from_config(cfg)
    bus.initialize()

    mcp = create_mcp_server(config=cfg, storage=bus)

    _, analysis = await mcp.call_tool("analyze_http_traffic", {})
    assert "total_flows" in analysis
    assert "status_code_distribution" in analysis

    _, diagnosis = await mcp.call_tool(
        "diagnose_network_session",
        {"session_type": "http"},
    )
    assert "health_status" in diagnosis
    assert "health_score" in diagnosis
