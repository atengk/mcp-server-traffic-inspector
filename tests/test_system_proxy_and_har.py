"""CA 证书引导、跨平台系统代理托管与标准 HAR 归档导出测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.har_exporter import HarExporter
from mcp_server_traffic_inspector.server import create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus
from mcp_server_traffic_inspector.system_proxy import SystemProxyManager, get_ca_certificate


def test_get_ca_certificate_with_and_without_existing_cert(tmp_path: Path) -> None:
    """get_ca_certificate 应正确识别证书路径、存在状态及跨平台信任安装指引。"""
    cert_dir = tmp_path / ".mitmproxy"

    # 1. 证书不存在场景
    res_missing = get_ca_certificate(custom_cert_dir=cert_dir)
    assert res_missing["exists"] is False
    assert "windows" in res_missing["instructions"]
    assert "linux" in res_missing["instructions"]

    # 2. 证书存在场景
    cert_dir.mkdir(parents=True, exist_ok=True)
    pem_file = cert_dir / "mitmproxy-ca-cert.pem"
    pem_file.write_text("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n")
    cer_file = cert_dir / "mitmproxy-ca-cert.cer"
    cer_file.write_bytes(b"MOCK_CER")

    res_found = get_ca_certificate(custom_cert_dir=cert_dir)
    assert res_found["exists"] is True
    assert res_found["ca_pem_path"] == str(pem_file.resolve())
    assert res_found["ca_cer_path"] == str(cer_file.resolve())
    assert "certutil" in res_found["instructions"]["windows"][0]


def test_toggle_system_proxy_non_windows_fallback() -> None:
    """非 Windows 环境（如 Linux/Docker）应优雅降级返回 supported=False 与环境变量说明。"""
    mgr = SystemProxyManager()
    mgr._is_windows = False

    result = mgr.toggle_proxy(enable=True, host="127.0.0.1", port=8080)
    assert result["supported"] is False
    assert result["system_proxy_enabled"] is False
    assert "export http_proxy" in result["message"]


def test_toggle_system_proxy_windows_and_restore() -> None:
    """Windows 环境下应能修改注册表并支持在退出时完整还原初始代理状态。"""
    mgr = SystemProxyManager()
    mgr._is_windows = True

    # 模拟原始状态：代理未开启
    mock_reg = {
        "ProxyEnable": 0,
        "ProxyServer": "old-proxy:8080",
    }

    def fake_read_registry() -> tuple[int, str]:
        return (mock_reg["ProxyEnable"], mock_reg["ProxyServer"])

    def fake_write_registry(enabled: int, server: str) -> None:
        mock_reg["ProxyEnable"] = enabled
        mock_reg["ProxyServer"] = server

    with (
        patch.object(mgr, "_read_registry", side_effect=fake_read_registry),
        patch.object(mgr, "_write_registry", side_effect=fake_write_registry),
        patch.object(mgr, "_refresh_system_settings"),
    ):
        # 1. 开启代理
        res_enable = mgr.toggle_proxy(enable=True, host="127.0.0.1", port=8888)
        assert res_enable["supported"] is True
        assert res_enable["system_proxy_enabled"] is True
        assert res_enable["proxy_server"] == "127.0.0.1:8888"
        assert mock_reg["ProxyEnable"] == 1
        assert mock_reg["ProxyServer"] == "127.0.0.1:8888"

        # 2. 模拟进程退出钩子还原
        mgr.restore_initial_state()
        assert mock_reg["ProxyEnable"] == 0
        assert mock_reg["ProxyServer"] == "old-proxy:8080"


def test_har_exporter_full_session(tmp_path: Path) -> None:
    """HarExporter 应将捕获流与完整 BodyPayload 导出为合规的 HAR 1.2 JSON 归档。"""
    bus = StorageBus(
        db_path=tmp_path / "har.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    # 录制两条请求：1 条标准 JSON，1 条二进制大载荷
    req_body = json.dumps({"action": "ping"}).encode("utf-8")
    resp_body = json.dumps({"result": "pong", "code": 0}).encode("utf-8")

    bus.record_http_flow(
        flow_id="f-har-1",
        session_id="sess-har",
        timestamp=1700000000.0,
        method="POST",
        scheme="https",
        host="api.domain.com",
        port=443,
        path="/v1/ping?foo=bar",
        request_headers={"Content-Type": "application/json", "Authorization": "Bearer token"},
        response_headers={"Content-Type": "application/json"},
        status_code=200,
        duration_ms=120.5,
        request_body=req_body,
        response_body=resp_body,
    )

    # 二进制数据流
    binary_bytes = b"\x00\x01\x02\x03\xff\xfe"
    bus.record_http_flow(
        flow_id="f-har-2",
        session_id="sess-har",
        timestamp=1700000005.0,
        method="GET",
        scheme="https",
        host="api.domain.com",
        port=443,
        path="/v1/avatar.png",
        request_headers={},
        response_headers={"Content-Type": "image/png"},
        status_code=200,
        duration_ms=45.0,
        request_body=b"",
        response_body=binary_bytes,
    )

    exporter = HarExporter(storage=bus)
    output_file = tmp_path / "exports" / "traffic.har"

    res = exporter.export_session(output_path=output_file, session_id="sess-har")
    assert res["flow_count"] == 2
    assert res["format"] == "har"
    assert Path(res["exported_path"]).is_file()

    # 验证 HAR 1.2 内容结构
    har_data = json.loads(output_file.read_text(encoding="utf-8"))
    log = har_data["log"]
    assert log["version"] == "1.2"
    assert log["creator"]["name"] == "mcp-server-traffic-inspector"
    assert len(log["entries"]) == 2

    # 验证第一条请求的 entries 字段映射
    entry1 = log["entries"][0]
    assert entry1["request"]["method"] == "POST"
    assert entry1["request"]["url"] == "https://api.domain.com/v1/ping?foo=bar"
    assert entry1["request"]["queryString"] == [{"name": "foo", "value": "bar"}]
    assert entry1["request"]["postData"]["text"] == json.dumps({"action": "ping"})
    assert entry1["response"]["status"] == 200
    assert entry1["response"]["content"]["text"] == json.dumps({"result": "pong", "code": 0})

    # 验证第二条二进制请求的 base64 编码保护
    entry2 = log["entries"][1]
    assert entry2["response"]["content"]["encoding"] == "base64"


def test_har_exporter_invalid_format_and_empty_session(tmp_path: Path) -> None:
    """HarExporter 应在前置卫语句中拒绝非法格式并处理空会话。"""
    bus = StorageBus(
        db_path=tmp_path / "empty.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()
    exporter = HarExporter(storage=bus)

    with pytest.raises(ValueError, match="不支持的导出格式"):
        exporter.export_session(output_path=tmp_path / "test.pcap", format="pcap")

    # 未指定 session_id 且整库为空时抛出明确异常
    with pytest.raises(ValueError, match="未找到可导出的 HTTP 会话数据"):
        exporter.export_session(output_path=tmp_path / "empty.har")

    # 指定了 session_id 但无流量时应生成合法空 HAR 归档
    empty_har_out = tmp_path / "valid_empty.har"
    empty_res = exporter.export_session(
        output_path=empty_har_out,
        session_id="empty-sess-1",
    )
    assert empty_res["flow_count"] == 0
    empty_har_data = json.loads(empty_har_out.read_text(encoding="utf-8"))
    assert empty_har_data["log"]["entries"] == []


def test_system_proxy_get_status_and_smart_restore_ownership() -> None:
    """SystemProxyManager 应正确探查代理状态，且 smart_restore 仅在归属匹配时复位。"""
    mgr = SystemProxyManager()
    mgr._is_windows = True

    mock_reg = {
        "ProxyEnable": 1,
        "ProxyServer": "127.0.0.1:7890",  # 第三方 Clash 代理
    }

    def fake_read() -> tuple[int, str]:
        return (mock_reg["ProxyEnable"], mock_reg["ProxyServer"])

    def fake_write(enabled: int, server: str) -> None:
        mock_reg["ProxyEnable"] = enabled
        mock_reg["ProxyServer"] = server

    with (
        patch.object(mgr, "_read_registry", side_effect=fake_read),
        patch.object(mgr, "_write_registry", side_effect=fake_write),
        patch.object(mgr, "_refresh_system_settings"),
    ):
        # 1. 探查当前指向第三方的代理状态
        status = mgr.get_proxy_status(expected_port=8080)
        assert status["system_proxy_enabled"] is True
        assert status["proxy_server"] == "127.0.0.1:7890"
        assert status["is_pointing_to_inspector"] is False

        # 2. 尝试智能复位 -> 检测到第三方所有权，跳过复位保护网络
        restore_res = mgr.smart_restore(expected_port=8080)
        assert restore_res["restored"] is False
        assert restore_res["reason"] == "external_proxy_owned"
        assert mock_reg["ProxyEnable"] == 1  # 保持开启

        # 3. 将代理修改为指向本抓包端口 127.0.0.1:8080
        mock_reg["ProxyServer"] = "127.0.0.1:8080"
        status_own = mgr.get_proxy_status(expected_port=8080)
        assert status_own["is_pointing_to_inspector"] is True

        # 4. 执行智能复位 -> 匹配成功，安全关闭代理
        restore_success = mgr.smart_restore(expected_port=8080)
        assert restore_success["restored"] is True
        assert restore_success["system_proxy_enabled"] is False
        assert mock_reg["ProxyEnable"] == 0


@pytest.mark.asyncio
async def test_ops_mcp_tools_registration(tmp_path: Path) -> None:
    """验证全部 19 个 MCP 工具均已注册且运维工具正常响应。"""
    config = parse_config([])
    bus = StorageBus(
        db_path=tmp_path / "server_test.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    server = create_mcp_server(config=config, storage=bus)
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]

    assert len(tool_names) == 19
    assert "get_ca_certificate" in tool_names
    assert "toggle_system_proxy" in tool_names
    assert "get_system_proxy_status" in tool_names
    assert "export_http_session" in tool_names

    # 调用 get_ca_certificate
    ca_res = await server.call_tool("get_ca_certificate", {})
    ca_data = ca_res[0].text if hasattr(ca_res[0], "text") else str(ca_res)
    assert "instructions" in ca_data

    # 调用 get_system_proxy_status
    status_res = await server.call_tool("get_system_proxy_status", {})
    status_dict = (
        status_res[1] if isinstance(status_res, tuple) and len(status_res) > 1 else status_res
    )
    assert "supported" in str(status_dict)
