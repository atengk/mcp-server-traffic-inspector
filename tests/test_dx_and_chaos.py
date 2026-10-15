"""DX 优化、受管进程双轨拉起、混沌故障与启发式嗅探单元测试。

@author Ateng
@since 2026-10-15
"""

from __future__ import annotations

import gzip
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.doctor import (
    get_ca_env_vars,
    trust_ca_certificate,
)
from mcp_server_traffic_inspector.pcap import (
    _extract_tls_sni,
    _heuristic_dissect_payload,
    parse_tcp_stream_turns_output,
)
from mcp_server_traffic_inspector.proxy_addon import TrafficCaptureAddon
from mcp_server_traffic_inspector.server import create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


def test_ca_env_vars_and_trust(tmp_path: Path) -> None:
    """验证 CA 环境变量生成与证书信任安装调用。"""
    envs = get_ca_env_vars()
    assert "NODE_EXTRA_CA_CERTS" in envs
    assert "SSL_CERT_FILE" in envs
    assert "REQUESTS_CA_BUNDLE" in envs
    assert "CURL_CA_BUNDLE" in envs

    # 1. 模拟 Windows 当前用户免提权导入
    with patch("sys.platform", "win32"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="CertUtil: -addstore command completed successfully.",
                stderr="",
            )
            res = trust_ca_certificate(system_wide=False)
            assert res["status"] == "ok"
            assert res["scope"] == "CurrentUser"
            assert "NODE_EXTRA_CA_CERTS" in res["env_vars"]
            # 校验 certutil 参数
            called_args = mock_run.call_args[0][0]
            assert "-user" in called_args
            assert "Root" in called_args

    # 2. 模拟系统级导入
    with patch("sys.platform", "win32"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Success", stderr="")
            res_sys = trust_ca_certificate(system_wide=True)
            assert res_sys["status"] == "ok"
            assert res_sys["scope"] == "LocalMachine"
            called_args = mock_run.call_args[0][0]
            assert "-user" not in called_args


@pytest.mark.asyncio
async def test_launch_and_inspect_process_tool(tmp_path: Path) -> None:
    """验证 launch_and_inspect_process 工具环境变量注入与受管退出能力。"""
    config = parse_config([])
    bus = StorageBus(
        db_path=tmp_path / "proc_test.db",
        bodies_dir=tmp_path / "proc_bodies",
        preserve_db=False,
    )
    bus.initialize()
    server = create_mcp_server(config=config, storage=bus)

    # 1. 测试同步等待并捕获 Python 子进程中的环境变量
    test_cmd = [
        sys.executable,
        "-c",
        "import os; print('PROXY=' + os.environ.get('HTTP_PROXY', 'none'))",
    ]
    res = await server.call_tool(
        "launch_and_inspect_process",
        {
            "command": test_cmd,
            "inject_proxy": True,
            "wait_for_exit": True,
            "timeout_seconds": 10,
        },
    )
    data = res[1] if isinstance(res, tuple) and len(res) > 1 else res
    assert data["status"] == "completed"
    assert data["exit_code"] == 0
    assert "PROXY=http://127.0.0.1:8080" in data["stdout"]

    # 2. 测试非等待模式 (running)
    bg_cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
    res_bg = await server.call_tool(
        "launch_and_inspect_process",
        {
            "command": bg_cmd,
            "wait_for_exit": False,
        },
    )
    bg_data = res_bg[1] if isinstance(res_bg, tuple) and len(res_bg) > 1 else res_bg
    assert bg_data["status"] == "running"
    assert bg_data["pid"] > 0


def test_chaos_rules_and_max_hits(tmp_path: Path) -> None:
    """验证拦截规则的延迟仿真、限次失效与 abort 连接切断逻辑。"""
    bus = StorageBus(
        db_path=tmp_path / "rules_test.db",
        bodies_dir=tmp_path / "rules_bodies",
        preserve_db=False,
    )
    bus.initialize()

    # 1. 添加限次规则 max_hits=2, action="abort", delay_ms=50
    rule = bus.add_intercept_rule(
        url_pattern=".*api/flaky.*",
        action="abort",
        delay_ms=50,
        max_hits=2,
    )
    rule_id = rule["rule_id"]
    assert rule["delay_ms"] == 50
    assert rule["max_hits"] == 2

    # 查询规则
    active_rules = bus.list_intercept_rules(only_enabled=True)
    assert len(active_rules) == 1
    assert active_rules[0]["hit_count"] == 0

    # 2. 模拟第 1 次命中
    bus.increment_rule_hit(rule_id)
    r1 = bus.list_intercept_rules(only_enabled=True)
    assert len(r1) == 1
    assert r1[0]["hit_count"] == 1
    assert r1[0]["enabled"] is True

    # 3. 模拟第 2 次命中 -> 应当自动禁用
    bus.increment_rule_hit(rule_id)
    r2_active = bus.list_intercept_rules(only_enabled=True)
    assert len(r2_active) == 0

    all_rules = bus.list_intercept_rules(only_enabled=False)
    assert len(all_rules) == 1
    assert all_rules[0]["hit_count"] == 2
    assert all_rules[0]["enabled"] is False

    # 4. 测试 TrafficCaptureAddon 对 action="abort" 的处理
    addon = TrafficCaptureAddon(storage=bus, session_id="test_sess")
    mock_flow = MagicMock()
    mock_flow.request.pretty_url = "https://example.com/api/flaky/data"
    mock_flow.request.headers = {}
    mock_flow.request.content = b""

    # 重新添加一条活跃的 abort 规则
    bus.add_intercept_rule(
        url_pattern=".*flaky.*",
        action="abort",
        delay_ms=10,
    )
    addon.request(mock_flow)
    # 验证 flow.kill() 被调用
    assert mock_flow.kill.called


def test_compact_flows_and_summary_metrics(tmp_path: Path) -> None:
    """验证 list_http_flows 的 query 模糊搜索、compact 紧凑模式与 summary_metrics 统计。"""
    bus = StorageBus(
        db_path=tmp_path / "flows_test.db",
        bodies_dir=tmp_path / "flows_bodies",
        preserve_db=False,
    )
    bus.initialize()
    sess_id = "test_sess_01"

    # 插入 3 条流：正常流、慢请求流、500 错误流
    bus.record_http_flow(
        flow_id="f1",
        session_id=sess_id,
        timestamp=time.time(),
        method="GET",
        scheme="https",
        host="api.github.com",
        port=443,
        path="/users/octocat",
        status_code=200,
        duration_ms=120.0,
        request_headers={"Accept": "application/json"},
        response_headers={"Content-Type": "application/json"},
        request_body=b"",
        response_body=b'{"user": "octocat"}',
    )
    bus.record_http_flow(
        flow_id="f2",
        session_id=sess_id,
        timestamp=time.time(),
        method="POST",
        scheme="https",
        host="api.github.com",
        port=443,
        path="/users/octocat/repos",
        status_code=500,
        duration_ms=500.0,
        request_headers={"Content-Type": "application/json"},
        response_headers={"Content-Type": "application/json"},
        request_body=b'{"name": "repo"}',
        response_body=b'{"error": "internal"}',
    )
    bus.record_http_flow(
        flow_id="f3",
        session_id=sess_id,
        timestamp=time.time(),
        method="GET",
        scheme="https",
        host="cdn.example.com",
        port=443,
        path="/assets/logo.png",
        status_code=200,
        duration_ms=30.0,
        request_headers={"Accept": "image/png"},
        response_headers={"Content-Type": "image/png"},
        request_body=b"",
        response_body=b"\x89PNG\r\n",
    )

    # 1. 模糊匹配 query="repos"
    res_query = bus.list_http_flows(query="repos")
    assert res_query["total"] == 1
    assert res_query["flows"][0]["id"] == "f2"

    # 2. 紧凑模式 compact=True
    res_compact = bus.list_http_flows(compact=True)
    assert res_compact["total"] == 3
    for f in res_compact["flows"]:
        assert "request_headers" not in f
        assert "response_headers" not in f
        assert "id" in f
        assert "method" in f
        assert "url" in f
        assert "status_code" in f
        assert "duration_ms" in f

    # 3. 校验 summary_metrics
    metrics = res_compact.get("summary_metrics", {})
    assert metrics["error_count"] == 1
    assert metrics["avg_duration_ms"] > 0


def test_heuristic_dissection() -> None:
    """验证启发式协议嗅探器：TLS SNI 提取、Gzip 解压与 Strings 提炼。"""
    # 1. 构造简易 TLS Client Hello 提取 SNI
    # TLS Record Header (5 bytes: 16 03 01 00 xx)
    # Handshake Header (4 bytes: 01 00 00 xx)
    # Version (2 bytes: 03 03)
    # Random (32 bytes)
    # Session ID Len (1 byte: 00)
    # Cipher Suites (2 bytes len + 2 bytes cipher)
    # Comp (1 byte len + 1 byte comp)
    # Extensions Len (2 bytes)
    # SNI Ext: type=00 00, len=xx, list_len=xx, type=00, name_len=xx, name="test.example.com"
    sni_host = b"test.example.com"
    sni_ext = (
        b"\x00\x00"  # ext type: server_name
        + (len(sni_host) + 5).to_bytes(2, "big")  # ext len
        + (len(sni_host) + 3).to_bytes(2, "big")  # list len
        + b"\x00"  # host_name type
        + len(sni_host).to_bytes(2, "big")  # name len
        + sni_host
    )
    ext_block = len(sni_ext).to_bytes(2, "big") + sni_ext
    client_hello_body = (
        b"\x03\x03"  # client version
        + (b"\x00" * 32)  # random
        + b"\x00"  # session id len
        + b"\x00\x02\x00\x9c"  # ciphers
        + b"\x01\x00"  # compression
        + ext_block
    )
    handshake = (
        b"\x01"  # Client Hello
        + len(client_hello_body).to_bytes(3, "big")
        + client_hello_body
    )
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    extracted_sni = _extract_tls_sni(record)
    assert extracted_sni == "test.example.com"

    heuristic_tls = _heuristic_dissect_payload(record)
    assert heuristic_tls.get("protocol_hint") == "TLS"
    assert heuristic_tls.get("tls_sni") == "test.example.com"

    # 2. Gzip 压缩流探测
    test_json = b'{"status": "ok", "message": "traffic-inspection"}'
    compressed_gzip = gzip.compress(test_json)
    heuristic_gzip = _heuristic_dissect_payload(compressed_gzip)
    assert "decompressed_preview" in heuristic_gzip
    assert "traffic-inspection" in heuristic_gzip["decompressed_preview"]

    # 3. 提取可打印 ASCII 字符串
    raw_mixed = b"\x00\x01\x02AntigravityTrafficAgent\xff\xfe\x00\x00Version1.0\xaa"
    heuristic_strings = _heuristic_dissect_payload(raw_mixed)
    strings = heuristic_strings.get("heuristic_strings", [])
    assert any("AntigravityTrafficAgent" in s for s in strings)
    assert any("Version1.0" in s for s in strings)

    # 4. 验证 parse_tcp_stream_turns_output 集成了 heuristic 属性
    # 模拟 TSV 行
    tsv_line = f"1\t1700000000.0\t192.168.1.10\t10.0.0.1\t\t\t54321\t443\t{record.hex()}"
    stream_res = parse_tcp_stream_turns_output([tsv_line], stream_id=0)
    assert stream_res["total_turns"] == 1
    turn = stream_res["turns"][0]
    assert "heuristic" in turn
    assert turn["heuristic"].get("protocol_hint") == "TLS"
    assert turn["heuristic"].get("tls_sni") == "test.example.com"
