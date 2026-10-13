"""FlowReplay 完整无损重放、参数变异 Diff 与 4 个流量操控 MCP 工具端到端测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.replay import FlowReplayEngine
from mcp_server_traffic_inspector.server import create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


async def test_replay_preserves_full_untruncated_request_body_over_2048_chars(
    tmp_path: Path,
) -> None:
    """当未传入 modify_body 时，replay_http_request 必须发送超过 2048 字符的完整原始请求体。"""
    bus = StorageBus(
        db_path=tmp_path / "replay_large.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    # 构造 5000 字节的原始请求体（大于 2048 预览截断阈值）
    original_req_body = ("X" * 5000).encode("utf-8")
    bus.record_http_flow(
        flow_id="flow-5000",
        session_id="sess-replay",
        timestamp=1700002000.0,
        method="POST",
        scheme="https",
        host="api.example.com",
        port=443,
        path="/v1/upload",
        status_code=200,
        duration_ms=120.0,
        request_headers={"Content-Type": "text/plain", "X-Origin": "old"},
        response_headers={"Content-Type": "application/json"},
        request_body=original_req_body,
        response_body=b'{"status": "v1", "count": 10}',
    )

    received: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        received["url"] = str(request.url)
        received["headers"] = dict(request.headers)
        received["body"] = request.content
        return httpx.Response(
            status_code=201,
            headers={"Content-Type": "application/json"},
            content=b'{"status": "v2", "count": 11}',
        )

    engine = FlowReplayEngine(storage=bus, transport=httpx.MockTransport(handler))
    result = await engine.replay(
        flow_id="flow-5000",
        modify_headers={"X-Origin": "new-replayed"},
    )

    assert len(received["body"]) == 5000
    assert received["body"] == original_req_body
    assert received["headers"]["x-origin"] == "new-replayed"

    assert result["flow_id"] == "flow-5000"
    assert result["diff"]["status_code_before"] == 200
    assert result["diff"]["status_code_after"] == 201
    assert result["diff"]["status_code_changed"] is True
    assert result["diff"]["body_changed"] is True
    assert "v1" in result["diff"]["body_diff_preview"]
    assert "v2" in result["diff"]["body_diff_preview"]


async def test_mcp_server_exposes_and_executes_manipulation_tools(
    tmp_path: Path,
) -> None:
    """FastMCP 服务应注册并正常执行 add/list/clear_intercept_rules 与 replay_http_request。"""
    db_file = tmp_path / "manip_mcp.db"
    cfg = parse_config(argv=["--db-path", str(db_file)], env={})
    bus = StorageBus.from_config(cfg)
    bus.initialize()

    bus.record_http_flow(
        flow_id="flow-to-replay",
        session_id="sess-m",
        timestamp=1700002100.0,
        method="POST",
        scheme="https",
        host="service.local",
        port=443,
        path="/api/pay",
        status_code=500,
        duration_ms=300.0,
        request_headers={"Content-Type": "application/json"},
        response_headers={"Content-Type": "application/json"},
        request_body=b'{"amount": 100}',
        response_body=b'{"ok": false}',
    )

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=f'{{"ok": true, "echo": {request.content.decode("utf-8")}}}'.encode(),
        )

    replay_engine = FlowReplayEngine(storage=bus, transport=httpx.MockTransport(mock_handler))
    mcp = create_mcp_server(config=cfg, storage=bus, replay_engine=replay_engine)

    # 1. 验证规则增删查 MCP 工具
    _, add_res = await mcp.call_tool(
        "add_intercept_rule",
        {
            "url_pattern": "*service.local/api/*",
            "action": "mock",
            "mock_status": 200,
            "mock_body": '{"mocked": true}',
        },
    )
    rule_id = add_res["rule_id"]
    assert add_res["status"] == "active"

    _, list_res = await mcp.call_tool("list_intercept_rules", {})
    # FastMCP 对返回 list 的工具可能包装在结构化返回值或文本中，校验规则存在
    assert rule_id in str(list_res)

    _, clear_res = await mcp.call_tool("clear_intercept_rules", {"rule_id": rule_id})
    assert clear_res["cleared_count"] == 1
    assert clear_res["target_rule_id"] == rule_id

    # 2. 验证参数变异重放 MCP 工具
    _, replay_res = await mcp.call_tool(
        "replay_http_request",
        {
            "flow_id": "flow-to-replay",
            "modify_url": "https://staging.service.local/api/pay",
            "modify_body": '{"amount": 250}',
        },
    )
    assert replay_res["target_url"] == "https://staging.service.local/api/pay"
    assert replay_res["diff"]["status_code_before"] == 500
    assert replay_res["diff"]["status_code_after"] == 200
    assert "250" in replay_res["replayed_response"]["body_preview"]
