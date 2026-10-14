"""WebSocket 长连接消息帧录制、心跳抑制、大载荷分流与 HAR 导出测试。

@author Ateng
@since 2026-10-14
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.har_exporter import HarExporter
from mcp_server_traffic_inspector.proxy_addon import TrafficCaptureAddon
from mcp_server_traffic_inspector.server import create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


def test_websocket_message_storage_and_heartbeat_filtering(tmp_path: Path) -> None:
    """StorageBus 应正确记录 WebSocket 消息帧，并支持在查询时抑制 PING/PONG 心跳帧。"""
    bus = StorageBus(
        db_path=tmp_path / "ws_test.db",
        bodies_dir=tmp_path / "bodies",
    )
    bus.initialize()

    flow_id = "ws_flow_001"
    session_id = "sess_ws"

    # 1. 记录客户端发送的文本消息
    m1 = bus.record_websocket_message(
        flow_id=flow_id,
        session_id=session_id,
        timestamp=1700000000.1,
        direction="client_to_server",
        opcode=1,
        opcode_name="TEXT",
        content='{"action":"subscribe","channel":"ticker"}',
    )

    # 2. 记录心跳 PING 帧
    m2 = bus.record_websocket_message(
        flow_id=flow_id,
        session_id=session_id,
        timestamp=1700000000.2,
        direction="client_to_server",
        opcode=9,
        opcode_name="PING",
        content=b"",
    )

    # 3. 记录心跳 PONG 帧
    m3 = bus.record_websocket_message(
        flow_id=flow_id,
        session_id=session_id,
        timestamp=1700000000.3,
        direction="server_to_client",
        opcode=10,
        opcode_name="PONG",
        content=b"",
    )

    # 4. 记录服务端推送的二进制消息
    m4 = bus.record_websocket_message(
        flow_id=flow_id,
        session_id=session_id,
        timestamp=1700000000.4,
        direction="server_to_client",
        opcode=2,
        opcode_name="BINARY",
        content=b"\x01\x02\x03\x04\x05",
    )

    # 查询 1: 默认抑制心跳 (include_heartbeats=False)
    res_filtered = bus.list_websocket_messages(flow_id=flow_id, include_heartbeats=False)
    assert res_filtered["total"] == 2
    msg_ids = [m["id"] for m in res_filtered["messages"]]
    assert m1 in msg_ids
    assert m4 in msg_ids
    assert m2 not in msg_ids
    assert m3 not in msg_ids

    # 查询 2: 包含心跳 (include_heartbeats=True)
    res_all = bus.list_websocket_messages(flow_id=flow_id, include_heartbeats=True)
    assert res_all["total"] == 4

    # 详情查询
    detail1 = bus.get_websocket_message_detail(m1)
    assert detail1 is not None
    assert detail1["direction"] == "client_to_server"
    assert detail1["opcode_name"] == "TEXT"
    assert "subscribe" in detail1["content"]

    detail4 = bus.get_websocket_message_detail(m4)
    assert detail4 is not None
    assert detail4["is_binary"] is True
    assert detail4["content_length"] == 5


def test_websocket_message_spills_large_payload_to_file(tmp_path: Path) -> None:
    """超过 256KB 的 WebSocket 消息载荷应自动分流落盘至 bodies 目录。"""
    bus = StorageBus(
        db_path=tmp_path / "ws_spill.db",
        bodies_dir=tmp_path / "bodies",
    )
    bus.initialize()

    large_text = "WS_DATA_" * 40000  # 320 KB
    msg_id = bus.record_websocket_message(
        flow_id="flow_large_ws",
        session_id="sess_large",
        timestamp=1700000001.0,
        direction="server_to_client",
        opcode=1,
        opcode_name="TEXT",
        content=large_text,
    )

    detail = bus.get_websocket_message_detail(msg_id, max_body_chars=100)
    assert detail is not None
    assert detail["truncated"] is True
    assert detail["file_path"] is not None
    spilled_path = Path(detail["file_path"])
    assert spilled_path.is_file()
    assert spilled_path.stat().st_size == len(large_text.encode("utf-8"))


def test_traffic_capture_addon_records_websocket_message(tmp_path: Path) -> None:
    """TrafficCaptureAddon.websocket_message 应拦截并持久化 WebSocket 帧。"""
    bus = StorageBus(
        db_path=tmp_path / "addon_ws.db",
        bodies_dir=tmp_path / "bodies",
    )
    bus.initialize()

    addon = TrafficCaptureAddon(storage=bus, session_id="sess_addon_ws")

    # 构造模拟 mitmproxy flow
    mock_msg = SimpleNamespace(
        from_client=True,
        type=1,  # TEXT
        content=b'{"type":"chat","text":"hello"}',
        timestamp=1700000010.5,
    )
    mock_ws = SimpleNamespace(messages=[mock_msg])
    mock_req = SimpleNamespace(pretty_host="chat.example.com", host="chat.example.com")
    mock_flow = SimpleNamespace(id="flow_chat_1", websocket=mock_ws, request=mock_req)

    addon.websocket_message(mock_flow)

    res = bus.list_websocket_messages(flow_id="flow_chat_1")
    assert res["total"] == 1
    assert res["messages"][0]["direction"] == "client_to_server"
    assert "chat" in res["messages"][0]["payload_preview"]


def test_har_exporter_attaches_websocket_messages(tmp_path: Path) -> None:
    """HarExporter 应将 WebSocket 帧组装到 Chrome DevTools _webSocketMessages 结构中。"""
    bus = StorageBus(
        db_path=tmp_path / "har_ws.db",
        bodies_dir=tmp_path / "bodies",
    )
    bus.initialize()

    flow_id = "flow_ws_handshake"
    session_id = "sess_har_ws"

    # 1. 记录 HTTP 握手流 (101 Switching Protocols)
    bus.record_http_flow(
        flow_id=flow_id,
        session_id=session_id,
        timestamp=1700000020.0,
        method="GET",
        scheme="https",
        host="ws.example.com",
        port=443,
        path="/socket",
        status_code=101,
        response_headers={"upgrade": "websocket", "connection": "Upgrade"},
    )

    # 2. 记录一条客户端发送与一条服务端响应的 WebSocket 消息
    bus.record_websocket_message(
        flow_id=flow_id,
        session_id=session_id,
        timestamp=1700000020.1,
        direction="client_to_server",
        opcode=1,
        opcode_name="TEXT",
        content="PING_REQ",
    )
    bus.record_websocket_message(
        flow_id=flow_id,
        session_id=session_id,
        timestamp=1700000020.2,
        direction="server_to_client",
        opcode=1,
        opcode_name="TEXT",
        content="PONG_RESP",
    )

    # 3. 导出 HAR 归档
    exporter = HarExporter(storage=bus)
    har_path = tmp_path / "ws_archive.har"
    exporter.export_session(output_path=har_path, session_id=session_id)

    har_data = json.loads(har_path.read_text(encoding="utf-8"))
    entries = har_data["log"]["entries"]
    assert len(entries) == 1

    entry0 = entries[0]
    assert "_webSocketMessages" in entry0
    ws_msgs = entry0["_webSocketMessages"]
    assert len(ws_msgs) == 2

    assert ws_msgs[0]["type"] == "send"
    assert ws_msgs[0]["data"] == "PING_REQ"
    assert ws_msgs[0]["opcode"] == 1

    assert ws_msgs[1]["type"] == "receive"
    assert ws_msgs[1]["data"] == "PONG_RESP"
    assert ws_msgs[1]["opcode"] == 1


@pytest.mark.asyncio
async def test_websocket_mcp_tools(tmp_path: Path) -> None:
    """FastMCP 应能正常暴露并调用 list_websocket_messages 与 get_websocket_message_detail。"""
    config = parse_config([])
    bus = StorageBus(db_path=tmp_path / "ws_mcp.db", bodies_dir=tmp_path / "bodies")
    bus.initialize()

    msg_id = bus.record_websocket_message(
        flow_id="flow_mcp_ws",
        session_id="sess_mcp",
        timestamp=1700000030.0,
        direction="client_to_server",
        opcode=1,
        opcode_name="TEXT",
        content="mcp_test_payload",
    )

    server = create_mcp_server(config=config, storage=bus)

    # 1. 调用 list_websocket_messages
    _, list_res = await server.call_tool("list_websocket_messages", {"flow_id": "flow_mcp_ws"})
    list_dict = (
        list_res["result"] if isinstance(list_res, dict) and "result" in list_res else list_res
    )
    assert list_dict["total"] == 1
    assert list_dict["messages"][0]["id"] == msg_id

    # 2. 调用 get_websocket_message_detail
    _, detail_res = await server.call_tool("get_websocket_message_detail", {"message_id": msg_id})
    detail_dict = (
        detail_res["result"]
        if isinstance(detail_res, dict) and "result" in detail_res
        else detail_res
    )
    assert detail_dict["id"] == msg_id
    assert detail_dict["content"] == "mcp_test_payload"
