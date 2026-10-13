"""CaptureSession 生命周期、filter_host 采集过滤、压缩载荷解压与 MCP 工具端到端测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_server_traffic_inspector.capture_manager import HttpCaptureManager
from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.proxy_addon import TrafficCaptureAddon
from mcp_server_traffic_inspector.server import create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


@dataclass
class FakeMitmRequest:
    """模拟 mitmproxy 请求对象。"""

    method: str = "GET"
    scheme: str = "https"
    pretty_host: str = "api.target.com"
    port: int = 443
    path: str = "/v1/data"
    headers: dict[str, str] = field(default_factory=dict)
    raw_content: bytes = b""
    timestamp_start: float = 1700000100.0
    timestamp_end: float = 1700000100.05

    def get_content(self, strict: bool = False) -> bytes:
        if self.headers.get("Content-Encoding") == "gzip":
            return gzip.decompress(self.raw_content)
        return self.raw_content


@dataclass
class FakeMitmResponse:
    """模拟 mitmproxy 响应对象。"""

    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    raw_content: bytes = b""
    timestamp_start: float = 1700000100.10
    timestamp_end: float = 1700000100.25

    def get_content(self, strict: bool = False) -> bytes:
        if self.headers.get("Content-Encoding") == "gzip":
            return gzip.decompress(self.raw_content)
        return self.raw_content


@dataclass
class FakeMitmFlow:
    """模拟 mitmproxy HTTPFlow 对象。"""

    id: str
    request: FakeMitmRequest
    response: FakeMitmResponse | None = None
    error: Any = None


class FakeWorkerProcess:
    """模拟受控 mitmdump 后台工作子进程。"""

    def __init__(self, cmd: list[str], env: dict[str, str]) -> None:
        self.cmd = cmd
        self.env = env
        self._returncode: int | None = None

    def poll(self) -> int | None:
        return self._returncode

    def terminate(self) -> None:
        self._returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        self._returncode = 0
        return 0

    def kill(self) -> None:
        self._returncode = -9


def test_proxy_addon_filters_by_host_and_decompresses_payload(tmp_path: Path) -> None:
    """代理插件在指定 filter_host 时仅入库目标域名流量，并自动解压 gzip 报文载荷。"""
    bus = StorageBus(
        db_path=tmp_path / "addon.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    addon = TrafficCaptureAddon(
        storage=bus,
        session_id="sess-filter",
        filter_host="target.com",
    )

    # 1. 非目标域名流量：插件不拦截修改，但不写入数据库
    ignored_flow = FakeMitmFlow(
        id="flow-ignored",
        request=FakeMitmRequest(pretty_host="other.example.org", path="/ping"),
        response=FakeMitmResponse(status_code=200, raw_content=b"pong"),
    )
    addon.response(ignored_flow)
    assert bus.count_flows(session_id="sess-filter") == 0

    # 2. 匹配目标域名的 gzip 压缩响应流量：应解压后写入 SQLite
    compressed_json = gzip.compress(b'{"message": "decompressed_success"}')
    matched_flow = FakeMitmFlow(
        id="flow-matched",
        request=FakeMitmRequest(
            method="POST",
            pretty_host="sub.target.com",
            path="/v1/submit",
            headers={"Content-Type": "application/json"},
            raw_content=b'{"q": 1}',
        ),
        response=FakeMitmResponse(
            status_code=201,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
            raw_content=compressed_json,
        ),
    )
    addon.response(matched_flow)

    assert bus.count_flows(session_id="sess-filter") == 1
    detail = bus.get_http_flow_detail("flow-matched")
    assert detail is not None
    assert detail["status_code"] == 201
    assert detail["response_body"]["preview"] == '{"message": "decompressed_success"}'


def test_capture_session_lifecycle_and_post_stop_query(tmp_path: Path) -> None:
    """CaptureSession 启停状态流转正常，且停止抓包后历史会话数据依然可查。"""
    bus = StorageBus(
        db_path=tmp_path / "lifecycle.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    spawned: list[FakeWorkerProcess] = []

    def fake_spawner(cmd: list[str], env: dict[str, str]) -> FakeWorkerProcess:
        proc = FakeWorkerProcess(cmd=cmd, env=env)
        spawned.append(proc)
        return proc

    manager = HttpCaptureManager(storage=bus, process_spawner=fake_spawner)

    # 1. 初始未抓包状态
    initial_status = manager.get_status()
    assert initial_status["is_capturing"] is False
    assert initial_status["flow_count"] == 0

    # 2. 启动抓包会话
    start_res = manager.start_capture(
        port=8888,
        listen_host="127.0.0.1",
        filter_host="api.example.com",
        ssl_insecure=True,
    )
    assert start_res["status"] == "running"
    assert start_res["port"] == 8888
    assert start_res["listen_host"] == "127.0.0.1"
    session_id = start_res["session_id"]
    assert session_id.startswith("sess_")
    assert len(spawned) == 1
    assert spawned[0].env["MCP_CAPTURE_SESSION_ID"] == session_id
    assert spawned[0].env["MCP_CAPTURE_FILTER_HOST"] == "api.example.com"

    # 3. 模拟子进程插件向共享 SQLite 写入 2 条流记录
    bus.record_http_flow(
        flow_id="f-101",
        session_id=session_id,
        timestamp=1700000201.0,
        method="GET",
        scheme="https",
        host="api.example.com",
        port=443,
        path="/items/1",
        status_code=200,
        duration_ms=30.0,
        response_body=b'{"id": 1}',
    )
    bus.record_http_flow(
        flow_id="f-102",
        session_id=session_id,
        timestamp=1700000202.0,
        method="GET",
        scheme="https",
        host="api.example.com",
        port=443,
        path="/items/2",
        status_code=200,
        duration_ms=40.0,
        response_body=b'{"id": 2}',
    )

    running_status = manager.get_status()
    assert running_status["is_capturing"] is True
    assert running_status["session_id"] == session_id
    assert running_status["flow_count"] == 2
    assert running_status["uptime_seconds"] >= 0.0

    # 4. 停止抓包会话并验证历史流依然可查
    stop_res = manager.stop_capture()
    assert stop_res["status"] == "stopped"
    assert stop_res["session_id"] == session_id
    assert stop_res["total_captured_flows"] == 2

    stopped_status = manager.get_status()
    assert stopped_status["is_capturing"] is False

    history = bus.list_http_flows(session_id=session_id)
    assert history["total"] == 2


async def test_mcp_server_exposes_five_http_capture_and_query_tools(
    tmp_path: Path,
) -> None:
    """FastMCP 服务应注册并正常调用 5 个 HTTP 抓包生命周期与检索详情工具。"""
    db_file = tmp_path / "mcp_tools.db"
    cfg = parse_config(argv=["--db-path", str(db_file)], env={})
    bus = StorageBus.from_config(cfg)
    manager = HttpCaptureManager(
        storage=bus,
        process_spawner=lambda cmd, env: FakeWorkerProcess(cmd=cmd, env=env),
    )
    mcp = create_mcp_server(config=cfg, storage=bus, capture_manager=manager)

    tools = await mcp.list_tools()
    tool_names = {t.name for t in tools}
    expected_tools = {
        "start_http_capture",
        "stop_http_capture",
        "get_capture_status",
        "list_http_flows",
        "get_http_flow_detail",
    }
    assert expected_tools.issubset(tool_names)

    # 端到端通过 FastMCP call_tool 调用生命周期与检索详情工具
    _, start_data = await mcp.call_tool("start_http_capture", {"port": 18080})
    session_id = start_data["session_id"]
    assert start_data["status"] == "running"

    bus.record_http_flow(
        flow_id="mcp-flow-1",
        session_id=session_id,
        timestamp=1700000300.0,
        method="POST",
        scheme="https",
        host="mcp.example.com",
        port=443,
        path="/v1/chat",
        status_code=200,
        duration_ms=55.5,
        request_headers={"Content-Type": "application/json"},
        response_headers={"Content-Type": "application/json"},
        request_body=b'{"prompt": "hi"}',
        response_body=b'{"reply": "hello"}',
    )

    _, status_data = await mcp.call_tool("get_capture_status", {})
    assert status_data["is_capturing"] is True
    assert status_data["flow_count"] == 1

    _, list_data = await mcp.call_tool("list_http_flows", {"session_id": session_id})
    assert list_data["total"] == 1
    assert list_data["flows"][0]["id"] == "mcp-flow-1"

    _, detail_data = await mcp.call_tool("get_http_flow_detail", {"flow_id": "mcp-flow-1"})
    assert detail_data["response_body"]["preview"] == '{"reply": "hello"}'

    _, stop_data = await mcp.call_tool("stop_http_capture", {})
    assert stop_data["status"] == "stopped"
    assert stop_data["total_captured_flows"] == 1
