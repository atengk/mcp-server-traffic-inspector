"""InterceptRule 动态拦截规则增删查与代理插件热同步拦截/改写测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_server_traffic_inspector.proxy_addon import TrafficCaptureAddon
from mcp_server_traffic_inspector.storage import StorageBus


@dataclass
class FakeRequest:
    """模拟支持 Header 改写的 mitmproxy 请求对象。"""

    method: str = "GET"
    scheme: str = "https"
    pretty_host: str = "api.example.com"
    port: int = 443
    path: str = "/v1/profile"
    headers: dict[str, str] = field(default_factory=dict)
    raw_content: bytes = b""
    timestamp_start: float = 1700001000.0
    timestamp_end: float = 1700001000.05

    @property
    def pretty_url(self) -> str:
        return f"{self.scheme}://{self.pretty_host}{self.path}"

    def get_content(self, strict: bool = False) -> bytes:
        return self.raw_content


@dataclass
class FakeResponse:
    """模拟支持 Header 改写的 mitmproxy 响应对象。"""

    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    raw_content: bytes = b""
    timestamp_start: float = 1700001000.06
    timestamp_end: float = 1700001000.12

    def get_content(self, strict: bool = False) -> bytes:
        return self.raw_content


@dataclass
class FakeFlow:
    """模拟 mitmproxy HTTPFlow 对象。"""

    id: str
    request: FakeRequest
    response: Any = None
    error: Any = None


def test_intercept_rules_crud_and_targeted_clear(tmp_path: Path) -> None:
    """StorageBus 应支持添加 mock/modify 规则、查询列表（空时返回 []）及按 ID 或全量清理。"""
    bus = StorageBus(
        db_path=tmp_path / "rules.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    assert bus.list_intercept_rules() == []

    r1 = bus.add_intercept_rule(
        url_pattern=r"^https://api\.example\.com/v1/mock.*",
        action="mock",
        mock_status=429,
        mock_headers={"Retry-After": "30"},
        mock_body='{"error": "rate_limited"}',
    )
    r2 = bus.add_intercept_rule(
        url_pattern="*api.example.com/v1/*",
        action="modify",
        modify_request_headers={"X-Injected-Auth": "Bearer token-xyz"},
        modify_response_headers={"X-Proxy-Tag": "intercepted"},
    )

    assert r1["status"] == "active"
    assert r2["action"] == "modify"

    rules = bus.list_intercept_rules()
    assert len(rules) == 2

    # 1. 指定 rule_id 仅删除单条规则
    del_one = bus.clear_intercept_rules(rule_id=r1["rule_id"])
    assert del_one == {"cleared_count": 1, "target_rule_id": r1["rule_id"]}
    remaining = bus.list_intercept_rules()
    assert len(remaining) == 1
    assert remaining[0]["id"] == r2["rule_id"]

    # 2. 不传 rule_id 清空全部剩余规则
    del_all = bus.clear_intercept_rules()
    assert del_all == {"cleared_count": 1, "target_rule_id": None}
    assert bus.list_intercept_rules() == []


def test_proxy_addon_applies_mock_and_modify_rules_dynamically(tmp_path: Path) -> None:
    """代理插件在 request/response 阶段应从 SQLite 热读取规则，执行 Mock 短路返回与 Header 改写。"""
    bus = StorageBus(
        db_path=tmp_path / "addon_rules.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    # 下发一条 Header 改写规则与一条 Mock 短路规则
    bus.add_intercept_rule(
        url_pattern="api.example.com/v1/",
        action="modify",
        modify_request_headers={"X-Custom-Req": "req-modified"},
        modify_response_headers={"X-Custom-Resp": "resp-modified"},
    )
    bus.add_intercept_rule(
        url_pattern=r"https://api\.example\.com/v1/short-circuit",
        action="mock",
        mock_status=503,
        mock_headers={"Content-Type": "application/json", "X-Mocked": "true"},
        mock_body='{"maintenance": true}',
    )

    addon = TrafficCaptureAddon(storage=bus, session_id="sess-rules")

    # 1. 验证 Mock 规则在 request 阶段直接构造响应并应用 modify 规则
    mock_flow = FakeFlow(
        id="flow-mocked",
        request=FakeRequest(
            pretty_host="api.example.com",
            path="/v1/short-circuit",
            headers={"Accept": "*/*"},
        ),
    )
    addon.request(mock_flow)
    assert mock_flow.request.headers["X-Custom-Req"] == "req-modified"
    assert mock_flow.response is not None
    assert mock_flow.response.status_code == 503

    # 触发 response 阶段验证响应头改写与入库
    addon.response(mock_flow)
    detail = bus.get_http_flow_detail("flow-mocked")
    assert detail is not None
    assert detail["status_code"] == 503
    assert detail["request_headers"]["X-Custom-Req"] == "req-modified"
    assert detail["response_headers"]["X-Custom-Resp"] == "resp-modified"
    assert detail["response_headers"]["X-Mocked"] == "true"
    assert detail["response_body"]["preview"] == '{"maintenance": true}'
