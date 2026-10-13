"""HttpFlow 多维检索与 BodyPayload 保真存储/防爆截断/大包分流测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path

from mcp_server_traffic_inspector.storage import StorageBus


def test_record_and_list_http_flows_with_multi_filters(tmp_path: Path) -> None:
    """list_http_flows 应支持按会话、域名、状态码、方法、耗时与排序检索，且不含 Body。"""
    bus = StorageBus(
        db_path=tmp_path / "flows.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    bus.record_http_flow(
        flow_id="flow-1",
        session_id="sess-a",
        timestamp=1700000001.0,
        method="GET",
        scheme="https",
        host="api.example.com",
        port=443,
        path="/v1/users",
        status_code=200,
        duration_ms=45.0,
        request_headers={"Accept": "application/json"},
        response_headers={"Content-Type": "application/json"},
        request_body=b"",
        response_body=b'{"users": []}',
    )
    bus.record_http_flow(
        flow_id="flow-2",
        session_id="sess-a",
        timestamp=1700000002.0,
        method="POST",
        scheme="https",
        host="api.example.com",
        port=443,
        path="/v1/orders",
        status_code=502,
        duration_ms=1250.5,
        request_headers={"Content-Type": "application/json"},
        response_headers={"Content-Type": "text/plain"},
        request_body=b'{"item": 1}',
        response_body=b"Bad Gateway",
    )
    bus.record_http_flow(
        flow_id="flow-3",
        session_id="sess-b",
        timestamp=1700000003.0,
        method="GET",
        scheme="http",
        host="Internal.Local",
        port=8080,
        path="/health",
        status_code=404,
        duration_ms=12.0,
        request_headers={},
        response_headers={},
        request_body=b"",
        response_body=b"Not Found",
    )

    # 1. 按 session_id 过滤
    res_sess_a = bus.list_http_flows(session_id="sess-a")
    assert res_sess_a["total"] == 2
    assert [f["id"] for f in res_sess_a["flows"]] == ["flow-2", "flow-1"]
    assert "request_body" not in res_sess_a["flows"][0]
    assert "response_body" not in res_sess_a["flows"][0]

    # 2. 按 status_family ("5xx") 与 min_duration_ms 过滤
    res_5xx = bus.list_http_flows(status_family="5xx", min_duration_ms=500.0)
    assert res_5xx["total"] == 1
    assert res_5xx["flows"][0]["id"] == "flow-2"

    # 3. 按 method、host 与 status_code 过滤
    res_404 = bus.list_http_flows(host="internal.local", method="get", status_code=404)
    assert res_404["total"] == 1
    assert res_404["flows"][0]["id"] == "flow-3"

    # 4. 按 duration_ms 排序
    res_sorted = bus.list_http_flows(sort_by="duration_ms")
    assert [f["id"] for f in res_sorted["flows"]] == ["flow-2", "flow-1", "flow-3"]

    # 5. 无匹配结果时返回空列表 []
    res_empty = bus.list_http_flows(host="nonexistent.domain")
    assert res_empty["total"] == 0
    assert res_empty["flows"] == []


def test_get_http_flow_detail_truncates_at_2048_and_supports_dump(
    tmp_path: Path,
) -> None:
    """get_http_flow_detail 默认按 2048 字符截断预览，并支持将完整载荷导出为文件。"""
    bus = StorageBus(
        db_path=tmp_path / "detail.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    long_text = "A" * 3000
    bus.record_http_flow(
        flow_id="flow-long",
        session_id="sess-1",
        timestamp=1700000010.0,
        method="POST",
        scheme="https",
        host="api.example.com",
        port=443,
        path="/v1/echo",
        status_code=200,
        duration_ms=88.0,
        request_headers={"X-Trace": "123"},
        response_headers={"Content-Type": "text/plain; charset=utf-8"},
        request_body=b"hello-request",
        response_body=long_text.encode("utf-8"),
    )

    detail = bus.get_http_flow_detail("flow-long", max_body_chars=2048, dump_body_to_file=False)
    assert detail is not None
    assert detail["request_headers"]["X-Trace"] == "123"
    assert detail["request_body"]["preview"] == "hello-request"
    assert detail["request_body"]["truncated"] is False
    assert detail["request_body"]["file_path"] is None

    assert len(detail["response_body"]["preview"]) == 2048
    assert detail["response_body"]["truncated"] is True
    assert detail["response_body"]["size"] == 3000
    assert detail["response_body"]["file_path"] is None

    # 开启 dump_body_to_file=True 时应将完整 3000 字节落盘并返回绝对路径
    dumped = bus.get_http_flow_detail("flow-long", max_body_chars=2048, dump_body_to_file=True)
    assert dumped is not None
    resp_path_str = dumped["response_body"]["file_path"]
    assert resp_path_str is not None
    resp_path = Path(resp_path_str)
    assert resp_path.is_file()
    assert resp_path.read_text(encoding="utf-8") == long_text


def test_record_http_flow_spills_payload_larger_than_256kb_to_file(
    tmp_path: Path,
) -> None:
    """超过 256KB 的 BodyPayload 应自动分流写入本地临时文件并在详情中返回路径。"""
    bus = StorageBus(
        db_path=tmp_path / "large.db",
        bodies_dir=tmp_path / "bodies",
        preserve_db=False,
    )
    bus.initialize()

    large_payload = ("Z" * (300 * 1024)).encode("utf-8")
    bus.record_http_flow(
        flow_id="flow-300k",
        session_id="sess-large",
        timestamp=1700000020.0,
        method="GET",
        scheme="https",
        host="cdn.example.com",
        port=443,
        path="/bundle.js",
        status_code=200,
        duration_ms=210.0,
        request_headers={},
        response_headers={"Content-Type": "application/javascript"},
        request_body=b"",
        response_body=large_payload,
    )

    detail = bus.get_http_flow_detail("flow-300k")
    assert detail is not None
    resp_info = detail["response_body"]
    assert resp_info["size"] == 300 * 1024
    assert resp_info["truncated"] is True
    assert len(resp_info["preview"]) == 2048
    assert resp_info["file_path"] is not None

    spilled_file = Path(resp_info["file_path"])
    assert spilled_file.is_file()
    assert spilled_file.read_bytes() == large_payload
