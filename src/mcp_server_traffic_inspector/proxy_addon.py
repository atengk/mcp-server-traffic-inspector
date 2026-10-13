"""mitmdump 流量采集插件模块，负责采集过滤、压缩载荷解压与 SQLite WAL 写入。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import gzip
import logging
import os
import time
import zlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from mcp_server_traffic_inspector.config import LOGGER_NAME
from mcp_server_traffic_inspector.storage import StorageBus

logger = logging.getLogger(LOGGER_NAME)


def _matches_filter_host(request_host: str, filter_host: str | None) -> bool:
    if not filter_host or not filter_host.strip():
        return True
    target = filter_host.strip().lower()
    host_lower = (request_host or "").strip().lower()
    if not host_lower:
        return False
    return host_lower == target or host_lower.endswith(f".{target}") or target in host_lower


def _extract_headers_dict(headers_obj: Any) -> dict[str, str]:
    if not headers_obj:
        return {}
    if isinstance(headers_obj, Mapping):
        return {str(k): str(v) for k, v in headers_obj.items()}
    if hasattr(headers_obj, "items"):
        return {str(k): str(v) for k, v in headers_obj.items()}
    return {}


def _extract_decompressed_body(message_obj: Any, headers: Mapping[str, str]) -> bytes:
    if message_obj is None:
        return b""

    if hasattr(message_obj, "get_content"):
        try:
            content = message_obj.get_content(strict=False)
            if content is not None:
                return bytes(content)
        except Exception as exc:
            logger.debug("调用 mitmproxy get_content 解压失败，回退至原始字节: %s", exc)

    raw = getattr(message_obj, "raw_content", None) or getattr(message_obj, "content", None) or b""
    raw_bytes = bytes(raw)
    if not raw_bytes:
        return b""

    encoding = ""
    for k, v in headers.items():
        if k.lower() == "content-encoding" and v:
            encoding = v.strip().lower()
            break

    try:
        if encoding == "gzip":
            return gzip.decompress(raw_bytes)
        if encoding == "deflate":
            return zlib.decompress(raw_bytes)
    except Exception as exc:
        logger.debug("手动解压 %s 载荷失败，保留原始字节: %s", encoding, exc)

    return raw_bytes


def _calculate_duration_ms(request_obj: Any, response_obj: Any) -> float | None:
    req_start = getattr(request_obj, "timestamp_start", None)
    if req_start is None:
        return None
    resp_end = (
        getattr(response_obj, "timestamp_end", None)
        or getattr(response_obj, "timestamp_start", None)
        or getattr(request_obj, "timestamp_end", None)
    )
    if resp_end is None:
        return None
    return round(max(0.0, (float(resp_end) - float(req_start)) * 1000.0), 2)


class TrafficCaptureAddon:
    """挂载于 mitmdump 子进程的 HTTP/HTTPS 流量录制插件。

    根据 filter_host 执行非侵入采集过滤（不阻断非目标流量转发），
    自动解压请求与响应 BodyPayload 并写入共享 SQLite WAL 总线。
    """

    def __init__(
        self,
        storage: StorageBus,
        session_id: str,
        filter_host: str | None = None,
    ) -> None:
        """初始化抓包插件实例。

        Args:
            storage: 指向共享 SQLite WAL 的 StorageBus 实例。
            session_id: 当前抓包会话 CaptureSession 的唯一 ID。
            filter_host: 可选的目标采集域名过滤条件。
        """
        self.storage = storage
        self.session_id = session_id
        self.filter_host = filter_host.strip() if filter_host and filter_host.strip() else None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> TrafficCaptureAddon:
        """从子进程环境变量初始化插件实例。

        Args:
            env: 环境变量映射表，为 None 时默认读取 os.environ。

        Returns:
            绑定了共享数据库与会话配置的 TrafficCaptureAddon 实例。
        """
        env_map = env if env is not None else os.environ
        db_path = Path(env_map["MCP_CAPTURE_DB_PATH"]).resolve()
        bodies_dir = Path(
            env_map.get("MCP_CAPTURE_BODIES_DIR") or db_path.parent / "bodies"
        ).resolve()
        session_id = env_map.get("MCP_CAPTURE_SESSION_ID") or f"sess_{uuid4().hex[:12]}"
        filter_host = env_map.get("MCP_CAPTURE_FILTER_HOST") or None

        storage = StorageBus(db_path=db_path, bodies_dir=bodies_dir, preserve_db=True)
        storage.initialize()
        return cls(storage=storage, session_id=session_id, filter_host=filter_host)

    def _persist_flow(self, flow: Any, has_error: bool = False) -> None:
        req = getattr(flow, "request", None)
        if req is None:
            return

        # 1. 执行 filter_host 采集过滤（非匹配域名直接跳过入库，不影响代理正常转发）
        host = str(getattr(req, "pretty_host", None) or getattr(req, "host", "") or "")
        if not _matches_filter_host(host, self.filter_host):
            return

        # 2. 提取并解压请求与响应头部及 BodyPayload
        resp = getattr(flow, "response", None)
        err = getattr(flow, "error", None)
        flow_id = str(getattr(flow, "id", None) or uuid4().hex)
        timestamp = float(getattr(req, "timestamp_start", None) or time.time())
        method = str(getattr(req, "method", "GET"))
        scheme = str(getattr(req, "scheme", "http"))
        port = int(getattr(req, "port", 443 if scheme == "https" else 80))
        path = str(getattr(req, "path", "/"))

        req_headers = _extract_headers_dict(getattr(req, "headers", None))
        resp_headers = _extract_headers_dict(getattr(resp, "headers", None)) if resp else {}
        req_body = _extract_decompressed_body(req, req_headers)
        resp_body = _extract_decompressed_body(resp, resp_headers) if resp else b""

        status_code = int(getattr(resp, "status_code", 0)) if resp is not None else None
        duration_ms = _calculate_duration_ms(req, resp)
        error_msg = str(getattr(err, "msg", err)) if err is not None else None

        # 3. 写入 SQLite WAL 共享数据总线
        try:
            self.storage.record_http_flow(
                flow_id=flow_id,
                session_id=self.session_id,
                timestamp=timestamp,
                method=method,
                scheme=scheme,
                host=host,
                port=port,
                path=path,
                status_code=status_code,
                duration_ms=duration_ms,
                request_headers=req_headers,
                response_headers=resp_headers,
                request_body=req_body,
                response_body=resp_body,
                has_error=has_error or (err is not None),
                error_message=error_msg,
            )
        except Exception as exc:
            logger.warning("写入 HttpFlow (%s) 至 SQLite 失败: %s", flow_id, exc)

    def response(self, flow: Any) -> None:
        """mitmproxy 响应完成事件钩子。

        Args:
            flow: mitmproxy HTTPFlow 实例。
        """
        self._persist_flow(flow, has_error=False)

    def error(self, flow: Any) -> None:
        """mitmproxy 请求/响应发生传输错误事件钩子。

        Args:
            flow: mitmproxy HTTPFlow 实例。
        """
        self._persist_flow(flow, has_error=True)


addons: list[TrafficCaptureAddon] = (
    [TrafficCaptureAddon.from_env()] if os.environ.get("MCP_CAPTURE_DB_PATH") else []
)
