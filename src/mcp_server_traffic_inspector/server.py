"""FastMCP 服务主控底座与进程生命周期清理编排模块。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from mcp_server_traffic_inspector.config import LOGGER_NAME, ServerConfig
from mcp_server_traffic_inspector.storage import StorageBus

logger = logging.getLogger(LOGGER_NAME)

SERVER_NAME = "mcp-server-traffic-inspector"
SERVER_INSTRUCTIONS = (
    "全栈网络流量巡检与抓包 MCP Server。"
    "支持 HTTP/HTTPS 代理抓包会话 (CaptureSession)、流量检索 (HttpFlow)、"
    "报文载荷预览与转储 (BodyPayload)、非阻塞规则拦截 (InterceptRule)、"
    "请求变异重放 (FlowReplay)、网卡/离线 PCAP 协议分析 (PcapCapture) "
    "及智能根因诊断 (SessionDiagnosis)。"
)


class LifecycleManager:
    """主控进程退出钩子管理器，负责按逆序安全回收子进程、系统代理与临时存储。"""

    def __init__(self) -> None:
        self._callbacks: list[Callable[[], None]] = []
        self._cleaned_up = False

    def register(self, callback: Callable[[], None]) -> None:
        """注册退出清理回调函数。

        Args:
            callback: 无参清理回调，将在服务终止时按后进先出顺序执行。
        """
        self._callbacks.append(callback)

    def run_cleanup(self) -> None:
        """幂等执行全部已注册的清理回调，单项异常不中断后续回收流程。"""
        if self._cleaned_up:
            return
        self._cleaned_up = True

        for callback in reversed(self._callbacks):
            try:
                callback()
            except Exception as exc:
                logger.warning("执行退出清理回调时发生异常: %s", exc)


def create_mcp_server(
    config: ServerConfig,
    storage: StorageBus | None = None,
) -> FastMCP:
    """构建并初始化 FastMCP 服务实例与共享 SQLite WAL 数据总线。

    Args:
        config: 服务端运行配置对象。
        storage: 可选的外部 StorageBus 实例；未传入时根据 config 自动构建并初始化。

    Returns:
        初始化完成的 FastMCP 服务对象。
    """
    # 1. 初始化共享 SQLite WAL 数据总线
    bus = storage or StorageBus.from_config(config)
    bus.initialize()

    # 2. 创建并配置 FastMCP 主控实例
    mcp = FastMCP(
        name=SERVER_NAME,
        instructions=SERVER_INSTRUCTIONS,
        host=config.host,
        port=config.port,
        log_level=config.log_level,
    )
    return mcp
