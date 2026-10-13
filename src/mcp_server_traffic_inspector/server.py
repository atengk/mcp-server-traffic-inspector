"""FastMCP 服务主控底座、MCP 工具注册与进程生命周期清理编排模块。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_server_traffic_inspector.capture_manager import HttpCaptureManager
from mcp_server_traffic_inspector.config import LOGGER_NAME, ServerConfig
from mcp_server_traffic_inspector.diagnostics import NetworkDiagnostics
from mcp_server_traffic_inspector.pcap import PcapCaptureManager
from mcp_server_traffic_inspector.replay import FlowReplayEngine
from mcp_server_traffic_inspector.storage import DEFAULT_PREVIEW_CHARS, StorageBus

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


def _register_http_tools(
    mcp: FastMCP,
    storage: StorageBus,
    manager: HttpCaptureManager,
) -> None:
    @mcp.tool()
    def start_http_capture(
        port: int = 8080,
        listen_host: str = "0.0.0.0",
        filter_host: str | None = None,
        ssl_insecure: bool = True,
    ) -> dict[str, Any]:
        """启动受控 mitmdump 后台代理会话 (CaptureSession) 捕获 HTTP/HTTPS 流量。

        Args:
            port: 代理监听端口，默认 8080。
            listen_host: 代理监听地址，默认 "0.0.0.0"。
            filter_host: 可选的目标采集域名（非目标域名正常转发，仅目标域名写入数据库）。
            ssl_insecure: 是否忽略上游服务端 TLS 证书错误，默认 True。

        Returns:
            包含运行状态、监听地址端口、session_id、数据库路径与 CA 证书路径的字典。
        """
        return manager.start_capture(
            port=port,
            listen_host=listen_host,
            filter_host=filter_host,
            ssl_insecure=ssl_insecure,
        )

    @mcp.tool()
    def stop_http_capture() -> dict[str, Any]:
        """停止当前正在运行的 HTTP/HTTPS 抓包代理会话并返回捕获统计。

        Returns:
            包含 status ("stopped")、session_id 与 total_captured_flows 的字典。
        """
        return manager.stop_capture()

    @mcp.tool()
    def get_capture_status() -> dict[str, Any]:
        """查询当前 HTTP 抓包代理运行状态、会话 ID、已捕获流数量与运行时长。

        Returns:
            包含 is_capturing、listen_host、port、session_id、flow_count 与 uptime_seconds 的字典。
        """
        return manager.get_status()

    @mcp.tool()
    def list_http_flows(
        limit: int = 20,
        offset: int = 0,
        session_id: str | None = None,
        host: str | None = None,
        status_code: int | None = None,
        status_family: str | None = None,
        method: str | None = None,
        min_duration_ms: float | None = None,
        sort_by: str = "timestamp",
    ) -> dict[str, Any]:
        """按多维条件分页检索已捕获的 HttpFlow 轻量元数据列表（不含 BodyPayload）。

        Args:
            limit: 单页返回最大条数，默认 20。
            offset: 分页起始偏移量，默认 0。
            session_id: 可选抓包会话 ID；未指定时检索全部已录制会话。
            host: 按目标域名子串过滤（不区分大小写）。
            status_code: 按精确 HTTP 状态码过滤。
            status_family: 按状态码族过滤（可选: 2xx, 3xx, 4xx, 5xx, error）。
            method: 按 HTTP 方法过滤（如 GET、POST）。
            min_duration_ms: 按最小请求耗时（毫秒）过滤慢请求。
            sort_by: 排序字段（timestamp、duration_ms、size）。

        Returns:
            包含 total、session_id 与 flows 列表的字典；无匹配数据时 flows 返回 []。
        """
        return storage.list_http_flows(
            limit=limit,
            offset=offset,
            session_id=session_id,
            host=host,
            status_code=status_code,
            status_family=status_family,
            method=method,
            min_duration_ms=min_duration_ms,
            sort_by=sort_by,
        )

    @mcp.tool()
    def get_http_flow_detail(
        flow_id: str,
        include_headers: bool = True,
        include_body: bool = True,
        max_body_chars: int = DEFAULT_PREVIEW_CHARS,
        dump_body_to_file: bool = False,
    ) -> dict[str, Any]:
        """查询单条 HttpFlow 的完整请求/响应头与截断预览 BodyPayload，支持导出完整载荷文件。

        Args:
            flow_id: 目标 HttpFlow 的唯一 ID。
            include_headers: 是否包含请求与响应 Headers，默认 True。
            include_body: 是否包含请求与响应 BodyPayload 预览，默认 True。
            max_body_chars: 文本载荷预览最大截断字符数，默认 2048。
            dump_body_to_file: 是否将完整原始载荷写出为本地文件并返回绝对路径，默认 False。

        Returns:
            包含请求行、状态码、耗时、Headers、截断预览与文件路径的详情字典。

        Raises:
            ValueError: 当指定的 flow_id 不存在时抛出。
        """
        detail = storage.get_http_flow_detail(
            flow_id,
            include_headers=include_headers,
            include_body=include_body,
            max_body_chars=max_body_chars,
            dump_body_to_file=dump_body_to_file,
        )
        if detail is None:
            raise ValueError(f"未找到指定的 HttpFlow 记录: {flow_id}")
        return detail


def _register_manipulation_tools(
    mcp: FastMCP,
    storage: StorageBus,
    replay_engine: FlowReplayEngine,
) -> None:
    @mcp.tool()
    async def replay_http_request(
        flow_id: str,
        modify_headers: dict[str, str] | None = None,
        modify_body: str | dict[str, Any] | list[Any] | None = None,
        modify_url: str | None = None,
    ) -> dict[str, Any]:
        """基于已捕获的历史 HttpFlow 执行参数变异重放 (FlowReplay)，并对比新旧响应差异。

        Args:
            flow_id: 待重放的历史 HttpFlow 唯一 ID。
            modify_headers: 可选的覆盖或新增请求头字典。
            modify_body: 可选的覆盖请求体文本；不传时使用存储层完整无损的原始请求体。
            modify_url: 可选的覆盖目标 URL；不传时使用原请求 URL。

        Returns:
            包含原响应摘要、新响应摘要及状态码、耗时与正文 Diff 预览的结构化对比字典。
        """
        return await replay_engine.replay(
            flow_id=flow_id,
            modify_headers=modify_headers,
            modify_body=modify_body,
            modify_url=modify_url,
        )

    @mcp.tool()
    def add_intercept_rule(
        url_pattern: str,
        action: str = "mock",
        mock_status: int = 200,
        mock_headers: dict[str, str] | None = None,
        mock_body: str | dict[str, Any] | list[Any] | None = None,
        modify_request_headers: dict[str, str] | None = None,
        modify_response_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """新增一条非阻塞动态拦截规则 (InterceptRule)，支持 Mock 短路返回与 Header 动态改写。

        Args:
            url_pattern: 目标 URL 匹配模式（支持正则、通配符或子串）。
            action: 规则动作，可选 'mock' 或 'modify'，默认 'mock'。
            mock_status: 当 action='mock' 时返回的状态码，默认 200。
            mock_headers: 当 action='mock' 时返回的自定义响应头。
            mock_body: 当 action='mock' 时返回的响应正文。
            modify_request_headers: 转发前注入或改写的请求头。
            modify_response_headers: 返回前注入或改写的响应头。

        Returns:
            包含 rule_id、action、url_pattern 与 status ("active") 的字典。
        """
        return storage.add_intercept_rule(
            url_pattern=url_pattern,
            action=action,
            mock_status=mock_status,
            mock_headers=mock_headers,
            mock_body=mock_body,
            modify_request_headers=modify_request_headers,
            modify_response_headers=modify_response_headers,
        )

    @mcp.tool()
    def list_intercept_rules() -> list[dict[str, Any]]:
        """查看当前配置的全部动态拦截与改写规则 (InterceptRule)。

        Returns:
            拦截规则字典列表；无规则时固定返回 []。
        """
        return storage.list_intercept_rules()

    @mcp.tool()
    def clear_intercept_rules(rule_id: str | None = None) -> dict[str, Any]:
        """清空全部动态拦截规则，或按指定 rule_id 移除单条规则。

        Args:
            rule_id: 可选的目标规则 ID；为空时清空全部规则。

        Returns:
            包含 cleared_count 与 target_rule_id 的清理结果字典。
        """
        return storage.clear_intercept_rules(rule_id=rule_id)


def _register_pcap_tools(
    mcp: FastMCP,
    pcap_manager: PcapCaptureManager,
) -> None:
    @mcp.tool()
    def list_network_interfaces() -> list[dict[str, Any]]:
        """枚举当前主机可用于抓包的网络接口列表。

        Returns:
            包含 index、name 与 description 的网卡列表；未安装 tshark 或无网卡时返回 []。
        """
        return pcap_manager.list_interfaces()

    @mcp.tool()
    def start_pcap_capture(
        interface: int | str = 1,
        output_path: str | None = None,
        bpf_filter: str | None = None,
        max_packets: int = 2000,
        duration_seconds: int = 60,
    ) -> dict[str, Any]:
        """在指定网卡上启动原始网络层数据包捕获 (PcapCapture)，受双重熔断阈值保护。

        Args:
            interface: 网卡索引或名称，默认 1。
            output_path: 保存目标 .pcap 文件绝对路径；为空时自动生成。
            bpf_filter: 可选的 Berkeley Packet Filter 表达式（如 'tcp and port 443'）。
            max_packets: 最大抓包数熔断上限，默认 2000 包。
            duration_seconds: 最大抓包时长熔断上限，默认 60 秒。

        Returns:
            包含状态、网卡、产出文件绝对路径与熔断限制的字典。
        """
        return pcap_manager.start_capture(
            interface=interface,
            output_path=output_path,
            bpf_filter=bpf_filter,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        )

    @mcp.tool()
    def stop_pcap_capture() -> dict[str, Any]:
        """停止当前正在运行的实时 PCAP 网卡抓包任务并返回数据包统计。

        Returns:
            包含 status ("stopped")、pcap_file 与 packet_count 的字典。
        """
        return pcap_manager.stop_capture()

    @mcp.tool()
    def analyze_pcap_file(
        file_path: str,
        display_filter: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """调用 tshark 对离线 .pcap/.pcapng 报文执行协议分布、TCP 重传率与 DNS 深度分析。

        Args:
            file_path: 本地 .pcap / .pcapng 文件路径。
            display_filter: 可选的 Wireshark Display Filter 过滤表达式。
            limit: 分析的最大报文上限数，默认 50。

        Returns:
            包含总报文数、协议占比、TCP 质量指标与 DNS 统计的诊断字典。
        """
        return pcap_manager.analyze_pcap(
            file_path=file_path,
            display_filter=display_filter,
            limit=limit,
        )


def _register_diagnostic_tools(
    mcp: FastMCP,
    diagnostics: NetworkDiagnostics,
) -> None:
    @mcp.tool()
    def analyze_http_traffic(
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """统计慢请求 Top 5、状态码分布、高频端点 Top 10 与总吞吐流量。

        Args:
            session_id: 可选的目标抓包会话 ID；未提供时默认统计最近一次抓包会话。

        Returns:
            包含慢请求排行、错误分布、高频端点及大报文消耗的聚合统计字典。
        """
        return diagnostics.analyze_http_traffic(session_id=session_id)

    @mcp.tool()
    def diagnose_network_session(
        session_type: str = "http",
        target: str | None = None,
    ) -> dict[str, Any]:
        """对 HTTP 流量或 PCAP 报文生成结构化健康度评分、异常项与根因诊断报告。

        Args:
            session_type: 诊断类型，可选 'http' 或 'pcap'，默认 'http'。
            target: 当 session_type='http' 时为可选 session_id；当 'pcap' 时为必填文件路径。

        Returns:
            包含健康度评分、健康状态、异常清单与排障建议的诊断报告。
        """
        return diagnostics.diagnose_network_session(
            session_type=session_type,
            target=target,
        )


def create_mcp_server(
    config: ServerConfig,
    storage: StorageBus | None = None,
    capture_manager: HttpCaptureManager | None = None,
    replay_engine: FlowReplayEngine | None = None,
    pcap_manager: PcapCaptureManager | None = None,
    diagnostics: NetworkDiagnostics | None = None,
    lifecycle: LifecycleManager | None = None,
) -> FastMCP:
    """构建并初始化 FastMCP 服务实例、共享 SQLite WAL 数据总线与 MCP 工具集。

    Args:
        config: 服务端运行配置对象。
        storage: 可选的外部 StorageBus 实例；未传入时根据 config 自动构建并初始化。
        capture_manager: 可选的外部 HttpCaptureManager 实例。
        replay_engine: 可选的外部 FlowReplayEngine 实例。
        pcap_manager: 可选的外部 PcapCaptureManager 实例。
        diagnostics: 可选的外部 NetworkDiagnostics 实例。
        lifecycle: 可选的生命周期管理器；传入时自动注册子进程停止钩子。

    Returns:
        完成工具注册的 FastMCP 服务对象。
    """
    # 1. 初始化共享 SQLite WAL 数据总线与核心业务管理器
    bus = storage or StorageBus.from_config(config)
    bus.initialize()
    manager = capture_manager or HttpCaptureManager(storage=bus)
    replayer = replay_engine or FlowReplayEngine(storage=bus)
    pcap_mgr = pcap_manager or PcapCaptureManager(tshark_path=config.tshark_path)
    diag_engine = diagnostics or NetworkDiagnostics(storage=bus, pcap_manager=pcap_mgr)

    if lifecycle is not None:
        lifecycle.register(lambda: None if manager.stop_capture() else None)
        lifecycle.register(lambda: None if pcap_mgr.stop_capture() else None)

    # 2. 创建 FastMCP 主控实例并注册各领域工具集
    mcp = FastMCP(
        name=SERVER_NAME,
        instructions=SERVER_INSTRUCTIONS,
        host=config.host,
        port=config.port,
        log_level=config.log_level,
    )
    _register_http_tools(mcp=mcp, storage=bus, manager=manager)
    _register_manipulation_tools(mcp=mcp, storage=bus, replay_engine=replayer)
    _register_pcap_tools(mcp=mcp, pcap_manager=pcap_mgr)
    _register_diagnostic_tools(mcp=mcp, diagnostics=diag_engine)
    return mcp
