"""网络层 (L3/L4) 网卡枚举、安全熔断实时抓包 (PcapCapture) 与离线协议深度分析模块。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from mcp_server_traffic_inspector.capture_manager import WorkerProcessProtocol
from mcp_server_traffic_inspector.config import LOGGER_NAME
from mcp_server_traffic_inspector.doctor import resolve_tshark_path
from mcp_server_traffic_inspector.pcap_slicer import (
    CaptureSidecar,
    build_slice_display_filter,
    slice_pcap_file,
)
from mcp_server_traffic_inspector.process_tracker import (
    ProcessFamilyTracker,
    ProcessInfo,
    SocketEntry,
)

logger = logging.getLogger(LOGGER_NAME)

KNOWN_PROTOCOLS = (
    "TCP",
    "UDP",
    "DNS",
    "TLS",
    "HTTP",
    "HTTPS",
    "ICMP",
    "ARP",
    "DHCP",
    "SSH",
    "QUIC",
    "FTP",
    "SMTP",
)


def parse_interface_list(tshark_output: str) -> list[dict[str, Any]]:
    """解析 tshark -D 标准输出为结构化网卡列表。

    Args:
        tshark_output: tshark -D 命令输出的纯文本内容。

    Returns:
        网卡字典列表；无匹配时返回空列表 []。
    """
    if not tshark_output or not tshark_output.strip():
        return []

    interfaces: list[dict[str, Any]] = []
    line_pattern = re.compile(r"^(\d+)\.\s+([^\s(]+(?:\s+[^\s(]+)*)(?:\s+\((.*)\))?$")

    for raw_line in tshark_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = line_pattern.match(line)
        if match:
            idx_str, name, desc = match.groups()
            interfaces.append(
                {
                    "index": int(idx_str),
                    "name": name.strip(),
                    "description": desc.strip() if desc else name.strip(),
                }
            )

    return interfaces


def parse_tshark_fields_output(
    tsv_lines: Sequence[str],
    file_path: str,
    total_packets: int | None = None,
) -> dict[str, Any]:
    """解析 tshark -T fields 报文提取字段为聚合网络指标。

    提取协议分布、TCP 重传率、RTT 往返时延（极值与均值）及 DNS 解析指标。

    Args:
        tsv_lines: 制表符分隔的 tshark 提取字段文本行序列。
        file_path: 目标 PCAP 文件路径。
        total_packets: 可选的文件内总数据包数；为 None 时以 tsv_lines 行数计量。

    Returns:
        包含协议占比、TCP 质量与 DNS 统计的结构化字典。
    """
    proto_counts: dict[str, int] = {}
    total_tcp = 0
    retrans_tcp = 0
    rtt_list_ms: list[float] = []

    dns_queries = 0
    dns_responses = 0
    dns_failures = 0
    dns_durations_ms: list[float] = []

    analyzed_count = 0

    for raw_line in tsv_lines:
        line = raw_line.strip()
        if not line:
            continue
        analyzed_count += 1
        cols = line.split("\t")
        while len(cols) < 7:
            cols.append("")

        _frame_num, proto_str, retrans_str, rtt_str, dns_resp_str, dns_rcode_str, dns_time_str = (
            cols[:7]
        )

        # 1. 统计协议分布
        proto_tokens = [t.upper() for t in proto_str.split(":") if t]
        matched_protos = set()
        for token in proto_tokens:
            for known in KNOWN_PROTOCOLS:
                if known in token:
                    matched_protos.add(known)
        for p in matched_protos:
            proto_counts[p] = proto_counts.get(p, 0) + 1

        # 2. 统计 TCP 重传与 ACK RTT 时延
        if "TCP" in matched_protos or "tcp" in proto_str.lower():
            total_tcp += 1
            if retrans_str and retrans_str.strip() == "1":
                retrans_tcp += 1
            if rtt_str and rtt_str.strip():
                try:
                    rtt_sec = float(rtt_str.strip().split(",")[0])
                    if rtt_sec >= 0.0:
                        rtt_list_ms.append(round(rtt_sec * 1000.0, 2))
                except ValueError:
                    pass

        # 3. 统计 DNS 请求、响应、异常状态码及响应耗时
        if "DNS" in matched_protos or "dns" in proto_str.lower():
            if dns_resp_str and dns_resp_str.strip() == "1":
                dns_responses += 1
                if dns_rcode_str and dns_rcode_str.strip():
                    try:
                        rcode = int(dns_rcode_str.strip().split(",")[0])
                        if rcode != 0:
                            dns_failures += 1
                    except ValueError:
                        pass
                if dns_time_str and dns_time_str.strip():
                    try:
                        d_time = float(dns_time_str.strip().split(",")[0])
                        if d_time >= 0.0:
                            dns_durations_ms.append(round(d_time * 1000.0, 2))
                    except ValueError:
                        pass
            elif dns_resp_str and dns_resp_str.strip() == "0":
                dns_queries += 1

    packet_total = total_packets if total_packets is not None else analyzed_count
    retrans_rate = round((retrans_tcp / total_tcp) * 100.0, 2) if total_tcp > 0 else 0.0

    rtt_stats: dict[str, float | None] = {
        "min": min(rtt_list_ms) if rtt_list_ms else None,
        "max": max(rtt_list_ms) if rtt_list_ms else None,
        "avg": round(sum(rtt_list_ms) / len(rtt_list_ms), 2) if rtt_list_ms else None,
    }

    avg_dns_ms = (
        round(sum(dns_durations_ms) / len(dns_durations_ms), 2) if dns_durations_ms else None
    )

    return {
        "file_path": file_path,
        "total_packets": packet_total,
        "analyzed_packets": analyzed_count,
        "protocol_distribution": dict(
            sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)
        ),
        "tcp_analysis": {
            "total_tcp_packets": total_tcp,
            "retransmission_packets": retrans_tcp,
            "retransmission_rate_pct": retrans_rate,
            "rtt_ms": rtt_stats,
        },
        "dns_analysis": {
            "query_count": dns_queries,
            "response_count": dns_responses,
            "failed_count": dns_failures,
            "avg_duration_ms": avg_dns_ms,
        },
    }


def _default_spawner(cmd: list[str], env: dict[str, str]) -> WorkerProcessProtocol:
    return subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
    )


class PcapCaptureManager:
    """管理原始网络层报文捕获 (PcapCapture) 与离线 PCAP 协议分析。"""

    def __init__(
        self,
        tshark_path: str | None = None,
        command_runner: Callable[[list[str]], str] | None = None,
        process_spawner: Callable[[list[str], dict[str, str]], WorkerProcessProtocol] | None = None,
        default_output_dir: Path | None = None,
        snapshot_fetcher: Callable[[], list[ProcessInfo]] | None = None,
        socket_fetcher: Callable[[], list[SocketEntry]] | None = None,
    ) -> None:
        """初始化 PCAP 捕获与分析管理器。

        Args:
            tshark_path: 显式指定的 tshark 可执行文件路径。
            command_runner: 可选的同步命令执行器（供测试注入），默认调用 subprocess.run。
            process_spawner: 可选的子进程启动器函数（供测试注入），默认调用 subprocess.Popen。
            default_output_dir: 默认抓包产出文件保存目录，为 None 时使用系统临时目录。
            snapshot_fetcher: 可选的进程快照获取器函数（供测试注入）。
            socket_fetcher: 可选的活跃套接字获取器函数（供测试注入）。
        """
        self._explicit_path = tshark_path
        self._runner = command_runner or self._run_command_sync
        self._spawner = process_spawner or _default_spawner
        self._default_dir = (default_output_dir or Path(tempfile.gettempdir())).resolve()
        self._snapshot_fetcher = snapshot_fetcher
        self._socket_fetcher = socket_fetcher

        self._process: WorkerProcessProtocol | None = None
        self._active_output_file: str | None = None
        self._active_interface: int | str | None = None
        self._started_at: float | None = None

        # 进程感知抓包状态
        self._active_tracker: ProcessFamilyTracker | None = None
        self._is_process_capture: bool = False
        self._active_final_target: Path | None = None
        self._active_keep_raw: bool = False

    def _run_command_sync(self, cmd: list[str]) -> str:
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30.0,
                check=False,
            )
            return completed.stdout or ""
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
            logger.warning("执行 tshark 命令失败 (%s): %s", cmd, exc)
            return ""

    def _resolve_binary(self) -> Path:
        resolved = resolve_tshark_path(self._explicit_path)
        if resolved is None:
            raise RuntimeError(
                "未检测到 tshark 可执行文件，无法执行 PCAP 相关操作。"
                "请安装 Wireshark/tshark 或配置 --tshark-path。"
            )
        return resolved

    def list_interfaces(self) -> list[dict[str, Any]]:
        """枚举当前主机可用的网络抓包接口列表。

        Returns:
            包含接口索引、名称与描述的列表；未检测到 tshark 或无网卡时返回空列表 []。
        """
        try:
            tshark_bin = self._resolve_binary()
        except RuntimeError:
            return []

        cmd = [str(tshark_bin), "-D"]
        output = self._runner(cmd)
        return parse_interface_list(output)

    def start_capture(
        self,
        *,
        interface: int | str = 1,
        output_path: str | None = None,
        bpf_filter: str | None = None,
        max_packets: int = 2000,
        duration_seconds: int = 60,
        process_path: str | None = None,
        process_name: str | None = None,
        target_pids: list[int] | None = None,
        include_child_processes: bool = True,
        keep_raw_pcap: bool = False,
    ) -> dict[str, Any]:
        """在指定网卡启动带双重安全熔断阈值的原始报文捕获 (PcapCapture)。

        支持基于进程路径、进程名称或显式 PID 家族树追踪与后处理时空切片。

        Args:
            interface: 网卡索引或名称，默认 1。
            output_path: 保存目标 .pcap 绝对路径；为空时自动生成于系统临时目录。
            bpf_filter: 可选的 BPF 抓包过滤表达式（如 'tcp port 80'）。
            max_packets: 最大抓包数熔断上限，默认 2000 包。
            duration_seconds: 最大抓包时长熔断上限，默认 60 秒。
            process_path: 可选的目标可执行文件绝对路径。
            process_name: 可选的目标进程名称通配符（如 'Weixin*.exe'）。
            target_pids: 可选的显式指定目标 PID 列表。
            include_child_processes: 是否递归追踪目标进程的所有派生子进程，默认 True。
            keep_raw_pcap: 是否保留全量中间抓包文件，默认 False（自动清理）。

        Returns:
            包含 status、interface、output_file、limits 及 process_filter 的字典。
        """
        # 1. 若已有运行中的实时抓包子进程，先执行安全停止
        if self._process is not None and self._process.poll() is None:
            self.stop_capture()

        # 2. 校验并组装输出文件绝对路径
        tshark_bin = self._resolve_binary()
        if output_path and output_path.strip():
            target_path = Path(output_path.strip()).expanduser().resolve()
        else:
            ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_path = (
                self._default_dir / f"pcap_capture_{ts_str}_{uuid4().hex[:6]}.pcap"
            ).resolve()

        target_path.parent.mkdir(parents=True, exist_ok=True)

        is_process_mode = bool(process_path or process_name or target_pids)
        self._is_process_capture = is_process_mode
        self._active_final_target = target_path
        self._active_keep_raw = keep_raw_pcap

        # 在进程抓包模式下，底层 tshark 捕获到中间原始文件
        capture_file = (
            target_path.parent / f"raw_{target_path.name}" if is_process_mode else target_path
        )

        if is_process_mode:
            self._active_tracker = ProcessFamilyTracker(
                process_path=process_path,
                process_name=process_name,
                target_pids=target_pids,
                include_child_processes=include_child_processes,
                poll_interval=0.1,
                snapshot_fetcher=self._snapshot_fetcher,
                socket_fetcher=self._socket_fetcher,
            )
            self._active_tracker.start()

        # 3. 构建并启动实施双重安全熔断的 tshark 子进程
        cmd = [
            str(tshark_bin),
            "-i",
            str(interface),
            "-w",
            str(capture_file),
            "-c",
            str(max(1, int(max_packets))),
            "-a",
            f"duration:{max(1, int(duration_seconds))}",
            "-q",
        ]
        if bpf_filter and bpf_filter.strip():
            cmd.extend(["-f", bpf_filter.strip()])

        self._process = self._spawner(cmd, dict(os.environ))
        self._active_output_file = str(capture_file)
        self._active_interface = interface
        self._started_at = time.monotonic()

        result: dict[str, Any] = {
            "status": "capturing",
            "interface": interface,
            "output_file": str(target_path),
            "limits": {
                "max_packets": int(max_packets),
                "duration_seconds": int(duration_seconds),
            },
        }
        if is_process_mode:
            result["process_filter"] = {
                "process_path": process_path,
                "process_name": process_name,
                "target_pids": target_pids,
                "include_child_processes": include_child_processes,
            }

        return result

    def stop_capture(self) -> dict[str, Any]:
        """优雅停止当前正在运行的实时 PCAP 抓包子进程，并执行切片与元数据落盘。

        Returns:
            包含 status ("stopped")、pcap_file 路径、packet_count 及拓扑元数据的字典。
        """
        # 1. 安全终止 tshark 子进程
        proc = self._process
        self._process = None
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception as exc:
                logger.warning("终止 tshark 实时抓包子进程异常: %s", exc)

        raw_capture_file = self._active_output_file
        final_target = self._active_final_target
        is_process_mode = self._is_process_capture
        tracker = self._active_tracker
        keep_raw = self._active_keep_raw

        self._active_output_file = None
        self._active_interface = None
        self._started_at = None
        self._active_tracker = None
        self._is_process_capture = False
        self._active_final_target = None
        self._active_keep_raw = False

        process_summary: dict[str, Any] | None = None
        server_topology: list[dict[str, Any]] = []

        # 2. 若启用了进程感知模式，执行时空切片并保存 Sidecar
        if is_process_mode and tracker is not None and final_target is not None:
            family, timeline = tracker.stop()
            process_summary = family.to_dict()
            server_topology = timeline.export_server_topology(family.all_pids)

            ports = timeline.get_active_ports(family.all_pids)
            display_filter = build_slice_display_filter(ports)

            if raw_capture_file and Path(raw_capture_file).is_file():
                try:
                    tshark_bin = self._resolve_binary()
                    slice_pcap_file(
                        raw_pcap_path=raw_capture_file,
                        target_pcap_path=final_target,
                        display_filter=display_filter,
                        tshark_bin=tshark_bin,
                        runner=self._runner,
                        keep_raw_pcap=keep_raw,
                    )
                except Exception as exc:
                    logger.warning("执行 PCAP 时空切片异常: %s", exc)

            CaptureSidecar.save(
                pcap_path=final_target,
                process_family=family,
                timeline=timeline,
            )
            pcap_file = str(final_target)
        else:
            pcap_file = raw_capture_file

        # 3. 统计最终切片文件的报文数量
        packet_count = 0
        if pcap_file and Path(pcap_file).is_file():
            try:
                tshark_bin = self._resolve_binary()
                count_out = self._runner(
                    [str(tshark_bin), "-r", str(pcap_file), "-T", "fields", "-e", "frame.number"]
                )
                packet_count = len([line for line in count_out.splitlines() if line.strip()])
            except Exception as exc:
                logger.debug("统计 PCAP 文件包数失败: %s", exc)

        res: dict[str, Any] = {
            "status": "stopped",
            "pcap_file": pcap_file,
            "packet_count": packet_count,
        }
        if is_process_mode:
            res["process_summary"] = process_summary
            res["server_topology"] = server_topology

        return res

    def analyze_pcap(
        self,
        file_path: str,
        display_filter: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """对指定的离线 .pcap / .pcapng 文件执行深度协议、TCP 重传与 DNS 质量分析。

        Args:
            file_path: 目标 PCAP 本地文件路径。
            display_filter: 可选的 Wireshark Display Filter 过滤表达式（如 'tcp' 或 'dns'）。
            limit: 分析的最大报文上限数，默认 50。

        Returns:
            包含协议分布、TCP 质量指标与 DNS 统计的结构化字典。

        Raises:
            ValueError: 当指定文件不存在时抛出。
            RuntimeError: 当 tshark 引擎不可用时抛出。
        """
        # 1. 验证目标文件有效性与 tshark 可用性
        path_obj = Path(file_path.strip()).expanduser().resolve()
        if not path_obj.is_file():
            raise ValueError(f"PCAP 文件不存在: {file_path}")

        tshark_bin = self._resolve_binary()

        # 2. 执行 tshark -T fields 字段提取
        cmd = [
            str(tshark_bin),
            "-r",
            str(path_obj),
            "-c",
            str(max(1, int(limit))),
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.protocols",
            "-e",
            "tcp.analysis.retransmission",
            "-e",
            "tcp.analysis.ack_rtt",
            "-e",
            "dns.flags.response",
            "-e",
            "dns.flags.rcode",
            "-e",
            "dns.time",
        ]
        if display_filter and display_filter.strip():
            cmd.extend(["-Y", display_filter.strip()])

        output = self._runner(cmd)
        tsv_lines = [line for line in output.splitlines() if line.strip()]

        # 3. 汇总聚合指标
        analysis = parse_tshark_fields_output(
            tsv_lines=tsv_lines,
            file_path=str(path_obj),
            total_packets=len(tsv_lines),
        )

        # 4. 若存在同名 .pcap.meta.json 伴随元数据，自动挂载多服务器拓扑与进程画像
        sidecar_meta = CaptureSidecar.load(path_obj)
        if sidecar_meta:
            analysis["process_summary"] = sidecar_meta.get("process_family")
            analysis["server_topology"] = sidecar_meta.get("server_topology", [])

        return analysis
