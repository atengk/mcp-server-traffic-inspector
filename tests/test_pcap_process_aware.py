"""基于目标进程家族与多服务器拓扑感知的底层网络抓包端到端集成测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.diagnostics import NetworkDiagnostics
from mcp_server_traffic_inspector.pcap import PcapCaptureManager
from mcp_server_traffic_inspector.process_tracker import ProcessInfo, SocketEntry
from mcp_server_traffic_inspector.server import LifecycleManager, create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


class MockWorkerProcess:
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


def test_process_aware_capture_full_lifecycle(tmp_path: Path) -> None:
    """基于进程路径启动抓包，应完成后台采样、停止切片与落盘 Sidecar 元数据全流程。"""
    fake_tshark = tmp_path / "tshark.exe"
    fake_tshark.write_bytes(b"bin")

    spawned_cmds: list[list[str]] = []
    executed_runner_cmds: list[list[str]] = []

    def spawner(cmd: list[str], env: dict[str, str]) -> MockWorkerProcess:
        spawned_cmds.append(cmd)
        return MockWorkerProcess(cmd, env)

    def runner(cmd: list[str]) -> str:
        executed_runner_cmds.append(cmd)
        # 如果是切片命令 (-w)，生成目标文件
        if "-w" in cmd:
            target_idx = cmd.index("-w") + 1
            Path(cmd[target_idx]).write_bytes(b"SLICED_PCAP_BYTES")
        # 如果是帧统计 (-e frame.number)，模拟 10 个数据包
        if "frame.number" in cmd:
            return "\n".join(str(i) for i in range(1, 11))
        return ""

    def mock_snapshots() -> list[ProcessInfo]:
        return [
            ProcessInfo(
                pid=1000,
                ppid=1,
                name="Weixin.exe",
                exe_path="C:\\Program Files\\Tencent\\Weixin\\Weixin.exe",
            ),
            ProcessInfo(
                pid=1001,
                ppid=1000,
                name="WeChatAppEx.exe",
                exe_path="C:\\Program Files\\Tencent\\Weixin\\plugin\\WeChatAppEx.exe",
            ),
        ]

    def mock_sockets() -> list[SocketEntry]:
        return [
            SocketEntry(
                proto="TCP",
                local_ip="192.168.1.10",
                local_port=52341,
                remote_ip="101.91.1.1",
                remote_port=443,
                pid=1000,
            ),
            SocketEntry(
                proto="TCP",
                local_ip="192.168.1.10",
                local_port=52342,
                remote_ip="101.91.2.2",
                remote_port=443,
                pid=1001,
            ),
        ]

    manager = PcapCaptureManager(
        tshark_path=str(fake_tshark),
        process_spawner=spawner,
        command_runner=runner,
        default_output_dir=tmp_path,
        snapshot_fetcher=mock_snapshots,
        socket_fetcher=mock_sockets,
    )

    # 1. 启动基于进程路径的抓包
    start_res = manager.start_capture(
        process_path="C:\\Program Files\\Tencent\\Weixin\\Weixin.exe",
        bpf_filter="tcp port 443",
        keep_raw_pcap=False,
    )

    assert start_res["status"] == "capturing"
    expected_path = "C:\\Program Files\\Tencent\\Weixin\\Weixin.exe"
    assert start_res["process_filter"]["process_path"] == expected_path

    # 模拟抓包过程中生成了原始全量 PCAP 文件
    raw_pcap_file = Path(start_res["output_file"])
    raw_pcap_file.write_bytes(b"RAW_INTERMEDIATE_PCAP")

    # 2. 停止抓包并切片
    stop_res = manager.stop_capture()

    assert stop_res["status"] == "stopped"
    assert stop_res["packet_count"] == 10
    assert "process_summary" in stop_res
    assert "server_topology" in stop_res

    # 验证 Sidecar 伴随文件已持久化
    final_pcap = Path(stop_res["pcap_file"])
    sidecar_file = final_pcap.parent / f"{final_pcap.name}.meta.json"
    assert sidecar_file.is_file()

    # 3. 验证离线分析 analyze_pcap 能挂载并呈现多服务器拓扑与进程矩阵
    def runner_analyze(cmd: list[str]) -> str:
        # 模拟 tshark -T fields 分析输出
        return "1\teth:ip:tcp\t0\t0.015\t\t\t\n2\teth:ip:tcp\t0\t0.020\t\t\t\n"

    manager._runner = runner_analyze
    analysis = manager.analyze_pcap(file_path=str(final_pcap))

    assert "server_topology" in analysis
    assert len(analysis["server_topology"]) == 2
    server_ips = {item["server_ip"] for item in analysis["server_topology"]}
    assert server_ips == {"101.91.1.1", "101.91.2.2"}
    assert "process_summary" in analysis


async def test_mcp_tools_support_process_aware_arguments(tmp_path: Path) -> None:
    """MCP 工具 start_pcap_capture 与 analyze_pcap_file 应正常响应进程树扩展参数。"""
    db_file = tmp_path / "proc_pcap_mcp.db"
    cfg = parse_config(argv=["--db-path", str(db_file)], env={})
    bus = StorageBus.from_config(cfg)
    bus.initialize()

    fake_tshark = tmp_path / "tshark.exe"
    fake_tshark.write_bytes(b"bin")

    def spawner(cmd: list[str], env: dict[str, str]) -> MockWorkerProcess:
        return MockWorkerProcess(cmd, env)

    manager = PcapCaptureManager(
        tshark_path=str(fake_tshark),
        process_spawner=spawner,
        default_output_dir=tmp_path,
    )

    lifecycle = LifecycleManager()
    mcp_app = create_mcp_server(
        config=cfg,
        storage=bus,
        pcap_manager=manager,
        lifecycle=lifecycle,
    )

    # 验证 start_pcap_capture 接受新参数
    _, res = await mcp_app.call_tool(
        "start_pcap_capture",
        {
            "process_name": "Weixin*.exe",
            "include_child_processes": True,
            "keep_raw_pcap": False,
        },
    )
    assert res["status"] == "capturing"
    assert res["process_filter"]["process_name"] == "Weixin*.exe"

    # 停止抓包
    _, stop_res = await mcp_app.call_tool("stop_pcap_capture", {})
    assert stop_res["status"] == "stopped"


def test_process_aware_capture_detects_proxy_redirection_and_diagnoses_health(
    tmp_path: Path,
) -> None:
    """双轨抓包且物理网卡切片包为 0 时，应智能识别代理回环分流并在诊断中评定为健康。"""
    fake_tshark = tmp_path / "tshark.exe"
    fake_tshark.write_bytes(b"bin")

    def spawner(cmd: list[str], env: dict[str, str]) -> MockWorkerProcess:
        return MockWorkerProcess(cmd, env)

    def runner(cmd: list[str]) -> str:
        if "-w" in cmd:
            target_idx = cmd.index("-w") + 1
            Path(cmd[target_idx]).write_bytes(b"EMPTY_SLICE_PCAP")
        if "frame.number" in cmd:
            return ""
        if "-r" in cmd and "fields" in cmd:
            return ""
        return ""

    def mock_snapshots() -> list[ProcessInfo]:
        return [
            ProcessInfo(
                pid=2000,
                ppid=1,
                name="ClientApp.exe",
                exe_path="C:\\App\\ClientApp.exe",
            ),
        ]

    # 模拟目标进程所有外联均指向本地代理回环 127.0.0.1:8080
    def mock_sockets() -> list[SocketEntry]:
        return [
            SocketEntry(
                proto="TCP",
                local_ip="127.0.0.1",
                local_port=54321,
                remote_ip="127.0.0.1",
                remote_port=8080,
                pid=2000,
            ),
        ]

    manager = PcapCaptureManager(
        tshark_path=str(fake_tshark),
        command_runner=runner,
        process_spawner=spawner,
        default_output_dir=tmp_path,
        snapshot_fetcher=mock_snapshots,
        socket_fetcher=mock_sockets,
    )

    start_res = manager.start_capture(
        process_name="ClientApp.exe",
        output_path=str(tmp_path / "target_redirected.pcap"),
    )
    raw_pcap_file = Path(start_res["output_file"])
    raw_pcap_file.write_bytes(b"RAW_PCAP_BYTES")

    stop_res = manager.stop_capture()

    assert stop_res["status"] == "stopped"
    assert stop_res["packet_count"] == 0
    assert "redirection_notice" in stop_res
    notice = stop_res["redirection_notice"]
    assert notice["is_redirected_to_proxy"] is True
    assert 8080 in notice["proxy_ports"]

    # 验证诊断引擎对该会话的评分与自解释
    bus = StorageBus(tmp_path / "d.db", tmp_path / "b", preserve_db=False)
    bus.initialize()
    diag = NetworkDiagnostics(storage=bus, pcap_manager=manager)
    diag_res = diag.diagnose_pcap_session(file_path=stop_res["pcap_file"])
    assert diag_res["health_status"] == "healthy"
    assert diag_res["health_score"] == 100
    assert diag_res["sidecar_loaded"] is True
    assert "代理分流正常" in diag_res["summary"]
    assert "redirection_notice" in diag_res


def test_pcap_raw_socket_loopback_redirection_and_diagnostics(tmp_path: Path) -> None:
    """验证目标进程走原生 TCP 套接字回环连接时的精准分流感知与 60 分降级诊断。"""
    fake_tshark = tmp_path / "fake_tshark.exe"
    fake_tshark.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    captured_cmds: list[list[str]] = []

    def spawner(cmd: list[str], env: dict[str, str]) -> MockWorkerProcess:
        captured_cmds.append(cmd)
        return MockWorkerProcess(cmd, env)

    def runner(cmd: list[str]) -> str:
        if "-w" in cmd:
            target_idx = cmd.index("-w") + 1
            Path(cmd[target_idx]).write_bytes(b"EMPTY_SLICE_PCAP")
        if "frame.number" in cmd:
            return ""
        if "-r" in cmd and "fields" in cmd:
            return ""
        return ""

    def mock_snapshots() -> list[ProcessInfo]:
        return [
            ProcessInfo(
                pid=3000,
                ppid=1,
                name="GameClient.exe",
                exe_path="C:\\Games\\GameClient.exe",
            ),
        ]

    # 模拟目标进程连接到 127.0.0.1:8000 和 127.0.0.2:843 (非受管 HTTP 代理端口 8080)
    def mock_sockets() -> list[SocketEntry]:
        return [
            SocketEntry(
                proto="TCP",
                local_ip="127.0.0.1",
                local_port=61234,
                remote_ip="127.0.0.1",
                remote_port=8000,
                pid=3000,
            ),
            SocketEntry(
                proto="TCP",
                local_ip="127.0.0.1",
                local_port=61235,
                remote_ip="127.0.0.2",
                remote_port=843,
                pid=3000,
            ),
        ]

    manager = PcapCaptureManager(
        tshark_path=str(fake_tshark),
        command_runner=runner,
        process_spawner=spawner,
        default_output_dir=tmp_path,
        snapshot_fetcher=mock_snapshots,
        socket_fetcher=mock_sockets,
    )
    manager.set_proxy_port_resolver(lambda: 8080)

    start_res = manager.start_capture(
        process_name="GameClient.exe",
        output_path=str(tmp_path / "game_target.pcap"),
    )
    raw_pcap_file = Path(start_res["output_file"])
    raw_pcap_file.write_bytes(b"RAW_PCAP_BYTES")

    stop_res = manager.stop_capture()

    assert stop_res["status"] == "stopped"
    assert stop_res["packet_count"] == 0
    assert "redirection_notice" in stop_res
    notice = stop_res["redirection_notice"]
    assert notice["is_redirected_to_proxy"] is False
    assert notice["has_raw_socket"] is True
    assert notice["raw_socket_ports"] == [843, 8000]
    assert "原生套接字" in notice["message"]

    # 验证诊断引擎识别到 raw_socket，降级为 60 分 (degraded)
    bus = StorageBus(tmp_path / "game.db", tmp_path / "game_blobs", preserve_db=False)
    bus.initialize()
    diag = NetworkDiagnostics(storage=bus, pcap_manager=manager)
    diag_res = diag.diagnose_pcap_session(file_path=stop_res["pcap_file"])
    assert diag_res["health_status"] == "degraded"
    assert diag_res["health_score"] == 60
    assert "原生套接字" in diag_res["summary"]
    assert any("loopback" in rec for rec in diag_res["recommendations"])


def test_pcap_interface_resolution_and_multi_interface_capture(tmp_path: Path) -> None:
    """验证 'loopback' 别名解析、'auto' 双轨网卡推导与多网卡合并传参。"""
    fake_tshark = tmp_path / "fake_tshark.exe"
    fake_tshark.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    captured_cmds: list[list[str]] = []

    def spawner(cmd: list[str], env: dict[str, str]) -> MockWorkerProcess:
        captured_cmds.append(cmd)
        return MockWorkerProcess(cmd, env)

    def runner(cmd: list[str]) -> str:
        if "-D" in cmd:
            return (
                "1. \\Device\\NPF_{WLAN_GUID} (WLAN)\n"
                "2. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n"
                "3. etwdump (Event Tracing for Windows)\n"
            )
        return ""

    manager = PcapCaptureManager(
        tshark_path=str(fake_tshark),
        command_runner=runner,
        process_spawner=spawner,
        default_output_dir=tmp_path,
    )

    # 1. 验证 loopback 语义别名
    loop_resolved = manager._normalize_interface("loopback")
    assert loop_resolved == "\\Device\\NPF_Loopback"

    # 2. 验证 auto 双轨自适应
    auto_resolved = manager._resolve_interfaces("auto")
    assert "\\Device\\NPF_{WLAN_GUID}" in auto_resolved
    assert "\\Device\\NPF_Loopback" in auto_resolved

    # 3. 验证网卡列表解析
    list_resolved = manager._resolve_interfaces(["WLAN", "loopback"])
    assert list_resolved == ["\\Device\\NPF_{WLAN_GUID}", "\\Device\\NPF_Loopback"]

    # 4. 验证 start_capture 产生多 -i 参数
    start_res = manager.start_capture(
        interface="auto",
        output_path=str(tmp_path / "auto_capture.pcap"),
    )
    assert start_res["status"] == "capturing"
    assert len(start_res["resolved_interfaces"]) == 2

    last_cmd = captured_cmds[-1]
    i_indices = [idx for idx, val in enumerate(last_cmd) if val == "-i"]
    assert len(i_indices) == 2
    assert last_cmd[i_indices[0] + 1] == "\\Device\\NPF_{WLAN_GUID}"
    assert last_cmd[i_indices[1] + 1] == "\\Device\\NPF_Loopback"

    manager.stop_capture()
