"""基于目标进程家族与多服务器拓扑感知的底层网络抓包端到端集成测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path

from mcp_server_traffic_inspector.config import parse_config
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
