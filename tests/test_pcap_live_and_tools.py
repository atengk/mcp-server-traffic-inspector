"""PcapCapture 实时抓包安全熔断控制与 4 个网络层 MCP 工具端到端测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path

from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.pcap import PcapCaptureManager
from mcp_server_traffic_inspector.server import LifecycleManager, create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


class FakePcapProcess:
    """模拟受控 tshark 抓包工作进程。"""

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


def test_pcap_capture_manager_applies_dual_safety_limits_and_stops(
    tmp_path: Path,
) -> None:
    """start_pcap_capture 应强制施加 max_packets=2000 与 duration=60 双重安全熔断参数。"""
    spawned_cmds: list[list[str]] = []

    fake_tshark_bin = tmp_path / "tshark.exe"
    fake_tshark_bin.write_bytes(b"bin")

    def spawner(cmd: list[str], env: dict[str, str]) -> FakePcapProcess:
        spawned_cmds.append(cmd)
        return FakePcapProcess(cmd=cmd, env=env)

    manager = PcapCaptureManager(
        tshark_path=str(fake_tshark_bin),
        process_spawner=spawner,
        default_output_dir=tmp_path,
    )

    # 1. 启动抓包并验证熔断阈值参数传递至命令行
    res = manager.start_capture(
        interface=2,
        bpf_filter="tcp and port 443",
        max_packets=2000,
        duration_seconds=60,
    )

    assert res["status"] == "capturing"
    assert res["interface"] == 2
    assert res["limits"]["max_packets"] == 2000
    assert res["limits"]["duration_seconds"] == 60

    cmd = spawned_cmds[0]
    assert "-i" in cmd and cmd[cmd.index("-i") + 1] == "2"
    assert "-c" in cmd and cmd[cmd.index("-c") + 1] == "2000"
    assert "-a" in cmd and cmd[cmd.index("-a") + 1] == "duration:60"
    assert "-f" in cmd and cmd[cmd.index("-f") + 1] == "tcp and port 443"

    # 2. 模拟抓包结束
    pcap_output = Path(res["output_file"])
    pcap_output.write_bytes(b"dummy-pcap-data")

    stop_res = manager.stop_capture()
    assert stop_res["status"] == "stopped"
    assert stop_res["pcap_file"] == str(pcap_output)


async def test_mcp_server_exposes_and_calls_four_pcap_tools(tmp_path: Path) -> None:
    """FastMCP 服务应注册并正常执行 4 个 PCAP 原始网络层工具。"""
    db_file = tmp_path / "pcap_mcp.db"
    cfg = parse_config(argv=["--db-path", str(db_file)], env={})
    bus = StorageBus.from_config(cfg)
    bus.initialize()

    fake_tshark_bin = tmp_path / "tshark.exe"
    fake_tshark_bin.write_bytes(b"bin")

    sample_pcap = tmp_path / "sample.pcap"
    sample_pcap.write_bytes(b"pcap-sample")

    def runner_mock(cmd: list[str]) -> str:
        if "-D" in cmd:
            return "1. eth0 (Primary)\n2. lo (Loopback)\n"
        if "-r" in cmd:
            return "1\teth:ethertype:ip:tcp\t\t0.012\t\t\t\n"
        return ""

    pcap_manager = PcapCaptureManager(
        tshark_path=str(fake_tshark_bin),
        command_runner=runner_mock,
        process_spawner=lambda c, e: FakePcapProcess(c, e),
        default_output_dir=tmp_path,
    )
    lifecycle = LifecycleManager()
    mcp = create_mcp_server(
        config=cfg,
        storage=bus,
        pcap_manager=pcap_manager,
        lifecycle=lifecycle,
    )

    # 1. 枚举网卡
    _, ifaces_res = await mcp.call_tool("list_network_interfaces", {})
    ifaces = (
        ifaces_res["result"]
        if isinstance(ifaces_res, dict) and "result" in ifaces_res
        else ifaces_res
    )
    assert len(ifaces) == 2
    assert ifaces[0]["name"] == "eth0"

    # 2. 启动与停止抓包
    _, start_info = await mcp.call_tool("start_pcap_capture", {"interface": "eth0"})
    assert start_info["status"] == "capturing"

    _, stop_info = await mcp.call_tool("stop_pcap_capture", {})
    assert stop_info["status"] == "stopped"

    # 3. 分析离线 PCAP
    _, analysis = await mcp.call_tool(
        "analyze_pcap_file",
        {"file_path": str(sample_pcap)},
    )
    assert analysis["total_packets"] == 1
    assert analysis["protocol_distribution"].get("TCP") == 1
