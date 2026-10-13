"""进程家族树 (ProcessFamily) 发现与套接字时序流 (SocketTimeline) 单元测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import time

from mcp_server_traffic_inspector.process_tracker import (
    ProcessFamily,
    ProcessFamilyDetector,
    ProcessFamilyTracker,
    ProcessInfo,
    SocketEntry,
    SocketTimeline,
)


def test_process_family_detector_recursively_discovers_children_within_allowed_path() -> None:
    """ProcessFamilyDetector 应递归发现合法子进程，并基于同目录白名单排除外部进程（如浏览器）。"""
    detector = ProcessFamilyDetector()

    # 构造模拟进程表
    # 根进程：Weixin.exe (PID: 1000)
    # 子进程 1：WeChatAppEx.exe (PID: 1001, PPID: 1000, 同目录) -> 纳管
    # 子进程 2：chrome.exe (PID: 1002, PPID: 1000, 外部目录) -> 排除
    # 孙进程 3：WeChatUtility.exe (PID: 1003, PPID: 1001, 同目录) -> 纳管
    # 无关进程：notepad.exe (PID: 2000, PPID: 500) -> 排除
    snapshot = [
        ProcessInfo(
            pid=1000,
            ppid=500,
            name="Weixin.exe",
            exe_path="C:\\Program Files\\Tencent\\Weixin\\Weixin.exe",
        ),
        ProcessInfo(
            pid=1001,
            ppid=1000,
            name="WeChatAppEx.exe",
            exe_path="C:\\Program Files\\Tencent\\Weixin\\plugin\\WeChatAppEx.exe",
        ),
        ProcessInfo(
            pid=1002,
            ppid=1000,
            name="chrome.exe",
            exe_path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        ),
        ProcessInfo(
            pid=1003,
            ppid=1001,
            name="WeChatUtility.exe",
            exe_path="C:\\Program Files\\Tencent\\Weixin\\WeChatUtility.exe",
        ),
        ProcessInfo(
            pid=2000,
            ppid=500,
            name="notepad.exe",
            exe_path="C:\\Windows\\notepad.exe",
        ),
    ]

    family = detector.resolve_family(
        snapshot=snapshot,
        process_path="C:\\Program Files\\Tencent\\Weixin\\Weixin.exe",
        include_child_processes=True,
    )

    assert isinstance(family, ProcessFamily)
    assert family.root_pid == 1000
    assert family.all_pids == {1000, 1001, 1003}
    assert len(family.members) == 3
    # 校验外部 chrome.exe 未被收纳
    assert 1002 not in family.all_pids


def test_process_family_detector_supports_process_name_pattern_and_target_pids() -> None:
    """ProcessFamilyDetector 支持进程名通配符与显式 target_pids。"""
    detector = ProcessFamilyDetector()

    slack_path = "C:\\Users\\admin\\AppData\\Local\\slack\\Slack.exe"
    snapshot = [
        ProcessInfo(pid=3000, ppid=100, name="Slack.exe", exe_path=slack_path),
        ProcessInfo(pid=3001, ppid=3000, name="Slack.exe", exe_path=slack_path),
    ]

    # 1. 进程名通配
    family_by_name = detector.resolve_family(
        snapshot=snapshot,
        process_name="slack*.exe",
        include_child_processes=True,
    )
    assert family_by_name.all_pids == {3000, 3001}

    # 2. 显式 target_pids
    family_by_pids = detector.resolve_family(
        snapshot=snapshot,
        target_pids=[3000],
        include_child_processes=False,
    )
    assert family_by_pids.all_pids == {3000}


def test_socket_timeline_records_and_retrieves_ports_and_topology() -> None:
    """SocketTimeline 应精准记录套接字时序，并能检索目标进程占用的端口集合与拓扑画像。"""
    timeline = SocketTimeline()
    t0 = 1000.0
    t1 = 1000.1

    # 时刻 t0 采样
    timeline.record_snapshot(
        timestamp=t0,
        entries=[
            SocketEntry(
                proto="TCP",
                local_ip="192.168.1.5",
                local_port=52341,
                remote_ip="101.91.1.1",
                remote_port=443,
                pid=1000,
                state="ESTABLISHED",
            ),
            SocketEntry(
                proto="UDP",
                local_ip="192.168.1.5",
                local_port=8000,
                remote_ip="0.0.0.0",
                remote_port=0,
                pid=1001,
            ),
            SocketEntry(
                proto="TCP",
                local_ip="192.168.1.5",
                local_port=55555,
                remote_ip="14.215.177.38",
                remote_port=80,
                pid=9999,
                state="ESTABLISHED",
            ),
        ],
    )

    # 时刻 t1 采样：微信打开新连接
    timeline.record_snapshot(
        timestamp=t1,
        entries=[
            SocketEntry(
                proto="TCP",
                local_ip="192.168.1.5",
                local_port=52341,
                remote_ip="101.91.1.1",
                remote_port=443,
                pid=1000,
                state="ESTABLISHED",
            ),
            SocketEntry(
                proto="TCP",
                local_ip="192.168.1.5",
                local_port=52342,
                remote_ip="101.91.2.2",
                remote_port=443,
                pid=1003,
                state="ESTABLISHED",
            ),
        ],
    )

    target_pids = {1000, 1001, 1003}

    # 1. 查询目标进程家族使用过的全部本地端口
    ports = timeline.get_active_ports(target_pids)
    assert ports == {52341, 8000, 52342}
    assert 55555 not in ports

    # 2. 导出对端服务器拓扑列表
    topology = timeline.export_server_topology(target_pids)
    assert len(topology) == 2
    server_ips = {item["server_ip"] for item in topology}
    assert server_ips == {"101.91.1.1", "101.91.2.2"}

    # 3. 序列化与反序列化
    serialized = timeline.to_dict()
    restored = SocketTimeline.from_dict(serialized)
    assert restored.get_active_ports(target_pids) == {52341, 8000, 52342}


def test_process_family_tracker_background_polling_and_delayed_attach() -> None:
    """ProcessFamilyTracker 应支持在后台异步轮询，并在进程延迟启动后动态接入。"""
    call_count = 0

    def mock_snapshots() -> list[ProcessInfo]:
        nonlocal call_count
        call_count += 1
        # 前 2 次调用时进程尚未启动
        if call_count < 3:
            return []
        # 第 3 次调用后进程启动
        return [
            ProcessInfo(
                pid=5000,
                ppid=1,
                name="delayed_app.exe",
                exe_path="C:\\Apps\\delayed_app.exe",
            ),
        ]

    def mock_sockets() -> list[SocketEntry]:
        if call_count >= 3:
            return [
                SocketEntry(
                    proto="TCP",
                    local_ip="127.0.0.1",
                    local_port=49152,
                    remote_ip="1.1.1.1",
                    remote_port=443,
                    pid=5000,
                ),
            ]
        return []

    tracker = ProcessFamilyTracker(
        process_name="delayed_app.exe",
        poll_interval=0.03,  # 30ms 快速测试
        snapshot_fetcher=mock_snapshots,
        socket_fetcher=mock_sockets,
    )

    tracker.start()
    time.sleep(0.12)  # 等待至少 3-4 次采样
    family, timeline = tracker.stop()

    assert family.root_pid == 5000
    assert family.all_pids == {5000}
    assert timeline.get_active_ports({5000}) == {49152}
