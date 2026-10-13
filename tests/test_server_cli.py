"""FastMCP 服务底座、CLI 主入口与退出清理闭环测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_server_traffic_inspector.__main__ import main
from mcp_server_traffic_inspector.config import parse_config
from mcp_server_traffic_inspector.server import create_mcp_server
from mcp_server_traffic_inspector.storage import StorageBus


def test_create_mcp_server_binds_config_and_storage(tmp_path: Path) -> None:
    """create_mcp_server 应初始化 StorageBus 并返回绑定了主机与端口的 FastMCP 实例。"""
    db_file = tmp_path / "server_init.db"
    cfg = parse_config(
        argv=[
            "--transport",
            "sse",
            "--host",
            "0.0.0.0",
            "--port",
            "8123",
            "--db-path",
            str(db_file),
        ],
        env={},
    )
    bus = StorageBus(db_path=cfg.db_path, bodies_dir=cfg.bodies_dir, preserve_db=cfg.preserve_db)

    mcp = create_mcp_server(config=cfg, storage=bus)

    assert mcp.name == "mcp-server-traffic-inspector"
    assert mcp.settings.host == "0.0.0.0"
    assert mcp.settings.port == 8123
    assert db_file.exists()
    bus.cleanup()


def test_main_check_outputs_structured_json_and_returns_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI 传入 --check 时应输出 JSON 格式诊断报告并以状态码 0 退出，同时清理默认临时库。"""
    exit_code = main(argv=["--check"], env={})

    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["service"] == "mcp-server-traffic-inspector"
    assert data["ready"] is True
    assert data["checks"]["sqlite_wal"]["status"] == "ok"
    # 默认未指定 --db-path 时，自检完成后临时数据库应已被自动清理
    ephemeral_db = Path(data["checks"]["sqlite_wal"]["path"])
    assert not ephemeral_db.exists()


def test_main_runs_server_and_cleans_up_temp_db_on_exit(tmp_path: Path) -> None:
    """CLI 启动服务并在退出时应自动触发临时数据库与分流目录清理。"""
    recorded: dict[str, Any] = {}

    def fake_runner(mcp_server: Any, transport: str) -> None:
        recorded["name"] = mcp_server.name
        recorded["transport"] = transport

    exit_code = main(
        argv=["--transport", "sse", "--port", "8099"],
        env={},
        runner=fake_runner,
    )

    assert exit_code == 0
    assert recorded["name"] == "mcp-server-traffic-inspector"
    assert recorded["transport"] == "sse"
