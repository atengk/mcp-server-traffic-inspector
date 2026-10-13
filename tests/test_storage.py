"""SQLite WAL 共享数据总线初始化、健康探针与生命周期清理测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

from pathlib import Path

from mcp_server_traffic_inspector.storage import StorageBus


def test_storage_bus_initializes_wal_and_core_tables(tmp_path: Path) -> None:
    """初始化 StorageBus 后应开启 WAL 模式并创建三张核心表与分流目录。"""
    db_file = tmp_path / "traffic_bus.db"
    bodies_dir = tmp_path / "bodies"
    bus = StorageBus(db_path=db_file, bodies_dir=bodies_dir, preserve_db=False)

    bus.initialize()
    health = bus.verify_health()

    assert health.writable is True
    assert health.journal_mode.lower() == "wal"
    assert set(health.tables) >= {"http_flows", "http_bodies", "intercept_rules"}
    assert db_file.exists()
    assert bodies_dir.is_dir()


def test_storage_bus_cleanup_removes_default_temp_db_and_bodies_dir(
    tmp_path: Path,
) -> None:
    """当 preserve_db=False 时，cleanup 应清理数据库文件、WAL 附属文件及载荷目录。"""
    db_file = tmp_path / "ephemeral.db"
    bodies_dir = tmp_path / "ephemeral_bodies"
    bus = StorageBus(db_path=db_file, bodies_dir=bodies_dir, preserve_db=False)

    bus.initialize()
    (bodies_dir / "payload_1.bin").write_bytes(b"binary-data")
    assert db_file.exists()
    assert bodies_dir.exists()

    bus.cleanup()

    assert not db_file.exists()
    assert not Path(f"{db_file}-wal").exists()
    assert not Path(f"{db_file}-shm").exists()
    assert not bodies_dir.exists()


def test_storage_bus_cleanup_preserves_explicit_db_file(tmp_path: Path) -> None:
    """当显式指定 --db-path (preserve_db=True) 时，cleanup 后必须保留数据库文件。"""
    db_file = tmp_path / "persistent.db"
    bodies_dir = tmp_path / "persistent_bodies"
    bus = StorageBus(db_path=db_file, bodies_dir=bodies_dir, preserve_db=True)

    bus.initialize()
    bus.cleanup()

    assert db_file.exists()
    health_after = bus.verify_health()
    assert health_after.writable is True
    assert set(health_after.tables) >= {"http_flows", "http_bodies", "intercept_rules"}
