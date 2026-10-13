"""基于共享 SQLite WAL 的进程间数据总线与保真载荷存储模块。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from mcp_server_traffic_inspector.config import LOGGER_NAME, ServerConfig

logger = logging.getLogger(LOGGER_NAME)

SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS http_flows (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    method TEXT NOT NULL,
    scheme TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    duration_ms REAL,
    request_headers TEXT,
    response_headers TEXT,
    request_content_type TEXT,
    response_content_type TEXT,
    request_body_size INTEGER DEFAULT 0,
    response_body_size INTEGER DEFAULT 0,
    has_error INTEGER DEFAULT 0,
    error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_session ON http_flows(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_flows_host_status ON http_flows(host, status_code);
CREATE INDEX IF NOT EXISTS idx_flows_duration ON http_flows(duration_ms DESC);

CREATE TABLE IF NOT EXISTS http_bodies (
    flow_id TEXT PRIMARY KEY,
    request_body_preview TEXT,
    response_body_preview TEXT,
    request_body BLOB,
    response_body BLOB,
    is_request_binary INTEGER DEFAULT 0,
    is_response_binary INTEGER DEFAULT 0,
    request_body_path TEXT,
    response_body_path TEXT,
    FOREIGN KEY(flow_id) REFERENCES http_flows(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS intercept_rules (
    id TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 1,
    url_pattern TEXT NOT NULL,
    action TEXT NOT NULL,
    mock_status INTEGER DEFAULT 200,
    mock_headers TEXT,
    mock_body TEXT,
    modify_request_headers TEXT,
    modify_response_headers TEXT,
    created_at REAL NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class StorageHealth:
    """SQLite WAL 共享数据总线健康度快照。

    Attributes:
        writable: 数据库与大载荷目录是否具备正常读写权限。
        journal_mode: 当前 SQLite 日志模式（预期为 wal）。
        tables: 已就绪的用户表名列表。
        db_path: 数据库文件绝对路径。
        bodies_dir: 大载荷分流目录绝对路径。
        error: 当探测异常时的错误原因描述，正常时为 None。
    """

    writable: bool
    journal_mode: str
    tables: list[str]
    db_path: Path
    bodies_dir: Path
    error: str | None = None


class StorageBus:
    """主控进程与抓包子进程共享的 SQLite WAL 数据总线管理器。

    负责初始化 WAL 并发模式与三张领域表（http_flows、http_bodies、intercept_rules），
    提供存储层健康自检，并在进程退出时按策略回收临时数据库与分流载荷文件。
    """

    def __init__(
        self,
        db_path: Path,
        bodies_dir: Path,
        preserve_db: bool = False,
    ) -> None:
        """初始化数据总线实例。

        Args:
            db_path: SQLite 数据库文件绝对路径。
            bodies_dir: 超出 256KB 的 BodyPayload 临时文件存放目录。
            preserve_db: 进程退出清理时是否保留数据库文件（显式指定 --db-path 时为 True）。
        """
        self.db_path = db_path.resolve()
        self.bodies_dir = bodies_dir.resolve()
        self.preserve_db = preserve_db

    @classmethod
    def from_config(cls, config: ServerConfig) -> StorageBus:
        """根据服务端全局配置构建 StorageBus 实例。

        Args:
            config: 解析完成的服务端配置对象。

        Returns:
            绑定了对应数据库路径、载荷目录与保留策略的 StorageBus 实例。
        """
        return cls(
            db_path=config.db_path,
            bodies_dir=config.bodies_dir,
            preserve_db=config.preserve_db,
        )

    def initialize(self) -> None:
        """创建数据库父目录与大载荷分流目录，开启 SQLite WAL 模式并建表。"""
        # 1. 确保数据库父目录与超大载荷分流目录存在
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.bodies_dir.mkdir(parents=True, exist_ok=True)

        # 2. 连接 SQLite 并开启 WAL 与外键约束，执行核心 DDL
        with closing(sqlite3.connect(self.db_path, timeout=10.0)) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.executescript(SCHEMA_DDL)
            conn.commit()

    def verify_health(self) -> StorageHealth:
        """探测当前 SQLite WAL 数据总线与分流目录的读写状态及表结构完整性。

        Returns:
            包含 WAL 状态、表清单与可写状态的 StorageHealth 诊断结果。
        """
        try:
            # 1. 验证大载荷分流目录可写性
            self.bodies_dir.mkdir(parents=True, exist_ok=True)
            probe_file = self.bodies_dir / ".write_probe"
            probe_file.write_bytes(b"ok")
            probe_file.unlink(missing_ok=True)

            # 2. 查询 SQLite journal_mode 与已创建的核心表
            with closing(sqlite3.connect(self.db_path, timeout=5.0)) as conn:
                mode_row = conn.execute("PRAGMA journal_mode;").fetchone()
                journal_mode = str(mode_row[0]) if mode_row else "unknown"
                table_rows = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
                ).fetchall()
                tables = [str(row[0]) for row in table_rows]

            return StorageHealth(
                writable=True,
                journal_mode=journal_mode,
                tables=tables,
                db_path=self.db_path,
                bodies_dir=self.bodies_dir,
                error=None,
            )
        except Exception as exc:
            logger.warning("SQLite WAL 数据总线健康自检失败: %s", exc)
            return StorageHealth(
                writable=False,
                journal_mode="error",
                tables=[],
                db_path=self.db_path,
                bodies_dir=self.bodies_dir,
                error=str(exc),
            )

    def cleanup(self) -> None:
        """按生命周期策略清理分流载荷目录与临时 SQLite 数据库文件。"""
        # 1. 始终清理当前进程专属的大载荷分流临时目录
        if self.bodies_dir.exists():
            try:
                shutil.rmtree(self.bodies_dir, ignore_errors=True)
            except OSError as exc:
                logger.warning("清理大载荷临时目录失败 (%s): %s", self.bodies_dir, exc)

        # 2. 若未显式指定保留数据库，则删除默认临时数据库及 WAL/SHM 附属文件
        if self.preserve_db:
            return

        for candidate in (
            self.db_path,
            Path(f"{self.db_path}-wal"),
            Path(f"{self.db_path}-shm"),
        ):
            try:
                candidate.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("清理临时数据库文件失败 (%s): %s", candidate, exc)
