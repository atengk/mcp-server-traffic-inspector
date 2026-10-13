"""CLI 参数、环境变量解析优先级与日志流隔离测试。

@author Ateng
@since 2026-10-13
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from mcp_server_traffic_inspector import __version__
from mcp_server_traffic_inspector.config import configure_logging, parse_config


def test_parse_config_uses_defaults_when_no_args_or_env() -> None:
    """未传入 CLI 参数与环境变量时应使用内置默认配置，且默认临时库标记为不保留。"""
    cfg = parse_config(argv=[], env={})

    assert cfg.transport == "stdio"
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 8000
    assert cfg.tshark_path is None
    assert cfg.log_level == "INFO"
    assert cfg.check is False
    assert cfg.preserve_db is False
    assert cfg.db_path.name.startswith("mcp_traffic_inspector_")
    assert cfg.db_path.suffix == ".db"
    assert cfg.bodies_dir.name.startswith("mcp_traffic_inspector_bodies_")


def test_parse_config_reads_environment_variables(tmp_path: Path) -> None:
    """未传 CLI 参数时应读取 MCP_TRAFFIC_INSPECTOR_* 环境变量，显式指定 db_path 时标记保留。"""
    custom_db = tmp_path / "env_custom.db"
    env = {
        "MCP_TRAFFIC_INSPECTOR_TRANSPORT": "sse",
        "MCP_TRAFFIC_INSPECTOR_HOST": "0.0.0.0",
        "MCP_TRAFFIC_INSPECTOR_PORT": "9000",
        "MCP_TRAFFIC_INSPECTOR_TSHARK_PATH": "/usr/local/bin/tshark",
        "MCP_TRAFFIC_INSPECTOR_DB_PATH": str(custom_db),
        "MCP_TRAFFIC_INSPECTOR_LOG_LEVEL": "debug",
    }

    cfg = parse_config(argv=[], env=env)

    assert cfg.transport == "sse"
    assert cfg.host == "0.0.0.0"
    assert cfg.port == 9000
    assert cfg.tshark_path == "/usr/local/bin/tshark"
    assert cfg.db_path == custom_db.resolve()
    assert cfg.preserve_db is True
    assert cfg.log_level == "DEBUG"


def test_parse_config_cli_overrides_environment_variables(tmp_path: Path) -> None:
    """CLI 命令行参数应优先于 MCP_TRAFFIC_INSPECTOR_* 环境变量。"""
    env_db = tmp_path / "env.db"
    cli_db = tmp_path / "cli.db"
    env = {
        "MCP_TRAFFIC_INSPECTOR_TRANSPORT": "stdio",
        "MCP_TRAFFIC_INSPECTOR_HOST": "127.0.0.1",
        "MCP_TRAFFIC_INSPECTOR_PORT": "8000",
        "MCP_TRAFFIC_INSPECTOR_TSHARK_PATH": "/env/tshark",
        "MCP_TRAFFIC_INSPECTOR_DB_PATH": str(env_db),
        "MCP_TRAFFIC_INSPECTOR_LOG_LEVEL": "ERROR",
    }
    argv = [
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "8888",
        "--tshark-path",
        "/cli/tshark",
        "--db-path",
        str(cli_db),
        "--log-level",
        "WARNING",
        "--doctor",
    ]

    cfg = parse_config(argv=argv, env=env)

    assert cfg.transport == "streamable-http"
    assert cfg.host == "0.0.0.0"
    assert cfg.port == 8888
    assert cfg.tshark_path == "/cli/tshark"
    assert cfg.db_path == cli_db.resolve()
    assert cfg.preserve_db is True
    assert cfg.log_level == "WARNING"
    assert cfg.check is True


def test_parse_config_version_and_help_exit_cleanly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """传入 -v/--version 与 -h/--help 时应输出对应文本并以状态码 0 退出。"""
    with pytest.raises(SystemExit) as ver_exc:
        parse_config(argv=["--version"], env={})
    assert ver_exc.value.code == 0
    ver_out = capsys.readouterr().out
    assert f"mcp-server-traffic-inspector {__version__}" in ver_out

    with pytest.raises(SystemExit) as help_exc:
        parse_config(argv=["--help"], env={})
    assert help_exc.value.code == 0
    help_out = capsys.readouterr().out
    assert "MCP_TRAFFIC_INSPECTOR_TRANSPORT" in help_out
    assert "--check" in help_out


def test_configure_logging_writes_only_to_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """配置日志后，所有日志记录必须输出至 stderr 流，绝不污染 stdout。"""
    stderr_buf = io.StringIO()
    logger = configure_logging(log_level="INFO", stream=stderr_buf)

    logger.info("MCP 服务初始化完成")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "MCP 服务初始化完成" in stderr_buf.getvalue()
