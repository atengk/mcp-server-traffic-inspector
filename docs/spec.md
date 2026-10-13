# mcp-server-traffic-inspector 技术规格说明书 (Technical Specification)

本文档是 `mcp-server-traffic-inspector` 的权威工程规格说明书（Spec）。记录了通过 Grilling 与领域建模收敛出的全部关键决策、系统架构设计、数据库 DDL、以及完整的 18 个 MCP Tools API 契约与非功能性约束。

---

## 1. 项目定位与领域边界

* **项目名称**：`mcp-server-traffic-inspector`
* **目标定位**：专为 AI Agent / LLM 打造的全功能网络流量巡检与抓包 MCP Server。
* **核心价值与边界**：
  * **应用层 (L7)**：基于受控 `mitmdump` 子进程实现七层 HTTP/HTTPS 流量代理拦截、会话（`CaptureSession`）与流（`HttpFlow`）多维检索、参数变异重放（`FlowReplay`）以及非阻塞规则拦截（`InterceptRule`：Mock 响应与请求/响应头改写）。
  * **网络层 (L3/L4)**：基于 `tshark` 实现原始网卡报文捕获（`PcapCapture` 实时抓包）与离线 `.pcap`/`.pcapng` 文件的深度协议分析（TCP 乱序/重传率、RTT 往返延迟、DNS 解析质量）。
  * **诊断与排障**：提供一键式网络会话全栈诊断（`SessionDiagnosis`），将 HTTP 慢请求、错误率分布与底层链路质量综合输出给 Agent。
  * **存储层保真 + 视图层防爆**：底层 SQLite + 临时文件保留完整的 `BodyPayload` 供重放、转储和 HAR 归档导出；MCP 列表工具仅输出轻量元数据，详情工具默认按 2048 字符截断预览并支持显式落盘完整文件。
  * **双模传输与跨平台自适应**：默认 `stdio` 模式直连桌面客户端，支持 `--transport sse` 与多架构 Docker 容器化远程部署；对 `tshark` 寻址及 Windows 系统注册表代理（`winreg`）实施跨平台自适应降级。

---

## 2. 核心架构与领域设计决策

### 2.1 架构决策记录 (ADR 索引)
1. **[ADR-0001：主控与抓包工作进程解耦架构](./adr/0001-controller-worker-process-decoupling.md)**：FastMCP 主控进程常驻，`mitmdump` 与 `tshark` 作为受控后台子进程运行，隔离事件循环阻塞与崩溃风险。
2. **[ADR-0002：基于共享 SQLite WAL 的进程间数据总线与保真存储](./adr/0002-sqlite-wal-shared-data-bus.md)**：单 MCP 实例周期共享同一 SQLite WAL 数据库（`%TEMP%/mcp_traffic_inspector_<pid>.db`），通过 `session_id` 逻辑隔离多次 `CaptureSession`；入库保留完整载荷（> 256KB 自动分流至临时文件），读取时动态截断。
3. **[ADR-0003：非阻塞规则拦截与事后重放替代交互式断点](./adr/0003-non-blocking-rule-interception.md)**：通过 SQLite `intercept_rules` 表热同步 Mock/改写规则，配合 `httpx` 独立重放，杜绝交互式挂起引发客户端超时。

### 2.2 过滤与代理双轨策略
* **`filter_host` 采集过滤语义**：当 `start_http_capture` 指定 `filter_host` 时，`mitmdump` 正常代理转发全部流量以保障客户端不断网，但仅将匹配目标域名的 `HttpFlow` 写入 SQLite。
* **系统代理双轨策略**：默认非侵入（由客户端或被测命令显式指向 `listen_host:port`）；同时提供 `toggle_system_proxy` 工具在 Windows 下自动托管注册表代理，并在进程退出时强制安全还原（Linux/容器环境返回显式代理配置指引）。

---

## 3. 数据模型设计 (SQLite DDL)

数据库文件位置：`%TEMP%/mcp_traffic_inspector_<pid>.db`（开启 `PRAGMA journal_mode=WAL;` 与 `PRAGMA synchronous=NORMAL;`）
超大载荷分流目录：`%TEMP%/mcp_traffic_inspector_bodies_<pid>/`

### 3.1 `http_flows` (`HttpFlow` 元数据索引表)
```sql
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
    request_headers TEXT,              -- JSON 对象字符串
    response_headers TEXT,             -- JSON 对象字符串
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
```

### 3.2 `http_bodies` (`BodyPayload` 保真存储与预览表)
```sql
CREATE TABLE IF NOT EXISTS http_bodies (
    flow_id TEXT PRIMARY KEY,
    request_body_preview TEXT,         -- 解码后前 2048 字符快速预览
    response_body_preview TEXT,        -- 解码后前 2048 字符快速预览
    request_body BLOB,                 -- 原始请求体字节 (≤ 256KB 时直接存库)
    response_body BLOB,                -- 原始响应体字节 (≤ 256KB 时直接存库)
    is_request_binary INTEGER DEFAULT 0,
    is_response_binary INTEGER DEFAULT 0,
    request_body_path TEXT,            -- 超出 256KB 时的本地临时文件绝对路径
    response_body_path TEXT,           -- 超出 256KB 时的本地临时文件绝对路径
    FOREIGN KEY(flow_id) REFERENCES http_flows(id) ON DELETE CASCADE
);
```

### 3.3 `intercept_rules` (`InterceptRule` 动态拦截规则表)
```sql
CREATE TABLE IF NOT EXISTS intercept_rules (
    id TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 1,
    url_pattern TEXT NOT NULL,         -- 支持正则或子串/通配匹配
    action TEXT NOT NULL,              -- 'mock' 或 'modify'
    mock_status INTEGER DEFAULT 200,
    mock_headers TEXT,                 -- JSON 对象字符串
    mock_body TEXT,
    modify_request_headers TEXT,       -- JSON 对象字符串
    modify_response_headers TEXT,      -- JSON 对象字符串
    created_at REAL NOT NULL
);
```

---

## 4. MCP Tools 完整 API 契约 (18 Tools)

### 4.1 HTTP/S 抓包生命周期 (`CaptureSession`)
1. **`start_http_capture`**
   * 入参：`port: int = 8080`, `listen_host: str = "0.0.0.0"`, `filter_host: Optional[str] = None`, `ssl_insecure: bool = True`
   * 响应：`{ "status": "running", "listen_host": str, "port": int, "session_id": str, "db_path": str, "ca_cert_path": str }`
2. **`stop_http_capture`**
   * 入参：无
   * 响应：`{ "status": "stopped", "session_id": Optional[str], "total_captured_flows": int }`
3. **`get_capture_status`**
   * 入参：无
   * 响应：`{ "is_capturing": bool, "listen_host": Optional[str], "port": Optional[int], "session_id": Optional[str], "flow_count": int, "uptime_seconds": float }`

### 4.2 流量检索与详情查询 (`HttpFlow` & `BodyPayload`)
4. **`list_http_flows`**
   * 入参：`limit: int = 20`, `offset: int = 0`, `session_id: Optional[str] = None`, `host: Optional[str] = None`, `status_code: Optional[int] = None`, `status_family: Optional[str] = None`, `method: Optional[str] = None`, `min_duration_ms: Optional[float] = None`, `sort_by: str = "timestamp"`
   * 响应：`{ "total": int, "session_id": Optional[str], "flows": [ { "id": str, "session_id": str, "time": str, "method": str, "url": str, "status_code": Optional[int], "duration_ms": Optional[float], "content_type": Optional[str], "size": int } ] }`（无匹配数据时 `flows` 固定返回 `[]`）
5. **`get_http_flow_detail`**
   * 入参：`flow_id: str`, `include_headers: bool = True`, `include_body: bool = True`, `max_body_chars: int = 2048`, `dump_body_to_file: bool = False`
   * 响应：包含请求行、状态码、耗时、请求/响应 Headers、按 `max_body_chars` 截断的解码文本预览（附带 `truncated: bool` 标识），以及当 `dump_body_to_file=True` 或超大包落盘时的本地文件绝对路径。

### 4.3 全栈分析与诊断 (`SessionDiagnosis`)
6. **`analyze_http_traffic`**
   * 入参：`session_id: Optional[str] = None`
   * 响应：慢请求 Top 5、状态码分布（2xx/3xx/4xx/5xx/error）、高频 API 端点 Top 10、总收发字节数与超大 Payload Top 3。
7. **`analyze_pcap_file`**
   * 入参：`file_path: str`, `display_filter: Optional[str] = None`, `limit: int = 50`
   * 响应：协议分布统计、TCP 重传包数与重传率、RTT 往返时延极值/均值、DNS 解析请求数与耗时分布。
8. **`diagnose_network_session`**
   * 入参：`session_type: str = "http"` (`"http"` 或 `"pcap"`), `target: Optional[str] = None`（当 `"http"` 时为可选 `session_id`，当 `"pcap"` 时为 `.pcap` 文件路径）
   * 响应：结构化健康度评分、异常项清单与根因定位建议（针对高频 4xx/5xx、慢接口、TCP 重传过高或 DNS 慢响应给出明确结论）。

### 4.4 原始网络层捕获 (`PcapCapture`)
9. **`list_network_interfaces`**
   * 入参：无
   * 响应：`[ { "index": int, "name": str, "description": str } ]`（无可用接口时返回 `[]`）
10. **`start_pcap_capture`**
    * 入参：`interface: Union[int, str] = 1`, `output_path: Optional[str] = None`, `bpf_filter: Optional[str] = None`, `max_packets: int = 2000`, `duration_seconds: int = 60`
    * 响应：`{ "status": "capturing", "interface": Union[int, str], "output_file": str, "limits": { "max_packets": int, "duration_seconds": int } }`
11. **`stop_pcap_capture`**
    * 入参：无
    * 响应：`{ "status": "stopped", "pcap_file": Optional[str], "packet_count": int }`

### 4.5 流量操控：重放与规则拦截 (`FlowReplay` & `InterceptRule`)
12. **`replay_http_request`**
    * 入参：`flow_id: str`, `modify_headers: Optional[Dict[str, str]] = None`, `modify_body: Optional[str] = None`, `modify_url: Optional[str] = None`
    * 响应：新响应报文摘要与历史旧响应的对比 Diff（状态码对比、耗时变化、Body 长度与内容差异预览）。
13. **`add_intercept_rule`**
    * 入参：`url_pattern: str`, `action: str = "mock"`, `mock_status: int = 200`, `mock_headers: Optional[Dict[str, str]] = None`, `mock_body: Optional[str] = None`, `modify_request_headers: Optional[Dict[str, str]] = None`, `modify_response_headers: Optional[Dict[str, str]] = None`
    * 响应：`{ "rule_id": str, "action": str, "url_pattern": str, "status": "active" }`
14. **`list_intercept_rules`**
    * 入参：无
    * 响应：`[ { "id": str, "enabled": bool, "url_pattern": str, "action": str, ... } ]`（无规则时返回 `[]`）
15. **`clear_intercept_rules`**
    * 入参：`rule_id: Optional[str] = None`（默认为空清空全部规则；若传入具体 `rule_id` 则仅移除该条规则）
    * 响应：`{ "cleared_count": int, "target_rule_id": Optional[str] }`

### 4.6 辅助与系统运维
16. **`get_ca_certificate`**
    * 入参：无
    * 响应：CA 证书路径（`mitmproxy-ca-cert.pem` / `.cer`）以及 Windows / Linux 证书信任安装指引。
17. **`toggle_system_proxy`**
    * 入参：`enable: bool`, `port: int = 8080`, `host: str = "127.0.0.1"`
    * 响应：`{ "supported": bool, "system_proxy_enabled": bool, "proxy_server": str, "message": str }`
18. **`export_http_session`**
    * 入参：`output_path: str`, `session_id: Optional[str] = None`, `format: str = "har"`
    * 响应：`{ "exported_path": str, "format": "har", "flow_count": int, "file_size_bytes": int }`

---

## 5. CLI 命令行参数与环境变量契约

入口命令：`mcp-server-traffic-inspector`（或 `python -m mcp_server_traffic_inspector`）
参数解析优先级：**CLI 命令行参数 > `MCP_TRAFFIC_INSPECTOR_*` 环境变量 > 内置默认值**。

| CLI 参数选项 | 对应环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-h, --help` | - | - | 输出完整的命令行参数说明、环境变量对照及客户端接入示例并退出 |
| `-v, --version` | - | - | 输出 `mcp-server-traffic-inspector <version>` 版本信息并退出 |
| `--check` / `--doctor` | - | `False` | 执行运行环境自检探针（检查 Python、`mitmdump`、`tshark` 路径与版本、CA 证书及临时目录权限），输出诊断结果后按健康状态返回退出码 `0` 或 `1` |
| `-t, --transport` | `MCP_TRAFFIC_INSPECTOR_TRANSPORT` | `stdio` | MCP 通信传输协议，可选值：`stdio`、`sse`、`streamable-http` |
| `--host` | `MCP_TRAFFIC_INSPECTOR_HOST` | `127.0.0.1` | 在 `sse` 或 `streamable-http` 模式下绑定的监听地址（Docker 容器内默认传入 `0.0.0.0`） |
| `-p, --port` | `MCP_TRAFFIC_INSPECTOR_PORT` | `8000` | 在 `sse` 或 `streamable-http` 模式下绑定的监听端口 |
| `--tshark-path` | `MCP_TRAFFIC_INSPECTOR_TSHARK_PATH` | 自动探测 | 显式指定 `tshark` 可执行文件绝对路径（高于 `PATH` 与 Windows 默认安装路径探测优先级） |
| `--db-path` | `MCP_TRAFFIC_INSPECTOR_DB_PATH` | `%TEMP%/mcp_traffic_inspector_<pid>.db` | 显式指定 SQLite 数据库文件路径；**当显式指定路径时，进程退出后保留该数据库文件不自动删除** |
| `--log-level` | `MCP_TRAFFIC_INSPECTOR_LOG_LEVEL` | `INFO` | 日志输出级别（`DEBUG`、`INFO`、`WARNING`、`ERROR`）；`stdio` 模式下日志强制输出至 `stderr` |

---

## 6. 系统非功能性与鲁棒性防护

1. **孤儿进程清理与异常熔断**：主控 MCP 进程绑定 `atexit` 与信号处理器（`SIGINT`/`SIGTERM`），退出时强制终止存活的 `mitmdump` 与 `tshark` 子进程、确保还原 Windows 系统代理状态，并清理默认临时数据库与分流载荷目录（若用户通过 `--db-path` 显式指定了数据库路径则保留）。
2. **上下文防爆截断**：列表接口绝不携带 Body；详情接口默认截断上限为 2048 字符，二进制内容返回类型与字节大小摘要，支持按需导出文件。
3. **高并发 I/O 隔离**：SQLite 全程开启 WAL 模式，主控查询与 `mitmdump` 子进程流式写入互不阻塞。

