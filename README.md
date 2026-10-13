# mcp-server-traffic-inspector

<p align="center">
  <strong>专为 AI Agent / LLM 打造的网络流量抓包、会话检索、底层链路诊断、请求重放与规则 Mock 全功能 MCP Server</strong>
</p>

<p align="center">
  <a href="https://github.com/atengk/mcp-server-traffic-inspector/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/atengk/mcp-server-traffic-inspector/ci.yml?branch=main&label=CI&style=flat-square" alt="CI Status" />
  </a>
  <a href="https://github.com/atengk/mcp-server-traffic-inspector/releases">
    <img src="https://img.shields.io/github/v/release/atengk/mcp-server-traffic-inspector?style=flat-square" alt="Release" />
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square" alt="License" />
  </a>
  <a href="./CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome" />
  </a>
</p>

---

## 📖 项目简介

`mcp-server-traffic-inspector` 是一款基于 Python 构建的工业级网络流量巡检与抓包 Model Context Protocol (MCP) Server。采用 **主控与受控子进程解耦架构**，通过共享 SQLite WAL 数据总线连接应用层（L7 `mitmproxy`）与传输层（L3/L4 `tshark`），赋予 AI Agent 完整的“开启抓包 -> 触发流量 -> 检索明细 -> 参数变异重放 / 规则 Mock -> 输出全栈诊断报告”闭环能力。

---

## ✨ 核心特性

- 🌐 **应用层 (L7) 流量拦截与操控**：基于受控 `mitmdump` 后台进程捕获 HTTP/HTTPS 流量，支持多条件分页检索、基于 `httpx` 的参数变异重放（Replay & Diff）及 SQLite 热同步非阻塞规则 Mock。
- 📡 **网络层 (L3/L4) PCAP 捕获与协议剖析**：集成 Wireshark `tshark` 引擎，支持网卡枚举、带双重安全熔断阈值（默认 2000 包 / 60 秒）的实时抓包及离线 `.pcap`/`.pcapng` 深度分析（TCP 重传率、RTT 时延、DNS 耗时）。
- 🩺 **一键全栈链路诊断**：自动聚合 HTTP 慢请求 Top 5、状态码分布、高频端点与底层 TCP/DNS 指标，输出结构化健康度与根因分析报告。
- 🛡️ **LLM 上下文防爆保护**：列表接口仅返回轻量元数据；详情接口自动解压并默认截断至 2048 字符，超大或二进制 Payload 支持一键落盘为本地文件。
- 🔌 **双模传输与跨平台部署**：默认支持本地 `stdio` 模式直连桌面客户端（Claude Desktop / Antigravity / Cursor），同时支持 `--transport sse` 模式及 Docker 容器化服务器端部署。

---

## 🛠️ 快速开始

### 1. 环境准备

- **Python**：`>= 3.11`（推荐使用 [`uv`](https://docs.astral.sh/uv/) 管理依赖与虚拟环境）
- **Wireshark / tshark**：用于 PCAP 实时捕获与底层协议分析（Windows 默认探测系统 `PATH` 或 `C:/Program Files/Wireshark/tshark.exe`；Docker 镜像已内置 `tshark`）

```bash
# 克隆仓库并激活 Git 规范提交守门钩子
git clone https://github.com/atengk/mcp-server-traffic-inspector.git
cd mcp-server-traffic-inspector
git config core.hooksPath .githooks

# 使用 uv 同步安装依赖
uv sync --all-extras --dev
```

### 2. 运行方式

#### 方式 A：本地 `stdio` 模式（默认，供桌面 MCP 客户端调用）

```bash
uv run mcp-server-traffic-inspector
```

在 MCP 客户端配置文件中添加：

```json
{
  "mcpServers": {
    "traffic-inspector": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/mcp-server-traffic-inspector",
        "run",
        "mcp-server-traffic-inspector"
      ]
    }
  }
}
```

#### 方式 B：远程服务器 `sse` / `streamable-http` 模式与 Docker 容器部署

```bash
# 直接命令行以 SSE 模式启动 (监听 8000 端口)
uv run mcp-server-traffic-inspector --transport sse --host 0.0.0.0 --port 8000

# 执行环境自检 (检查 mitmdump、tshark、CA 证书与临时目录状态)
uv run mcp-server-traffic-inspector --check

# 或使用 Docker 容器运行 (8000 为 MCP SSE 端口，8080 为 HTTP/HTTPS 代理端口)
docker run -d --name traffic-inspector -p 8000:8000 -p 8080:8080 ghcr.io/atengk/mcp-server-traffic-inspector:latest
```

### 3. CLI 参数与环境变量 (`MCP_TRAFFIC_INSPECTOR_*`)

参数优先级：**CLI 命令行参数 > 环境变量 > 默认值**。

| CLI 参数 | 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-h, --help` | - | - | 查看完整命令行帮助信息并退出 |
| `-v, --version` | - | - | 查看当前版本号并退出 |
| `--check` / `--doctor` | - | `False` | 运行环境依赖自检探针（检测 `mitmdump`、`tshark`、CA 证书与存储权限） |
| `-t, --transport` | `MCP_TRAFFIC_INSPECTOR_TRANSPORT` | `stdio` | 传输模式：`stdio`、`sse`、`streamable-http` |
| `--host` | `MCP_TRAFFIC_INSPECTOR_HOST` | `127.0.0.1` | `sse` / `streamable-http` 绑定监听地址 |
| `-p, --port` | `MCP_TRAFFIC_INSPECTOR_PORT` | `8000` | `sse` / `streamable-http` 绑定监听端口 |
| `--tshark-path` | `MCP_TRAFFIC_INSPECTOR_TSHARK_PATH` | 自动探测 | 自定义 `tshark` 可执行文件绝对路径 |
| `--db-path` | `MCP_TRAFFIC_INSPECTOR_DB_PATH` | 系统临时目录 | 自定义 SQLite 数据库路径（显式指定时退出不自动删除） |
| `--log-level` | `MCP_TRAFFIC_INSPECTOR_LOG_LEVEL` | `INFO` | 日志级别：`DEBUG`、`INFO`、`WARNING`、`ERROR` |

---

## 🧰 MCP Tools 能力矩阵 (18 Tools)

| 分类 | 工具名称 | 功能说明 |
| :--- | :--- | :--- |
| **HTTP 抓包生命周期** | `start_http_capture` | 启动受控 `mitmdump` 代理子进程，返回监听端口、会话 ID 与 CA 证书路径 |
| | `stop_http_capture` | 优雅停止 HTTP 抓包代理，返回捕获流统计 |
| | `get_capture_status` | 查询当前代理运行状态、端口、捕获流数量与运行时长 |
| **流量检索与详情** | `list_http_flows` | 按域名、状态码/范围、方法、最小耗时分页检索 HTTP 流摘要 |
| | `get_http_flow_detail` | 查看指定 Flow 的完整请求/响应头与截断预览 Body（支持导出完整文件） |
| **全栈分析与诊断** | `analyze_http_traffic` | 统计慢请求 Top 5、状态码分布、高频接口 Top 10 与流量消耗 |
| | `analyze_pcap_file` | 调用 `tshark` 分析离线 PCAP 的协议分布、TCP 重传率、RTT 与 DNS 指标 |
| | `diagnose_network_session` | 综合 HTTP 或 PCAP 指标生成结构化网络健康度与故障根因诊断报告 |
| **PCAP 原始抓包** | `list_network_interfaces` | 枚举当前主机可用的抓包网卡接口列表 |
| | `start_pcap_capture` | 启动网卡实时抓包（默认施加 2000 包 / 60 秒安全熔断保护） |
| | `stop_pcap_capture` | 停止实时 PCAP 抓包并返回生成的 `.pcap` 文件路径与包数 |
| **重放与规则 Mock** | `replay_http_request` | 基于历史 Flow 修改 URL/Headers/Body 后重放请求，并输出新旧响应 Diff |
| | `add_intercept_rule` | 动态下发非阻塞 Mock 响应或请求/响应头改写规则 |
| | `list_intercept_rules` | 查看当前生效的全部动态拦截与改写规则 |
| | `clear_intercept_rules` | 一键清空所有动态拦截规则 |
| **系统代理与辅助** | `get_ca_certificate` | 获取 `mitmproxy` CA 根证书路径及信任安装指引 |
| | `toggle_system_proxy` | 开启或还原 Windows 系统全局代理（支持退出自动安全还原与跨平台降级提示） |
| | `export_http_session` | 将捕获的 HTTP 会话流量导出为标准 HAR 格式归档文件 |

---

## 🚀 版本发版与发布指南

本项目集成了现代化的多通道自动化发版流水线：

### 方式一：GitHub 网页端一键发版 (`workflow_dispatch`)
前往 GitHub 仓库 **Actions -> Release -> Run workflow**，输入目标版本号（如 `v0.1.0`）即可一键完成打标、Wheel/sdist 编译、SHA-256 校验和生成、Changelog 提取与 Release 发布。

### 方式二：使用本地发版防呆脚本 (`scripts/release.sh`)
```bash
# 安全演练模式（仅自检并预览拟执行动作，零污染 Git 状态）
bash scripts/release.sh --dry-run

# 交互式发版向导（自动同步 pyproject.toml 版本号并推送标签）
bash scripts/release.sh
```

---

## 📂 仓库目录结构

```text
.
├── .github/
│   ├── ISSUE_TEMPLATE/             # Bug 与 Feature 反馈模板及治理配置
│   ├── workflows/
│   │   ├── ci.yml                  # PR 标题守门、ShellCheck、uv + Ruff 静态检查与 pytest 单测
│   │   ├── release.yml             # 自动化发版、Wheel/sdist 打包、Checksums 与 git-cliff 日志
│   │   ├── publish.yml             # PyPI 官方包自动发布 (Trusted Publisher OIDC)
│   │   └── docker.yml              # 多架构 (amd64/arm64) Docker 镜像构建并推送至 GHCR
│   ├── CODEOWNERS                  # 代码属主自动指派配置
│   ├── dependabot.yml              # GitHub Actions、pip 与 Docker 依赖月度自动巡检
│   └── PULL_REQUEST_TEMPLATE.md    # Pull Request 标准模板
├── .githooks/
│   └── commit-msg                  # Git 原生 Conventional Commits 守门钩子
├── scripts/
│   ├── commit.sh                   # 规范化提交助手 (支持交互向导与 AI 静默参数调用)
│   └── release.sh                  # 全生命周期发版防呆脚本 (含 pyproject.toml 版本自动递增)
├── src/
│   └── mcp_server_traffic_inspector/
│       └── __init__.py             # Python 核心源码包
├── tests/                          # 单元测试与端到端测试套件
├── .cliff.toml                     # git-cliff 变更日志生成配置
├── Dockerfile                      # 内置 tshark 与 uv 的多架构容器镜像定义 (默认 SSE 模式)
├── pyproject.toml                  # Python 标准包配置与工具链声明
├── CODE_OF_CONDUCT.md              # 社区行为准则
├── CONTRIBUTING.md                 # 贡献指南与规范说明
├── LICENSE                         # Apache-2.0 开源许可证
├── README.md                       # 项目主文档
└── SECURITY.md                     # 安全策略与漏洞披露指南
```

---

## 🤝 参与贡献

欢迎任何形式的贡献与建议！请在提交代码前仔细阅读我们的 [贡献指南 (CONTRIBUTING.md)](./CONTRIBUTING.md)。

---

## 📄 开源许可证

本项目基于 [Apache License 2.0](./LICENSE) 协议开源。
