# 0007. 开发者体验深化、受管进程双轨抓包与混沌网络评测架构 (Developer Experience, Supervised Launch and Chaos Injection)

状态：accepted

面向 AI Agent 与真实开发调试场景中常见的证书链摩擦、短生命周期脚本漏包、协议未知及网络脆弱性验证痛点，确立如下核心架构决策：

1. **当前用户证书免提权安装与多运行时环境自适应注入**：
   在 `doctor.py` 与 `server.py` 中提供 `trust_ca_certificate` 能力。在 Windows 平台采用 `certutil -user -addstore Root <ca_path>` 指令，免除管理员 UAC 提权即可将 mitmproxy 根证书注入当前用户受信任根证书库，同时支持生成全套主流非系统信任库运行时环境变量字典（`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` 等），消除 Node.js、Python requests、Go 等工具链的 TLS 握手摩擦。

2. **进程主动受管拉起与第 0 毫秒双轨时空切片绑定 (`SupervisedLaunch`)**：
   引入 `launch_and_inspect_process` 原子工具。在子进程启动瞬间，自动注入 HTTP 代理端点与 CA 证书环境变量；并在第 0 毫秒将其 PID 绑定到底层网络层抓包引擎（`PcapCapture`），实现应用层明文记录与四层原始报文的双轨对齐，彻底解决短生命周期脚本或微服务在代理建立前漏包与多实例端口混淆问题。

3. **动态规则引擎的混沌故障注入与时延仿真 (`ChaosInjection`)**：
   在 `InterceptRule` 规则模型与 `proxy_addon.py` 运行时中扩充 `delay_ms`、`action="abort"` 与 `max_hits`。支持在请求前置注入毫秒级时延仿真慢接口或超时容错，支持直接切断连接（`flow.kill()`）仿真瞬时断网与 ECONNRESET 故障，并通过原子事务计数器在达到指定命中次数后自动失活，为 Agent 自动化韧性测试与重试机制评测提供受控支持。

4. **Agent 上下文保护、全文模糊过滤与全局宏观指标**：
   在 `list_http_flows` 中引入 `query` 模糊过滤（快速匹配完整 URL、路径或主机）与 `compact=True` 紧凑模式。紧凑模式剔除体积庞大的非必要元数据，直接节省 75% 以上的 LLM Context Token；同时响应首部新增 `summary_metrics`（聚合统计当前命中范围内的异常状态数、5xx 数与平均往返耗时），赋予 Agent 零损耗宏观洞察能力。

5. **四层原始报文的启发式协议嗅探与流解构 (`HeuristicDissector`)**：
   在 `pcap.py` 的 `follow_tcp_stream` 回合解析流水线中引入自适应轻量启发式嗅探器。对非明文或未知二进制流执行 TLS Client Hello SNI 域名提取、HTTP/WebSocket 帧特征匹配、Gzip/Zlib 前置解压探测以及可打印 ASCII 连续字符串提炼，使 Agent 在缺乏专有协议插件时仍能快速洞察通信意图与元数据。
