# mcp-server-traffic-inspector 领域词汇表 (Context Glossary)

面向 AI Agent 的全栈网络流量抓包、检索、协议诊断、请求重放与动态拦截领域上下文。

## 领域语言 (Language)

**CaptureSession (抓包会话)**:
从调用启动抓包到停止抓包之间的一段逻辑录制周期，以唯一 `session_id` 标识；同一 MCP 服务实例下的多个会话共享底层存储并支持跨会话或按会话检索。
_Avoid_: Connection (连接), Instance (实例), DatabaseFile (数据库文件)

**HttpFlow (HTTP 流)**:
一次完整的七层 HTTP/HTTPS 请求与响应生命周期记录，归属于特定 `CaptureSession`，包含请求行、头部、状态码、耗时及关联的载荷。
_Avoid_: Transaction (事务), Packet (数据包), Connection (连接), RequestRecord (请求记录)

**BodyPayload (报文载荷)**:
隶属于单一 `HttpFlow` 的请求体或响应体数据，底层保持完整原始字节供重放与归档导出使用，向模型呈现时转换为解码后的截断预览文本。
_Avoid_: RawPacket (原始包), StreamChunk (流分片)

**PcapCapture (PCAP 捕获)**:
发生在三层/四层网络接口上的原始数据包录制过程或其产出的 `.pcap`/`.pcapng` 报文文件。
_Avoid_: Flow (流), ProxySession (代理会话), Dump (转储)

**InterceptRule (拦截规则)**:
预设在代理引擎中的非阻塞匹配策略，用于在请求或响应经过代理时自动返回模拟数据（Mock）或改写请求/响应头部（Modify）。
_Avoid_: Breakpoint (断点), Filter (过滤器), FirewallRule (防火墙规则)

**FlowReplay (流重放)**:
基于已捕获的历史 `HttpFlow`，在可选变异其 URL、头部或请求体后重新向目标发起独立请求并对比新旧响应差异的动作。
_Avoid_: Retry (重试), Forward (转发), ProxyPass (代理透传)

**SessionDiagnosis (会话诊断)**:
结合应用层 `HttpFlow` 统计指标或网络层 `PcapCapture` 协议指标，生成的结构化健康度评估与异常根因结论。
_Avoid_: LogAnalysis (日志分析), Trace (链路追踪)

**ProcessFamily (进程家族)**:
由指定目标可执行文件作为根进程及其派生出的全部合法子进程构成的动态进程集合。
_Avoid_: ProcessGroup (进程组), SubprocessList (子进程列表), TaskList (任务列表)

**SocketTimeline (套接字时序流)**:
在抓包生命周期内记录的本地与远端套接字端点、时间戳与进程 PID 绑定关系的时序数据集合。
_Avoid_: PortSnapshot (端口快照), ConnectionHistory (连接历史), SocketCache (套接字缓存)

**CaptureSidecar (捕获伴随元数据)**:
与抓包文件伴随落盘的结构化元数据文件，持久化存储套接字时序与进程拓扑信息供离线分析挂载。
_Avoid_: AuxiliaryFile (辅助文件), TraceMeta (追踪元数据), LogIndex (日志索引)

**ServerTopology (多服务器连接拓扑)**:
归属于特定进程家族或抓包会话的全部远端通信端点画像，按服务 IP、端口、域名/ISP 及网络质量聚合的多维视图。
_Avoid_: NetworkGraph (网络图谱), ServiceMap (服务地图), NodeList (节点列表)

**ProcessTrafficMatrix (进程通信行为矩阵)**:
按进程家族内各主/子进程细分统计的流量消耗、报文计数与协议分布多维矩阵视图。
_Avoid_: ProcessStats (进程统计), ProcessBreakdown (进程细分)

**TcpStream (TCP 会话流)**:
在底层网络抓包文件中由两端四层套接字元组唯一标识、按时间序列连续交互的端到端单向或双向通信流。
_Avoid_: TcpSession (TCP 会话), RawSocket (裸套接字), WireStream (网线流)

**TcpStreamChunk (TCP 流切片)**:
归属于特定 `TcpStream`、由同一方向连续传输的一组应用层报文载荷聚合而成的结构化时序交互块。
_Avoid_: PacketChunk (数据包块), SegmentSlice (段切片), MessageBlock (消息块)

**WebSocketMessage (WebSocket 消息)**:
依托七层 HTTP 握手升级长连接建立后，在客户端与服务端之间双向流转的单条结构化帧载荷单元。
_Avoid_: WsFrame (WS 帧), SocketMsg (套接字消息), PushEvent (推送事件)

**ProxyRedirectionNotice (代理重定向感知通知)**:
在双轨抓包环境下，系统检测到目标流量已被上层代理接管至本地环回而未经过物理网卡时生成的自解释拓扑诊断提示。
_Avoid_: DropWarning (丢包警告), FilterAlert (过滤告警), RouteError (路由错误)

**HarArchive (HAR 归档)**:
遵循 HTTP Archive 1.2 规范的结构化归档文件，用于无损固化与外发交付完整抓包生命周期内的 HTTP 流及长连接帧记录。
_Avoid_: TrafficExport (流量导出), HttpDump (HTTP 转储), SessionLog (会话日志)

