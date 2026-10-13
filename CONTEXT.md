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
