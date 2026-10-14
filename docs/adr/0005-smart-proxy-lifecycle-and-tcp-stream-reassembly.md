# 0005. 智能代理所有权生命周期与结构化 TCP 会话流重组架构 (Smart Proxy Lifecycle and Structured TCP Stream Reassembly)

状态：accepted

面向全栈流量采集与协议逆向场景，对系统代理生命周期管理、双轨抓包重定向感知以及四层 TCP 裸流重组确立如下核心架构决策：

1. **系统代理所有权感知（Proxy Ownership Check）与生命周期闭环**：
   在优雅停止 HTTP 抓包代理时（`stop_http_capture`），支持一键复位系统代理；但复位前必须执行注册表所有权安全探测，仅当当前系统全局代理的服务器与端口（如 `127.0.0.1:8080`）严格指向当前受管抓包实例时才触发复位；若系统代理指向第三方代理（如 Clash 7890 端口），则跳过复位并标记提示，防止破坏宿主机既有网络环境。在 `start_http_capture` 中提供可选的 `auto_set_system_proxy` 联动，实现启停单步自愈闭环。

2. **基于 Tshark 结构化字段提取的 Python 轮次 TCP 流重组**：
   对于 PCAP 文件中的裸 TCP 会话流提取（Follow TCP Stream），放弃依赖 `tshark -z follow,tcp` 人类控制台排版文本，采用 `tshark -T fields -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.payload` 输出每帧纯 Hex 载荷，在 Python 运行时按交互轮次（Turn-based Exchange）聚合连续同向报文为结构化 `TcpStreamChunk`，提供精准双向 Hex/ASCII 视图与原始 `.bin` 导出。

3. **双轨抓包 0 包头智能重定向感知**：
   在同时启用全局代理与物理网卡抓包（双轨模式）时，应用层流量已被重定向至回环接口，导致物理网卡切片抓包数为 0。系统结合套接字拓扑（`SocketTimeline`）感知到该拓扑特征后，注入自解释的 `ProxyRedirectionNotice`，并在会话诊断引擎中维持健康状态（100 分），杜绝将正常的代理分流误判为网络故障。
