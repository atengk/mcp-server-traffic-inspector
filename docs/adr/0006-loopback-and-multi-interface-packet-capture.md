# 0006. 回环原生套接字分流感知与多网卡协同抓包架构 (Loopback Raw Socket Aware Capture and Multi-Interface Reassembly)

状态：accepted

面向桌面混合型应用（如微端客户端、私有 TCP 协议）及本地 TUN / 代理工具场景，针对底层抓包网络盲区与误导性假阳性诊断确立如下核心架构决策：

1. **端口感知精准协议分流与假阳性根除**：
   重构 `redirection_notice` 判定逻辑。系统通过套接字时序（`SocketTimeline`）感知到 `127.0.0.0/8` 回环通信时，严密比对目标端口与当前受管 HTTP 抓包端口（如 8080）。若仅流经受管代理端口，维持全量 HTTP 明文已记录断言（健康分 100）；若存在非代理端口（如 8000、843、9000 等），则判定为原生套接字流量（`RawSocketTraffic`），发出结构化告警通知并降级健康评分至 60 分（degraded），给出明确引导，彻底消除误导性断言。

2. **跨平台 Loopback 别名自适应解析**：
   在 `start_pcap_capture` 的 `interface` 选项中引入 `"loopback"` 统一语义别名。在 Windows 下自适应枚举并定位 Npcap 的 `\Device\NPF_Loopback` 虚拟适配器，在 Linux/macOS 下自动映射至 `lo` / `lo0`，屏蔽底层驱动命名差异。

3. **基于 Tshark 原生多接口的 MultiInterfaceCapture 协同捕获**：
   当用户传入 `interface="auto"` 或网卡列表时，底层直接利用 Tshark 原生多 `-i` 参数机制（如 `tshark -i <phys> -i <loopback>`）实施多网络接口并发捕获，将物理外联通信与回环原生套接字报文按纳秒时序统一聚合入单一 PCAP 报文文件，消除双轨抓包中的网卡监听盲区。
