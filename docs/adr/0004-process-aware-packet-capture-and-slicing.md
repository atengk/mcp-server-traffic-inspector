# 0004. 进程感知数据包捕获与时空切片架构 (Process-Aware Packet Capture and Spatiotemporal Slicing)

状态：accepted

面向目标进程家族（ProcessFamily）的底层网络抓包采用“全网卡捕获 + 动态套接字时序流（SocketTimeline）采样 + 离线时空对齐切片”，并在落盘时生成伴随元数据（CaptureSidecar），彻底放弃在抓包过程中动态重启 tshark 以刷新 BPF 的方案。

由于 libpcap/Npcap 在捕获启动后无法动态重载内核 BPF 规则，若每次检测到新端口便重启捕获进程，必然导致 TCP 三次握手丢失与报文碎片化。通过全网卡粗捕获并在抓包结束时依据 100ms 采样的 SocketTimeline 执行精准切片，既保证了 TCP 连接生命周期与握手包的 100% 完整性，又生成了与标准以太网完全兼容的干净 PCAP 及用于多服务器拓扑审计的伴随元数据。
