# 0001. 主控与抓包工作进程解耦架构 (Controller-Worker Process Decoupling)

状态：accepted

MCP Server 主控进程（FastMCP）与底层流量捕获引擎（`mitmdump` 代理及 `tshark` 抓包器）采用受控操作系统子进程方式解耦运行，而非在单一 Python 进程内共享或嵌套 `asyncio` 事件循环。

`mitmproxy` 内部深度绑定自定义事件循环与信号处理，若直接嵌入 FastMCP 进程内运行，高并发代理流量或 TLS 握手阻塞极易导致 MCP `stdio`/`sse` JSON-RPC 通信管道饥饿甚至死锁。通过子进程隔离，主控进程可随时对抓包引擎执行启停、超时熔断与异常清理，确保与 AI 客户端的协议通道永不中断。
