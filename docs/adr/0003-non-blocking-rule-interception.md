# 0003. 非阻塞规则拦截与事后重放替代交互式断点 (Non-blocking Rule Interception over Breakpoints)

状态：accepted

流量操控能力采用“SQLite 规则表热同步的非阻塞拦截（Mock / Header 改写）”加“基于 `httpx` 的事后参数变异重放（`FlowReplay`）”，明确放弃传统抓包工具的交互式挂起断点（Interactive Breakpoints）。

AI Agent 的单次推理与工具调用往返通常耗时数秒至数十秒；若在代理层挂起真实客户端请求等待 LLM 决策放行，必然触发客户端或上游网关的 TCP/HTTP 超时断连。通过预设动态规则与事后独立重放，既满足了异常注入、鉴权改写与接口调试诉求，又保证了被测应用链路的实时响应性。
