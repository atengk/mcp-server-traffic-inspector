# 0002. 基于共享 SQLite WAL 的进程间数据总线与保真存储 (SQLite WAL Shared Data Bus)

状态：accepted

MCP 主控进程与 `mitmdump` 子进程之间使用开启了 WAL（Write-Ahead Logging）模式的本地共享 SQLite 数据库作为唯一数据总线，并在存储层保留完整报文载荷（超大载荷分流至本地临时文件），仅在 MCP 工具输出层执行 2048 字符截断。

相比于通过标准输入输出管道传输 NDJSON 或暴露内部 REST 接口，SQLite WAL 支持子进程高频并发写入与主控进程复杂多条件过滤、分页、慢请求排序及聚合统计查询互不阻塞。同时，“存储层保真 + 视图层截断”消除了 LLM 上下文防爆与请求重放（`FlowReplay`）、HAR 归档导出及完整文件转储之间的数据完整性矛盾。
