# ==============================================================================
# mcp-server-traffic-inspector 容器化镜像构建配置 (支持 linux/amd64, linux/arm64)
#
# 内置 Python 3.12、uv、mitmproxy 与 tshark，默认以 SSE 模式暴露 MCP 服务与抓包代理端口。
# ==============================================================================

FROM python:3.14-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# 安装 tshark (Wireshark CLI) 与根证书组件
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        tshark \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 引入官方 uv 二进制
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# 复制工程描述与源码并安装至系统环境
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN uv pip install --system --no-cache .

# 8000: MCP Server SSE 监听端口
# 8080: mitmdump HTTP/HTTPS 抓包代理默认端口
EXPOSE 8000 8080

ENTRYPOINT ["mcp-server-traffic-inspector"]
CMD ["--transport", "sse", "--host", "0.0.0.0", "--port", "8000"]
