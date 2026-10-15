# 0008. 标准二元流水线模型与统一发版编排架构 (Dual-Workflow Standard and Unified Release Orchestration)

状态：accepted

面向开源工程持续交付过程中的算力冗余、多流竞态、环境矩阵繁杂及发布渠道割裂痛点，深度对标 `atengk/oss-template` 工业级流水线标准，确立如下核心架构决策：

1. **二元工作流模型收敛与清晰职责划分 (`DualWorkflowStandard`)**：
   将原本分散割裂的 `ci.yml`、`docker.yml` 与 `publish.yml` 彻底合流收敛，废除各自触发导致的重复构建与标签竞态。全工程仅维护标准二元工作流：
   - `ci.yml`：专注于 Pull Request 与主干推送的自动化质量门禁、脚本安全审查与跨版本兼容性矩阵验证；
   - `release.yml`：专注于语义化版本 Tag 发布的不可变单次制品构建与全渠道扇出交付。

2. **变更影响面前置评估与短路网关 (`ShortCircuitGateway`)**：
   在 CI 流水线入口引入 `dorny/paths-filter@v4`，精准识别源码、工程配置与纯文档资产变更：
   - 针对纯 Markdown 文档、架构图、Issue 模板及配置说明改动，直接短路跳过耗时的依赖安装与测试矩阵；
   - 通过聚合网关任务 `all-checks-passed` 统一输出终审通过状态戳记，既严格满足 GitHub Branch Protection 保护规则，又杜绝无谓的 Actions 算力与排队损耗。

3. **分层兼容性矩阵与高性能工具链加速**：
   全面继承并深化工程原生的 `astral-sh/setup-uv` 高效包管理器与环境缓存机制：
   - 在 Pull Request 阶段执行 Python 3.12 极速冒烟测试，为开发者提供秒级门禁反馈；
   - 在主干推送阶段自动展开至 `["3.11", "3.12", "3.13"]` 跨版本兼容性测试矩阵，并结合 ShellCheck 对仓库内所有 Shell 脚本进行静态语法安全审计。

4. **不可变单次构建与全渠道扇出交付 (`UnifiedReleaseOrchestrator`)**：
   在发版编排器中落实“单次构建，多处交付”原则：
   - 由独立构建作业通过 `uv build` 单次产出不可变分发包（sdist / wheel），并提取生成标准 SHA-256 校验和清册（`checksums-sha256.txt`）；
   - 以并行扇出（Fan-Out）模式分发至 GitHub Releases（自动归档制品与校验和）、PyPI（基于 OIDC Trusted Publishing 实现零密钥凭据发布，并保留 API Token 容灾）、以及 GHCR（通过 Buildx / QEMU 构建 `linux/amd64` 与 `linux/arm64` 双架构生产级容器镜像）；
   - 发版末尾自动聚合各渠道交付状态，在 GitHub Actions Step Summary 输出富文本发布看板。
