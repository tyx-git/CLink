# CLink 实施需求

为了顺利推进 CLink 的开发与验证，需要提前准备以下资源和条件：

1. **构建工具链**
   - CMake ≥ 3.24 与 Ninja（或 CLinkMSBuild）用于多平台构建。
   - 支持 C++20 的编译器：MSVC 19.3+/Clang 15+/GCC 12+。
   - clang-tidy、clang-format 等代码质量工具。

2. **开发/测试设备**
   - 至少一台 Windows 11 或 Windows Server 2022 工作站（8 核 CPU、16 GB 内存、50 GB 可用磁盘）。
   - 一台 Linux 服务器（Ubuntu 22.04 或同等 LTS），配置建议 4 vCPU、8 GB 内存、50 GB 存储、≥1 Mbps 上下行带宽，并提供固定公网 IP。

3. **CI/自动化**
   - 可访问的 Git 仓库与 CI 环境（GitHub Actions/GitLab CI/Azure DevOps）。
   - 能够保存构建产物/符号的对象存储或制品仓库。

4. **依赖与凭据**
   - 第三方库获取渠道（fmt、spdlog、Boost.Asio、OpenSSL/BoringSSL、msquic 等）。
   - 证书/密钥管理位置（企业 CA、HSM 或安全文件共享）。

5. **运维配套**
   - 日志与指标汇聚服务（如 Elastic/Prometheus）以便接收 CVPN 输出。
   - 可开放 TCP 9443/UDP 443 等端口的网络环境，允许心跳与管理 RPC。

