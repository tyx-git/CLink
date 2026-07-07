#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <asio.hpp>

#include "src/share/core/config/configuration.hpp"
#include "src/share/core/logging/logger.hpp"
#include "src/server/core/registry.hpp"
#include "src/share/core/ipc/ipc.hpp"
#include "src/server/core/network/session_manager.hpp"
#include "src/server/core/security/auth.hpp"
#include "src/server/core/policy/engine.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"

#ifndef CLINK_SOURCE_DIR
#define CLINK_SOURCE_DIR "."
#endif

namespace clink::core {

// 返回默认配置文件路径：{源码目录}/config/clink.init.toml
inline std::filesystem::path default_config_path() {
    return std::filesystem::path{CLINK_SOURCE_DIR} / "config" / "clink.init.toml";
}

// daemon 启动参数：身份标签、角色、心跳间隔、配置路径、日志级别和热重载开关
struct ApplicationOptions {
    std::string identity{"clink"};            // 日志中标识自身，如 "clinkd: windows"
    std::string role{"service"};               // 角色："service" 或 "client"
    std::chrono::milliseconds heartbeat_interval{std::chrono::seconds(5)};   // 主循环睡眠间隔
    std::filesystem::path config_path{default_config_path()};                   // 配置文件路径，可被 --config 覆盖
    logging::Level log_level{logging::Level::info};  // 默认日志级别 info
    bool auto_reload_config{false};                   // 是否自动监听配置文件变更并热重载
};

// daemon 主控类：负责所有子系统的生命周期管理（初始化→运行→关停）
class Application {
public:
    explicit Application(ApplicationOptions options = {});

    void initialize();                                           // 阶段一：加载配置、创建子系统、启动 IPC server
    void run();                                                  // 阶段二：启动模块 + io_context 事件循环
    void shutdown(std::chrono::milliseconds timeout = std::chrono::seconds(5)); // 阶段三：逆序关停所有子系统
    void request_stop() noexcept { running_.store(false); }      // 信号处理器调用此方法，主循环检测到 running_=false 后退出

    [[nodiscard]] const ApplicationOptions& options() const noexcept { return options_; }
    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    [[nodiscard]] const config::Configuration& configuration() const noexcept { return configuration_; }
    [[nodiscard]] std::shared_ptr<logging::Logger> logger() const noexcept { return logger_; }
    [[nodiscard]] ModuleRegistry& modules() noexcept { return *module_registry_; }
    [[nodiscard]] const ModuleRegistry& modules() const noexcept { return *module_registry_; }
    [[nodiscard]] network::SessionManager* session_manager() noexcept { return session_manager_.get(); }
    [[nodiscard]] asio::io_context& io_context() noexcept { return io_context_; }
    
    void start_ipc_server(const std::string& address);  // 启动 Named Pipe / Unix Socket IPC 服务端
    ipc::IpcClient& ipc_client();                        // 获取 IPC 客户端（用于 clinkd 主动向外通信）

    // 本地会话状态：断开中 / 连接中 / 已连接 / 断连中
    enum class SessionState {
        Disconnected,
        Connecting,
        Connected,
        Disconnecting
    };

    std::string connect_session(const std::string& endpoint_override = "");  // 发起出站连接（cli 的 connect 命令）
    void disconnect_session();                                                 // 断开当前会话
    std::string get_session_status() const;                                    // 收集会话状态 JSON 字符串

    void reload_configuration();   // 热重载配置：重新加载 toml 并调用 apply_configuration()
    void set_auto_reload(bool enable);

private:
    void initialize_logging();                                    // 根据配置初始化 spdlog 日志系统
    void log_lifecycle(const std::string& stage) const;            // 输出统一格式的生命周期日志
    void load_configuration();                                     // 从 toml 文件加载配置
    bool apply_configuration();                                    // 核心组装方法：创建会话管理器、监听器、模块
    bool apply_process_manager_runtime_configuration();            // 单独重载 PM 运行时配置（SOCKS/注入）
    void start_modules();                                          // 启动所有已注册模块
    void stop_modules();                                           // 停止所有模块
    void setup_config_watcher();                                   // 设置配置文件变更监听
    void start_config_watcher_timer();                             // 启动定时轮询检查配置文件 mtime
    void setup_ipc_handlers();                                     // 注册 IPC 命令到内部操作的分发表
    void on_session_event(network::SessionEvent event, const std::string& session_id); // 会话状态变更回调

    asio::io_context io_context_;                                              // 主异步事件循环
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> io_work_; // 防止 io_context 无任务时退出
    std::thread io_thread_;                                                     // 独立线程跑 io_context
    mutable std::mutex io_thread_state_mutex_;
    std::condition_variable io_thread_stopped_cv_;                              // shutdown 等待 io 线程退出的通知
    bool io_thread_stopped_{false};
    asio::steady_timer config_watcher_timer_{io_context_};                       // 配置文件热重载定时器

    ApplicationOptions options_{};           // 启动参数
    config::Configuration configuration_{};   // 当前生效配置
    bool modules_started_{false};             // 模块是否已启动（防重复 start/stop）
    std::shared_ptr<logging::Logger> logger_;                     // spdlog 日志封装
    std::shared_ptr<ModuleRegistry> module_registry_;             // 模块注册表（管理 Heartbeat/Metrics 等）
    std::shared_ptr<network::SessionManager> session_manager_;    // 会话管理器（数据面核心）
    std::shared_ptr<security::AuthService> auth_service_;         // 认证服务（PSK 鉴权）
    std::shared_ptr<security::CredentialStore> credential_store_; // 凭据存储（Windows DPAPI）
    std::shared_ptr<policy::PolicyEngine> policy_engine_;         // 策略引擎（准入控制）
    std::unique_ptr<ipc::IpcServer> ipc_server_;                  // IPC 服务器（接收 cli 命令）
    std::unique_ptr<ipc::IpcClient> ipc_client_;                  // IPC 客户端
    
    // 进程管理器：管理 SOCKS 代理 + 进程注入链路
    std::shared_ptr<void> process_manager_; // 用 void* 避免在 header 中引入 process_manager 头文件依赖
    
    // 三个原子状态标志位：保证 initialize/run/shutdown 幂等执行
    std::atomic<bool> initialized_{false};          // initialize() 防重入
    std::atomic<bool> running_{false};              // run() 防重入 + 主循环退出条件
    std::atomic<bool> shutdown_called_{false};       // shutdown() 防重入
    std::atomic<bool> control_runtime_ready_{false};  // 控制面运行时是否就绪
    std::atomic<SessionState> session_state_{SessionState::Disconnected}; // 会话状态机
    std::atomic<int> active_session_count_{0};       // 活跃会话数
    mutable std::mutex control_state_mutex_;          // 保护下面几个控制面状态字符串
    std::string session_id_{clink::protocol::control_plane::kValueNone};  // 当前代表会话 ID
    std::string last_connect_phase_{clink::protocol::control_plane::kStatusIdle};    // 上次连接阶段
    std::string last_connect_reason_{clink::protocol::control_plane::kValueNone};    // 上次连接原因码
    std::string last_connect_message_{};                                              // 上次连接详情
    std::string applied_listener_signature_{};   // 当前生效 listener 的配置签名（用于检测变更）
    std::string effective_ipc_address_{};                     // 当前生效的 IPC 地址
    std::string effective_process_manager_signature_{};        // PM 配置签名
    std::string effective_logging_signature_{};                // 日志配置签名

    // 配置签名对比逻辑：重载时比对签名判断哪些配置域发生变化
    // 签名不变则跳过重建，签名变则热加载，某些域（如 ipc.address）标记需重启

    std::atomic<bool> auto_reload_{false};             // 配置文件热重载开关
    std::filesystem::file_time_type last_config_time_;   // 上次检查时的配置文件修改时间
};

}  // namespace clink::core
