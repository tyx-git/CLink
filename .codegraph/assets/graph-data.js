window.CLINK_GRAPH = {
  "meta": {
    "title": "CLink 数据流图",
    "version": "0.2.0",
    "defaultViewId": "home",
    "generatedAt": "2026-06-12T00:00:00Z",
    "description": "CLink daemon、clink CLI、IPC、进程集成、VIF、TLS transport、远端监听、转发与可观测路径的静态数据流模型。"
  },
  "views": [
    {
      "id": "home",
      "title": "总览",
      "description": "从操作员命令与本地应用流量出发，贯穿 IPC、本地 daemon 模块、TLS transport、远端策略、远端转发与遥测的 CLink 运行时全链路地图。",
      "badges": [
        "默认视图",
        "Control plane 控制面",
        "Data plane 数据面",
        "IPv4/IPv6 双栈",
        "运行时"
      ],
      "nodes": [
        "user-script",
        "clink-cli",
        "ipc-client",
        "ipc-server",
        "local-daemon",
        "local-application",
        "socks-server",
        "target-process",
        "hook-dll",
        "process-manager",
        "os-network-stack",
        "virtual-interface",
        "session-manager-local",
        "tls-transport",
        "buffer-pool",
        "remote-listener",
        "remote-auth-policy",
        "session-manager-remote",
        "remote-forwarding",
        "observability"
      ],
      "edges": [
        "user-script-to-cli",
        "cli-to-ipc",
        "ipc-to-local-daemon",
        "ipc-server-to-daemon",
        "daemon-to-socks",
        "local-app-to-socks",
        "socks-to-session-manager",
        "socks-to-process-manager",
        "process-manager-to-target",
        "process-manager-to-hook",
        "hook-to-process-manager",
        "hook-to-local-app",
        "os-stack-to-vif",
        "daemon-to-vif",
        "vif-to-session-manager",
        "local-session-to-transport",
        "transport-to-buffer-pool",
        "tls-to-buffer-pool",
        "transport-to-remote-listener",
        "listener-to-auth-policy",
        "auth-policy-to-remote-session",
        "remote-session-to-forwarding",
        "remote-forwarding-to-os-stack",
        "daemon-to-observability",
        "session-to-observability",
        "transport-to-observability",
        "process-to-observability",
        "remote-to-observability"
      ],
      "groups": [
        "control-plane",
        "local-data-plane",
        "process-integration",
        "transport",
        "remote-edge",
        "observability"
      ],
      "deepDive": {
        "summary": "总览视图跟踪命令与载荷如何跨过本地 daemon 边界，经由可选的进程或 VIF 捕获进入共享会话状态，再穿过 TLS transport，最后从远端转发侧退出。",
        "purpose": "用于快速判断 CLink 控制面、数据面、进程集成、VIF、TLS transport、远端入口与可观测性之间的依赖关系。",
        "runtimeFlow": "clink 先通过 IPC 下发控制意图；本地流量随后从 SOCKS、Hook DLL 或 VIF 汇入 SessionManager；会话帧经 TLS transport 到达远端监听器，再由策略校验后转发。",
        "moduleComposition": "本地由 clink、IPC server、clinkd、SOCKS server、ProcessManager、VIF 与 SessionManager 协作；远端由 TLS listener、认证策略、远端 SessionManager 与 remote forwarding 协作。",
        "sourceReadingPath": "建议先读 src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md 理解控制契约，再看 src/server/core/network/session_manager.cpp、src/server/core/network/tls_adapter.cpp 与 src/server/modules/socks_server/socks_server.cpp 串起数据路径。",
        "importantStates": [
          "daemon 是否运行并接受 IPC 请求。",
          "SOCKS、ProcessManager、VIF 等捕获模块是否按配置启用。",
          "SessionManager 中会话打开、排队、关闭与背压状态。",
          "TLS transport 握手、读写与错误状态。",
          "远端策略是否允许创建转发会话。"
        ],
        "edgeCases": [
          "本地只启用 SOCKS 或只启用 VIF 时，数据仍应汇入同一 SessionManager。",
          "IPv4/IPv6 目标必须在捕获、会话、TLS transport 与远端转发之间保持一致。",
          "进程 Hook 安装失败时不应影响显式 SOCKS 路径。",
          "远端拒绝策略时应关闭会话并保留可诊断日志。"
        ],
        "riskBoundaries": [
          "IPC 是短生命周期 clink 与长期运行 clinkd 的本地进程边界。",
          "Hook DLL 与 ProcessManager 跨越进程与权限边界。",
          "VIF 路径跨越路由与虚拟网卡权限边界。",
          "TLS transport 与 remote forwarding 跨越远端访问边界。"
        ],
        "debuggingChecklist": [
          "先确认 clink 命令是否收到 IPC 响应。",
          "检查 daemon 日志中的模块启动、监听地址与配置拒绝信息。",
          "查看 SessionManager 计数器确认流量是否创建会话。",
          "用 TLS adapter 与可靠性测试定位 transport 层读写问题。",
          "用远端转发日志确认目标连接和关闭原因。"
        ],
        "dualStackReview": [
          "检查监听地址、VIF 路由、SOCKS 目标和远端转发目标是否保留 IPv4/IPv6 语义。",
          "避免把 hostname、IPv4 literal、IPv6 literal 在会话元数据中折叠成错误地址族。",
          "确认策略约束不会意外暴露或屏蔽某个地址族。"
        ],
        "testsToRead": [
          "tests/ipc_linux_test.cpp：覆盖本地 IPC 基础路径。",
          "tests/server/socks_server_test.cpp：覆盖 SOCKS 握手与目标解析。",
          "tests/network/session_manager_test.cpp：覆盖会话生命周期。",
          "tests/network/tls_adapter_test.cpp：覆盖 TLS transport 行为。",
          "tests/application_connect_test.cpp：覆盖端到端连接。"
        ],
        "sections": [
          {
            "title": "Control plane 控制面建立",
            "body": "自动化脚本调用 clink，CLI 通过 IPC client 序列化控制请求，daemon 侧 IPC server 校验后分发给 daemon 模块。"
          },
          {
            "title": "本地数据捕获",
            "body": "流量可以来自 SOCKS、进程 Hook 集成或 VIF，随后汇聚到本地 SessionManager。"
          },
          {
            "title": "安全传输与远端转发",
            "body": "本地 SessionManager 将流量封帧后交给 TLS transport，复用 BufferPool，到达远端监听器，经策略检查后转发到远端 OS network stack。"
          }
        ]
      },
      "type": "overview"
    },
    {
      "id": "cli-control",
      "title": "CLI 控制端",
      "description": "聚焦 user-script、clink CLI 与 IPC client 如何把一次操作转换为 daemon 可执行的控制面请求。",
      "type": "focused",
      "nodes": [
        "user-script",
        "clink-cli",
        "ipc-client",
        "ipc-server",
        "local-daemon",
        "observability"
      ],
      "edges": [
        "user-script-to-cli",
        "cli-to-ipc",
        "ipc-to-local-daemon",
        "ipc-server-to-daemon",
        "daemon-to-observability"
      ],
      "groups": [
        "control-plane",
        "observability"
      ],
      "badges": [
        "CLI",
        "IPC",
        "控制面",
        "短生命周期 client"
      ],
      "deepDive": {
        "summary": "CLI 控制端视图把短生命周期 clink 进程与长期运行 daemon 的控制面分界单独展开。",
        "purpose": "说明 clink CLI 如何承接脚本或人工输入，并把控制意图按共享 protocol schema 交给本地 daemon。",
        "runtimeFlow": "user-script 启动 clink；clink CLI 解析参数和配置路径后创建 IPC client；IPC client 发送请求；daemon 侧 IPC server 接收并分发给 local-daemon，结果再回到 CLI 输出。",
        "moduleComposition": "入口层由 user-script 和 clink-cli 组成，client IPC 逻辑负责序列化，daemon IPC server 负责接入，local-daemon 执行状态变更，observability 记录命令结果和拒绝原因。",
        "sourceReadingPath": "先读 src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md，再看 src/client/core/ipc/ipc.hpp、src/server/core/daemon/daemon.hpp 与 tests/ipc_linux_test.cpp。",
        "importantStates": [
          "CLI 参数是否解析为明确的控制请求。",
          "CLINK_CONFIG_PATH 等环境覆盖是否参与本次命令。",
          "IPC endpoint 是否可达，daemon 是否正在运行。",
          "控制请求是否被 daemon 接受并返回结构化结果。"
        ],
        "edgeCases": [
          "daemon 未运行时 CLI 必须给出可诊断错误。",
          "控制 schema 字段缺失或版本不匹配时应在 IPC 边界被拒绝。",
          "命令完成后 CLI 退出，但 daemon 状态仍由 local-daemon 维护。",
          "重复命令应保持幂等或返回明确的当前状态。"
        ],
        "riskBoundaries": [
          "CLI 与 daemon 之间的 IPC 是本地进程边界。",
          "配置路径和命令参数是控制面信任入口。",
          "CLI 输出不应泄露不必要的 daemon 内部状态。"
        ],
        "debuggingChecklist": [
          "确认 clink 可执行文件来自当前构建输出。",
          "检查 CLI stderr 与返回码，区分解析错误和 daemon 拒绝。",
          "查看 daemon 日志中对应 IPC request id 或命令名称。",
          "对照 CONTROL_PLANE_SCHEMA.md 检查请求字段。"
        ],
        "dualStackReview": [
          "CLI 控制端本身不打开目标 socket，但地址参数必须保留 IPv4/IPv6 字面量格式。",
          "不要在命令解析阶段把 IPv6 冒号分隔地址误当成 host:port 分隔符。",
          "IPC payload 应把地址族语义交给后续 SOCKS、VIF 或 forwarding 处理。"
        ],
        "testsToRead": [
          "tests/ipc_linux_test.cpp：验证 IPC 基础往返。",
          "tests/application_connect_test.cpp：观察 CLI 驱动的端到端路径。",
          "tests/logging/config_test.cpp：理解配置输入如何影响运行时。"
        ]
      }
    },
    {
      "id": "ipc-control-plane",
      "title": "IPC 控制面",
      "description": "聚焦 IPC client、IPC server、local-daemon 与共享 protocol schema 的请求分发边界。",
      "type": "focused",
      "nodes": [
        "clink-cli",
        "ipc-client",
        "ipc-server",
        "local-daemon",
        "observability"
      ],
      "edges": [
        "cli-to-ipc",
        "ipc-to-local-daemon",
        "ipc-server-to-daemon",
        "daemon-to-observability"
      ],
      "groups": [
        "control-plane",
        "observability"
      ],
      "badges": [
        "IPC",
        "protocol schema",
        "daemon 边界",
        "本地控制"
      ],
      "deepDive": {
        "summary": "IPC 控制面视图强调短请求、强契约和 daemon 状态分发之间的关系。",
        "purpose": "帮助审查控制面请求在 IPC 边界上的字段、状态、错误传播和日志证据。",
        "runtimeFlow": "clink CLI 把请求交给 IPC client；IPC client 连接 daemon endpoint；IPC server 读取请求并按 schema 校验；local-daemon 根据命令更新模块或返回状态。",
        "moduleComposition": "IPC client 与 server 是传输封装，CONTROL_PLANE_SCHEMA.md 是字段契约，local-daemon 是命令执行者，observability 记录成功、拒绝和异常。",
        "sourceReadingPath": "从 src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md 开始，然后读 src/client/core/ipc/ipc.hpp、src/server/core/daemon/daemon.hpp 和 tests/ipc_linux_test.cpp。",
        "importantStates": [
          "IPC endpoint 名称或路径是否与平台匹配。",
          "请求字段是否满足 schema。",
          "daemon 是否处于可接受控制命令的生命周期阶段。",
          "响应是否带有足够错误信息供 CLI 呈现。"
        ],
        "edgeCases": [
          "Unix domain socket 或 Windows named pipe 不存在时应快速失败。",
          "daemon 正在关闭时 IPC server 不应启动新的长操作。",
          "未知命令或字段版本漂移必须被拒绝。",
          "部分写入或连接中断应产生明确日志。"
        ],
        "riskBoundaries": [
          "IPC 边界隔离非 daemon 进程与 daemon 内部状态。",
          "schema 字段是兼容性边界，不能由 UI 文案替代。",
          "本地权限和 endpoint 可访问性影响谁能控制 daemon。"
        ],
        "debuggingChecklist": [
          "确认 daemon endpoint 已创建且权限符合预期。",
          "用 IPC 测试复现最小请求。",
          "查看 daemon 日志中的 request parse、dispatch 与 response 记录。",
          "对照 schema 检查新增字段是否有默认值或拒绝路径。"
        ],
        "dualStackReview": [
          "IPC 控制面一般使用 loopback、Unix domain socket 或 named pipe，不直接承载 IPv4/IPv6 payload。",
          "如果控制请求包含 bind 或 target 地址，应在 schema 中保留地址族信息。",
          "不要让 IPC 层做会破坏 IPv6 literal 的字符串拼接。"
        ],
        "testsToRead": [
          "tests/ipc_linux_test.cpp：控制面 IPC 契约。",
          "tests/logging/config_test.cpp：配置输入与错误路径。",
          "tests/application_connect_test.cpp：控制面启动数据面后的整体行为。"
        ]
      }
    },
    {
      "id": "daemon-lifecycle",
      "title": "daemon 生命周期",
      "description": "聚焦 local-daemon 如何启动、配置、启停 SOCKS、VIF、ProcessManager、SessionManager 与 observability。",
      "type": "focused",
      "nodes": [
        "ipc-server",
        "local-daemon",
        "socks-server",
        "process-manager",
        "virtual-interface",
        "session-manager-local",
        "tls-transport",
        "observability"
      ],
      "edges": [
        "ipc-server-to-daemon",
        "daemon-to-socks",
        "daemon-to-vif",
        "socks-to-session-manager",
        "vif-to-session-manager",
        "local-session-to-transport",
        "daemon-to-observability",
        "session-to-observability",
        "transport-to-observability"
      ],
      "groups": [
        "control-plane",
        "local-data-plane",
        "process-integration",
        "transport",
        "observability"
      ],
      "badges": [
        "daemon",
        "生命周期",
        "模块编排",
        "配置开关"
      ],
      "deepDive": {
        "summary": "daemon 生命周期视图把 clinkd 的启动、模块启停、运行期状态和关闭路径放在同一导航页。",
        "purpose": "呈现 clinkd 作为长期进程如何根据控制面和配置协调各运行时模块。",
        "runtimeFlow": "IPC server 把命令交给 local-daemon；daemon 初始化配置和日志，按开关启动 SOCKS、ProcessManager、VIF、SessionManager 与 TLS transport；关闭时按依赖顺序停止监听、清理 session 和释放资源。",
        "moduleComposition": "local-daemon 是编排中心；SOCKS、ProcessManager、VIF 是本地捕获模块；SessionManager 管理会话；TLS transport 连接远端；observability 贯穿启动、运行和关闭。",
        "sourceReadingPath": "先看 README.md 的运行时开关，再读 src/server/core/daemon/daemon.hpp、src/share/core/config/configuration.cpp、src/server/core/network/session_manager.cpp。",
        "importantStates": [
          "daemon 是否已完成配置加载。",
          "CLINK_DISABLE_VIF 与 CLINK_DISABLE_PROCESS_MANAGER 是否改变模块集合。",
          "监听 socket 与 VIF adapter 是否启动成功。",
          "活动 session 是否允许关闭或需要 drain。"
        ],
        "edgeCases": [
          "配置错误时应阻止半初始化模块继续运行。",
          "某个可选模块失败不应破坏已启用的独立路径，除非配置要求强依赖。",
          "关闭过程中应避免新 session 进入。",
          "transport 断开时 daemon 应传播 session close 并保留诊断信息。"
        ],
        "riskBoundaries": [
          "daemon 持有本地权限、监听端口和模块生命周期。",
          "VIF 与 ProcessManager 可能跨越提权或进程边界。",
          "配置文件决定暴露面和远端访问能力。"
        ],
        "debuggingChecklist": [
          "检查 daemon 启动日志中的配置摘要和模块启停顺序。",
          "确认禁用开关是否生效。",
          "观察 SessionManager active session 计数是否在关闭后归零。",
          "用 transport 与 application 测试区分 daemon 编排问题和网络问题。"
        ],
        "dualStackReview": [
          "daemon 的 bind、route 和 forwarding 配置都应显式考虑 IPv4/IPv6。",
          "关闭某个捕获模块不应改变其他模块的地址族处理。",
          "日志中应保留地址族，方便判断 dual-stack bind 或 route 问题。"
        ],
        "testsToRead": [
          "tests/application_connect_test.cpp：端到端 daemon 行为。",
          "tests/network/session_manager_test.cpp：session 生命周期。",
          "tests/network/reliability_test.cpp：关闭和异常传播。",
          "tests/logging/config_test.cpp：配置加载与日志。"
        ]
      }
    },
    {
      "id": "tcp-tls-dual-stack",
      "title": "TCP/TLS 与 IPv4/IPv6",
      "description": "聚焦 session frame 经 TCP/TLS transport 穿越本地与远端，同时保留 IPv4/IPv6 目标语义。",
      "type": "focused",
      "nodes": [
        "session-manager-local",
        "tls-transport",
        "buffer-pool",
        "remote-listener",
        "remote-auth-policy",
        "session-manager-remote",
        "remote-forwarding",
        "os-network-stack",
        "observability"
      ],
      "edges": [
        "local-session-to-transport",
        "transport-to-buffer-pool",
        "tls-to-buffer-pool",
        "transport-to-remote-listener",
        "listener-to-auth-policy",
        "auth-policy-to-remote-session",
        "remote-session-to-forwarding",
        "remote-forwarding-to-os-stack",
        "transport-to-observability",
        "session-to-observability",
        "remote-to-observability"
      ],
      "groups": [
        "transport",
        "remote-edge",
        "observability"
      ],
      "badges": [
        "TCP/TLS",
        "IPv4/IPv6",
        "remote listener",
        "SessionManager"
      ],
      "deepDive": {
        "summary": "TCP/TLS 与 IPv4/IPv6 视图把 transport socket、安全 channel 和目标地址族分开审查。",
        "purpose": "用于审查加密 transport、远端入口和 dual-stack 元数据在整条数据面上的一致性。",
        "runtimeFlow": "本地 SessionManager 把 payload 封为 frame；TLS transport 通过 TCP/TLS 连接 remote-listener；远端策略批准后，远端 SessionManager 重建 stream 并交给 remote-forwarding 打开 IPv4 或 IPv6 目标。",
        "moduleComposition": "SessionManager 负责 framing 与 close 传播，TLS transport 负责加密 I/O，BufferPool 降低分配压力，remote listener 与 auth policy 控制入口，remote forwarding 负责最终 TCP 连接。",
        "sourceReadingPath": "按顺序阅读 src/server/core/network/session_manager.cpp、src/server/core/network/tls_adapter.cpp、src/server/core/network/transport_listener.hpp、src/server/core/network/transport_adapter.hpp 和 tests/network/tls_adapter_test.cpp。",
        "importantStates": [
          "TLS handshake 是否完成。",
          "transport socket 当前使用 IPv4 还是 IPv6。",
          "session frame 队列是否存在背压。",
          "远端 policy 是否允许目标地址族。"
        ],
        "edgeCases": [
          "TLS 证书或配置不匹配会阻断所有 session。",
          "IPv6 literal 与端口组合格式错误会导致远端目标解析失败。",
          "transport 断流时本地和远端 session 都应收到 close。",
          "BufferPool 压力过高可能放大延迟。"
        ],
        "riskBoundaries": [
          "TLS transport 是离开本地主机的安全边界。",
          "remote listener 是远端暴露边界。",
          "remote forwarding 是访问远端网络的授权边界。"
        ],
        "debuggingChecklist": [
          "先确认 TLS adapter 测试是否通过。",
          "查看 handshake、record read/write 和 close 日志。",
          "检查 session id 在本地与远端日志中是否连续。",
          "确认远端目标地址族和 policy 判断一致。"
        ],
        "dualStackReview": [
          "transport 连接地址族与被转发目标地址族可以不同，二者不能混淆。",
          "IPv4-mapped IPv6 地址需要明确处理策略。",
          "remote listener bind 到 :: 时要确认是否同时接受 IPv4。",
          "日志和 telemetry 应记录目标地址族。"
        ],
        "testsToRead": [
          "tests/network/tls_adapter_test.cpp：TLS transport 行为。",
          "tests/network/tcp_framing_test.cpp：TCP framing 与 session payload。",
          "tests/network/reliability_test.cpp：断流和关闭传播。",
          "tests/application_connect_test.cpp：真实连接路径。"
        ]
      }
    },
    {
      "id": "socks-forwarding",
      "title": "SOCKS 转发",
      "description": "聚焦 local-application 通过 SOCKS server 进入 SessionManager，再经 TLS 到远端 forwarding 的路径。",
      "type": "focused",
      "nodes": [
        "local-application",
        "socks-server",
        "process-manager",
        "session-manager-local",
        "tls-transport",
        "remote-listener",
        "session-manager-remote",
        "remote-forwarding",
        "os-network-stack",
        "observability",
        "local-daemon",
        "remote-auth-policy"
      ],
      "edges": [
        "local-app-to-socks",
        "daemon-to-socks",
        "socks-to-session-manager",
        "socks-to-process-manager",
        "local-session-to-transport",
        "transport-to-remote-listener",
        "auth-policy-to-remote-session",
        "remote-session-to-forwarding",
        "remote-forwarding-to-os-stack",
        "session-to-observability",
        "remote-to-observability"
      ],
      "groups": [
        "local-data-plane",
        "process-integration",
        "transport",
        "remote-edge",
        "observability"
      ],
      "badges": [
        "SOCKS",
        "local application",
        "remote forwarding",
        "显式代理"
      ],
      "deepDive": {
        "summary": "SOCKS 转发视图把显式代理入口、目标解析和远端出口串成单一路径。",
        "purpose": "用于跟踪显式代理路径：应用连接 SOCKS server 后如何形成 tunnel session 并在远端打开目标连接。",
        "runtimeFlow": "local-application 连接 SOCKS server；SOCKS server 完成握手和目标解析；请求进入 SessionManager；TLS transport 发送 frame；远端 SessionManager 经 policy 约束后调用 remote-forwarding。",
        "moduleComposition": "SOCKS server 负责协议解析，ProcessManager 可提供进程上下文，SessionManager 统一生命周期，TLS transport 承载字节，remote forwarding 执行目标连接。",
        "sourceReadingPath": "先读 src/server/modules/socks_server/socks_server.cpp，再读 src/server/core/network/session_manager.cpp、src/server/core/network/tls_adapter.cpp 和 tests/server/socks_server_test.cpp。",
        "importantStates": [
          "SOCKS listener 是否绑定到预期地址。",
          "握手版本、认证选择和 connect request 是否有效。",
          "目标 host、port、地址族是否进入 session 元数据。",
          "远端 forwarding 是否成功打开目标 socket。"
        ],
        "edgeCases": [
          "应用发送不完整 SOCKS 握手时应关闭并记录原因。",
          "域名、IPv4 literal、IPv6 literal 都需要清晰解析。",
          "ProcessManager 不可用时显式 SOCKS 路径仍应工作。",
          "远端连接拒绝应回传给本地应用而不是静默悬挂。"
        ],
        "riskBoundaries": [
          "SOCKS listener 是本地应用进入 tunnel 的访问边界。",
          "目标解析结果决定远端访问范围。",
          "SOCKS 与 ProcessManager 的关联不应扩大授权范围。"
        ],
        "debuggingChecklist": [
          "用 socks_server 测试确认握手和目标解析。",
          "检查 daemon 日志中的 SOCKS accept、connect request 与 session id。",
          "查看远端 forwarding 日志确认目标连接结果。",
          "对失败请求比对本地应用错误和 daemon close 原因。"
        ],
        "dualStackReview": [
          "SOCKS ATYP 字段必须区分 IPv4、domain 和 IPv6。",
          "IPv6 literal 不应在 host:port 拼接中丢失方括号语义。",
          "远端 forwarding 应按 SOCKS 解析出的地址族打开 socket。"
        ],
        "testsToRead": [
          "tests/server/socks_server_test.cpp：SOCKS 协议路径。",
          "tests/application_connect_test.cpp：应用经代理连接。",
          "tests/network/tcp_framing_test.cpp：payload framing。",
          "tests/network/session_manager_test.cpp：会话生命周期。"
        ]
      }
    },
    {
      "id": "process-injection",
      "title": "进程注入链路",
      "description": "聚焦 ProcessManager、target-process、Hook DLL、Hook IPC、MinHook 与 SOCKS/session 之间的跨进程链路。",
      "type": "focused",
      "nodes": [
        "local-daemon",
        "socks-server",
        "target-process",
        "hook-dll",
        "process-manager",
        "local-application",
        "session-manager-local",
        "observability"
      ],
      "edges": [
        "daemon-to-socks",
        "socks-to-process-manager",
        "process-manager-to-target",
        "process-manager-to-hook",
        "hook-to-process-manager",
        "hook-to-local-app",
        "socks-to-session-manager",
        "process-to-observability",
        "session-to-observability"
      ],
      "groups": [
        "local-data-plane",
        "process-integration",
        "observability"
      ],
      "badges": [
        "ProcessManager",
        "Hook IPC",
        "MinHook",
        "进程边界"
      ],
      "deepDive": {
        "summary": "进程注入链路视图单独标出 ProcessManager、Hook DLL、Hook IPC 和 MinHook 带来的权限与调试边界。",
        "purpose": "说明 Windows-only 进程集成如何在不改应用代码的情况下把目标进程流量导入 CLink。",
        "runtimeFlow": "local-daemon 启动 ProcessManager；ProcessManager 选择 target-process 并注入 Hook DLL；Hook DLL 通过 MinHook 拦截网络调用，经 Hook IPC 把意图交回 ProcessManager 或引导 local-application 走 SOCKS/session 路径。",
        "moduleComposition": "ProcessManager 负责编排、注入和 Hook IPC；Hook DLL 位于目标进程内；target-process 是被集成应用；SOCKS server 与 SessionManager 继续承担数据面入口；observability 记录注入状态。",
        "sourceReadingPath": "从 src/server/modules/process_inject 与 src/client/modules/process_inject 开始，再对照 CLINK_BUILD_CLIENT_HOOK 构建门控和 tests/application_connect_test.cpp。",
        "importantStates": [
          "CLINK_DISABLE_PROCESS_MANAGER 是否关闭该链路。",
          "CLINK_BUILD_CLIENT_HOOK 是否构建 Hook DLL。",
          "target-process 是否匹配选择规则和权限要求。",
          "Hook IPC 是否建立并报告 hook 安装状态。"
        ],
        "edgeCases": [
          "目标进程权限不足或位数不匹配会导致注入失败。",
          "MinHook 安装部分成功时必须避免破坏目标进程网络调用。",
          "Hook IPC 断开时应回滚或降级，不应造成进程崩溃。",
          "禁用 ProcessManager 时 SOCKS 显式路径仍应可用。"
        ],
        "riskBoundaries": [
          "注入链路跨越 daemon 与 target-process 的进程边界。",
          "Hook DLL 在第三方进程内运行，属于高风险权限边界。",
          "Hook IPC 消息必须被视为跨进程输入。"
        ],
        "debuggingChecklist": [
          "先确认构建是否包含 CLINK_BUILD_CLIENT_HOOK。",
          "查看 ProcessManager 日志中的进程枚举、注入和 Hook IPC 状态。",
          "检查 target-process 内 Hook DLL 加载与 MinHook 安装结果。",
          "用显式 SOCKS 路径对比判断问题是否仅在注入链路。"
        ],
        "dualStackReview": [
          "Hook 应保留应用原始 IPv4/IPv6 目标参数。",
          "Windows socket API 中 sockaddr 与 sockaddr_in6 不能按同一种结构解释。",
          "Hook IPC 中的目标地址族应与 SessionManager 元数据一致。"
        ],
        "testsToRead": [
          "tests/application_connect_test.cpp：端到端行为对照。",
          "tests/server/socks_server_test.cpp：注入降级到 SOCKS 时的入口行为。",
          "tests/network/session_manager_test.cpp：Hook 汇入后的 session 生命周期。"
        ]
      }
    },
    {
      "id": "virtual-interface-vif",
      "title": "虚拟网卡 / VIF",
      "description": "聚焦 OS network stack、Virtual interface、VIF route 与 SessionManager 的透明捕获路径。",
      "type": "focused",
      "nodes": [
        "local-daemon",
        "os-network-stack",
        "virtual-interface",
        "session-manager-local",
        "tls-transport",
        "remote-forwarding",
        "observability"
      ],
      "edges": [
        "os-stack-to-vif",
        "daemon-to-vif",
        "vif-to-session-manager",
        "local-session-to-transport",
        "remote-forwarding-to-os-stack",
        "daemon-to-observability",
        "session-to-observability"
      ],
      "groups": [
        "local-data-plane",
        "transport",
        "remote-edge",
        "observability"
      ],
      "badges": [
        "VIF",
        "Wintun",
        "route",
        "transparent capture"
      ],
      "deepDive": {
        "summary": "虚拟网卡 / VIF 视图把 route、adapter、packet 解析和 session 汇聚作为一个高权限数据入口审查。",
        "purpose": "帮助审查虚拟网卡捕获路径如何从 OS route 接管 packet，并转换为 CLink session。",
        "runtimeFlow": "local-daemon 根据配置启用 VIF；OS network stack 按 route 把 packet 送入 Virtual interface；VIF 解析 packet 并创建 session 事件；SessionManager 经 TLS transport 发送到远端；响应再经远端和本地网络栈返回。",
        "moduleComposition": "local-daemon 负责 VIF 生命周期与 route 指令，OS network stack 负责路由，Virtual interface 负责 packet 捕获，SessionManager 负责 stream 化，observability 提供 route 与 session 证据。",
        "sourceReadingPath": "先读 README.md 中 CLINK_DISABLE_VIF 与 Wintun 相关说明，再看 src/share/core/config/configuration.cpp、src/server/core/network/session_manager.cpp 和 tests/network/session_manager_test.cpp。",
        "importantStates": [
          "CLINK_DISABLE_VIF 是否关闭该路径。",
          "adapter 是否创建并获得必要权限。",
          "route 是否把目标流量导向 VIF。",
          "packet 是否成功映射为 session 元数据。"
        ],
        "edgeCases": [
          "缺少提权或 Wintun 不可用会阻止 adapter 启动。",
          "route 冲突可能导致流量绕过 VIF 或形成回环。",
          "MTU 与分片处理错误会造成部分连接异常。",
          "IPv6 路由缺失时 IPv4 正常但 IPv6 静默失败。"
        ],
        "riskBoundaries": [
          "VIF 修改本机路由和虚拟网卡状态，属于高权限边界。",
          "透明捕获可能覆盖不使用 SOCKS 的应用流量。",
          "route 配置错误可能扩大或缩小捕获范围。"
        ],
        "debuggingChecklist": [
          "检查 daemon 启动日志中的 VIF enable、adapter 和 route 记录。",
          "确认 OS route table 与预期一致。",
          "查看 SessionManager 是否收到来自 VIF 的新 session。",
          "对比禁用 VIF 后 SOCKS 路径是否仍正常。"
        ],
        "dualStackReview": [
          "VIF 必须分别处理 IPv4 header 与 IPv6 header。",
          "IPv4 route 和 IPv6 route 应分别验证。",
          "远端 forwarding 收到的目标地址族应来自 packet 解析结果。",
          "不要把 IPv6 neighbor 或本地链路流量误导入远端 tunnel。"
        ],
        "testsToRead": [
          "tests/network/session_manager_test.cpp：VIF 汇入后的 session 处理。",
          "tests/application_connect_test.cpp：透明路径的端到端对照。",
          "tests/network/reliability_test.cpp：异常关闭与恢复。"
        ]
      }
    },
    {
      "id": "zero-copy-forwarding",
      "title": "零拷贝转发",
      "description": "聚焦 BufferPool、SessionManager 与 TLS transport 之间的 buffer 复用、背压和 payload 传递。",
      "type": "focused",
      "nodes": [
        "socks-server",
        "session-manager-local",
        "tls-transport",
        "buffer-pool",
        "session-manager-remote",
        "remote-forwarding",
        "observability",
        "remote-listener"
      ],
      "edges": [
        "socks-to-session-manager",
        "local-session-to-transport",
        "transport-to-buffer-pool",
        "tls-to-buffer-pool",
        "transport-to-remote-listener",
        "remote-session-to-forwarding",
        "session-to-observability",
        "transport-to-observability"
      ],
      "groups": [
        "local-data-plane",
        "transport",
        "remote-edge",
        "observability"
      ],
      "badges": [
        "BufferPool",
        "zero-copy",
        "memory-pressure",
        "backpressure"
      ],
      "deepDive": {
        "summary": "零拷贝转发视图把 BufferPool 放到 SessionManager 与 TLS transport 的交界处审查。",
        "purpose": "用于审查高吞吐转发中 payload buffer 如何复用，以及背压如何在 session 与 transport 间传播。",
        "runtimeFlow": "SOCKS 或其他入口把 payload 交给 SessionManager；SessionManager 用 BufferPool 管理 frame buffer；TLS transport 加密发送并归还 buffer；远端 SessionManager 与 forwarding 继续流式处理响应。",
        "moduleComposition": "SessionManager 负责生命周期和排队，BufferPool 提供可复用内存，TLS transport 使用 buffer 进行 record I/O，observability 暴露分配压力和吞吐信号。",
        "sourceReadingPath": "先读 src/server/core/memory/buffer_pool.hpp，再读 src/server/core/network/session_manager.cpp、src/server/core/network/tls_adapter.cpp、tests/network/zero_copy_test.cpp。",
        "importantStates": [
          "buffer 是否处于 checked-out 或 returned 状态。",
          "SessionManager 队列是否积压。",
          "TLS transport 写入是否被 peer 背压阻塞。",
          "memory-pressure telemetry 是否升高。"
        ],
        "edgeCases": [
          "buffer 泄漏会让长连接逐步耗尽池容量。",
          "重复归还可能造成数据损坏。",
          "复用 buffer 前未清理敏感字节会产生泄露风险。",
          "过大 payload 或突发流量会触发额外分配和延迟尖峰。"
        ],
        "riskBoundaries": [
          "BufferPool 是内存复用边界，必须保证所有权清晰。",
          "payload 字节可能包含用户数据，复用时要避免跨 session 泄露。",
          "背压策略决定 daemon 资源是否可被流量耗尽。"
        ],
        "debuggingChecklist": [
          "运行 zero-copy 测试确认 checkout 与 return 行为。",
          "查看 SessionManager queue depth 与 active session。",
          "检查 TLS stress 测试中的 allocation 和 latency 信号。",
          "定位 close 路径是否归还所有 buffer。"
        ],
        "dualStackReview": [
          "BufferPool 与地址族无关，但 buffer 携带的 frame 必须关联正确 session 元数据。",
          "IPv4 与 IPv6 连接在高吞吐下应触发相同的归还规则。",
          "不要通过 buffer 内容推断地址族，地址族应来自 session metadata。"
        ],
        "testsToRead": [
          "tests/network/zero_copy_test.cpp：buffer 复用与所有权。",
          "tests/performance/tls_stress_test.cpp：高负载 transport。",
          "tests/network/session_manager_test.cpp：队列与生命周期。",
          "tests/network/tcp_framing_test.cpp：frame payload。"
        ]
      }
    },
    {
      "id": "observability-debugging",
      "title": "观测与调试",
      "description": "聚焦 observability 如何汇聚 daemon、session、transport、process 和 remote forwarding 的诊断信号。",
      "type": "focused",
      "nodes": [
        "local-daemon",
        "session-manager-local",
        "tls-transport",
        "process-manager",
        "remote-forwarding",
        "observability"
      ],
      "edges": [
        "daemon-to-observability",
        "session-to-observability",
        "transport-to-observability",
        "process-to-observability",
        "remote-to-observability"
      ],
      "groups": [
        "control-plane",
        "local-data-plane",
        "process-integration",
        "transport",
        "remote-edge",
        "observability"
      ],
      "badges": [
        "logs",
        "telemetry",
        "debugging",
        "timestamp [LEVEL] [module]"
      ],
      "deepDive": {
        "summary": "观测与调试视图把分散在 daemon、session、transport、process 与 remote 的诊断信号集中展示。",
        "purpose": "提供按信号来源排查 CLink 问题的导航：先定位控制面、数据面、transport、进程集成或远端出口。",
        "runtimeFlow": "local-daemon 记录模块启停；SessionManager 记录 session 生命周期；TLS transport 记录 handshake 与 I/O；ProcessManager 记录注入状态；remote-forwarding 记录目标连接；observability 汇总日志和 counter。",
        "moduleComposition": "每个运行时模块发出日志或 telemetry，observability 节点表示统一的诊断面，日志格式保持 timestamp [LEVEL] [module] message。",
        "sourceReadingPath": "先读 README.md 的运行时 knobs，再看 tests/logging/config_test.cpp、src/server/core/network/session_manager.cpp、src/server/core/network/tls_adapter.cpp 与 process_inject 模块日志。",
        "importantStates": [
          "daemon 启动阶段是否已完成。",
          "session id 是否贯穿本地和远端。",
          "transport 是否处于 handshake、open、closing 或 failed。",
          "ProcessManager 与 VIF 是否按配置启用。"
        ],
        "edgeCases": [
          "缺少 request 或 session id 会让跨模块追踪困难。",
          "日志级别过低可能隐藏策略拒绝或 route 问题。",
          "高频 payload 日志不应泄露用户数据。",
          "远端错误需要回传足够上下文供本地定位。"
        ],
        "riskBoundaries": [
          "日志可能包含地址、进程名和配置路径，应控制敏感信息。",
          "telemetry sample 影响性能与可见性平衡。",
          "debug 输出不能改变数据面时序或扩展访问权限。"
        ],
        "debuggingChecklist": [
          "按时间线排列 CLI、daemon、本地 session、TLS 和远端 forwarding 日志。",
          "确认每个失败都有模块名、错误码或 close reason。",
          "用 CLINK_TELEMETRY_SAMPLE 调整采样观察压力。",
          "把显式 SOCKS、VIF、ProcessManager 路径分开复现。"
        ],
        "dualStackReview": [
          "日志中应显示 IPv4/IPv6 bind、target 或 route，而不是只显示字符串地址。",
          "dual-stack 问题优先检查 listener bind、SOCKS ATYP、VIF route 与 remote target。",
          "IPv6 失败但 IPv4 正常时要查看 policy 和 remote listener 暴露范围。"
        ],
        "testsToRead": [
          "tests/logging/config_test.cpp：日志和配置诊断。",
          "tests/network/reliability_test.cpp：错误与关闭信号。",
          "tests/performance/tls_stress_test.cpp：压力 telemetry。",
          "tests/application_connect_test.cpp：端到端时间线。"
        ]
      }
    },
    {
      "id": "risk-boundary-overview",
      "title": "风险边界总览",
      "description": "聚焦 IPC、ProcessManager、VIF、TLS、remote policy 与 remote forwarding 的权限和数据边界。",
      "type": "focused",
      "nodes": [
        "clink-cli",
        "ipc-server",
        "local-daemon",
        "process-manager",
        "hook-dll",
        "virtual-interface",
        "tls-transport",
        "remote-listener",
        "remote-auth-policy",
        "remote-forwarding",
        "observability",
        "ipc-client",
        "session-manager-local",
        "session-manager-remote"
      ],
      "edges": [
        "cli-to-ipc",
        "ipc-server-to-daemon",
        "process-manager-to-hook",
        "hook-to-process-manager",
        "daemon-to-vif",
        "local-session-to-transport",
        "transport-to-remote-listener",
        "listener-to-auth-policy",
        "remote-session-to-forwarding",
        "remote-to-observability"
      ],
      "groups": [
        "control-plane",
        "process-integration",
        "local-data-plane",
        "transport",
        "remote-edge",
        "observability"
      ],
      "badges": [
        "risk",
        "privilege",
        "remote-access",
        "data-leak"
      ],
      "deepDive": {
        "summary": "风险边界总览视图把各专题中的权限、认证、路由和远端访问边界集中到一页。",
        "purpose": "用于从安全和运维角度快速识别 CLink 中跨进程、跨权限、跨主机和跨网络的边界。",
        "runtimeFlow": "控制命令从 CLI 经 IPC 到 daemon；daemon 可启用 ProcessManager 或 VIF；payload 经 TLS transport 到 remote listener；remote auth policy 决定是否允许 remote forwarding；observability 留下审计线索。",
        "moduleComposition": "IPC server、ProcessManager、VIF、TLS transport、remote listener、auth policy、remote forwarding 是主要边界组件，observability 用于证明边界决策。",
        "sourceReadingPath": "先读 CONTROL_PLANE_SCHEMA.md 和 README.md 的运行时开关，再按风险读 process_inject、configuration.cpp、tls_adapter.cpp、transport_listener.hpp、session_manager.cpp。",
        "importantStates": [
          "谁可以访问 IPC endpoint。",
          "哪些模块需要提权或跨进程执行。",
          "TLS peer 和远端 policy 是否匹配。",
          "remote forwarding 允许访问的目标范围。"
        ],
        "edgeCases": [
          "IPC endpoint 权限过宽会让非预期本地用户控制 daemon。",
          "Hook DLL 或 VIF 启用后影响范围可能超出单个应用。",
          "remote policy 过宽会扩大远端网络访问。",
          "日志不足会让拒绝和越界访问难以审计。"
        ],
        "riskBoundaries": [
          "IPC 是本地控制边界。",
          "ProcessManager 与 Hook DLL 是跨进程边界。",
          "VIF 是路由和虚拟网卡权限边界。",
          "TLS 与 remote listener 是跨主机安全边界。",
          "remote forwarding 是远端网络访问边界。"
        ],
        "debuggingChecklist": [
          "列出当前启用的模块和对应配置来源。",
          "检查 IPC endpoint 权限和 daemon 运行用户。",
          "确认 TLS 配置、远端 bind 和 auth policy。",
          "审查 remote forwarding 日志中是否存在非预期目标。"
        ],
        "dualStackReview": [
          "风险审查要分别列出 IPv4 与 IPv6 暴露面。",
          "remote listener 双栈 bind 可能比单栈 bind 暴露更多入口。",
          "VIF route 与 policy 需要同时覆盖 IPv4/IPv6。",
          "不能只用 IPv4 测试证明 IPv6 安全边界正确。"
        ],
        "testsToRead": [
          "tests/ipc_linux_test.cpp：IPC 边界。",
          "tests/logging/config_test.cpp：配置与审计。",
          "tests/network/tls_adapter_test.cpp：TLS 边界。",
          "tests/application_connect_test.cpp：端到端访问范围。"
        ]
      }
    },
    {
      "id": "source-index",
      "title": "源码索引",
      "description": "按阅读顺序索引 CLink control plane、data plane、transport、process_inject、VIF 与测试入口。",
      "type": "focused",
      "nodes": [
        "user-script",
        "clink-cli",
        "ipc-client",
        "ipc-server",
        "local-daemon",
        "socks-server",
        "process-manager",
        "hook-dll",
        "virtual-interface",
        "session-manager-local",
        "tls-transport",
        "buffer-pool",
        "remote-listener",
        "remote-auth-policy",
        "session-manager-remote",
        "remote-forwarding",
        "observability"
      ],
      "edges": [
        "user-script-to-cli",
        "cli-to-ipc",
        "ipc-to-local-daemon",
        "ipc-server-to-daemon",
        "daemon-to-socks",
        "daemon-to-vif",
        "socks-to-session-manager",
        "process-manager-to-hook",
        "vif-to-session-manager",
        "local-session-to-transport",
        "transport-to-buffer-pool",
        "transport-to-remote-listener",
        "listener-to-auth-policy",
        "auth-policy-to-remote-session",
        "remote-session-to-forwarding",
        "remote-to-observability"
      ],
      "groups": [
        "control-plane",
        "local-data-plane",
        "process-integration",
        "transport",
        "remote-edge",
        "observability"
      ],
      "badges": [
        "source files",
        "tests",
        "CONTROL_PLANE_SCHEMA.md",
        "reading path"
      ],
      "deepDive": {
        "summary": "源码索引视图以文件和测试为主线，把其他专题视图连接成可执行的阅读路径。",
        "purpose": "给代码阅读者提供从契约到运行时再到测试的专题索引，避免在模块迁移目录中迷路。",
        "runtimeFlow": "从 README.md 与 CONTROL_PLANE_SCHEMA.md 建立运行时和控制契约，再沿 CLI、IPC、daemon、SOCKS/VIF/ProcessManager、SessionManager、TLS transport、remote forwarding 的顺序读源码，最后用测试验证理解。",
        "moduleComposition": "索引覆盖 client core、server core、server modules、client modules、share protocol、share config、network tests、logging tests 和 performance tests。",
        "sourceReadingPath": "推荐顺序：src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md、src/client/core/ipc/ipc.hpp、src/server/core/daemon/daemon.hpp、src/server/modules/socks_server/socks_server.cpp、src/server/core/network/session_manager.cpp、src/server/core/network/tls_adapter.cpp、src/server/core/memory/buffer_pool.hpp。",
        "importantStates": [
          "当前阅读目标属于 control plane、local data plane、transport、remote edge 还是 observability。",
          "模块是否位于新目录或兼容 forwarding shim。",
          "测试是否覆盖对应运行时路径。",
          "源码中的配置开关是否与 README.md 一致。"
        ],
        "edgeCases": [
          "旧 include root 可能只是兼容 shim，应继续追到 src/server/core 或 src/client/core。",
          "Windows-only process_inject 代码受 CLINK_BUILD_CLIENT_HOOK 门控。",
          "性能目标可能没有接入 ctest，需要手动运行。",
          "只读单个模块容易忽略 SessionManager 与 transport 的共享状态。"
        ],
        "riskBoundaries": [
          "源码索引不是运行时边界，但会标出需要重点审查的 IPC、Hook、VIF、TLS 和 remote-access 代码。",
          "读取测试时要区分单元覆盖、集成覆盖和性能覆盖。",
          "跨平台代码应注意 Windows 与 WSL 构建目录分离。"
        ],
        "debuggingChecklist": [
          "先用源码索引确定相关 node 的 sourceFiles。",
          "按 edge 的 sourceFiles 查找数据从哪里进入和离开。",
          "在 testsToRead 中找最接近的验证入口。",
          "遇到双栈问题时回到 TCP/TLS 与 IPv4/IPv6 视图交叉检查。"
        ],
        "dualStackReview": [
          "源码阅读时把地址解析、bind、route、forwarding target 四类双栈点分开标记。",
          "检查 tests 是否同时覆盖 IPv4 与 IPv6，未覆盖时以现有行为说明风险。",
          "Windows named pipe、Unix domain socket 与 TCP socket 的地址族语义不要混淆。"
        ],
        "testsToRead": [
          "tests/ipc_linux_test.cpp：control plane 起点。",
          "tests/server/socks_server_test.cpp：SOCKS 入口。",
          "tests/network/session_manager_test.cpp：session core。",
          "tests/network/tls_adapter_test.cpp：TLS transport。",
          "tests/network/zero_copy_test.cpp：BufferPool。",
          "tests/application_connect_test.cpp：端到端验证。"
        ]
      }
    }
  ],
  "nodes": {
    "user-script": {
      "id": "user-script",
      "label": "用户脚本 / 操作员",
      "kind": "control",
      "layer": "entry",
      "position": {
        "x": 60,
        "y": 70
      },
      "summary": "人或自动化入口，负责启动 clink 命令并提供配置覆盖。",
      "inputs": [
        "Shell 参数",
        "环境变量",
        "配置路径覆盖"
      ],
      "outputs": [
        "CLI 命令调用",
        "控制面意图"
      ],
      "sourceFiles": [
        "README.md",
        "CMakePresets.json"
      ],
      "tests": [
        "tests/application_connect_test.cpp"
      ],
      "addressFamilies": [
        "not-applicable"
      ],
      "risk": [
        "low",
        "config"
      ],
      "implementationStatus": "已记录的运行时入口",
      "details": {
        "basic": {
          "role": "在 CLI 联系 daemon 之前提供操作意图和运行时开关。",
          "receives": "接收命令行参数、CLINK_CONFIG_PATH 等环境值以及本地 shell 状态。",
          "emits": "启动带参数的 clink 进程，用这些参数描述期望的 tunnel 操作。",
          "whyItExists": "CLink 让操作控制保持显式，使脚本和人工操作可以使用同一套面向 daemon 的流程。"
        },
        "deep": {
          "codePath": "README.md 说明运行时开关；client build target 产出 clink 可执行文件。",
          "dataFlow": "操作意图会变成结构化 CLI 输入，并被序列化为 IPC payload。",
          "runtimeBehavior": "只有发出命令时该节点才处于活动状态；命令完成后 daemon 仍继续运行。",
          "failureModes": "路径错误、daemon 状态缺失或参数无效，会在 IPC 分发前后表现为 CLI 错误。",
          "debugSignals": "命令 stderr、daemon 日志项和控制面响应可定位被拒绝或格式异常的请求。",
          "ipv4Ipv6Notes": "地址族选择可来自命令或配置值，但这一层不处理数据包。"
        }
      }
    },
    "clink-cli": {
      "id": "clink-cli",
      "label": "clink CLI",
      "kind": "control",
      "layer": "client",
      "position": {
        "x": 220,
        "y": 70
      },
      "summary": "短生命周期 client 进程，把命令转换为本地 daemon IPC 请求。",
      "inputs": [
        "操作员命令",
        "配置文件路径",
        "daemon endpoint 默认值"
      ],
      "outputs": [
        "序列化的控制面请求",
        "面向用户的状态"
      ],
      "sourceFiles": [
        "src/client/core/ipc/ipc.hpp",
        "src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md"
      ],
      "tests": [
        "tests/ipc_linux_test.cpp",
        "tests/application_connect_test.cpp"
      ],
      "addressFamilies": [
        "loopback",
        "unix-domain-socket",
        "windows-named-pipe",
        "not-applicable"
      ],
      "risk": [
        "low",
        "ipc"
      ],
      "implementationStatus": "已实现的 client 控制面参与者",
      "details": {
        "basic": {
          "role": "规范化用户命令，并通过本地 IPC 把持久工作交给 clinkd。",
          "receives": "从用户脚本节点接收参数和命令选项。",
          "emits": "发出 IPC client 调用，并向操作员输出文本状态。",
          "whyItExists": "CLI 与 daemon 分离后，tunnel 状态不会保存在短生命周期命令进程中。"
        },
        "deep": {
          "codePath": "Client IPC 声明位于 src/client/core/ipc，共享协议契约位于 src/share/include/clink/protocol。",
          "dataFlow": "命令字段被编组成符合控制面 schema 的请求 payload。",
          "runtimeBehavior": "进程连接 daemon、等待响应、报告成功或失败，然后退出。",
          "failureModes": "daemon 不可用、schema 不匹配、权限拒绝或超时都会阻止命令完成。",
          "debugSignals": "CLI 状态文本、IPC 错误码和 daemon 侧请求日志可定位失败阶段。",
          "ipv4Ipv6Notes": "CLI 可以传递请求的 bind 或 destination 地址族，但自身不打开数据面 socket。"
        }
      }
    },
    "ipc-client": {
      "id": "ipc-client",
      "label": "IPC client",
      "kind": "control",
      "layer": "client",
      "position": {
        "x": 380,
        "y": 70
      },
      "summary": "clink 用来访问 daemon 的 client 侧本地 IPC 适配器。",
      "inputs": [
        "控制请求对象",
        "daemon IPC endpoint（本地端点）"
      ],
      "outputs": [
        "已封帧 IPC 消息",
        "控制响应"
      ],
      "sourceFiles": [
        "src/client/core/ipc/ipc.hpp",
        "src/share/core/ipc/ipc.hpp",
        "src/share/core/ipc/ipc_linux.cpp",
        "src/share/core/ipc/ipc_win.cpp"
      ],
      "tests": [
        "tests/ipc_linux_test.cpp"
      ],
      "addressFamilies": [
        "unix-domain-socket",
        "windows-named-pipe",
        "loopback"
      ],
      "risk": [
        "medium",
        "ipc",
        "process-boundary"
      ],
      "implementationStatus": "已实现的共享 IPC endpoint client",
      "details": {
        "basic": {
          "role": "把控制面消息带过本地进程边界。",
          "receives": "接收来自 CLI 的序列化请求，以及平台默认的 endpoint 选择。",
          "emits": "向 daemon 侧 IPC server 发送 IPC frame，并把解码后的响应返回给 CLI。",
          "whyItExists": "CLink 需要一个本地且感知平台差异的桥梁，连接短生命周期命令与长期运行的 daemon。"
        },
        "deep": {
          "codePath": "共享 IPC 抽象和平台实现位于 src/share/core/ipc，client wrapper 位于 src/client/core/ipc。",
          "dataFlow": "请求字节离开 CLI，穿过本地 socket 或 pipe，再以响应字节形式返回。",
          "runtimeBehavior": "适配器连接 endpoint，写入一个请求 frame 或 stream payload，读取回复，并在命令完成时关闭。",
          "failureModes": "socket 路径不一致、named-pipe ACL、中断读取和陈旧 daemon endpoint 都可能破坏控制投递。",
          "debugSignals": "IPC 测试、平台 errno 值和 daemon accept 日志可区分连接失败与协议失败。",
          "ipv4Ipv6Notes": "IPC 是本地通信，通常不是 IPv4 或 IPv6 数据流量；loopback transport 仅作为兼容选项存在。"
        }
      }
    },
    "ipc-server": {
      "id": "ipc-server",
      "label": "daemon IPC server",
      "kind": "control",
      "layer": "daemon",
      "position": {
        "x": 540,
        "y": 70
      },
      "summary": "daemon 侧 IPC endpoint，接受来自 clink client 的控制面请求。",
      "inputs": [
        "IPC frame（封帧消息）",
        "共享协议常量",
        "daemon 运行时状态"
      ],
      "outputs": [
        "已校验请求",
        "控制响应"
      ],
      "sourceFiles": [
        "src/server/core/ipc/ipc.hpp",
        "src/share/core/ipc/ipc.hpp",
        "src/share/core/ipc/ipc_message_utils.hpp"
      ],
      "tests": [
        "tests/ipc_linux_test.cpp",
        "tests/server/ipc_proxy_test.cpp"
      ],
      "addressFamilies": [
        "unix-domain-socket",
        "windows-named-pipe",
        "loopback"
      ],
      "risk": [
        "medium",
        "ipc",
        "daemon-lifecycle"
      ],
      "implementationStatus": "已实现的 daemon 控制面 endpoint",
      "details": {
        "basic": {
          "role": "接收本地控制请求，并交给 daemon core 执行。",
          "receives": "接收来自 ipc-client 的封帧消息和 daemon 生命周期信号。",
          "emits": "向 local-daemon 发出已校验操作，并把响应返回给 client。",
          "whyItExists": "daemon 必须通过一个本地控制面边界协调所有 tunnel 状态。"
        },
        "deep": {
          "codePath": "Server IPC 声明位于 src/server/core/ipc，并与 src/share/core/ipc 共享封帧 helper。",
          "dataFlow": "本地 IPC 字节被解码为与 schema 对齐的请求对象，并与响应序列化配对。",
          "runtimeBehavior": "server 随 clinkd 常驻，在 daemon 生命周期内接受多个 client 命令，并保护 daemon 状态更新。",
          "failureModes": "格式错误的 frame、不兼容 schema 版本、endpoint 权限或 daemon 关闭都会导致请求被拒绝。",
          "debugSignals": "daemon 日志、IPC proxy 测试和请求标识可暴露已接受、已拒绝和超时的操作。",
          "ipv4Ipv6Notes": "IPC server 会配置数据面 endpoint，但自身仍是本地 transport 组件。"
        }
      }
    },
    "local-daemon": {
      "id": "local-daemon",
      "label": "clinkd 本地 daemon",
      "kind": "control",
      "layer": "daemon",
      "position": {
        "x": 700,
        "y": 160
      },
      "summary": "长期运行的协调者，拥有本地 tunnel 生命周期、模块、会话与可观测性。",
      "inputs": [
        "已校验控制请求",
        "配置",
        "模块事件",
        "关闭信号"
      ],
      "outputs": [
        "模块命令",
        "会话生命周期变化",
        "遥测事件"
      ],
      "sourceFiles": [
        "src/share/core/config/configuration.cpp",
        "src/server/core/network/session_manager.cpp",
        "src/server/core/observability/telemetry.cpp"
      ],
      "tests": [
        "tests/application_connect_test.cpp",
        "tests/network/session_manager_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "loopback",
        "virtual-adapter",
        "not-applicable"
      ],
      "risk": [
        "medium",
        "daemon-lifecycle",
        "config"
      ],
      "implementationStatus": "已实现的 daemon 运行时协调者",
      "details": {
        "basic": {
          "role": "协调本地模块，并把配置意图转成数据面运行时状态。",
          "receives": "接收 IPC server 的请求、配置值和本地捕获模块事件。",
          "emits": "向 SOCKS、VIF、ProcessManager、SessionManager、transport 和 telemetry 组件发出命令。",
          "whyItExists": "持久 tunnel 状态和共享模块生命周期需要一个超越单次 CLI 调用的权威协调点。"
        },
        "deep": {
          "codePath": "Daemon 行为分布在 src/server/core、src/server/modules 与共享配置工具中。",
          "dataFlow": "控制输入会改变模块状态；数据面模块把事件和 session id 报回 daemon core。",
          "runtimeBehavior": "daemon 启动 listener，负责关闭顺序，监督模块可用性，并记录运行时信号。",
          "failureModes": "配置错误、端口冲突、缺少权限、模块启动失败或 transport 错误可能造成部分服务可用。",
          "debugSignals": "带时间戳的 daemon 日志和 telemetry counter 展示模块启动、会话变化与错误边界。",
          "ipv4Ipv6Notes": "daemon 在选择 listener bind、VIF route 和远端转发目标时必须保留 IPv4 与 IPv6 意图。"
        }
      }
    },
    "local-application": {
      "id": "local-application",
      "label": "本地应用",
      "kind": "data",
      "layer": "local-workload",
      "position": {
        "x": 60,
        "y": 300
      },
      "summary": "其出站流量由 CLink 通过 SOCKS、Hook 或 VIF 捕获并承载的应用。",
      "inputs": [
        "用户工作负载",
        "OS networking API（系统网络接口）",
        "已注入 hook 状态"
      ],
      "outputs": [
        "TCP connect 请求",
        "payload 字节",
        "DNS 或地址选择意图"
      ],
      "sourceFiles": [
        "README.md",
        "src/server/modules/socks_server/socks_server.cpp",
        "src/server/modules/process_manager/process_manager.cpp"
      ],
      "tests": [
        "tests/application_connect_test.cpp",
        "tests/server/socks_server_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "loopback",
        "process"
      ],
      "risk": [
        "medium",
        "data-leak",
        "process-boundary"
      ],
      "implementationStatus": "运行时图谱中表示的外部工作负载",
      "details": {
        "basic": {
          "role": "产生 tunnel 要承载的应用流量。",
          "receives": "接收用户请求、进程级网络调用和可选 hook 指引。",
          "emits": "向 SOCKS、Hook 或 OS networking 路径发出 connect 请求和字节流。",
          "whyItExists": "只有本地工作负载流量能够被捕获并转发时，tunnel 才有价值。"
        },
        "deep": {
          "codePath": "应用行为位于仓库之外；CLink 集成点由 SOCKS 和 ProcessManager 模块表示。",
          "dataFlow": "应用字节通过配置的本地捕获机制进入数据面，并变成 session payload。",
          "runtimeBehavior": "启用 Hook 或 VIF 捕获时应用可能感知不到 CLink；使用 SOCKS 时则需要显式配置。",
          "failureModes": "代理设置错误、不兼容的进程 Hook、路由绕过或不支持的地址族可能导致流量泄漏或丢弃。",
          "debugSignals": "SOCKS accept 日志、ProcessManager 事件和会话创建 telemetry 可确认流量是否到达 CLink。",
          "ipv4Ipv6Notes": "应用可能发出 IPv4 literal、IPv6 literal、hostname 或双栈目标选择，下游节点必须保持这些信息。"
        }
      }
    },
    "socks-server": {
      "id": "socks-server",
      "label": "SOCKS server",
      "kind": "data",
      "layer": "local-capture",
      "position": {
        "x": 240,
        "y": 300
      },
      "summary": "本地 SOCKS listener，接受显式代理流量并转换为 tunnel session。",
      "inputs": [
        "SOCKS handshake（握手数据）",
        "目标地址",
        "应用 payload"
      ],
      "outputs": [
        "session open 请求",
        "已封帧 payload 字节",
        "目标元数据"
      ],
      "sourceFiles": [
        "src/server/modules/socks_server/socks_server.cpp",
        "src/server/modules/socks_server/socks_server.hpp"
      ],
      "tests": [
        "tests/server/socks_server_test.cpp",
        "tests/application_connect_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "loopback"
      ],
      "risk": [
        "medium",
        "remote-access",
        "dual-stack"
      ],
      "implementationStatus": "已实现的本地数据面模块",
      "details": {
        "basic": {
          "role": "接收显式代理连接，并启动对应的 CLink session。",
          "receives": "接收本地应用连接、SOCKS 命令、目标 host 和 port 以及 payload 字节。",
          "emits": "向本地 SessionManager 发出已校验的目标元数据和字节流。",
          "whyItExists": "SOCKS 提供可移植的捕获路径，不要求进程注入或虚拟网卡权限。"
        },
        "deep": {
          "codePath": "SOCKS 模块代码位于 src/server/modules/socks_server，测试位于 tests/server/socks_server_test.cpp。",
          "dataFlow": "handshake 字段建立 session 元数据，之后应用 payload 被流式送入 session-manager-local。",
          "runtimeBehavior": "listener 接受 loopback proxy client，并把每个已接受连接映射为 tunnel session。",
          "failureModes": "不支持的 SOCKS 命令、格式错误的目标、listener bind 失败和 client 断开都会导致 session 拒绝或拆除。",
          "debugSignals": "SOCKS 测试、accept 日志、目标标签和 session counter 可暴露 handshake 与 streaming 失败。",
          "ipv4Ipv6Notes": "server 必须保留 IPv4、IPv6 和 hostname 目标，使远端转发到达预期地址族。"
        }
      }
    },
    "target-process": {
      "id": "target-process",
      "label": "目标进程",
      "kind": "risk",
      "layer": "process-integration",
      "position": {
        "x": 60,
        "y": 500
      },
      "summary": "被选中用于基于 Hook 的网络捕获和策略应用的 Windows 进程。",
      "inputs": [
        "进程标识符",
        "启动或附加请求",
        "Hook payload（注入载荷）"
      ],
      "outputs": [
        "被拦截的网络调用",
        "进程生命周期事件"
      ],
      "sourceFiles": [
        "src/server/modules/process_manager/process_manager.cpp",
        "src/server/modules/process_inject/CMakeLists.txt"
      ],
      "tests": [
        "tests/server/dll_integration_test.cpp"
      ],
      "addressFamilies": [
        "process",
        "ipv4",
        "ipv6"
      ],
      "risk": [
        "high",
        "injection",
        "process-boundary",
        "privilege"
      ],
      "implementationStatus": "受 Windows gate 控制的进程集成目标",
      "details": {
        "basic": {
          "role": "当 CLink 使用 Hook 捕获而非显式代理设置时，表示工作负载进程。",
          "receives": "接收来自 ProcessManager 的附加决策和 Hook DLL 状态。",
          "emits": "通过 Hook DLL 发出进程生命周期变化和被拦截的网络操作。",
          "whyItExists": "有些应用无法配置 SOCKS，需要透明的进程级集成。"
        },
        "deep": {
          "codePath": "进程管理代码位于 src/server/modules/process_manager，Windows Hook build wiring 位于 process_inject 模块。",
          "dataFlow": "目标进程中的网络调用被拦截，并表示为可进入 tunnel 的 connect 与 payload 事件。",
          "runtimeBehavior": "仅当 ProcessManager 和 Hook build 选项启用时可用；否则此路径关闭。",
          "failureModes": "架构不匹配、权限缺失、反篡改控制或进程退出可能阻止 Hook 安装或稳定捕获。",
          "debugSignals": "ProcessManager 日志、DLL 集成测试和 Hook IPC 事件可识别附加与拦截结果。",
          "ipv4Ipv6Notes": "Hook 调用必须在转换为 session 之前保留 socket family 和目标信息。"
        }
      }
    },
    "hook-dll": {
      "id": "hook-dll",
      "label": "Hook DLL",
      "kind": "risk",
      "layer": "process-integration",
      "position": {
        "x": 240,
        "y": 500
      },
      "summary": "注入到 client 进程内的 Hook 组件，把进程网络活动报告给 ProcessManager。",
      "inputs": [
        "被拦截的 socket 调用",
        "Hook IPC 协议",
        "进程上下文"
      ],
      "outputs": [
        "Hook 事件",
        "策略决策",
        "已捕获 payload 元数据"
      ],
      "sourceFiles": [
        "src/share/core/ipc/hook_ipc_protocol.hpp",
        "src/client/modules/process_inject/CMakeLists.txt",
        "src/server/modules/process_inject/CMakeLists.txt"
      ],
      "tests": [
        "tests/server/dll_integration_test.cpp",
        "tests/server/ipc_proxy_test.cpp"
      ],
      "addressFamilies": [
        "process",
        "ipv4",
        "ipv6"
      ],
      "risk": [
        "high",
        "injection",
        "ipc",
        "privilege"
      ],
      "implementationStatus": "受 build gate 控制的 Windows Hook 组件",
      "details": {
        "basic": {
          "role": "把 target-process 的 socket 活动桥接到 daemon 管理的策略和 session 状态。",
          "receives": "接收目标进程内部的 socket API 活动和进程本地状态。",
          "emits": "向 ProcessManager 发送 Hook IPC 消息，并把控制决策返回进程内。",
          "whyItExists": "DLL 是透明应用捕获所需的进程内观察点。"
        },
        "deep": {
          "codePath": "Hook IPC 契约位于 src/share/core/ipc/hook_ipc_protocol.hpp，进程注入 build target 位于 client 和 server 模块。",
          "dataFlow": "Hook 事件编码目标、socket family 和操作状态，供 ProcessManager 转换为 tunnel 动作。",
          "runtimeBehavior": "Hook 在目标进程内部运行，必须在与 daemon 通信时避免扰乱应用线程。",
          "failureModes": "死锁、不兼容 ABI、IPC handshake 失败或不安全重入都可能中断捕获或目标进程。",
          "debugSignals": "Hook 协议日志和 DLL 集成覆盖可显示进程内桥接是否存活。",
          "ipv4Ipv6Notes": "捕获到的 socket 调用包含地址族细节，必须通过 Hook IPC 完整保留。"
        }
      }
    },
    "process-manager": {
      "id": "process-manager",
      "label": "ProcessManager",
      "kind": "risk",
      "layer": "daemon-module",
      "position": {
        "x": 420,
        "y": 430
      },
      "summary": "daemon 模块，拥有进程附加、Hook 通信和 Hook 来源 session 转换。",
      "inputs": [
        "daemon 配置",
        "目标进程元数据",
        "Hook IPC 事件",
        "SOCKS 策略提示"
      ],
      "outputs": [
        "附加操作",
        "session 请求",
        "进程 telemetry"
      ],
      "sourceFiles": [
        "src/server/modules/process_manager/process_manager.cpp",
        "src/server/modules/process_manager/process_manager.hpp",
        "src/server/modules/process_manager/ipc_proxy_session.hpp"
      ],
      "tests": [
        "tests/server/ipc_proxy_test.cpp",
        "tests/server/dll_integration_test.cpp"
      ],
      "addressFamilies": [
        "process",
        "ipv4",
        "ipv6",
        "loopback"
      ],
      "risk": [
        "high",
        "injection",
        "process-boundary",
        "privilege"
      ],
      "implementationStatus": "已实现模块，Hook 路径受平台 gate 控制",
      "details": {
        "basic": {
          "role": "协调目标进程选择、Hook 生命周期，以及把 Hook 事件转换为 tunnel session。",
          "receives": "接收 daemon 命令、SOCKS 关联提示、目标进程状态和 Hook IPC 消息。",
          "emits": "发出附加请求、Hook 响应、session 请求和进程集成 telemetry。",
          "whyItExists": "透明进程捕获需要 daemon 拥有的权威组件来监督高风险的进程内组件。"
        },
        "deep": {
          "codePath": "ProcessManager 模块和 IPC proxy session helper 位于 src/server/modules/process_manager。",
          "dataFlow": "进程与 Hook 事件变成 session 元数据，同时 daemon 策略响应会回传给 Hook。",
          "runtimeBehavior": "模块可由配置关闭，并且仅在请求且支持进程集成时活动。",
          "failureModes": "权限失败、陈旧进程 handle、Hook IPC 丢失和格式错误的进程事件都可能破坏捕获。",
          "debugSignals": "ProcessManager 日志、IPC proxy 测试和 DLL 集成测试可隔离附加与 Hook channel 失败。",
          "ipv4Ipv6Notes": "它必须把目标地址族和 socket 元数据传给 session-manager-local，避免破坏双栈行为。"
        }
      }
    },
    "os-network-stack": {
      "id": "os-network-stack",
      "label": "OS network stack",
      "kind": "data",
      "layer": "platform",
      "position": {
        "x": 60,
        "y": 700
      },
      "summary": "主机网络层，可把流量直接路由、送入 VIF，或从远端转发送往目标网络。",
      "inputs": [
        "应用 socket",
        "虚拟网卡 packet",
        "远端转发 connect"
      ],
      "outputs": [
        "已路由 packet",
        "目标 TCP connection",
        "kernel 网络事件"
      ],
      "sourceFiles": [
        "README.md",
        "src/share/core/config/configuration.cpp"
      ],
      "tests": [
        "tests/application_connect_test.cpp",
        "tests/network/tcp_framing_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "virtual-adapter",
        "loopback"
      ],
      "risk": [
        "medium",
        "routing",
        "dual-stack"
      ],
      "implementationStatus": "图谱中表示的外部平台依赖",
      "details": {
        "basic": {
          "role": "为 CLink 捕获和转发点周围提供平台路由基础。",
          "receives": "接收来自本地工作负载、VIF 和 remote-forwarding 的 packet 与 socket 请求。",
          "emits": "把 IPv4 或 IPv6 流量路由到下一个捕获点或最终目标。",
          "whyItExists": "CLink 必须与主机路由和地址族行为协作，而不是替代 OS stack。"
        },
        "deep": {
          "codePath": "平台网络大多位于仓库之外；CLink 通过配置、VIF 集成和 socket listener 与其交互。",
          "dataFlow": "流量可能在本地侧通过 VIF 进入 CLink，或在远端侧通过 remote-forwarding 离开 CLink。",
          "runtimeBehavior": "路由、adapter 状态和 firewall 策略决定哪些流量到达 CLink，哪些正常退出。",
          "failureModes": "路由冲突、adapter 失败、firewall 规则或 DNS/地址族不匹配都可能导致流量绕过或阻断。",
          "debugSignals": "路由表、daemon bind 日志、连接失败和 session counter 有助于识别 OS 层问题。",
          "ipv4Ipv6Notes": "双栈正确性依赖保留 IPv4 与 IPv6 route，并避免隐式地址族转换。"
        }
      }
    },
    "virtual-interface": {
      "id": "virtual-interface",
      "label": "Virtual interface",
      "kind": "data",
      "layer": "local-capture",
      "position": {
        "x": 260,
        "y": 700
      },
      "summary": "可选 VIF 捕获路径，接收已路由 packet 并送入 daemon session。",
      "inputs": [
        "OS 路由 packet",
        "daemon route 配置",
        "adapter 生命周期状态"
      ],
      "outputs": [
        "由 packet 派生的 session 事件",
        "已捕获 payload 字节",
        "adapter telemetry（网卡遥测）"
      ],
      "sourceFiles": [
        "README.md",
        "src/share/core/config/configuration.cpp"
      ],
      "tests": [
        "tests/application_connect_test.cpp",
        "tests/network/session_manager_test.cpp"
      ],
      "addressFamilies": [
        "virtual-adapter",
        "ipv4",
        "ipv6"
      ],
      "risk": [
        "high",
        "routing",
        "privilege",
        "dual-stack"
      ],
      "implementationStatus": "由 CLINK_DISABLE_VIF 控制的可选运行时路径",
      "details": {
        "basic": {
          "role": "在不逐个配置应用代理的情况下捕获已路由流量。",
          "receives": "接收来自 OS network stack 的 packet，以及来自 local-daemon 的 route 指令。",
          "emits": "向 session-manager-local 发出 session 创建和 payload 事件。",
          "whyItExists": "虚拟网卡支持对不能使用 SOCKS 或 Hook 的应用进行透明流量捕获。"
        },
        "deep": {
          "codePath": "VIF 行为由 README.md 中记录的运行时配置控制，并通过 daemon 模块协调。",
          "dataFlow": "packet 从 OS routing 进入，被映射为 session 元数据，并变成 tunnel payload stream。",
          "runtimeBehavior": "adapter 路径可能需要提权设置，也可在 VIF 不可用的环境中关闭。",
          "failureModes": "缺少权限、路由冲突、adapter 启动失败或 MTU 问题都可能阻止可靠捕获。",
          "debugSignals": "daemon 启动日志、route 状态和 SessionManager counter 可显示 VIF 流量是否转换为 session。",
          "ipv4Ipv6Notes": "packet 捕获必须区分 IPv4 与 IPv6 header，并传递正确的远端转发目标地址族。"
        }
      }
    },
    "session-manager-local": {
      "id": "session-manager-local",
      "label": "本地 SessionManager",
      "kind": "data",
      "layer": "session",
      "position": {
        "x": 560,
        "y": 540
      },
      "summary": "本地 tunnel session 生命周期、封帧、背压和 transport 交接的权威组件。",
      "inputs": [
        "SOCKS session 请求",
        "Hook session 请求",
        "VIF packet flow（虚拟网卡包流）",
        "daemon 生命周期命令"
      ],
      "outputs": [
        "transport frame（传输帧）",
        "session close 事件",
        "telemetry counter（遥测计数器）"
      ],
      "sourceFiles": [
        "src/server/core/network/session_manager.cpp",
        "src/server/core/network/session_manager.hpp",
        "src/server/core/network/session_manager_impl.hpp"
      ],
      "tests": [
        "tests/network/session_manager_test.cpp",
        "tests/network/reliability_test.cpp",
        "tests/network/tcp_framing_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "loopback",
        "virtual-adapter",
        "process"
      ],
      "risk": [
        "medium",
        "memory-pressure",
        "dual-stack"
      ],
      "implementationStatus": "已实现的 session core",
      "details": {
        "basic": {
          "role": "把本地捕获机制汇聚为一致的 stream/session 模型。",
          "receives": "接收来自本地模块的 open 请求、payload 字节、目标元数据和 close 信号。",
          "emits": "向 tls-transport 和 observability 发出已封帧数据与生命周期事件。",
          "whyItExists": "transport 不应该关心流量来自 SOCKS、Hook 还是 VIF 捕获。"
        },
        "deep": {
          "codePath": "SessionManager 实现和模板位于 src/server/core/network。",
          "dataFlow": "本地字节关联到 session id 后被封帧、排队并交给 transport 层。",
          "runtimeBehavior": "manager 跟踪活动 session、背压、可靠性行为和关闭清理。",
          "failureModes": "session 泄漏、顺序错误、peer 停滞、过度缓冲或 close 处理不匹配都会降低 tunnel 可靠性。",
          "debugSignals": "SessionManager 测试、可靠性测试、telemetry counter 和日志暴露生命周期与封帧问题。",
          "ipv4Ipv6Notes": "目标元数据保持地址族可见，使远端转发打开正确 endpoint。"
        }
      }
    },
    "tls-transport": {
      "id": "tls-transport",
      "label": "TLS transport",
      "kind": "data",
      "layer": "transport",
      "position": {
        "x": 760,
        "y": 540
      },
      "summary": "加密 transport 适配器，在本地与远端 CLink endpoint 之间承载 session frame。",
      "inputs": [
        "session frame（会话帧）",
        "TLS 配置",
        "buffer slice（缓冲切片）"
      ],
      "outputs": [
        "加密 record",
        "解密后的远端 frame",
        "transport telemetry（传输遥测）"
      ],
      "sourceFiles": [
        "src/server/core/network/tls_adapter.cpp",
        "src/server/core/network/tls_adapter.hpp",
        "src/client/core/network/tls_adapter.cpp",
        "src/share/core/network/tls_helpers.cpp"
      ],
      "tests": [
        "tests/network/tls_adapter_test.cpp",
        "tests/performance/tls_stress_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6"
      ],
      "risk": [
        "high",
        "tls",
        "remote-access"
      ],
      "implementationStatus": "已实现的加密 transport 适配器",
      "details": {
        "basic": {
          "role": "保护 tunnel payload，并跨网络承载已封帧 session。",
          "receives": "接收来自本地 SessionManager 的 session frame，以及来自 BufferPool 的可复用 buffer。",
          "emits": "向 remote-listener 发送 TLS record，并把解密后的 frame 送回 session 逻辑。",
          "whyItExists": "CLink 需要为离开本地主机的数据提供机密性和完整性。"
        },
        "deep": {
          "codePath": "TLS adapter 实现在 src/server/core/network 和 src/client/core/network，共享 helper 位于 src/share/core/network。",
          "dataFlow": "session frame 被加密为发往 remote listener 的 record；入站 record 被解密为 frame。",
          "runtimeBehavior": "adapter 在负载下管理 handshake、stream 读写、错误处理和 buffer 复用。",
          "failureModes": "handshake 失败、证书或配置不匹配、短读、背压或 record 损坏都会停止 session。",
          "debugSignals": "TLS adapter 测试、TLS stress 测试、transport 日志和错误 counter 指示加密或 I/O 的失败位置。",
          "ipv4Ipv6Notes": "transport socket 可通过 IPv4 或 IPv6 连接，同时承载任一地址族的 session 元数据。"
        }
      }
    },
    "buffer-pool": {
      "id": "buffer-pool",
      "label": "BufferPool",
      "kind": "data",
      "layer": "memory",
      "position": {
        "x": 760,
        "y": 700
      },
      "summary": "可复用内存池，用于降低 session 与 transport payload 的分配抖动。",
      "inputs": [
        "分配请求",
        "归还的 buffer",
        "payload 大小提示"
      ],
      "outputs": [
        "可复用 byte buffer",
        "压力信号",
        "性能 counter"
      ],
      "sourceFiles": [
        "src/server/core/memory/buffer_pool.hpp"
      ],
      "tests": [
        "tests/network/zero_copy_test.cpp",
        "tests/performance/tls_stress_test.cpp"
      ],
      "addressFamilies": [
        "memory",
        "not-applicable"
      ],
      "risk": [
        "medium",
        "memory-pressure"
      ],
      "implementationStatus": "已实现的内存优化原语",
      "details": {
        "basic": {
          "role": "为 session 和 TLS 路径提供可复用 buffer，使高吞吐流量保持高效。",
          "receives": "接收 transport 和 framing code 的 buffer checkout 与 return 调用。",
          "emits": "提供自有 byte storage，并向 observability 发出内存压力信号。",
          "whyItExists": "避免频繁分配可在大量活动 session 下减少延迟和内存抖动。"
        },
        "deep": {
          "codePath": "BufferPool 位于 src/server/core/memory/buffer_pool.hpp，并由 zero-copy 与 stress 测试覆盖。",
          "dataFlow": "payload 字节在 session framing 与 TLS record 之间移动时存放在可复用 buffer 中。",
          "runtimeBehavior": "buffer 在 checked-out 与 returned 状态间循环；流量突发超过池容量时压力升高。",
          "failureModes": "泄漏、重复归还、无界增长或陈旧数据复用会影响性能或正确性。",
          "debugSignals": "zero-copy 测试、stress 测试和内存相关 telemetry 暴露分配与复用问题。",
          "ipv4Ipv6Notes": "buffer 本身与地址族无关，但承载的字节会由其他位置的元数据标识 IPv4 或 IPv6 目标。"
        }
      }
    },
    "remote-listener": {
      "id": "remote-listener",
      "label": "远端 listener",
      "kind": "data",
      "layer": "remote-edge",
      "position": {
        "x": 980,
        "y": 540
      },
      "summary": "远端侧 network listener，接受加密的 CLink transport connection。",
      "inputs": [
        "TLS connection（加密连接）",
        "远端 bind 配置",
        "listener 生命周期事件"
      ],
      "outputs": [
        "已接受安全 channel",
        "connection 元数据",
        "listener telemetry（监听遥测）"
      ],
      "sourceFiles": [
        "src/server/core/network/transport_listener.hpp",
        "src/server/core/network/transport_adapter.hpp",
        "src/server/core/network/tls_adapter.cpp"
      ],
      "tests": [
        "tests/network/tls_adapter_test.cpp",
        "tests/network/reliability_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6"
      ],
      "risk": [
        "high",
        "remote-access",
        "tls"
      ],
      "implementationStatus": "已实现的远端 endpoint listener 抽象",
      "details": {
        "basic": {
          "role": "作为加密 tunnel connection 的网络 accept 边界。",
          "receives": "接收来自本地 endpoint 的入站 TLS transport connection。",
          "emits": "向 remote-auth-policy 发出已接受 channel 和 peer 元数据。",
          "whyItExists": "远端 CLink 组件需要一个受控入口点，然后才允许任何 forwarding。"
        },
        "deep": {
          "codePath": "listener 与 transport 抽象位于 src/server/core/network，TLS 实现位于 tls_adapter.cpp。",
          "dataFlow": "加密 record 来自 tls-transport，并变成供策略和 session 处理的远端 channel。",
          "runtimeBehavior": "listener 绑定配置的 IPv4 或 IPv6 地址，接受 connection，并交给策略检查。",
          "failureModes": "bind 冲突、firewall 规则、协议不匹配或 TLS accept 失败都会阻止创建远端 session。",
          "debugSignals": "listener 日志、TLS 测试和可靠性测试可区分 bind、handshake 与 stream 失败。",
          "ipv4Ipv6Notes": "远端 bind 配置必须有意暴露 IPv4、IPv6 或两者。"
        }
      }
    },
    "remote-auth-policy": {
      "id": "remote-auth-policy",
      "label": "远端认证策略",
      "kind": "config",
      "layer": "remote-edge",
      "position": {
        "x": 1180,
        "y": 440
      },
      "summary": "策略检查点，用于校验远端 transport peer 和 forwarding 权限。",
      "inputs": [
        "peer 身份",
        "TLS channel 元数据",
        "forwarding 策略配置"
      ],
      "outputs": [
        "允许或拒绝决策",
        "策略审计事件",
        "session 约束"
      ],
      "sourceFiles": [
        "src/share/core/config/configuration.cpp",
        "src/share/core/config/config_signature.hpp",
        "src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md"
      ],
      "tests": [
        "tests/logging/config_test.cpp",
        "tests/application_connect_test.cpp"
      ],
      "addressFamilies": [
        "not-applicable",
        "ipv4",
        "ipv6"
      ],
      "risk": [
        "high",
        "auth",
        "remote-access",
        "config"
      ],
      "implementationStatus": "图谱中表示的配置驱动策略点",
      "details": {
        "basic": {
          "role": "决定已接受的远端 transport channel 是否可以创建 forwarding session。",
          "receives": "接收来自 remote-listener 的 peer 元数据和来自配置的策略设置。",
          "emits": "向 session-manager-remote 发出接受或拒绝决策以及约束。",
          "whyItExists": "远端入口必须在触达目标网络之前完成认证并受到约束。"
        },
        "deep": {
          "codePath": "配置解析和签名位于 src/share/core/config，请求字段记录在 control-plane schema 中。",
          "dataFlow": "远端 connection 元数据先按配置策略评估，然后 session frame 才会被接纳。",
          "runtimeBehavior": "策略检查在 connection 或 session 建立时运行，并为被拒绝访问发出审计数据。",
          "failureModes": "错误配置、陈旧凭据、过宽策略或缺少审计路径会造成可用性或暴露风险。",
          "debugSignals": "配置测试、策略相关日志和 remote listener 事件显示 connection 被接受或拒绝的原因。",
          "ipv4Ipv6Notes": "策略可能约束目标地址族或 bind 暴露范围，因此必须保留地址族元数据。"
        }
      }
    },
    "session-manager-remote": {
      "id": "session-manager-remote",
      "label": "远端 SessionManager",
      "kind": "data",
      "layer": "session",
      "position": {
        "x": 1180,
        "y": 620
      },
      "summary": "远端侧 session 权威组件，从 transport frame 重建 session 并协调 forwarding。",
      "inputs": [
        "已授权 channel",
        "解密后的 session frame",
        "远端策略约束"
      ],
      "outputs": [
        "forwarding open 请求",
        "payload stream（载荷流）",
        "远端 session telemetry"
      ],
      "sourceFiles": [
        "src/server/core/network/session_manager.cpp",
        "src/server/core/network/session_manager.hpp",
        "src/server/core/network/session_manager_impl.hpp"
      ],
      "tests": [
        "tests/network/session_manager_test.cpp",
        "tests/network/reliability_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6"
      ],
      "risk": [
        "medium",
        "remote-access",
        "memory-pressure"
      ],
      "implementationStatus": "远端侧使用的已实现共享 session core",
      "details": {
        "basic": {
          "role": "把已授权 transport frame 转成远端 forwarding 工作。",
          "receives": "接收策略批准的 channel 状态和已解码 session frame。",
          "emits": "发出目标 connect 请求、payload 字节、close 事件和 telemetry。",
          "whyItExists": "远端侧需要对称的 session 生命周期处理，字节才能到达目标 socket。"
        },
        "deep": {
          "codePath": "src/server/core/network 下的 SessionManager 代码处理本地与远端路径共享的 framing 和 lifecycle。",
          "dataFlow": "来自 transport 的 frame 被解码为按 session 区分的 stream，并按目标元数据转发。",
          "runtimeBehavior": "manager 跟踪远端 session 状态、close 传播、可靠性以及面向 forwarding socket 的背压。",
          "failureModes": "frame 顺序不匹配、策略约束拒绝、目标失败或 transport 丢失都可能关闭远端 session。",
          "debugSignals": "可靠性测试、session 日志和远端 telemetry counter 暴露逐 session 的远端失败。",
          "ipv4Ipv6Notes": "它会把从本地捕获路径收到的目标地址族原样传给 remote-forwarding。"
        }
      }
    },
    "remote-forwarding": {
      "id": "remote-forwarding",
      "label": "远端转发",
      "kind": "data",
      "layer": "remote-egress",
      "position": {
        "x": 1380,
        "y": 620
      },
      "summary": "远端出口路径，打开目标 connection，并在远端网络之间双向流式传输 payload。",
      "inputs": [
        "forwarding 请求",
        "目标元数据",
        "payload 字节"
      ],
      "outputs": [
        "远端 socket connection",
        "响应 payload 字节",
        "forwarding telemetry（转发遥测）"
      ],
      "sourceFiles": [
        "src/server/core/network/transport_adapter.hpp",
        "src/server/core/network/session_manager.cpp"
      ],
      "tests": [
        "tests/application_connect_test.cpp",
        "tests/network/tcp_framing_test.cpp"
      ],
      "addressFamilies": [
        "ipv4",
        "ipv6"
      ],
      "risk": [
        "high",
        "remote-access",
        "data-leak",
        "dual-stack"
      ],
      "implementationStatus": "表示为远端出口数据面行为",
      "details": {
        "basic": {
          "role": "把已授权 tunnel session 连接到最终远端目标。",
          "receives": "接收来自 session-manager-remote 的目标地址、端口、地址族和 payload stream。",
          "emits": "通过远端 OS network stack 发出 socket traffic，并把响应字节送回 session。",
          "whyItExists": "CLink 必须在远端侧把 tunnel session 转换成真实网络连接。"
        },
        "deep": {
          "codePath": "forwarding 使用 src/server/core/network 下的 transport 与 session 抽象；集成覆盖会执行应用连接。",
          "dataFlow": "远端 session payload 写入目标 socket，响应字节再封帧后经 transport 返回。",
          "runtimeBehavior": "每个已授权 session 映射为 remote connect、stream copy、背压处理和 close 传播。",
          "failureModes": "目标拒绝、DNS 不匹配、地址族不匹配、超时或半关闭都可能中断 forwarding。",
          "debugSignals": "应用连接测试、TCP framing 测试和远端日志可定位 connect 与 stream-copy 失败。",
          "ipv4Ipv6Notes": "出口 socket 必须使用本地捕获和远端策略选定的地址族。"
        }
      }
    },
    "observability": {
      "id": "observability",
      "label": "可观测性",
      "kind": "observe",
      "layer": "cross-cutting",
      "position": {
        "x": 1460,
        "y": 220
      },
      "summary": "日志和 telemetry 层，记录 daemon、模块、session、transport 与策略信号。",
      "inputs": [
        "daemon 事件",
        "session counter（会话计数器）",
        "transport 错误",
        "策略决策",
        "进程事件"
      ],
      "outputs": [
        "结构化日志",
        "telemetry sample（遥测样本）",
        "调试证据"
      ],
      "sourceFiles": [
        "src/server/core/observability/telemetry.cpp",
        "src/server/core/observability/telemetry.hpp",
        "src/share/core/logging/logger.cpp",
        "src/share/core/logging/config.cpp"
      ],
      "tests": [
        "tests/logging/logger_test.cpp",
        "tests/logging/config_test.cpp",
        "tests/performance/log_performance_test.cpp"
      ],
      "addressFamilies": [
        "not-applicable"
      ],
      "risk": [
        "low",
        "observability",
        "data-leak"
      ],
      "implementationStatus": "已实现的日志和 telemetry 支持",
      "details": {
        "basic": {
          "role": "让运行时状态和失败可见，但不参与 payload forwarding 决策。",
          "receives": "接收 daemon core、本地模块、SessionManager、transport、进程集成和远端转发的事件。",
          "emits": "向操作员和测试提供日志、sample、counter 与调试上下文。",
          "whyItExists": "跨平台 tunnel 需要证据来诊断控制、数据、策略和性能问题。"
        },
        "deep": {
          "codePath": "Telemetry 代码位于 src/server/core/observability，logging 代码位于 src/share/core/logging。",
          "dataFlow": "操作和失败的元数据会被记录，同时 payload 数据应避免被意外写入日志。",
          "runtimeBehavior": "CLINK_TELEMETRY_SAMPLE 可调节 sampling，日志路径由共享 logging 配置控制。",
          "failureModes": "过量日志、缺少 correlation id、昂贵 sampling 或敏感 payload 日志都会降低安全性或性能。",
          "debugSignals": "logger 测试、config 测试、性能测试和 daemon 日志输出可验证可观测行为。",
          "ipv4Ipv6Notes": "日志在有助诊断时应包含地址族元数据，同时避免不必要暴露敏感目标。"
        }
      }
    }
  },
  "edges": {
    "user-script-to-cli": {
      "id": "user-script-to-cli",
      "from": "user-script",
      "to": "clink-cli",
      "label": "操作员命令启动 CLI",
      "kind": "control",
      "dataType": "argv / env / config 意图",
      "addressFamilies": [
        "not-applicable"
      ],
      "sourceFiles": [
        "README.md"
      ],
      "notes": [
        "脚本和人工控制面操作的入口边。"
      ],
      "risk": [
        "low",
        "config"
      ],
      "implementationStatus": "已记录的运行时行为"
    },
    "cli-to-ipc": {
      "id": "cli-to-ipc",
      "from": "clink-cli",
      "to": "ipc-client",
      "label": "CLI 序列化控制请求",
      "kind": "control",
      "dataType": "控制面请求",
      "addressFamilies": [
        "not-applicable",
        "loopback"
      ],
      "sourceFiles": [
        "src/client/core/ipc/ipc.hpp",
        "src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md"
      ],
      "notes": [
        "命令在跨越进程边界前会变成与 schema 对齐的 IPC payload。"
      ],
      "risk": [
        "low",
        "ipc"
      ],
      "implementationStatus": "已实现"
    },
    "ipc-to-local-daemon": {
      "id": "ipc-to-local-daemon",
      "from": "ipc-client",
      "to": "ipc-server",
      "label": "本地 IPC frame 进入 daemon",
      "kind": "control",
      "dataType": "已封帧 IPC 消息",
      "addressFamilies": [
        "unix-domain-socket",
        "windows-named-pipe",
        "loopback"
      ],
      "sourceFiles": [
        "src/share/core/ipc/ipc_linux.cpp",
        "src/share/core/ipc/ipc_win.cpp",
        "src/share/core/ipc/ipc_message_utils.hpp"
      ],
      "notes": [
        "平台 IPC transport 在本地承载控制请求和响应。"
      ],
      "risk": [
        "medium",
        "ipc",
        "process-boundary"
      ],
      "implementationStatus": "已实现"
    },
    "ipc-server-to-daemon": {
      "id": "ipc-server-to-daemon",
      "from": "ipc-server",
      "to": "local-daemon",
      "label": "已校验请求分发",
      "kind": "control",
      "dataType": "daemon 操作",
      "addressFamilies": [
        "not-applicable"
      ],
      "sourceFiles": [
        "src/server/core/ipc/ipc.hpp",
        "src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md"
      ],
      "notes": [
        "daemon 接收的是已校验操作，而不是原始 CLI 状态。"
      ],
      "risk": [
        "medium",
        "daemon-lifecycle"
      ],
      "implementationStatus": "已实现"
    },
    "daemon-to-socks": {
      "id": "daemon-to-socks",
      "from": "local-daemon",
      "to": "socks-server",
      "label": "daemon 配置 SOCKS listener",
      "kind": "control",
      "dataType": "listener 生命周期命令",
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "loopback"
      ],
      "sourceFiles": [
        "src/server/modules/socks_server/socks_server.cpp",
        "src/share/core/config/configuration.cpp"
      ],
      "notes": [
        "daemon 生命周期和配置决定本地 SOCKS 是否可用。"
      ],
      "risk": [
        "medium",
        "remote-access",
        "config"
      ],
      "implementationStatus": "已实现"
    },
    "local-app-to-socks": {
      "id": "local-app-to-socks",
      "from": "local-application",
      "to": "socks-server",
      "label": "应用代理流量进入 SOCKS",
      "kind": "data",
      "dataType": "SOCKS handshake 与 TCP payload",
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "loopback"
      ],
      "sourceFiles": [
        "src/server/modules/socks_server/socks_server.cpp"
      ],
      "notes": [
        "显式代理模式把本地应用 connection 转换为 tunnel session。"
      ],
      "risk": [
        "medium",
        "dual-stack"
      ],
      "implementationStatus": "已实现"
    },
    "socks-to-session-manager": {
      "id": "socks-to-session-manager",
      "from": "socks-server",
      "to": "session-manager-local",
      "label": "SOCKS 目标变成本地 session",
      "kind": "data",
      "dataType": "目标元数据加字节流",
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "loopback"
      ],
      "sourceFiles": [
        "src/server/modules/socks_server/socks_server.cpp",
        "src/server/core/network/session_manager.cpp"
      ],
      "notes": [
        "每个已接受的 SOCKS connection 都映射为受管理的 tunnel session。"
      ],
      "risk": [
        "medium",
        "dual-stack"
      ],
      "implementationStatus": "已实现"
    },
    "socks-to-process-manager": {
      "id": "socks-to-process-manager",
      "from": "socks-server",
      "to": "process-manager",
      "label": "SOCKS 关联通知进程策略",
      "kind": "control",
      "dataType": "进程 / session 关联元数据",
      "addressFamilies": [
        "loopback",
        "process",
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/modules/socks_server/socks_server.cpp",
        "src/server/modules/process_manager/process_manager.cpp"
      ],
      "notes": [
        "ProcessManager 可把显式代理流量与受管理进程状态关联起来。"
      ],
      "risk": [
        "medium",
        "process-boundary",
        "ipc"
      ],
      "implementationStatus": "已实现的模块交互"
    },
    "process-manager-to-target": {
      "id": "process-manager-to-target",
      "from": "process-manager",
      "to": "target-process",
      "label": "附加或监督进程",
      "kind": "risk",
      "dataType": "进程生命周期命令",
      "addressFamilies": [
        "process"
      ],
      "sourceFiles": [
        "src/server/modules/process_manager/process_manager.cpp"
      ],
      "notes": [
        "进程集成风险较高，并受平台 gate 控制。"
      ],
      "risk": [
        "high",
        "privilege",
        "injection"
      ],
      "implementationStatus": "受平台 gate 控制"
    },
    "process-manager-to-hook": {
      "id": "process-manager-to-hook",
      "from": "process-manager",
      "to": "hook-dll",
      "label": "安装并配置 Hook channel",
      "kind": "risk",
      "dataType": "Hook 设置与策略消息",
      "addressFamilies": [
        "process"
      ],
      "sourceFiles": [
        "src/server/modules/process_manager/process_manager.cpp",
        "src/share/core/ipc/hook_ipc_protocol.hpp"
      ],
      "notes": [
        "daemon 拥有的 ProcessManager 控制 Hook 设置和策略交换。"
      ],
      "risk": [
        "high",
        "injection",
        "privilege"
      ],
      "implementationStatus": "受平台 gate 控制"
    },
    "hook-to-process-manager": {
      "id": "hook-to-process-manager",
      "from": "hook-dll",
      "to": "process-manager",
      "label": "Hook 报告被拦截的网络调用",
      "kind": "risk",
      "dataType": "Hook IPC 事件流",
      "addressFamilies": [
        "process",
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/share/core/ipc/hook_ipc_protocol.hpp",
        "src/server/modules/process_manager/ipc_proxy_session.hpp"
      ],
      "notes": [
        "捕获到的调用会先回到 daemon，再转换为 tunnel session。"
      ],
      "risk": [
        "high",
        "ipc",
        "injection"
      ],
      "implementationStatus": "受平台 gate 控制"
    },
    "hook-to-local-app": {
      "id": "hook-to-local-app",
      "from": "hook-dll",
      "to": "local-application",
      "label": "Hook 应用进程内网络决策",
      "kind": "risk",
      "dataType": "socket 拦截结果",
      "addressFamilies": [
        "process",
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/share/core/ipc/hook_ipc_protocol.hpp"
      ],
      "notes": [
        "进程内 Hook 会影响应用网络调用如何继续。"
      ],
      "risk": [
        "high",
        "process-boundary",
        "injection"
      ],
      "implementationStatus": "受平台 gate 控制"
    },
    "os-stack-to-vif": {
      "id": "os-stack-to-vif",
      "from": "os-network-stack",
      "to": "virtual-interface",
      "label": "路由 packet 进入虚拟网卡",
      "kind": "data",
      "dataType": "IP packet（网络包）",
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "virtual-adapter"
      ],
      "sourceFiles": [
        "README.md",
        "src/share/core/config/configuration.cpp"
      ],
      "notes": [
        "主机路由决定哪些 packet 进入 VIF 捕获路径。"
      ],
      "risk": [
        "high",
        "routing",
        "dual-stack"
      ],
      "implementationStatus": "可选运行时路径"
    },
    "daemon-to-vif": {
      "id": "daemon-to-vif",
      "from": "local-daemon",
      "to": "virtual-interface",
      "label": "daemon 管理 VIF 生命周期",
      "kind": "control",
      "dataType": "adapter 配置",
      "addressFamilies": [
        "virtual-adapter",
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "README.md",
        "src/share/core/config/configuration.cpp"
      ],
      "notes": [
        "CLINK_DISABLE_VIF 可在运行时移除此路径。"
      ],
      "risk": [
        "high",
        "privilege",
        "routing"
      ],
      "implementationStatus": "可选运行时路径"
    },
    "vif-to-session-manager": {
      "id": "vif-to-session-manager",
      "from": "virtual-interface",
      "to": "session-manager-local",
      "label": "捕获 packet 变成 tunnel session",
      "kind": "data",
      "dataType": "由 packet 派生的 session stream",
      "addressFamilies": [
        "virtual-adapter",
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/core/network/session_manager.cpp",
        "README.md"
      ],
      "notes": [
        "VIF 路径在本地 SessionManager 处与 SOCKS 和 Hook 捕获汇合。"
      ],
      "risk": [
        "high",
        "routing",
        "dual-stack"
      ],
      "implementationStatus": "可选运行时路径"
    },
    "local-session-to-transport": {
      "id": "local-session-to-transport",
      "from": "session-manager-local",
      "to": "tls-transport",
      "label": "本地 session frame 进入加密 transport",
      "kind": "data",
      "dataType": "session frame（会话帧）",
      "addressFamilies": [
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/core/network/session_manager.cpp",
        "src/server/core/network/tls_adapter.cpp"
      ],
      "notes": [
        "所有本地捕获模式在离开主机前都会汇聚到这里。"
      ],
      "risk": [
        "medium",
        "tls",
        "memory-pressure"
      ],
      "implementationStatus": "已实现"
    },
    "transport-to-buffer-pool": {
      "id": "transport-to-buffer-pool",
      "from": "tls-transport",
      "to": "buffer-pool",
      "label": "transport 借用可复用 buffer",
      "kind": "data",
      "dataType": "buffer 租约",
      "addressFamilies": [
        "memory",
        "not-applicable"
      ],
      "sourceFiles": [
        "src/server/core/network/tls_adapter.cpp",
        "src/server/core/memory/buffer_pool.hpp"
      ],
      "notes": [
        "buffer 复用会减少加密 I/O 中的分配抖动。"
      ],
      "risk": [
        "medium",
        "memory-pressure"
      ],
      "implementationStatus": "已实现"
    },
    "tls-to-buffer-pool": {
      "id": "tls-to-buffer-pool",
      "from": "tls-transport",
      "to": "buffer-pool",
      "label": "TLS record 复用 payload buffer",
      "kind": "data",
      "dataType": "TLS record buffer（记录缓冲区）",
      "addressFamilies": [
        "memory",
        "not-applicable"
      ],
      "sourceFiles": [
        "src/server/core/network/tls_adapter.cpp",
        "src/server/core/memory/buffer_pool.hpp"
      ],
      "notes": [
        "必需的总览边，用于展示 TLS 与 buffer 复用之间的内存流。"
      ],
      "risk": [
        "medium",
        "tls",
        "memory-pressure"
      ],
      "implementationStatus": "已实现"
    },
    "transport-to-remote-listener": {
      "id": "transport-to-remote-listener",
      "from": "tls-transport",
      "to": "remote-listener",
      "label": "加密 tunnel 到达远端 listener",
      "kind": "data",
      "dataType": "TLS stream（加密流）",
      "addressFamilies": [
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/core/network/tls_adapter.cpp",
        "src/server/core/network/transport_listener.hpp"
      ],
      "notes": [
        "本地 transport 与远端入口之间的网络侧边。"
      ],
      "risk": [
        "high",
        "tls",
        "remote-access"
      ],
      "implementationStatus": "已实现的抽象"
    },
    "listener-to-auth-policy": {
      "id": "listener-to-auth-policy",
      "from": "remote-listener",
      "to": "remote-auth-policy",
      "label": "已接受 channel 接受策略检查",
      "kind": "control",
      "dataType": "peer 元数据与 channel 属性",
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "not-applicable"
      ],
      "sourceFiles": [
        "src/share/core/config/configuration.cpp",
        "src/share/core/config/config_signature.hpp"
      ],
      "notes": [
        "远端入口应先通过策略检查，然后才能启用 forwarding。"
      ],
      "risk": [
        "high",
        "auth",
        "remote-access"
      ],
      "implementationStatus": "配置驱动"
    },
    "auth-policy-to-remote-session": {
      "id": "auth-policy-to-remote-session",
      "from": "remote-auth-policy",
      "to": "session-manager-remote",
      "label": "策略授权远端 session",
      "kind": "control",
      "dataType": "授权决策与约束",
      "addressFamilies": [
        "ipv4",
        "ipv6",
        "not-applicable"
      ],
      "sourceFiles": [
        "src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md",
        "src/server/core/network/session_manager.cpp"
      ],
      "notes": [
        "只有策略接受后，远端 session 处理才会开始。"
      ],
      "risk": [
        "high",
        "auth",
        "remote-access"
      ],
      "implementationStatus": "表示的策略流"
    },
    "remote-session-to-forwarding": {
      "id": "remote-session-to-forwarding",
      "from": "session-manager-remote",
      "to": "remote-forwarding",
      "label": "远端 session 打开目标 stream",
      "kind": "data",
      "dataType": "forwarding 请求与 payload stream",
      "addressFamilies": [
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/core/network/session_manager.cpp",
        "src/server/core/network/transport_adapter.hpp"
      ],
      "notes": [
        "session 元数据变成远端出口 socket 工作。"
      ],
      "risk": [
        "high",
        "remote-access",
        "dual-stack"
      ],
      "implementationStatus": "表示的数据面流"
    },
    "remote-forwarding-to-os-stack": {
      "id": "remote-forwarding-to-os-stack",
      "from": "remote-forwarding",
      "to": "os-network-stack",
      "label": "远端出口使用 OS socket",
      "kind": "data",
      "dataType": "TCP connect 与 payload",
      "addressFamilies": [
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/core/network/transport_adapter.hpp"
      ],
      "notes": [
        "tunnel 通过远端主机 network stack 退出。"
      ],
      "risk": [
        "high",
        "data-leak",
        "routing"
      ],
      "implementationStatus": "表示的远端出口"
    },
    "daemon-to-observability": {
      "id": "daemon-to-observability",
      "from": "local-daemon",
      "to": "observability",
      "label": "daemon 生命周期发出日志和 telemetry",
      "kind": "observe",
      "dataType": "生命周期事件",
      "addressFamilies": [
        "not-applicable"
      ],
      "sourceFiles": [
        "src/server/core/observability/telemetry.cpp",
        "src/share/core/logging/logger.cpp"
      ],
      "notes": [
        "启动、关闭和模块状态应在日志中可见。"
      ],
      "risk": [
        "low",
        "observability"
      ],
      "implementationStatus": "已实现"
    },
    "session-to-observability": {
      "id": "session-to-observability",
      "from": "session-manager-local",
      "to": "observability",
      "label": "session counter 进入 telemetry",
      "kind": "observe",
      "dataType": "session metric（会话指标）",
      "addressFamilies": [
        "not-applicable",
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/core/network/session_manager.cpp",
        "src/server/core/observability/telemetry.cpp"
      ],
      "notes": [
        "session 数量和关闭原因是关键调试信号。"
      ],
      "risk": [
        "low",
        "observability"
      ],
      "implementationStatus": "已实现"
    },
    "transport-to-observability": {
      "id": "transport-to-observability",
      "from": "tls-transport",
      "to": "observability",
      "label": "采样 transport 错误与吞吐",
      "kind": "observe",
      "dataType": "transport metric（传输指标）",
      "addressFamilies": [
        "not-applicable",
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/core/network/tls_adapter.cpp",
        "src/server/core/observability/telemetry.cpp"
      ],
      "notes": [
        "TLS 与 stream 错误必须可诊断，同时不能记录 payload。"
      ],
      "risk": [
        "low",
        "observability",
        "tls"
      ],
      "implementationStatus": "已实现"
    },
    "process-to-observability": {
      "id": "process-to-observability",
      "from": "process-manager",
      "to": "observability",
      "label": "进程集成报告附加与 Hook 状态",
      "kind": "observe",
      "dataType": "进程集成事件",
      "addressFamilies": [
        "not-applicable",
        "process"
      ],
      "sourceFiles": [
        "src/server/modules/process_manager/process_manager.cpp",
        "src/share/core/logging/logger.cpp"
      ],
      "notes": [
        "高风险进程操作需要清晰的审计和调试证据。"
      ],
      "risk": [
        "medium",
        "observability",
        "injection"
      ],
      "implementationStatus": "已实现的模块 telemetry"
    },
    "remote-to-observability": {
      "id": "remote-to-observability",
      "from": "remote-forwarding",
      "to": "observability",
      "label": "远端转发发出 connect 与 close 结果",
      "kind": "observe",
      "dataType": "远端转发事件",
      "addressFamilies": [
        "not-applicable",
        "ipv4",
        "ipv6"
      ],
      "sourceFiles": [
        "src/server/core/network/session_manager.cpp",
        "src/share/core/logging/logger.cpp"
      ],
      "notes": [
        "远端出口可见性是诊断目标失败所必需的。"
      ],
      "risk": [
        "medium",
        "observability",
        "data-leak"
      ],
      "implementationStatus": "表示的 telemetry 流"
    }
  },
  "groups": {
    "control-plane": {
      "id": "control-plane",
      "label": "Control plane 控制面",
      "bounds": {
        "x": 0,
        "y": 10,
        "width": 860,
        "height": 250
      },
      "nodes": [
        "user-script",
        "clink-cli",
        "ipc-client",
        "ipc-server",
        "local-daemon"
      ],
      "summary": "命令与 daemon 生命周期路径。"
    },
    "local-data-plane": {
      "id": "local-data-plane",
      "label": "本地 Data plane",
      "bounds": {
        "x": 0,
        "y": 240,
        "width": 720,
        "height": 560
      },
      "nodes": [
        "local-application",
        "socks-server",
        "os-network-stack",
        "virtual-interface",
        "session-manager-local"
      ],
      "summary": "本地流量捕获与 session 创建路径。"
    },
    "process-integration": {
      "id": "process-integration",
      "label": "进程集成",
      "bounds": {
        "x": 0,
        "y": 370,
        "width": 580,
        "height": 230
      },
      "nodes": [
        "target-process",
        "hook-dll",
        "process-manager"
      ],
      "summary": "受平台 gate 控制的进程捕获与 Hook 监督路径。"
    },
    "transport": {
      "id": "transport",
      "label": "Transport 与内存",
      "bounds": {
        "x": 700,
        "y": 480,
        "width": 220,
        "height": 320
      },
      "nodes": [
        "tls-transport",
        "buffer-pool"
      ],
      "summary": "加密 stream 与可复用 buffer 路径。"
    },
    "remote-edge": {
      "id": "remote-edge",
      "label": "远端边界",
      "bounds": {
        "x": 920,
        "y": 380,
        "width": 620,
        "height": 340
      },
      "nodes": [
        "remote-listener",
        "remote-auth-policy",
        "session-manager-remote",
        "remote-forwarding"
      ],
      "summary": "远端入口、策略、session 重建与出口路径。"
    },
    "observability": {
      "id": "observability",
      "label": "可观测性",
      "bounds": {
        "x": 1400,
        "y": 160,
        "width": 220,
        "height": 160
      },
      "nodes": [
        "observability"
      ],
      "summary": "日志、telemetry 与诊断证据。"
    }
  },
  "legends": {
    "colors": [
      {
        "label": "控制",
        "color": "#65d6ff"
      },
      {
        "label": "数据",
        "color": "#77e39c"
      },
      {
        "label": "风险",
        "color": "#ff8f8f"
      },
      {
        "label": "观测",
        "color": "#d4a8ff"
      },
      {
        "label": "配置",
        "color": "#ffd27a"
      }
    ],
    "risk": {
      "low": "常规运行风险，可用标准诊断手段处理。",
      "medium": "需要谨慎配置或运行时监控。",
      "high": "跨越权限、远端访问、注入或路由边界。"
    },
    "addressFamilies": {
      "ipv4": "IPv4 socket、packet 或目标元数据。",
      "ipv6": "IPv6 socket、packet 或目标元数据。",
      "loopback": "仅限 localhost 的控制或代理 transport。",
      "unix-domain-socket": "Unix 本地 IPC endpoint。",
      "windows-named-pipe": "Windows 本地 IPC endpoint。",
      "virtual-adapter": "虚拟网卡 packet 路径。",
      "process": "进程本地集成路径。",
      "memory": "内存中的 payload 移动。",
      "not-applicable": "此节点或边没有地址族语义。"
    }
  },
  "glossary": {
    "control-plane": "用于协调 daemon 与 client 行为的命令、请求、响应和策略决策。",
    "data-plane": "控制决策完成后承载应用 payload 的运行时流量路径。",
    "dual-stack": "同时表示 IPv4 与 IPv6 行为，使地址族选择保持可见。",
    "VIF": "启用时用于透明 packet 捕获的 virtual interface 路径。",
    "hook IPC": "注入式 Hook 代码与 daemon ProcessManager 之间的进程集成通信 channel。",
    "session frame": "与一个逻辑 connection 关联的 tunnel payload 和生命周期元数据单元。"
  }
};
