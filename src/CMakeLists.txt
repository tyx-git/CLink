# Core library for shared components
add_library(clink-core STATIC
    ../server/src/application.cpp
    ../server/src/config/configuration.cpp
    ../server/src/logging/config.cpp
    ../server/src/logging/logger.cpp
    ../server/src/modules/registry.cpp
    ../server/src/ipc.cpp
    ../server/src/network/session_manager.cpp
    ../server/src/network/virtual_interface.cpp
    ../server/src/network/tcp_adapter.cpp
    ../server/src/network/tls_adapter.cpp
    ../server/src/network/acl.cpp
    ../server/src/network/rate_limiter.cpp
    ../server/src/network/packet.cpp
    ../server/src/network/reliability_engine.cpp
    ../server/src/modules/heartbeat.cpp
    ../server/src/modules/metrics.cpp
    ../server/src/modules/socks_server.cpp
    ../server/src/modules/process_manager.cpp
    ../server/src/observability/telemetry.cpp
)

target_include_directories(clink-core PUBLIC 
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/external/spdlog/include
    ${CMAKE_SOURCE_DIR}/external/openssl/include
    ${CMAKE_SOURCE_DIR}/server/modules/process_inject/include
)

target_link_directories(clink-core PUBLIC
    ${CMAKE_SOURCE_DIR}/external/openssl/lib
)

target_link_libraries(clink-core PUBLIC 
    spdlog::spdlog
    asio
    ssl
    crypto
    ws2_32
    mswsock
    crypt32
    nlohmann_json::nlohmann_json
)

if(WIN32)
    target_link_libraries(clink-core PUBLIC
        clink-process-server
    )
endif()


add_library(clink::core ALIAS clink-core)

set_project_options(clink-core)

add_executable(clink-server
    ../server/src/main.cpp
    ../server/resources/clink-server.rc
)

target_link_libraries(clink-server PRIVATE 
    clink::core
)

set_project_options(clink-server)

# Output binaries to Out directory
set_target_properties(clink-server PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
)

# Client core library
add_library(clink-client-core STATIC
    ../client/src/application.cpp
    ../client/src/config/configuration.cpp
    ../client/src/logging/config.cpp
    ../client/src/logging/logger.cpp
    ../client/src/modules/registry.cpp
    ../client/src/ipc.cpp
    ../client/src/network/tls_adapter.cpp
    ../client/src/network/packet.cpp
    ../server/src/modules/socks_server.cpp
    ../server/src/modules/process_manager.cpp
)

target_include_directories(clink-client-core PUBLIC 
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/external/spdlog/include
    ${CMAKE_SOURCE_DIR}/external/openssl/include
    ${CMAKE_SOURCE_DIR}/client/modules/process_inject/include
)

target_link_directories(clink-client-core PUBLIC
    ${CMAKE_SOURCE_DIR}/external/openssl/lib
)

target_link_libraries(clink-client-core PUBLIC 
    spdlog::spdlog
    asio
    ssl
    crypto
    ws2_32
    mswsock
    crypt32
    nlohmann_json
)

if(WIN32)
    target_link_libraries(clink-client-core PUBLIC
        clink-process-server
    )
endif()

add_executable(clink-cli
    ../client/src/main.cpp
    ../client/resources/clink-cli.rc
)

target_link_libraries(clink-cli PRIVATE 
    clink-client-core
)

set_project_options(clink-cli)

set_target_properties(clink-cli PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
)
