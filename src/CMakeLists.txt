# Shared core library for common components
add_library(clink-share-core STATIC
    share/core/config/configuration.cpp
    share/core/logging/config.cpp
    share/core/logging/logger.cpp
    share/core/network/packet.cpp
    share/core/network/tls_helpers.cpp
)

# Platform-specific shared IPC implementation
if (WIN32)
    target_sources(clink-share-core PRIVATE share/core/ipc/ipc_win.cpp)
elseif (UNIX AND NOT APPLE)
    target_sources(clink-share-core PRIVATE share/core/ipc/ipc_linux.cpp)
endif()

target_include_directories(clink-share-core PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/external/spdlog/include
    ${CMAKE_SOURCE_DIR}/external/openssl/include
)

target_link_directories(clink-share-core PUBLIC
    ${CMAKE_SOURCE_DIR}/external/openssl/lib
)

target_link_libraries(clink-share-core PUBLIC
    spdlog::spdlog
    asio
    ssl
    crypto
    nlohmann_json::nlohmann_json
)

if (WIN32)
    target_link_libraries(clink-share-core PUBLIC
        ws2_32
        mswsock
        crypt32
    )
    target_compile_definitions(clink-share-core PRIVATE _WIN32)
elseif (UNIX AND NOT APPLE)
    target_compile_definitions(clink-share-core PRIVATE __linux__)
endif()

set_project_options(clink-share-core)

# Core library for shared components
add_library(clink-core STATIC
    server/core/application/application.cpp
    server/core/registry.cpp
    server/core/network/session_manager.cpp
    server/core/network/virtual_interface.cpp
    server/core/network/tcp_adapter.cpp
    server/core/network/tls_adapter.cpp
    server/core/network/acl.cpp
    server/core/network/rate_limiter.cpp
    server/core/network/reliability_engine.cpp
    server/modules/heartbeat/heartbeat.cpp
    server/modules/metrics/metrics.cpp
    server/modules/socks_server/socks_server.cpp
    server/modules/process_manager/process_manager.cpp
    server/core/observability/telemetry.cpp
)

# IPC implementation is now in clink-share-core

target_include_directories(clink-core PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/external/spdlog/include
    ${CMAKE_SOURCE_DIR}/external/openssl/include
    ${CMAKE_SOURCE_DIR}/src/server/modules/process_inject/include
)

target_link_directories(clink-core PUBLIC
    ${CMAKE_SOURCE_DIR}/external/openssl/lib
)

target_link_libraries(clink-core PUBLIC
    clink-share-core
)

if (WIN32)
    target_link_libraries(clink-core PUBLIC
        clink-inject
    )
    target_compile_definitions(clink-core PRIVATE _WIN32)
elseif (UNIX AND NOT APPLE)
    target_compile_definitions(clink-core PRIVATE __linux__)
endif()


add_library(clink::core ALIAS clink-core)

set_project_options(clink-core)

if (WIN32)
    add_executable(clinkd
        server/main.cpp
        server/resources/clinkd.rc
    )
else()
    add_executable(clinkd
        server/main.cpp
    )
endif()

target_link_libraries(clinkd PRIVATE 
    clink::core
)

set_project_options(clinkd)

# Output binaries to Out directory
set_target_properties(clinkd PROPERTIES
    OUTPUT_NAME "clinkd"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
)

# Client core library
add_library(clink-client-core STATIC
    client/core/application/application.cpp
    client/core/registry.cpp
    client/core/network/tls_adapter.cpp
)

# IPC implementation is now in clink-share-core

target_include_directories(clink-client-core PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/external/spdlog/include
    ${CMAKE_SOURCE_DIR}/external/openssl/include
    ${CMAKE_SOURCE_DIR}/src/client/modules/process_inject/include
)

target_link_directories(clink-client-core PUBLIC
    ${CMAKE_SOURCE_DIR}/external/openssl/lib
)

target_link_libraries(clink-client-core PUBLIC
    clink-share-core
)

if (WIN32)
    target_link_libraries(clink-client-core PUBLIC
        clink-inject
    )
    target_compile_definitions(clink-client-core PRIVATE _WIN32)
elseif (UNIX AND NOT APPLE)
    target_compile_definitions(clink-client-core PRIVATE __linux__)
endif()

if (WIN32)
    add_executable(clink
        client/main.cpp
        client/resources/clink.rc
    )
else()
    add_executable(clink
        client/main.cpp
    )
endif()

target_link_libraries(clink PRIVATE 
    clink-client-core
)

set_project_options(clink)

set_target_properties(clink PROPERTIES
    OUTPUT_NAME "clink"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
)
