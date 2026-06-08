# Original smoke test
add_executable(clink-tests main.cpp)
target_link_libraries(clink-tests PRIVATE clink::core)
set_project_options(clink-tests)
add_test(NAME clink-core-smoke COMMAND clink-tests)
if(WIN32)
    set_tests_properties(clink-core-smoke PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${CMAKE_SOURCE_DIR}/Out")
endif()

# Catch2 tests for logging system
if(CLINK_ENABLE_TESTS AND TARGET Catch2::Catch2WithMain)
    add_executable(clink-logging-tests
        logging/logger_test.cpp
        logging/config_test.cpp
    )

    target_link_libraries(clink-logging-tests
        PRIVATE
            clink::core
            Catch2::Catch2WithMain
    )

    set_project_options(clink-logging-tests)

    add_test(NAME clink-logging-tests COMMAND clink-logging-tests)
endif()

# Network reliability tests
if(CLINK_ENABLE_TESTS AND TARGET Catch2::Catch2WithMain)
    add_executable(clink-network-tests-v2
        network/reliability_test.cpp
        network/tls_adapter_test.cpp
        network/session_manager_test.cpp
        network/zero_copy_test.cpp
        network/tcp_framing_test.cpp
        application_connect_test.cpp
        ipc_linux_test.cpp
    )

    if(WIN32)
        target_sources(clink-network-tests-v2 PRIVATE
            server/ipc_proxy_test.cpp
            server/socks_server_test.cpp
        )
    endif()

    target_link_libraries(clink-network-tests-v2
        PRIVATE
            clink::core
            Catch2::Catch2WithMain
    )

    if(WIN32)
        target_link_libraries(clink-network-tests-v2 PRIVATE clink-inject)
    endif()

    set_project_options(clink-network-tests-v2)

    add_test(NAME clink-network-tests-v2 COMMAND clink-network-tests-v2 --order decl)
    if(WIN32)
        set_tests_properties(clink-network-tests-v2 PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${CMAKE_SOURCE_DIR}/Out")

        if(TARGET clink-hook)
            add_executable(clink-hook-tests
                server/dll_integration_test.cpp
            )
            target_include_directories(clink-hook-tests
                PRIVATE
                    ${CMAKE_SOURCE_DIR}
                    ${CMAKE_SOURCE_DIR}/src/client/modules/process_inject/include
            )
            target_link_libraries(clink-hook-tests
                PRIVATE
                    Catch2::Catch2WithMain
                    asio
                    ws2_32
            )
            add_dependencies(clink-hook-tests clink-hook)
            set_project_options(clink-hook-tests)
            add_test(NAME clink-hook-tests COMMAND clink-hook-tests)
            set_tests_properties(clink-hook-tests PROPERTIES
                ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${CMAKE_SOURCE_DIR}/Out")
        else()
            message(STATUS "Skipping clink-hook-tests because clink-hook target is not available")
        endif()
    endif()
endif()

# Performance tests for logging system
if(CLINK_ENABLE_TESTS AND TARGET Catch2::Catch2WithMain)
    add_executable(clink-logging-perf-tests
        performance/log_performance_test.cpp
    )

    target_link_libraries(clink-logging-perf-tests
        PRIVATE
            clink::core
            Catch2::Catch2WithMain
    )

    set_project_options(clink-logging-perf-tests)

    # Performance tests are not run by default with ctest
    # They need to be run manually to collect performance data
    # add_test(NAME clink-logging-perf-tests COMMAND clink-logging-perf-tests)
endif()

# Performance tests for network system
if(CLINK_ENABLE_TESTS AND TARGET Catch2::Catch2WithMain)
    add_executable(clink-network-perf-tests
        performance/tls_stress_test.cpp
    )

    target_link_libraries(clink-network-perf-tests
        PRIVATE
            clink::core
    )

    set_project_options(clink-network-perf-tests)
endif()
