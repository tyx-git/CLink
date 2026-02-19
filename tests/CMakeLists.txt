# Original smoke test
add_executable(clink-tests main.cpp)
target_link_libraries(clink-tests PRIVATE clink::core)
set_project_options(clink-tests)
add_test(NAME clink-core-smoke COMMAND clink-tests)

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

    target_include_directories(clink-logging-tests
        PRIVATE
            ${CMAKE_SOURCE_DIR}/include
    )

    set_project_options(clink-logging-tests)

    add_test(NAME clink-logging-tests COMMAND clink-logging-tests)
endif()

# Network reliability tests
if(CLINK_ENABLE_TESTS AND TARGET Catch2::Catch2WithMain)
    add_executable(clink-network-tests
        network/reliability_test.cpp
        network/tls_adapter_test.cpp
        network/session_manager_test.cpp
        network/zero_copy_test.cpp
    )

    target_link_libraries(clink-network-tests
        PRIVATE
            clink::core
            Catch2::Catch2WithMain
    )

    target_include_directories(clink-network-tests
        PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/server/include
    )

    set_project_options(clink-network-tests)

    add_test(NAME clink-network-tests COMMAND clink-network-tests)
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

    target_include_directories(clink-logging-perf-tests
        PRIVATE
            ${CMAKE_SOURCE_DIR}/include
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

    target_include_directories(clink-network-perf-tests
        PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/server/include
    )
    
    set_project_options(clink-network-perf-tests)
endif()
