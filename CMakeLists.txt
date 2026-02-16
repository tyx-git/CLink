cmake_minimum_required(VERSION 3.24)

project(CLINK VERSION 1.1.0 LANGUAGES CXX)

option(CLINK_ENABLE_TESTS "Enable tests" ON)

# Remove -fprofile-abs-path flag which is not supported by MinGW
string(REPLACE "-fprofile-abs-path" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
string(STRIP "${CMAKE_CXX_FLAGS_DEBUG}" CMAKE_CXX_FLAGS_DEBUG)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Include CPM for dependency management
include(cmake/CPM.cmake)

include(cmake/ProjectOptions.cmake)

# Add spdlog dependency via CPM
# Try to use local spdlog if available
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/spdlog/CMakeLists.txt")
    message(STATUS "Using local spdlog from external/spdlog")
    add_subdirectory(external/spdlog)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/spdlog-1.14.1/CMakeLists.txt")
    message(STATUS "Using local spdlog from external/spdlog-1.14.1")
    add_subdirectory(external/spdlog-1.14.1)
else()
    # Fallback to CPM download
    CPMAddPackage(
        NAME spdlog
        GITHUB_REPOSITORY gabime/spdlog
        VERSION 1.14.1
        OPTIONS
            "SPDLOG_BUILD_EXAMPLE OFF"
            "SPDLOG_BUILD_TESTS OFF"
            "SPDLOG_BUILD_SHARED OFF"
            "SPDLOG_FMT_EXTERNAL OFF"
    )
endif()

# Add Catch2 for testing (if enabled)
if(CLINK_ENABLE_TESTS)
    # Try to use local Catch2 if available
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/Catch2-3.5.3/CMakeLists.txt")
        message(STATUS "Using local Catch2 from external/Catch2-3.5.3")
        add_subdirectory(external/Catch2-3.5.3)
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/Catch2/CMakeLists.txt")
        message(STATUS "Using local Catch2 from external/Catch2")
        add_subdirectory(external/Catch2)
    else()
        # Fallback to CPM download
        CPMAddPackage(
            NAME Catch2
            GITHUB_REPOSITORY catchorg/Catch2
            VERSION 3.5.3
            OPTIONS
                "CATCH_INSTALL_DOCS OFF"
                "CATCH_INSTALL_EXTRAS OFF"
                "CATCH_BUILD_EXTRA_TESTS OFF"
                "CATCH_BUILD_TESTING OFF"
                "CATCH_ENABLE_WERROR OFF"
        )
    endif()
endif()

# Add Asio dependency via CPM
CPMAddPackage(
    NAME Asio
    GITHUB_REPOSITORY chriskohlhoff/asio
    GIT_TAG asio-1-30-2
    DOWNLOAD_ONLY YES
)

if (Asio_ADDED)
    add_library(asio INTERFACE)
    target_include_directories(asio SYSTEM INTERFACE ${Asio_SOURCE_DIR}/asio/include)
    target_compile_definitions(asio INTERFACE ASIO_STANDALONE)
    if(WIN32)
        target_compile_definitions(asio INTERFACE _WIN32_WINNT=0x0601)
    endif()
endif()

add_subdirectory(src)

if(CLINK_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
