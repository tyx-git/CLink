set(CLINK_PROCESS_SERVER_SOURCES
    src/process_injector.cpp
)

if (WIN32)
    list(APPEND CLINK_PROCESS_SERVER_SOURCES
        src/injector_main.cpp
        src/process_ipc_server.cpp
    )
endif()

add_library(clink-process-server SHARED
    ${CLINK_PROCESS_SERVER_SOURCES}
)

set_target_properties(clink-process-server PROPERTIES
    OUTPUT_NAME "clink-process-manager"
    PREFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
)

target_include_directories(clink-process-server PUBLIC
    include
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/src/server/modules/process_inject/include
)

target_link_libraries(clink-process-server PUBLIC
    asio
)

if (WIN32)
    target_link_libraries(clink-process-server PUBLIC
        ws2_32
    )
endif()

# Legacy hook implementation (server-side) is kept off by default to avoid
# behavior drift with src/client/modules/process_inject/src/dll_main.cpp.
option(CLINK_BUILD_LEGACY_SERVER_HOOK "Build legacy server hook DLL" OFF)
if (CLINK_BUILD_LEGACY_SERVER_HOOK)
    add_library(clink-hook-v2 SHARED
        src/dll_main.cpp
        src/hook_manager.cpp
    )

    set_target_properties(clink-hook-v2 PROPERTIES
        OUTPUT_NAME "clink-hook-v2"
        PREFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
    )

    target_include_directories(clink-hook-v2 PUBLIC
        include
    )

    target_link_libraries(clink-hook-v2 PUBLIC
        minhook
        ws2_32
    )
endif()
