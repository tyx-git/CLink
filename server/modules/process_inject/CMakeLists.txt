add_library(clink-process-server SHARED
    src/injector_main.cpp
    src/process_ipc_server.cpp
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
)

target_link_libraries(clink-process-server PUBLIC
    minhook
    asio
    ws2_32
)

# Target for the injected DLL
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
