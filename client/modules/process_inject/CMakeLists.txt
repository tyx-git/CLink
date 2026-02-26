add_library(clink-process-client SHARED
    src/dll_main.cpp
)

set_target_properties(clink-process-client PROPERTIES 
    OUTPUT_NAME "clink-client-hook"
    PREFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
)

target_include_directories(clink-process-client PUBLIC
    include
)

target_link_libraries(clink-process-client PUBLIC
    minhook
    asio
    ws2_32
)
