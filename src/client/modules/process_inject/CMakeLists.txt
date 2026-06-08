add_library(clink-hook SHARED
    src/dll_main.cpp
)

set_target_properties(clink-hook PROPERTIES 
    OUTPUT_NAME "clink-hook"
    PREFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/Out"
)

target_include_directories(clink-hook PUBLIC
    include
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(clink-hook PUBLIC
    minhook
    asio
    ws2_32
)
