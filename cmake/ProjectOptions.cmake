set(PROJECT_WARNINGS
    -Wall
    -Wextra
    -Wpedantic
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wcast-align
    -Wunused
    -Woverloaded-virtual
    -Wconversion
    -Wsign-conversion
    -Wnull-dereference
    -Wdouble-promotion
    -Wformat=2
)

macro(set_project_options target)
    target_compile_options(${target} PRIVATE ${PROJECT_WARNINGS})
    target_compile_features(${target} PRIVATE cxx_std_20)
endmacro()
