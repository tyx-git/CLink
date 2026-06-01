# MinGW toolchain file for Windows builds
# Set MINGW_ROOT environment variable to override the default path
# Example: set MINGW_ROOT=D:\Software\Language\mingw64

if(DEFINED ENV{MINGW_ROOT})
    set(MINGW_ROOT "$ENV{MINGW_ROOT}")
else()
    set(MINGW_ROOT "D:/Software/Language/mingw64")
endif()

set(CMAKE_C_COMPILER "${MINGW_ROOT}/bin/gcc.exe")
set(CMAKE_CXX_COMPILER "${MINGW_ROOT}/bin/g++.exe")
