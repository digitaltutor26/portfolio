cmake_minimum_required(VERSION 3.16)
project(WinForensics VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DUNICODE -D_UNICODE)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

include_directories(include)

set(SOURCES
    src/main.cpp
    src/common.cpp
    src/hash.cpp
    src/file_info.cpp
    src/artifact_collector.cpp
    src/report.cpp
)

add_executable(winforensics ${SOURCES})

if(WIN32)
    target_link_libraries(winforensics PRIVATE shlwapi)
endif()

install(TARGETS winforensics DESTINATION bin)
