cmake_minimum_required(VERSION 3.16)
project(WinForensics VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /utf-8)
    add_definitions(-DUNICODE -D_UNICODE)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(WIN32)
        add_compile_options(-finput-charset=utf-8 -fexec-charset=utf-8)
    endif()
endif()

# ── 공유 라이브러리 (main.cpp 제외한 모든 모듈) ─────────────────
# 실행 파일과 테스트가 동일한 코드를 링크하도록 정적 라이브러리로 분리
set(CORE_SOURCES
    src/common.cpp
    src/hash.cpp
    src/file_info.cpp
    src/artifact_collector.cpp
    src/lnk_parser.cpp
    src/mft_parser.cpp
    src/report.cpp
)

add_library(winforensics_core STATIC ${CORE_SOURCES})
target_include_directories(winforensics_core PUBLIC include)

if(WIN32)
    target_link_libraries(winforensics_core PRIVATE shlwapi)
endif()

# ── 실행 파일 ───────────────────────────────────────────────────
add_executable(winforensics src/main.cpp)
target_link_libraries(winforensics PRIVATE winforensics_core)

install(TARGETS winforensics DESTINATION bin)

# ── 단위 테스트 ─────────────────────────────────────────────────
option(BUILD_TESTING "Build unit tests" ON)
if(BUILD_TESTING)
    enable_testing()
    add_executable(test_winforensics tests/test_main.cpp)
    target_link_libraries(test_winforensics PRIVATE winforensics_core)
    add_test(NAME UnitTests COMMAND test_winforensics)
endif()

# Qt GUI application
option(BUILD_GUI "Build Qt GUI application" ON)
if(BUILD_GUI)
    find_package(Qt6 COMPONENTS Core Widgets Concurrent QUIET)
    if(Qt6_FOUND)
        set(QT_VER 6)
    else()
        find_package(Qt5 COMPONENTS Core Widgets Concurrent QUIET)
        if(Qt5_FOUND)
            set(QT_VER 5)
        endif()
    endif()

    if(DEFINED QT_VER)
        set(CMAKE_AUTOMOC ON)
        set(CMAKE_AUTOUIC ON)
        set(CMAKE_AUTORCC ON)
        set(GUI_SOURCES
            src/main_gui.cpp
            ui/worker.cpp
            ui/main_window.cpp
            ui/analyze_tab.cpp
            ui/artifacts_tab.cpp
            ui/timeline_tab.cpp
            ui/lnk_tab.cpp
        )
        add_executable(winforensics_gui WIN32 ${GUI_SOURCES})
        target_include_directories(winforensics_gui PRIVATE include ui)
        target_link_libraries(winforensics_gui PRIVATE
            winforensics_core
            Qt${QT_VER}::Core
            Qt${QT_VER}::Widgets
            Qt${QT_VER}::Concurrent
        )
        if(WIN32)
            target_link_libraries(winforensics_gui PRIVATE shlwapi)
        endif()
        message(STATUS "Qt${QT_VER} GUI build enabled")
    else()
        message(STATUS "Qt not found -- GUI build skipped")
    endif()
endif()
