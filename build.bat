@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

:: ================================================================
::  WinForensics - 최초 빌드 스크립트
::  Qt 버전이나 설치 경로가 다를 경우 아래 변수만 수정하세요.
:: ================================================================
set QT_VER=6.11.1
set QT_PATH=C:\Qt\%QT_VER%\mingw_64
set MINGW_PATH=C:\Qt\Tools\mingw1310_64\bin
set CMAKE_PATH=C:\Qt\Tools\CMake_64\bin
:: ================================================================

set PATH=%QT_PATH%\bin;%MINGW_PATH%;%CMAKE_PATH%;%PATH%

echo.
echo ============================================
echo   WinForensics Build  (Qt %QT_VER% / MinGW)
echo ============================================
echo.

echo [1/3] CMake 구성 중...
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_PREFIX_PATH=%QT_PATH%
if errorlevel 1 goto :fail
echo.

echo [2/3] 컴파일 중...
cmake --build build --parallel
if errorlevel 1 goto :fail
echo.

echo [3/3] Qt DLL 배포 중...
%QT_PATH%\bin\windeployqt6.exe build\winforensics_gui.exe
if errorlevel 1 goto :fail

echo.
echo ============================================
echo   빌드 완료!
echo   GUI : build\winforensics_gui.exe
echo   CLI : build\winforensics.exe
echo ============================================
echo.
pause
exit /b 0

:fail
echo.
echo [오류] 빌드 실패 -- 위 메시지를 확인하세요.
pause
exit /b 1
