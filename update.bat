@echo off
setlocal EnableDelayedExpansion

:: ================================================================
::  WinForensics - Update Script  (git pull + rebuild)
::  Run this whenever source code is updated on GitHub.
:: ================================================================
set QT_VER=6.11.1
set QT_PATH=C:\Qt\%QT_VER%\mingw_64
set MINGW_PATH=C:\Qt\Tools\mingw1310_64\bin
set CMAKE_PATH=C:\Qt\Tools\CMake_64\bin
:: ================================================================

set PATH=%QT_PATH%\bin;%MINGW_PATH%;%CMAKE_PATH%;%PATH%

echo.
echo ============================================
echo  WinForensics Update
echo ============================================
echo.

echo [1/3] Pulling latest source from GitHub...
git pull origin main
if errorlevel 1 goto gitfail

echo.
echo [2/3] Rebuilding...
cmake --build build --parallel
if errorlevel 1 (
    echo.
    echo Rebuild failed - CMakeLists.txt may have changed.
    echo Run build.bat instead for a full reconfigure.
    pause
    exit /b 1
)

echo.
echo [3/3] Copying executables to project root...
copy /y build\winforensics_gui.exe .
copy /y build\winforensics.exe .

echo.
echo ============================================
echo  Update complete!
echo  GUI : winforensics_gui.exe
echo  CLI : winforensics.exe --help
echo ============================================
echo.
pause
exit /b 0

:gitfail
echo.
echo [ERROR] git pull failed.
echo Make sure Git for Windows is installed and you have internet access.
pause
exit /b 1
