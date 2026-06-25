@echo off
setlocal EnableDelayedExpansion

:: ================================================================
::  WinForensics - First Build Script
::  Edit QT_VER if your Qt version is different.
:: ================================================================
set QT_VER=6.11.1
set QT_PATH=C:\Qt\%QT_VER%\mingw_64
set MINGW_PATH=C:\Qt\Tools\mingw1310_64\bin
set CMAKE_PATH=C:\Qt\Tools\CMake_64\bin
:: ================================================================

set PATH=%QT_PATH%\bin;%MINGW_PATH%;%CMAKE_PATH%;%PATH%

echo.
echo ============================================
echo  WinForensics Build  (Qt %QT_VER% / MinGW)
echo ============================================
echo.

:: Clear cmake cache so Qt is re-detected cleanly
if exist build\CMakeCache.txt del /f build\CMakeCache.txt

echo [1/3] CMake configure...
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=%QT_PATH%"
if errorlevel 1 goto fail

echo.
echo [2/3] Compiling...
cmake --build build --parallel
if errorlevel 1 goto fail

echo.
echo [3/3] Deploying Qt DLLs...
"%QT_PATH%\bin\windeployqt6.exe" "build\winforensics_gui.exe"
if errorlevel 1 goto fail

echo.
echo [4/4] Copying executables to project root...
copy /y build\winforensics_gui.exe .
copy /y build\winforensics.exe .
:: Copy MinGW runtime DLLs needed by CLI exe
copy /y "%MINGW_PATH%\libgcc_s_seh-1.dll" .
copy /y "%MINGW_PATH%\libstdc++-6.dll" .
copy /y "%MINGW_PATH%\libwinpthread-1.dll" .

echo.
echo ============================================
echo  Build complete!
echo  GUI : winforensics_gui.exe  (double-click)
echo  CLI : winforensics.exe --help
echo ============================================
echo.
pause
exit /b 0

:fail
echo.
echo [ERROR] Build failed. Check the message above.
pause
exit /b 1
