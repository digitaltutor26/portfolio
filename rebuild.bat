@echo off
:: Quick rebuild after source update (no DLL re-deploy needed)
set PATH=C:\Qt\Tools\mingw1310_64\bin;C:\Qt\Tools\CMake_64\bin;%PATH%

echo Rebuilding...
cmake --build build --parallel
if errorlevel 1 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)
echo [OK] build\winforensics_gui.exe  /  build\winforensics.exe
pause
