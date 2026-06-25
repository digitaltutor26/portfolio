@echo off
chcp 65001 >nul
:: 소스 수정 후 재빌드 전용 (DLL 재배포 불필요)
set PATH=C:\Qt\Tools\mingw1310_64\bin;C:\Qt\Tools\CMake_64\bin;%PATH%

echo 재빌드 중...
cmake --build build --parallel
if errorlevel 1 (
    echo [오류] 빌드 실패
    pause
    exit /b 1
)
echo [완료] build\winforensics_gui.exe / build\winforensics.exe
pause
