# WinForensics

[![CI](https://github.com/digitaltutor26/portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/digitaltutor26/portfolio/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)

Windows 디지털 포렌식 도구 — **C++17 + Qt6 GUI** 구현

파일 메타데이터 분석, MD5/SHA-256 해시 계산, Windows 활동 흔적(Artifact) 수집, LNK 파일 파싱, $MFT $SI/$FN 타임스탬프 비교, 통합 타임라인 생성을 지원하며 Text / CSV / JSON 세 가지 형식으로 보고서를 출력합니다. GUI 모드와 CLI 모드를 모두 제공합니다.

> [!IMPORTANT]
> **새 Windows PC에 처음 설치하는 경우** → 아래 [Windows 설치 가이드](#windows-설치-가이드) 섹션을 먼저 확인하세요.

---

## 기능

| 명령어 / 모드 | 설명 |
|--------|------|
| `analyze` | 파일/폴더의 메타데이터(크기, 타임스탬프, 카테고리, 해시, 매직 바이트) 분석 |
| `artifacts` | Windows 활동 흔적 수집 (Recent, Prefetch, Temp, Downloads) |
| `timeline` | 파일 이벤트 + 아티팩트를 합친 통합 활동 타임라인 생성 |
| `lnk` | LNK 바로가기 파일 파싱 — 원본 경로, MAC 타임스탬프, 볼륨 정보 추출 |
| `mft` | $MFT 파일에서 $SI/$FN 타임스탬프 비교 — 타임스탬프 조작 탐지 |
| **Qt GUI** | 위 모든 기능을 탭 기반 그래픽 인터페이스로 제공 |

**지원 파일 카테고리**: Executable · Script · Document · Image · Video · Audio · Archive · Database · Log

**지원 출력 형식**: Text (콘솔) · CSV (Excel) · JSON (자동화 연동)

---

## 빌드 요구사항

| 항목 | 요구사항 |
|------|----------|
| OS | Windows 10/11 (전체 기능) / Linux·macOS (analyze 일부) |
| CMake | 3.16 이상 |
| 컴파일러 | MSVC (Visual Studio 2019+) 또는 MinGW-w64 (GCC 10+) |
| Qt (GUI 선택) | Qt 6.x (Core · Widgets · Concurrent) |

---

## Windows 설치 가이드

> [!IMPORTANT]
> **처음 설치하거나 새 PC에서 시작하는 경우 이 섹션을 따라주세요.**

---

### 1단계 — 사전 소프트웨어 설치 (최초 1회)

| 소프트웨어 | 설명 | 설치 옵션 |
|-----------|------|----------|
| **Git for Windows** | 소스 코드 다운로드 및 업데이트 | 설치 시 기본 옵션 유지 |
| **Qt 6.11.1** | GUI 빌드에 필요 | Qt Installer → `Qt 6.11.1` → `MinGW 64-bit` 체크 |

> Qt Installer 실행 시 **MinGW 64-bit** 컴포넌트와 함께 **Qt 6.11.1** 을 선택해야 합니다.  
> 기본 설치 경로: `C:\Qt\6.11.1\mingw_64`

---

### 2단계 — 소스 클론 (최초 1회)

cmd(명령 프롬프트)를 열고 아래 명령 실행:

```cmd
git clone https://github.com/digitaltutor26/portfolio.git D:\portfolio
cd D:\portfolio
```

---

### 3단계 — 최초 빌드 (최초 1회)

```cmd
build.bat
```

빌드 완료 후 `D:\portfolio`에 아래 파일이 생성됩니다:

| 파일 | 설명 |
|------|------|
| `winforensics_gui.exe` | GUI 버전 — 더블클릭으로 실행 |
| `winforensics.exe` | CLI 버전 — cmd에서 실행 |

---

### 4단계 — 업데이트 (소스 변경 시)

GitHub에 새 수정사항이 반영된 경우:

```cmd
cd D:\portfolio
update.bat
```

`update.bat` 는 최신 소스를 자동으로 받아 재빌드합니다.

> [!NOTE]
> `CMakeLists.txt` 가 변경된 경우 `update.bat` 대신 `build.bat` 를 실행하세요.

---

## 빌드 방법

### CLI 전용 (Qt 불필요)

**Visual Studio (MSVC)**
```bat
cmake -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_GUI=OFF
cmake --build build --config Release
```

**MinGW-w64**
```bat
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF
cmake --build build --parallel
```

빌드 결과물: `build/Release/winforensics.exe` (MSVC) 또는 `build/winforensics.exe` (MinGW)

---

### Qt GUI 포함 빌드

Qt 6.x가 설치되어 있어야 합니다. MinGW 기준:

```bat
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

빌드 결과물: `build/winforensics_gui.exe`

#### Qt DLL 배포 (최초 1회)

빌드 후 같은 폴더에서 실행해야 Qt DLL이 인식됩니다. `windeployqt6`로 필요한 DLL을 자동으로 복사합니다:

```bat
C:\Qt\6.x.x\mingw_64\bin\windeployqt6.exe build\winforensics_gui.exe
```

> `6.x.x`를 설치된 Qt 버전으로 변경하세요 (예: `6.11.1`).  
> DLL 복사는 최초 1회만 필요하며, 이후 재빌드 시에는 생략해도 됩니다.

#### 소스 수정 후 재빌드

```bat
cmake --build build --parallel
```

이것만 실행하면 됩니다.

---

## 사용법

```
winforensics <command> [path] [options]

Commands:
  analyze  <path>   파일/폴더 메타데이터 분석
  artifacts         Windows 활동 흔적 수집
  timeline <path>   통합 활동 타임라인 생성

Options:
  --format <fmt>    출력 형식: text | csv | json  (기본: text)
  --output <file>   결과를 파일로 저장
  --hash            MD5 + SHA-256 해시 계산 (analyze/timeline)
  --recursive       하위 폴더 재귀 탐색 (analyze/timeline)
  --recent          최근 파일 수집 (artifacts/timeline)
  --prefetch        Prefetch 실행 기록 수집 (artifacts/timeline)
  --temp            임시 파일 수집 (artifacts/timeline)
  --downloads       다운로드 폴더 수집 (artifacts/timeline)
  --all             모든 아티팩트 유형 수집
  --help            도움말 출력
```

### 예시

```bat
:: 파일 1개 분석 (해시 포함)
winforensics analyze C:\Windows\notepad.exe --hash

:: 폴더 재귀 분석 → CSV 저장
winforensics analyze C:\Users\John\Documents --recursive --format csv --output report.csv

:: Prefetch + 최근 파일 수집 → JSON
winforensics artifacts --prefetch --recent --format json --output artifacts.json

:: 통합 타임라인 → JSON
winforensics timeline C:\Users\John --all --hash --format json --output timeline.json
```

---

## 테스트 실행

```bat
cmake -B build -DBUILD_TESTING=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

테스트는 MD5 (RFC 1321) · SHA-256 · CSV/JSON 이스케이프 · 타임라인 정렬 등을 검증합니다.

---

## 아키텍처

```
include/
  common.h               공통 유틸리티 (타임스탬프, 인코딩 변환)
  hash.h                 MD5 / SHA-256 인터페이스
  file_info.h            파일 메타데이터 구조체 및 수집기
  artifact_collector.h   Windows 아티팩트 수집기
  lnk_parser.h           MS-SHLLINK LNK 파일 파서
  mft_parser.h           $MFT $SI/$FN 타임스탬프 파서
  report.h               보고서 출력 (Text / CSV / JSON)

src/
  main.cpp               CLI 진입점
  main_gui.cpp           Qt GUI 진입점
  common.cpp             유틸리티 구현 (thread-safe localtime)
  hash.cpp               MD5 (RFC 1321) · SHA-256 (FIPS 180-4) 구현
  file_info.cpp          파일 메타데이터 수집
  artifact_collector.cpp Windows Artifact 수집
  lnk_parser.cpp         LNK 바이너리 파싱 구현
  mft_parser.cpp         $MFT 레코드 파싱 구현
  report.cpp             보고서 출력

ui/
  main_window.h/cpp      메인 윈도우 (탭 컨테이너)
  analyze_tab.h/cpp      파일 분석 탭
  artifacts_tab.h/cpp    아티팩트 수집 탭
  timeline_tab.h/cpp     타임라인 탭
  lnk_tab.h/cpp          LNK / $MFT 분석 탭
  worker.h/cpp           백그라운드 작업 스레드

tests/
  test_main.cpp          단위 테스트 (공식 테스트 벡터 포함)

.github/workflows/
  ci.yml                 Windows MSVC · MinGW · Linux GCC 빌드 매트릭스
```

---

## 수집 아티팩트 상세

| 종류 | 위치 | 포렌식 활용 |
|------|------|------------|
| Recent Files | `%APPDATA%\Microsoft\Windows\Recent\` | 최근 열어본 파일 추적 |
| Prefetch | `%SystemRoot%\Prefetch\` | 프로그램 실행 이력 및 마지막 실행 시각 |
| Temp Files | `%TEMP%\` | 악성코드 임시 파일, 삭제된 작업 흔적 |
| Downloads | `%USERPROFILE%\Downloads\` | 외부 수신 파일 확인 |

> Prefetch 수집은 Windows 10에서 관리자 권한이 필요할 수 있습니다.

---

## 해시 알고리즘

| 알고리즘 | 표준 | 출력 | 특징 |
|----------|------|------|------|
| MD5 | RFC 1321 | 32자 (128비트) | 빠른 중복 확인용 |
| SHA-256 | FIPS 180-4 | 64자 (256비트) | 무결성 검증 권장 |

두 알고리즘 모두 외부 라이브러리 없이 직접 구현되었습니다.

---

## 라이선스

[MIT License](LICENSE)
