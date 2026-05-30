# WinForensics

[![CI](https://github.com/digitaltutor26/portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/digitaltutor26/portfolio/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)

Windows 디지털 포렌식 도구 — **외부 의존성 없는 순수 C++17** 구현

파일 메타데이터 분석, MD5/SHA-256 해시 계산, Windows 활동 흔적(Artifact) 수집, 통합 타임라인 생성을 지원하며 Text / CSV / JSON 세 가지 형식으로 보고서를 출력합니다.

---

## 기능

| 명령어 | 설명 |
|--------|------|
| `analyze` | 파일/폴더의 메타데이터(크기, 타임스탬프, 카테고리, 해시, 매직 바이트) 분석 |
| `artifacts` | Windows 활동 흔적 수집 (Recent, Prefetch, Temp, Downloads) |
| `timeline` | 파일 이벤트 + 아티팩트를 합친 통합 활동 타임라인 생성 |

**지원 파일 카테고리**: Executable · Script · Document · Image · Video · Audio · Archive · Database · Log

**지원 출력 형식**: Text (콘솔) · CSV (Excel) · JSON (자동화 연동)

---

## 빌드 요구사항

| 항목 | 요구사항 |
|------|----------|
| OS | Windows 10/11 (전체 기능) / Linux·macOS (analyze 일부) |
| CMake | 3.16 이상 |
| 컴파일러 | MSVC (Visual Studio 2019+) 또는 MinGW-w64 (GCC 10+) |

---

## 빌드 방법

### Visual Studio (MSVC)
```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### MinGW-w64
```bat
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

빌드 결과물: `build/Release/winforensics.exe` (MSVC) 또는 `build/winforensics.exe` (MinGW)

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
  report.h               보고서 출력 (Text / CSV / JSON)

src/
  main.cpp               CLI 진입점
  common.cpp             유틸리티 구현 (thread-safe localtime)
  hash.cpp               MD5 (RFC 1321) · SHA-256 (FIPS 180-4) 구현
  file_info.cpp          파일 메타데이터 수집
  artifact_collector.cpp Windows Artifact 수집
  report.cpp             보고서 출력

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
