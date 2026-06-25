# WinForensics 사용 설명서

Windows 디지털 포렌식 도구 — GUI 모드와 CLI 모드를 모두 지원합니다.

---

## 목차

1. [빌드 방법](#1-빌드-방법)
2. [GUI 사용법](#2-gui-사용법)
3. [CLI 사용법](#3-cli-사용법)
4. [출력 형식](#4-출력-형식)

---

## 1. 빌드 방법

### 사전 요구사항

| 항목 | 버전 | 설치 위치 |
|------|------|-----------|
| Qt | 6.11.1 (MinGW 64-bit) | https://www.qt.io/download |
| CMake | 3.16 이상 | Qt 설치 시 함께 제공 |
| MinGW-w64 | Qt 설치 시 포함 | `C:\Qt\Tools\mingw1310_64` |

> Qt 설치 시 **Qt 6.11.1 > MinGW 64-bit** 컴포넌트와 **Qt Tools > CMake** 를 반드시 선택하세요.

---

### 최초 빌드 (처음 한 번만)

프로젝트 폴더에서 `build.bat` 를 더블클릭하거나 cmd에서 실행합니다.

```bat
build.bat
```

내부적으로 아래 세 단계를 자동 수행합니다:

1. CMake 구성
2. 소스 컴파일
3. Qt DLL 자동 배포 (`windeployqt6`)

완료 후 생성되는 파일:

```
build\
  winforensics_gui.exe   ← Qt GUI 버전 (그래픽 인터페이스)
  winforensics.exe       ← CLI 버전 (명령줄)
```

---

### 소스 수정 후 재빌드

GitHub에서 업데이트된 소스를 받은 후에는 `rebuild.bat`만 실행하면 됩니다.  
DLL 재배포는 필요하지 않습니다.

```bat
rebuild.bat
```

---

### Qt 경로가 다른 경우

`build.bat` 상단의 변수를 실제 설치 경로에 맞게 수정합니다.

```bat
set QT_VER=6.11.1          ← Qt 버전
set QT_PATH=C:\Qt\%QT_VER%\mingw_64
set MINGW_PATH=C:\Qt\Tools\mingw1310_64\bin
set CMAKE_PATH=C:\Qt\Tools\CMake_64\bin
```

---

## 2. GUI 사용법

`build\winforensics_gui.exe` 를 더블클릭하여 실행합니다.

화면 상단의 탭으로 각 기능을 전환합니다.

---

### 탭 1 — 파일 분석

파일 또는 폴더의 메타데이터를 분석합니다.

| 항목 | 설명 |
|------|------|
| 경로 | 분석할 파일 또는 폴더 경로 입력 (찾아보기 버튼 사용 가능) |
| 해시 계산 | 체크 시 MD5 + SHA-256 해시 계산 (시간 소요) |
| 재귀 탐색 | 체크 시 하위 폴더까지 모두 탐색 |
| 분석 시작 | 분석 실행 |

**결과 테이블 열:**

| 파일명 | 크기 | 카테고리 | 매직 바이트 | 생성 | 수정 | 접근 | 숨김 | 시스템 | 읽기전용 | MD5 | SHA256 |

**지원 카테고리:** Executable · Script · Document · Image · Video · Audio · Archive · Database · Log

결과는 **CSV 저장** 또는 **JSON 저장** 버튼으로 파일로 내보낼 수 있습니다.

---

### 탭 2 — 아티팩트

Windows 활동 흔적(Artifact)을 수집합니다.  
**Windows 에서만 실제 데이터가 수집됩니다.**

| 항목 | 수집 경로 | 포렌식 활용 |
|------|-----------|------------|
| Recent | `%APPDATA%\Microsoft\Windows\Recent\` | 최근 열어본 파일 목록 |
| Prefetch | `%SystemRoot%\Prefetch\` | 프로그램 실행 이력 및 마지막 실행 시각 |
| Temp | `%TEMP%\` | 악성코드 임시 파일, 삭제된 작업 흔적 |
| Downloads | `%USERPROFILE%\Downloads\` | 외부에서 수신한 파일 확인 |

원하는 항목을 체크한 후 **수집 시작**을 클릭합니다.  
Prefetch 수집은 관리자 권한이 필요할 수 있습니다.

---

### 탭 3 — 타임라인

파일 이벤트와 아티팩트를 통합한 시간순 활동 타임라인을 생성합니다.

- **경로(선택):** 분석할 파일/폴더 경로 (비워두면 아티팩트만 수집)
- **해시 / 재귀:** 파일 분석 옵션
- **Recent / Prefetch / Temp / Downloads:** 포함할 아티팩트 선택
- **타임라인 생성:** 실행

이벤트 종류별 행 색상:

| 색상 | 이벤트 종류 |
|------|-----------|
| 연두색 | Created (파일 생성) |
| 주황색 | Modified (파일 수정) |
| 하늘색 | Accessed (파일 접근) |
| 연보라 | RecentFile (최근 파일) |
| 살구색 | Prefetch (프로그램 실행) |

---

### 탭 4 — LNK / $MFT

LNK 바로가기 파일을 파싱하고, $MFT 타임스탬프 조작 여부를 탐지합니다.

#### LNK 경로
- 단일 `.lnk` 파일 또는 폴더(예: `%APPDATA%\Microsoft\Windows\Recent`) 입력
- **찾아보기** 버튼으로 선택 가능

#### $MFT 경로 (선택)
- 원시 `$MFT` 파일 경로 입력 시 $SI/$FN 타임스탬프 비교 수행
- 비워두면 LNK 분석만 진행

**LNK 파일 목록 테이블:**

| LNK 파일 | 대상 경로 | 드라이브 | 시리얼 | 레이블 | 컴퓨터 | 생성 | 수정 | 접근 |

**$MFT 타임스탬프 테이블** (LNK 행 선택 시 표시):

| 레코드# | 파일명 | 상태 | $SI 생성 | $SI 수정 | $SI MFT수정 | $SI 접근 | $FN 생성 | $FN 수정 | $FN MFT수정 | $FN 접근 |

**타임스탬프 조작 탐지:**

- 행 배경이 **빨간색** + 굵은 글씨 → `$SI`와 `$FN` 타임스탬프 불일치 (조작 의심)
- 상태 열에 `⚠` 표시
- 해당 셀에 마우스를 올리면 불일치 상세 내용 표시

---

## 3. CLI 사용법

`build\winforensics.exe` 를 cmd에서 실행합니다.

```
winforensics <command> [path] [options]
```

### 명령어

| 명령어 | 설명 |
|--------|------|
| `analyze <path>` | 파일/폴더 메타데이터 분석 |
| `artifacts` | Windows 활동 흔적 수집 |
| `timeline <path>` | 통합 활동 타임라인 생성 |

### 옵션

| 옵션 | 설명 |
|------|------|
| `--format <fmt>` | 출력 형식: `text` \| `csv` \| `json` (기본: `text`) |
| `--output <file>` | 결과를 파일로 저장 |
| `--hash` | MD5 + SHA-256 해시 계산 (`analyze` / `timeline`) |
| `--recursive` | 하위 폴더 재귀 탐색 (`analyze` / `timeline`) |
| `--recent` | Recent 파일 수집 (`artifacts` / `timeline`) |
| `--prefetch` | Prefetch 수집 (`artifacts` / `timeline`) |
| `--temp` | Temp 파일 수집 (`artifacts` / `timeline`) |
| `--downloads` | Downloads 폴더 수집 (`artifacts` / `timeline`) |
| `--all` | 모든 아티팩트 유형 수집 |
| `--help` | 도움말 출력 |

### 사용 예시

```bat
:: 파일 1개 분석 (해시 포함)
winforensics analyze C:\Windows\notepad.exe --hash

:: 폴더 재귀 분석 → CSV 파일 저장
winforensics analyze C:\Users\사용자\Documents --recursive --format csv --output report.csv

:: Prefetch + Recent 수집 → JSON 저장
winforensics artifacts --prefetch --recent --format json --output artifacts.json

:: 통합 타임라인 → JSON 저장
winforensics timeline C:\Users\사용자 --all --hash --format json --output timeline.json

:: 도움말
winforensics --help
```

---

## 4. 출력 형식

### text (기본)

콘솔에 사람이 읽기 쉬운 형태로 출력합니다.

### csv

Excel에서 열 수 있는 CSV 형식으로 저장합니다.

```
name,size,category,created,modified,...
notepad.exe,201216,Executable,2024-01-15 09:00:00,...
```

### json

자동화 도구 연동에 적합한 JSON 형식으로 저장합니다.

```json
[
  {
    "name": "notepad.exe",
    "size": 201216,
    "category": "Executable",
    "created": "2024-01-15 09:00:00",
    ...
  }
]
```

---

## 해시 알고리즘

| 알고리즘 | 표준 | 출력 길이 | 용도 |
|----------|------|-----------|------|
| MD5 | RFC 1321 | 32자 (128비트) | 빠른 중복 파일 확인 |
| SHA-256 | FIPS 180-4 | 64자 (256비트) | 파일 무결성 검증 (권장) |

두 알고리즘 모두 외부 라이브러리 없이 직접 구현되었습니다.

---

*WinForensics v1.0 — MIT License*
