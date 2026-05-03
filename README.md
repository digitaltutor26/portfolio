# WinForensics

Windows 환경의 컴퓨터 활동 흔적을 수집·분석하는 디지털 포렌식 도구입니다.  
외부 라이브러리 없이 **순수 C++17**로 구현했습니다.

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **파일 메타데이터 분석** | 크기, MAC 타임스탬프, 파일 카테고리, 매직 바이트, 속성(숨김/시스템/읽기전용) |
| **해시 계산** | MD5 (RFC 1321) · SHA-256 (FIPS 180-4) — 외부 라이브러리 없이 직접 구현 |
| **Windows 아티팩트 수집** | 최근 파일(Recent), 프리패치(Prefetch), 임시 파일(Temp), 다운로드(Downloads) |
| **활동 타임라인 생성** | 파일 이벤트와 아티팩트를 통합해 시간순으로 재구성 |
| **다양한 출력 형식** | Text (가독성) · CSV (엑셀) · JSON (자동화·연동) |

---

## 프로젝트 구조

```
WinForensics/
├── CMakeLists.txt               # 빌드 설정 (CMake 3.16+, C++17)
├── include/
│   ├── common.h                 # 공통 유틸리티 (타임스탬프, 16진수, Windows 변환)
│   ├── hash.h                   # MD5 / SHA-256 인터페이스
│   ├── file_info.h              # 파일 메타데이터 구조체 및 수집기
│   ├── artifact_collector.h     # Windows 아티팩트 수집기
│   └── report.h                 # 보고서 출력기 (Text / CSV / JSON)
└── src/
    ├── main.cpp                 # CLI 진입점, 명령 파싱
    ├── common.cpp               # FILETIME 변환, 환경변수 확장 등
    ├── hash.cpp                 # MD5 · SHA-256 알고리즘 구현
    ├── file_info.cpp            # 파일 메타데이터 수집 구현
    ├── artifact_collector.cpp   # Windows API 기반 아티팩트 수집
    └── report.cpp               # 보고서 출력 구현
```

---

## 빌드 방법

### 요구 환경

- Windows 10 / 11
- CMake 3.16 이상
- MSVC (Visual Studio 2019+) 또는 MinGW-w64 (GCC 10+)

### Visual Studio (MSVC)

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

빌드 결과물: `build\Release\winforensics.exe`

### MinGW-w64

```bat
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

빌드 결과물: `build\winforensics.exe`

---

## 사용법

```
winforensics <command> [options]

Commands:
  analyze  <path>   파일 또는 폴더 메타데이터 분석
  artifacts         Windows 컴퓨터 활동 흔적 수집
  timeline <path>   파일 + 아티팩트 통합 활동 타임라인 생성

Options:
  --format <fmt>    출력 형식: text | csv | json  (기본값: text)
  --output <file>   결과를 파일로 저장 (기본값: 화면 출력)
  --hash            MD5 + SHA-256 해시 계산 (analyze / timeline)
  --recursive       하위 폴더 재귀 탐색 (analyze / timeline)
  --recent          최근 파일 수집 (artifacts / timeline)
  --prefetch        프리패치 실행 기록 수집 (artifacts / timeline)
  --temp            임시 파일 수집 (artifacts / timeline)
  --downloads       다운로드 폴더 수집 (artifacts / timeline)
  --all             모든 아티팩트 수집 (artifacts 기본 동작)
  --help            도움말 표시
```

---

## 사용 예시

### 단일 파일 분석 (해시 포함)

```bat
winforensics analyze C:\Users\홍길동\Desktop\suspect.exe --hash
```

```
Path     : C:\Users\홍길동\Desktop\suspect.exe
Name     : suspect.exe
Size     : 204800 bytes
Category : Executable
Magic    : 4d5a900000030000
Created  : 2024-07-10 09:15:33
Modified : 2024-07-10 09:15:33
Accessed : 2024-07-15 14:22:01
Hidden   : No
System   : No
ReadOnly : No
MD5      : d41d8cd98f00b204e9800998ecf8427e
SHA256   : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 폴더 전체 분석 → CSV 저장

```bat
winforensics analyze C:\Users\홍길동\Documents --recursive --format csv --output docs_report.csv
```

### 프리패치 + 최근 파일 수집

```bat
winforensics artifacts --prefetch --recent --format text
```

```
=== Windows Artifact Report ===
Total artifacts: 3

[Prefetch]
  Name      : NOTEPAD.EXE-A1B2C3D4.pf
  Path      : C:\Windows\Prefetch\NOTEPAD.EXE-A1B2C3D4.pf
  Timestamp : 2024-07-15 14:20:05
  Size      : 28672 bytes
  Info      : Executed: NOTEPAD.EXE

[RecentFile]
  Name      : 보고서.docx.lnk
  Path      : C:\Users\홍길동\AppData\Roaming\Microsoft\Windows\Recent\보고서.docx.lnk
  Timestamp : 2024-07-15 13:45:11
  Size      : 1024 bytes
  Info      : Recently accessed file (LNK shortcut)
```

### 통합 활동 타임라인 → JSON 저장

```bat
winforensics timeline C:\Users\홍길동 --all --format json --output timeline.json
```

---

## 수집하는 Windows 아티팩트

| 종류 | 위치 | 포렌식 활용 |
|------|------|------------|
| **Recent Files** | `%APPDATA%\Microsoft\Windows\Recent\` | 사용자가 열어본 파일 목록 확인 |
| **Prefetch** | `C:\Windows\Prefetch\` | 실행된 프로그램과 마지막 실행 시각 확인 |
| **Temp Files** | `%TEMP%\` | 비정상 종료·악성코드 잔여 파일 확인 |
| **Downloads** | `%USERPROFILE%\Downloads\` | 외부에서 내려받은 파일 확인 |

> **Prefetch 수집**은 Windows 10/11에서 관리자 권한이 필요할 수 있습니다.

---

## MAC 타임스탬프 (M·A·C Time)

포렌식에서 파일 시각 정보는 핵심 증거입니다.

| 구분 | 의미 | 비고 |
|------|------|------|
| **M** (Modified)  | 파일 내용이 마지막으로 수정된 시각 | 가장 자주 변경됨 |
| **A** (Accessed)  | 파일이 마지막으로 열린·읽힌 시각 | 읽기만 해도 갱신 |
| **C** (Created)   | 파일이 처음 생성된 시각 | 복사 시 변경될 수 있음 |

---

## 파일 카테고리 분류

| 카테고리 | 해당 확장자 | 포렌식 중요도 |
|----------|------------|--------------|
| Executable | exe, dll, sys, scr, com, msi, drv | ★★★ 최우선 분석 |
| Script | bat, cmd, ps1, vbs, js, py, sh | ★★★ 자동 실행 공격 확인 |
| Archive | zip, rar, 7z, cab | ★★ 악성 파일 은닉 확인 |
| Document | doc/x, xls/x, pdf, html | ★★ 피해자 활동 확인 |
| Database | db, sqlite, mdb | ★★ 기록·채팅 이력 확인 |
| Log | log, evtx, evt | ★★ 시스템 이벤트 확인 |
| Image / Video / Audio | jpg, mp4, mp3 … | ★ 일반 분류 |

---

## 해시 알고리즘

두 알고리즘 모두 외부 라이브러리 없이 표준 규격 그대로 구현했습니다.

| 알고리즘 | 표준 | 해시 길이 | 용도 |
|----------|------|-----------|------|
| **MD5** | RFC 1321 | 128비트 (32자리 16진수) | 빠른 무결성 확인 |
| **SHA-256** | FIPS 180-4 | 256비트 (64자리 16진수) | 신뢰도 높은 증거 보전 |

> 포렌식 현장에서는 두 해시를 함께 기록해 위·변조 여부를 확인합니다.

---

## 출력 형식 비교

### Text

```
Path     : C:\Windows\System32\notepad.exe
Size     : 204800 bytes
Category : Executable
Modified : 2024-01-15 09:00:00
```

### CSV (엑셀에서 바로 열기 가능)

```csv
Path,Name,Size,Category,Magic,Created,Modified,Accessed,Hidden,System,ReadOnly,MD5,SHA256
C:\Windows\System32\notepad.exe,notepad.exe,204800,Executable,4d5a9000,...
```

### JSON (다른 도구와 연동 가능)

```json
[
  {
    "path": "C:\\Windows\\System32\\notepad.exe",
    "name": "notepad.exe",
    "size": 204800,
    "category": "Executable",
    "magic": "4d5a9000...",
    "modified": "2024-01-15 09:00:00"
  }
]
```

---

## 향후 계획 (요구사항 명세서 기반 업데이트 예정)

- [ ] Windows 이벤트 로그(`.evtx`) 파싱
- [ ] LNK 파일 내부 원본 경로 추출
- [ ] 레지스트리 MRU 키 분석
- [ ] 브라우저 히스토리(Chrome / Edge) 수집
- [ ] HTML 형식 보고서 생성

---

## 라이선스

이 프로젝트는 학습 및 포렌식 연구 목적으로 작성되었습니다.
