// ============================================================
// artifact_collector.cpp  -  Windows 컴퓨터 활동 흔적 수집 구현
// ============================================================
// Windows는 사용자가 컴퓨터를 쓰면서 여러 곳에 자동으로 흔적을 남깁니다.
// 이 파일은 그 흔적들을 찾아 Artifact 구조체로 수집합니다.
//
// 수집 대상:
//   1) Recent Files  - 최근에 열어본 파일의 바로가기(.lnk)
//   2) Prefetch      - 실행된 프로그램의 캐시 파일(.pf)
//   3) Temp Files    - 프로그램 실행 중 만들어진 임시 파일
//   4) Downloads     - 다운로드 폴더의 파일
// ============================================================
#include "artifact_collector.h"
#include "common.h"     // expandEnvVar, wstringToString, filetimeToTimet 등

#include <algorithm>    // std::sort
#include <filesystem>   // std::filesystem (폴더 경로 처리)

// Windows 전용 API
#ifdef _WIN32
#include <windows.h>    // FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW 등
#include <shlobj.h>     // Windows Shell 관련 (여기서는 include만)
#endif

namespace forensics {

namespace fs = std::filesystem;

// ============================================================
// typeName : ArtifactType 열거값 → 출력용 문자열
// ============================================================
std::string ArtifactCollector::typeName(ArtifactType t) {
    switch (t) {
        case ArtifactType::RecentFile:     return "RecentFile";
        case ArtifactType::PrefetchEntry:  return "Prefetch";
        case ArtifactType::TempFile:       return "TempFile";
        case ArtifactType::DownloadedFile: return "Download";
        default:                           return "Unknown";
    }
}

// ============================================================
// ── Windows 전용 구현 ─────────────────────────────────────────
// ============================================================
#ifdef _WIN32

// ============================================================
// scanDir : 지정한 폴더를 탐색해서 아티팩트 목록 반환
// ============================================================
// 매개변수:
//   dirPath     : 탐색할 폴더 경로 (환경 변수가 이미 펼쳐진 실제 경로)
//   type        : 수집할 아티팩트 종류 (RecentFile, Prefetch 등)
//   description : 각 항목에 붙을 기본 설명
//   extFilter   : 이 확장자만 수집 (빈 문자열이면 모든 파일)
std::vector<Artifact> ArtifactCollector::scanDir(const std::string& dirPath,
                                                  ArtifactType       type,
                                                  const std::string& description,
                                                  const std::string& extFilter) {
    std::vector<Artifact> results;

    // Windows API는 wstring(유니코드)을 요구하므로 변환
    std::wstring wDirPath(dirPath.begin(), dirPath.end());

    // 검색 패턴: "폴더경로\*"  (* = 모든 파일)
    std::wstring searchPath = wDirPath + L"\\*";

    // ── Windows 파일 탐색 API ────────────────────────────────
    // WIN32_FIND_DATAW : 발견된 파일의 정보를 담는 구조체
    //   cFileName       - 파일명 (유니코드)
    //   dwFileAttributes- 속성 플래그 (디렉터리 여부 등)
    //   ftLastWriteTime - 마지막 수정 시각 (FILETIME 형식)
    //   nFileSizeLow/High - 파일 크기 (32비트 두 개로 64비트 표현)
    WIN32_FIND_DATAW ffd;

    // FindFirstFileW : searchPath 패턴에 맞는 첫 번째 항목을 찾음
    //                  반환값 HANDLE을 이후 FindNextFileW에 전달
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);

    // INVALID_HANDLE_VALUE : 폴더가 없거나 접근 불가 등의 실패
    if (hFind == INVALID_HANDLE_VALUE) return results;

    // do-while : FindNextFileW로 파일이 없어질 때까지 반복
    do {
        // 디렉터리(폴더) 항목은 건너뜀 (파일만 수집)
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        // 파일명을 유니코드(wstring)에서 UTF-8(string)으로 변환
        std::string fileName = wstringToString(ffd.cFileName);
        std::string filePath = dirPath + "\\" + fileName; // 전체 경로 조합

        // ── 확장자 필터 (대소문자 구분 없이) ─────────────────
        if (!extFilter.empty()) {
            fs::path p(fileName);
            std::string ext = p.extension().string();

            // 확장자 앞의 점(.) 제거: ".lnk" → "lnk"
            if (!ext.empty() && ext[0] == '.') ext = ext.substr(1);

            // 소문자로 변환해서 비교 (예: "LNK" → "lnk")
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

            // 필터와 다른 확장자면 건너뜀
            if (ext != extFilter) continue;
        }

        // ── Artifact 구조체에 정보 채우기 ───────────────────
        Artifact a;
        a.type        = type;
        a.typeName    = typeName(type);
        a.path        = filePath;
        a.name        = fileName;
        a.description = description;

        // 마지막 수정 시각을 이벤트 타임스탬프로 사용
        // Recent 파일: 마지막으로 접근한 시각
        // Prefetch 파일: 마지막으로 프로그램을 실행한 시각
        a.timestamp    = filetimeToTimet(ffd.ftLastWriteTime);
        a.timestampStr = filetimeToString(ffd.ftLastWriteTime);

        // 파일 크기 계산: DWORD(32비트) 두 개를 합쳐 64비트 값으로
        // (4GB 이상 파일도 처리 가능)
        ULARGE_INTEGER fileSize;
        fileSize.LowPart  = ffd.nFileSizeLow;   // 크기의 하위 32비트
        fileSize.HighPart = ffd.nFileSizeHigh;  // 크기의 상위 32비트
        a.size = fileSize.QuadPart;             // 64비트 크기

        // std::move : 복사 대신 이동으로 성능 향상
        results.push_back(std::move(a));

    } while (FindNextFileW(hFind, &ffd)); // 다음 파일로 이동, 없으면 루프 종료

    FindClose(hFind); // 핸들 반드시 닫기 (리소스 누수 방지)
    return results;
}

// ============================================================
// collectRecentFiles : 최근 파일 바로가기(.lnk) 수집
// ============================================================
// Windows는 파일 탐색기나 프로그램에서 파일을 열 때마다
// %APPDATA%\Microsoft\Windows\Recent\ 에 .lnk(바로가기) 파일을 자동으로 생성합니다.
// 이 파일들의 이름이나 타임스탬프로 "언제 어떤 파일을 열었는지" 확인 가능합니다.
std::vector<Artifact> ArtifactCollector::collectRecentFiles() {
    // expandEnvVar : "%APPDATA%" → 실제 경로로 치환
    // 예) "C:\Users\홍길동\AppData\Roaming\Microsoft\Windows\Recent"
    std::string recentPath = expandEnvVar("%APPDATA%\\Microsoft\\Windows\\Recent");

    return scanDir(
        recentPath,
        ArtifactType::RecentFile,
        "Recently accessed file (LNK shortcut)", // 기본 설명
        "lnk"                                    // .lnk 파일만 수집
    );
}

// ============================================================
// collectPrefetch : 프리패치 실행 기록(.pf) 수집
// ============================================================
// Windows Prefetch란?
//   Windows는 자주 사용하는 프로그램의 실행 패턴을 미리 캐싱해 빠르게 실행합니다.
//   이 캐시 파일(.pf)이 C:\Windows\Prefetch\에 저장됩니다.
//
// 파일명 형식: 프로그램명-해시값.pf
//   예) NOTEPAD.EXE-A1B2C3D4.pf
//       CHROME.EXE-FF001122.pf
//
// 포렌식 활용:
//   - 어떤 프로그램이 실행됐는지 확인
//   - .pf 파일의 수정 시각 = 해당 프로그램의 마지막 실행 시각
//   - 악성코드가 실행됐더라도 삭제 후에도 프리패치 기록이 남을 수 있음
//
// 주의: Windows 10에서는 관리자 권한이 필요할 수 있습니다.
std::vector<Artifact> ArtifactCollector::collectPrefetch() {
    // %SystemRoot% = "C:\Windows"
    std::string prefetchPath = expandEnvVar("%SystemRoot%\\Prefetch");

    auto results = scanDir(
        prefetchPath,
        ArtifactType::PrefetchEntry,
        "Program execution record", // 기본 설명 (나중에 덮어씀)
        "pf"                        // .pf 파일만 수집
    );

    // ── 파일명에서 프로그램 이름 추출 ──────────────────────────
    // "NOTEPAD.EXE-A1B2C3D4.pf" → description을 "Executed: NOTEPAD.EXE"로 변경
    for (auto& a : results) {
        fs::path p(a.name);
        std::string stem = p.stem().string(); // 확장자 제거: "NOTEPAD.EXE-A1B2C3D4"

        // 마지막 '-' 기호 위치를 찾아 그 앞부분만 추출
        auto dashPos = stem.rfind('-'); // rfind = 뒤에서부터 검색
        if (dashPos != std::string::npos) {
            // "NOTEPAD.EXE-A1B2C3D4" → "Executed: NOTEPAD.EXE"
            a.description = "Executed: " + stem.substr(0, dashPos);
        }
    }
    return results;
}

// ============================================================
// collectTempFiles : 임시 폴더(%TEMP%) 파일 수집
// ============================================================
// 많은 프로그램이 작업 중 임시 파일을 만들고 종료 시 지우는데,
// 비정상 종료나 악성코드의 경우 임시 파일이 그대로 남아 있을 수 있습니다.
// 예) 압축 해제 중간 파일, 다운로드 부분 파일, 임시 실행 파일 등
std::vector<Artifact> ArtifactCollector::collectTempFiles() {
    std::string tempPath = expandEnvVar("%TEMP%"); // 예) C:\Users\홍길동\AppData\Local\Temp

    return scanDir(
        tempPath,
        ArtifactType::TempFile,
        "Temporary file",
        "" // 확장자 필터 없음 = 모든 파일 수집
    );
}

// ============================================================
// collectDownloads : 다운로드 폴더 파일 수집
// ============================================================
// 인터넷 브라우저, 다운로드 매니저 등이 파일을 저장하는 기본 위치입니다.
// 어떤 파일을 외부에서 받았는지 확인하는 데 중요합니다.
std::vector<Artifact> ArtifactCollector::collectDownloads() {
    std::string dlPath = expandEnvVar("%USERPROFILE%\\Downloads");
    // %USERPROFILE% 예) C:\Users\홍길동

    return scanDir(
        dlPath,
        ArtifactType::DownloadedFile,
        "Downloaded file",
        "" // 모든 파일
    );
}

#else
// ============================================================
// Windows가 아닌 환경에서는 빈 목록 반환 (스텁 구현)
// ============================================================
// 이 함수들은 Windows 전용 API를 사용하므로
// Linux/macOS에서는 컴파일 오류 없이 빈 결과만 반환합니다.
std::vector<Artifact> ArtifactCollector::collectRecentFiles()  { return {}; }
std::vector<Artifact> ArtifactCollector::collectPrefetch()     { return {}; }
std::vector<Artifact> ArtifactCollector::collectTempFiles()    { return {}; }
std::vector<Artifact> ArtifactCollector::collectDownloads()    { return {}; }

#endif // _WIN32

// ============================================================
// collectAll : 4가지 아티팩트를 모두 수집 후 시간 역순 정렬
// ============================================================
// 모든 아티팩트를 하나의 목록으로 합쳐 "언제 무슨 일이 있었는지"
// 한눈에 볼 수 있도록 최신 순으로 정렬합니다.
std::vector<Artifact> ArtifactCollector::collectAll() {
    std::vector<Artifact> all;

    // 4가지 수집 함수를 호출하고 결과를 all에 이어 붙임
    // 범위 기반 for문으로 4개의 임시 벡터를 순서대로 처리
    for (auto& v : { collectRecentFiles(), collectPrefetch(),
                     collectTempFiles(),   collectDownloads() })
        all.insert(all.end(), v.begin(), v.end());

    // 타임스탬프 내림차순 정렬 (timestamp가 클수록 최신 = 위에 오도록)
    std::sort(all.begin(), all.end(),
        [](const Artifact& a, const Artifact& b) {
            return a.timestamp > b.timestamp; // > : 내림차순
        });

    return all;
}

} // namespace forensics
