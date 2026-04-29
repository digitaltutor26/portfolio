// ============================================================
// artifact_collector.h  -  Windows 컴퓨터 활동 흔적 수집 선언
// ============================================================
// '아티팩트(Artifact)'란 컴퓨터를 사용하면서 자동으로 남겨지는
// 디지털 흔적을 말합니다. 포렌식 수사관은 이 흔적들을 모아서
// "언제 무엇을 했는지"를 재구성합니다.
//
// Windows가 자동으로 만드는 주요 흔적:
//
//   1. Recent Files (최근 파일)
//      위치: %APPDATA%\Microsoft\Windows\Recent\
//      내용: 사용자가 최근에 열었던 파일의 바로가기(.lnk) 파일
//      활용: "이 사람이 어떤 파일을 열어봤는가?" 파악
//
//   2. Prefetch 파일
//      위치: C:\Windows\Prefetch\
//      내용: 프로그램 실행 기록 + 마지막 실행 시각
//      파일명 형식: 프로그램명-해시값.pf  예) NOTEPAD.EXE-A1B2C3D4.pf
//      활용: "언제 어떤 프로그램을 실행했는가?" 파악
//
//   3. Temp 파일 (임시 파일)
//      위치: %TEMP%\
//      내용: 프로그램 실행 중 만들어진 임시 파일들
//      활용: 악성코드 분석, 삭제된 작업 흔적 확인
//
//   4. Downloads (다운로드 폴더)
//      위치: %USERPROFILE%\Downloads\
//      내용: 브라우저 등으로 내려받은 파일들
//      활용: "외부에서 무엇을 받았는가?" 확인
// ============================================================
#pragma once

#include <string>   // std::string
#include <vector>   // std::vector
#include <ctime>    // std::time_t

namespace forensics {

// ── ArtifactType 열거형 : 아티팩트의 종류 ───────────────────
enum class ArtifactType {
    RecentFile,     // 최근 열어본 파일 (.lnk 바로가기)
    PrefetchEntry,  // 프리패치 실행 기록 (.pf 파일)
    TempFile,       // 임시 파일
    DownloadedFile  // 다운로드된 파일
};

// ── Artifact 구조체 : 아티팩트 1개의 정보를 담는 그릇 ────────
struct Artifact {
    ArtifactType type;           // 위 열거형 중 하나
    std::string  typeName;       // 화면 출력용 타입 이름 (예: "Prefetch")
    std::string  path;           // 아티팩트 파일의 전체 경로
    std::string  name;           // 파일명
    std::string  description;    // 추가 설명 (예: "Executed: NOTEPAD.EXE")
    std::time_t  timestamp    = 0; // 이벤트 발생 시각 (숫자, 정렬에 사용)
    std::string  timestampStr;   // 시각 문자열 (출력용)
    uint64_t     size         = 0; // 파일 크기 (바이트)
};

// ── ArtifactCollector 클래스 : 아티팩트를 실제로 수집하는 기능 ─
class ArtifactCollector {
public:
    // 각 함수는 해당 위치의 파일 목록을 Artifact 벡터로 반환합니다.
    // Windows가 아닌 환경(Linux 등)에서는 빈 목록을 반환합니다.

    // collectRecentFiles : 최근 파일 바로가기(.lnk) 목록 수집
    static std::vector<Artifact> collectRecentFiles();

    // collectPrefetch : 프리패치 실행 기록(.pf) 목록 수집
    //                  관리자 권한이 필요한 경우가 있습니다.
    static std::vector<Artifact> collectPrefetch();

    // collectTempFiles : 임시 폴더의 파일 목록 수집
    static std::vector<Artifact> collectTempFiles();

    // collectDownloads : 다운로드 폴더의 파일 목록 수집
    static std::vector<Artifact> collectDownloads();

    // collectAll : 위 4가지를 모두 수집해서 시간순으로 정렬해 반환
    static std::vector<Artifact> collectAll();

private:
    // typeName : ArtifactType 열거값을 문자열로 변환하는 내부 함수
    static std::string typeName(ArtifactType t);

#ifdef _WIN32
    // scanDir : Windows API를 써서 특정 폴더를 탐색하는 내부 공통 함수
    //   dirPath    : 탐색할 폴더 경로
    //   type       : 수집할 아티팩트 종류
    //   description: 각 항목에 붙을 설명
    //   extFilter  : 특정 확장자만 필터링 (빈 문자열이면 전체)
    static std::vector<Artifact> scanDir(const std::string& dirPath,
                                         ArtifactType       type,
                                         const std::string& description,
                                         const std::string& extFilter = "");
#endif
};

} // namespace forensics
