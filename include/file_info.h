// ============================================================
// file_info.h  -  파일 메타데이터 수집 선언
// ============================================================
// 포렌식에서 파일 분석이란 단순히 내용을 보는 것뿐 아니라
// 파일에 대한 '부가 정보(메타데이터)'를 모두 수집하는 것입니다.
//
// 예) 수사관이 "이 파일이 언제 만들어졌고, 언제 마지막으로 열었고,
//     원본에서 변조된 건 아닌지" 확인해야 할 때 이 정보를 씁니다.
//
// 이 파일에서 다루는 주요 개념:
//   - 타임스탬프 : 파일의 생성/수정/접근 시각 (MAC Time)
//   - 매직 바이트 : 파일 앞부분의 고정 바이트로 진짜 파일 형식 파악
//   - 파일 카테고리 : 확장자로 파일을 분류 (실행파일, 문서, 이미지 등)
//   - 속성 : 숨김/시스템/읽기전용 여부
// ============================================================
#pragma once

#include <string>      // std::string
#include <vector>      // std::vector (동적 배열)
#include <cstdint>     // uint64_t (8바이트 정수, 파일 크기에 사용)
#include <ctime>       // std::time_t
#include <filesystem>  // std::filesystem::path

namespace forensics {

namespace fs = std::filesystem;

// ── 파일 카테고리 열거형 ─────────────────────────────────────
// enum class : 관련 있는 상수들을 하나의 타입으로 묶는 방법
// 확장자를 보고 이 중 하나로 분류합니다.
enum class FileCategory {
    Executable,  // 실행 파일 (.exe, .dll, .sys, .com 등) - 악성코드 분석 시 우선 확인
    Script,      // 스크립트 (.bat, .ps1, .vbs, .py 등)   - 자동 실행 공격에 자주 사용
    Document,    // 문서 (.doc, .pdf, .xlsx 등)           - 피해자가 열었던 파일 확인
    Image,       // 이미지 (.jpg, .png, .bmp 등)
    Video,       // 동영상 (.mp4, .avi, .mkv 등)
    Audio,       // 오디오 (.mp3, .wav 등)
    Archive,     // 압축 파일 (.zip, .rar, .7z 등)        - 악성 파일 숨기기에 자주 이용
    Database,    // 데이터베이스 (.db, .sqlite, .mdb 등)  - 기록·로그 저장소
    Log,         // 로그 파일 (.log, .evtx, .evt 등)      - 시스템 활동 기록
    Unknown      // 알 수 없는 형식
};

// ── FileInfo 구조체 : 파일 1개의 모든 메타데이터를 담는 그릇 ────
// struct : 여러 타입의 데이터를 하나의 이름으로 묶는 사용자 정의 타입
struct FileInfo {
    std::string  path;           // 파일의 전체 경로  (예: C:\Users\홍길동\Desktop\test.exe)
    std::string  name;           // 파일명만          (예: test.exe)
    std::string  extension;      // 확장자(소문자)    (예: exe)
    uint64_t     size        = 0; // 파일 크기 (바이트 단위, 0으로 기본 초기화)

    // ── MAC Time (포렌식 핵심 3대 타임스탬프) ─────────────────────
    // M : Modified  - 파일 내용이 마지막으로 수정된 시각
    // A : Accessed  - 파일이 마지막으로 열린/읽힌 시각
    // C : Created   - 파일이 처음 만들어진 시각
    // time_t는 숫자(계산용), string은 "2024-07-15 13:22:01" 형태(출력용)
    std::time_t  createdTime  = 0;
    std::time_t  modifiedTime = 0;
    std::time_t  accessedTime = 0;
    std::string  created;        // 생성 시각 문자열
    std::string  modified;       // 수정 시각 문자열
    std::string  accessed;       // 접근 시각 문자열

    // ── 해시값 ──────────────────────────────────────────────────
    std::string  md5;            // MD5  해시 (32자리 16진수 문자열)
    std::string  sha256;         // SHA-256 해시 (64자리 16진수 문자열)

    // ── 매직 바이트 ─────────────────────────────────────────────
    // 파일 앞 8바이트를 16진수로 표현한 값
    // 확장자가 .jpg로 되어있어도 실제 내용이 exe이면 매직 바이트가 다릅니다.
    // 예) Windows EXE : "4d5a9000..." (MZ 로 시작)
    //     JPEG 이미지 : "ffd8ffe0..." (FF D8 로 시작)
    std::string  magic;

    FileCategory category   = FileCategory::Unknown; // 파일 카테고리

    // ── Windows 파일 속성 ────────────────────────────────────────
    bool         isHidden   = false; // 숨김 파일 여부 (탐색기에서 안 보임)
    bool         isSystem   = false; // 시스템 파일 여부 (OS 핵심 파일)
    bool         isReadOnly = false; // 읽기 전용 여부 (수정 불가)
};

// ── FileInfoCollector 클래스 : 파일 정보를 실제로 수집하는 기능 ──
class FileInfoCollector {
public:
    // collect : 파일 1개의 메타데이터를 모아 FileInfo로 반환
    //           computeHash = true 면 해시 계산도 수행 (느림 주의)
    static FileInfo collect(const fs::path& path, bool computeHash = false);

    // scanDirectory : 폴더 안의 모든 파일을 수집해서 목록으로 반환
    //                 recursive = true 면 하위 폴더까지 재귀적으로 탐색
    static std::vector<FileInfo> scanDirectory(const fs::path& dir,
                                               bool recursive   = false,
                                               bool computeHash = false);

    // categorize   : 소문자 확장자 문자열을 받아 FileCategory를 반환
    // categoryName : FileCategory 열거값을 읽기 쉬운 문자열로 변환
    static FileCategory categorize(const std::string& lowerExt);
    static std::string  categoryName(FileCategory cat);

private:
    // readMagic : 파일 앞 8바이트를 읽어 16진수 문자열로 반환 (내부용)
    static std::string readMagic(const fs::path& path);
};

} // namespace forensics
