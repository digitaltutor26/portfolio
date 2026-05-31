// ============================================================
// file_info.cpp  -  파일 메타데이터 수집 구현
// ============================================================
// 파일 1개 또는 폴더 전체를 분석해 메타데이터(크기, 시간,
// 해시, 매직 바이트 등)를 수집하는 기능을 구현합니다.
// ============================================================
#include "file_info.h"
#include "hash.h"      // MD5 / SHA-256 해시 계산
#include "common.h"    // formatTimestamp, filetimeToTimet 등

#include <fstream>     // std::ifstream (파일 읽기)
#include <algorithm>   // std::transform, std::sort
#include <cctype>      // std::tolower

// Windows 환경에서만 파일 속성 API 사용
#ifdef _WIN32
#include <windows.h>
#endif

namespace forensics {

// ============================================================
// categorize : 파일 확장자 → FileCategory 열거값
// ============================================================
// 수사 현장에서 "실행 파일이 몇 개인가?", "스크립트 파일이 있는가?" 등을
// 빠르게 분류할 때 사용합니다.
FileCategory FileInfoCollector::categorize(const std::string& ext) {
    // static : 함수가 여러 번 호출되어도 테이블은 딱 한 번만 만들어집니다.
    // 구조체 배열로 "확장자 → 카테고리" 매핑을 표현합니다.
    static const struct { const char* e; FileCategory c; } table[] = {

        // ── 실행 파일 (가장 위험도 높음, 포렌식에서 우선 분석 대상) ───
        {"exe", FileCategory::Executable},  // 일반 실행 파일
        {"dll", FileCategory::Executable},  // 동적 링크 라이브러리 (프로그램이 로드해서 사용)
        {"sys", FileCategory::Executable},  // 커널 드라이버 (시스템 핵심, 루트킷에 악용)
        {"scr", FileCategory::Executable},  // 화면 보호기 (exe와 동일한 포맷)
        {"com", FileCategory::Executable},  // 옛날 DOS 실행 파일
        {"msi", FileCategory::Executable},  // Windows 설치 패키지
        {"drv", FileCategory::Executable},  // 장치 드라이버

        // ── 스크립트 (코드를 실행할 수 있어 악성코드에 자주 이용됨) ──
        {"bat", FileCategory::Script},  // 배치 파일 (cmd.exe가 실행)
        {"cmd", FileCategory::Script},  // 배치 파일 (bat와 동일)
        {"ps1", FileCategory::Script},  // PowerShell 스크립트 (강력한 관리 언어)
        {"vbs", FileCategory::Script},  // VBScript (피싱 메일 첨부에 자주 사용)
        {"js",  FileCategory::Script},  // JScript
        {"jse", FileCategory::Script},  // 인코딩된 JScript
        {"wsf", FileCategory::Script},  // Windows 스크립트 파일
        {"wsh", FileCategory::Script},  // Windows 스크립트 호스트
        {"py",  FileCategory::Script},  // Python 스크립트
        {"rb",  FileCategory::Script},  // Ruby 스크립트
        {"sh",  FileCategory::Script},  // 쉘 스크립트 (Linux/macOS)

        // ── 문서 파일 (피해자가 열었던 문서, 개인 정보 포함 가능) ────
        {"doc",  FileCategory::Document}, {"docx", FileCategory::Document}, // Word
        {"xls",  FileCategory::Document}, {"xlsx", FileCategory::Document}, // Excel
        {"ppt",  FileCategory::Document}, {"pptx", FileCategory::Document}, // PowerPoint
        {"pdf",  FileCategory::Document},  // PDF
        {"txt",  FileCategory::Document},  // 텍스트
        {"rtf",  FileCategory::Document},  // 서식 있는 텍스트
        {"odt",  FileCategory::Document},  // LibreOffice 문서
        {"csv",  FileCategory::Document},  // CSV (데이터 테이블)
        {"xml",  FileCategory::Document},  // XML
        {"html", FileCategory::Document}, {"htm", FileCategory::Document}, // 웹 페이지

        // ── 이미지 ──────────────────────────────────────────────────
        {"jpg",  FileCategory::Image}, {"jpeg", FileCategory::Image},
        {"png",  FileCategory::Image}, {"bmp",  FileCategory::Image},
        {"gif",  FileCategory::Image}, {"tif",  FileCategory::Image},
        {"tiff", FileCategory::Image}, {"ico",  FileCategory::Image},
        {"webp", FileCategory::Image},

        // ── 동영상 ──────────────────────────────────────────────────
        {"mp4",  FileCategory::Video}, {"avi",  FileCategory::Video},
        {"mkv",  FileCategory::Video}, {"mov",  FileCategory::Video},
        {"wmv",  FileCategory::Video}, {"flv",  FileCategory::Video},

        // ── 오디오 ──────────────────────────────────────────────────
        {"mp3",  FileCategory::Audio}, {"wav",  FileCategory::Audio},
        {"flac", FileCategory::Audio}, {"aac",  FileCategory::Audio},
        {"wma",  FileCategory::Audio},

        // ── 압축 파일 (악성 파일을 숨기는 용도로 자주 악용) ─────────
        {"zip",  FileCategory::Archive}, {"rar", FileCategory::Archive},
        {"7z",   FileCategory::Archive}, {"tar", FileCategory::Archive},
        {"gz",   FileCategory::Archive}, {"bz2", FileCategory::Archive},
        {"cab",  FileCategory::Archive}, // Windows Cabinet (설치 파일에 사용)

        // ── 데이터베이스 (기록·채팅 이력 등 중요 증거 포함 가능) ───
        {"db",    FileCategory::Database},
        {"sqlite", FileCategory::Database}, // SQLite (Android 앱 등에서 많이 사용)
        {"mdb",   FileCategory::Database},  // Access DB
        {"accdb", FileCategory::Database},  // Access DB (최신)
        {"ldb",   FileCategory::Database},  // Access 잠금 파일

        // ── 로그 파일 (시스템 활동 기록의 핵심 증거) ────────────────
        {"log",  FileCategory::Log},  // 일반 텍스트 로그
        {"evtx", FileCategory::Log},  // Windows 이벤트 로그 (바이너리 형식)
        {"evt",  FileCategory::Log},  // 구형 Windows 이벤트 로그
    };

    // 테이블을 순서대로 검색해서 일치하는 항목 반환
    for (auto& row : table)
        if (ext == row.e) return row.c;

    return FileCategory::Unknown; // 목록에 없으면 미분류
}

// ============================================================
// categoryName : FileCategory 열거값 → 출력용 문자열
// ============================================================
std::string FileInfoCollector::categoryName(FileCategory cat) {
    switch (cat) {
        case FileCategory::Executable: return "Executable";
        case FileCategory::Script:     return "Script";
        case FileCategory::Document:   return "Document";
        case FileCategory::Image:      return "Image";
        case FileCategory::Video:      return "Video";
        case FileCategory::Audio:      return "Audio";
        case FileCategory::Archive:    return "Archive";
        case FileCategory::Database:   return "Database";
        case FileCategory::Log:        return "Log";
        default:                       return "Unknown";
    }
}

// ============================================================
// readMagic : 파일 앞 8바이트(매직 바이트)를 16진수 문자열로 반환
// ============================================================
// [매직 바이트란?]
//   거의 모든 파일 형식은 파일의 맨 앞에 고정된 서명 바이트를 가집니다.
//   이것을 '매직 넘버' 또는 '파일 시그니처'라고 합니다.
//   확장자는 바꿀 수 있지만 매직 바이트는 파일 내용에 포함되어 있어서
//   파일 형식을 더 신뢰할 수 있게 판별할 수 있습니다.
//
//   예시 매직 바이트:
//     Windows EXE/DLL : 4D 5A ...    ("MZ" 문자 - Mark Zbikowski의 이니셜)
//     JPEG 이미지     : FF D8 FF E0 ...
//     PNG 이미지      : 89 50 4E 47 ... (89 PNG ...)
//     ZIP 압축 파일   : 50 4B 03 04 ... ("PK" - Philip Katz의 이니셜)
//     PDF 문서        : 25 50 44 46 ... ("%PDF")
std::string FileInfoCollector::readMagic(const fs::path& path) {
    std::ifstream f(path, std::ios::binary); // 바이너리 모드 필수
    if (!f) return ""; // 파일을 열 수 없으면 빈 문자열

    uint8_t buf[8] = {}; // 8바이트 버퍼, 0으로 초기화
    f.read(reinterpret_cast<char*>(buf), sizeof(buf)); // 최대 8바이트 읽기
    auto n = static_cast<size_t>(f.gcount()); // 실제 읽은 바이트 수

    return bytesToHex(buf, n); // 바이트를 16진수 문자열로 변환
}

// ============================================================
// collect : 파일 1개의 메타데이터를 모두 수집해서 FileInfo로 반환
// ============================================================
// 매개변수 path       : 분석할 파일 경로
//           computeHash : true이면 MD5와 SHA-256 해시 계산 (시간 소요됨)
FileInfo FileInfoCollector::collect(const fs::path& path, bool computeHash) {
    FileInfo fi; // 결과를 담을 구조체 (모든 필드가 기본값으로 초기화됨)

    // ── 경로와 파일명 추출 ──────────────────────────────────────
    fi.path = path.string();           // 예: C:\Users\test\notepad.exe
    fi.name = path.filename().string(); // 예: notepad.exe

    // ── 확장자 추출 및 소문자 변환 ─────────────────────────────
    // path.extension()은 "." 포함해서 반환하므로 첫 글자(.) 제거
    std::string rawExt = path.extension().string();
    if (!rawExt.empty() && rawExt[0] == '.') rawExt = rawExt.substr(1);

    // 대소문자 구분 없이 비교하기 위해 소문자로 통일
    // 예) "EXE" → "exe", "Jpg" → "jpg"
    std::string ext = rawExt;
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    fi.extension = ext;
    fi.category  = categorize(ext); // 확장자로 카테고리 분류

    // ── 파일 크기와 시간 정보 수집 ─────────────────────────────
    std::error_code ec; // 예외 대신 에러 코드로 처리 (파일이 없거나 권한 없을 때)

    if (fs::exists(path, ec)) {
        auto sz = fs::file_size(path, ec);
        if (!ec) fi.size = sz; // 읽기 실패 시 0 유지

        // 수정 시각 (std::filesystem 기본 제공, 크로스 플랫폼)
        auto modTime = fs::last_write_time(path, ec);
        if (!ec) {
            // file_time_type을 time_t로 변환하는 번거로운 과정
            // C++20에서는 더 간단한 방법이 있지만 여기서는 C++17 방식 사용
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                modTime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
            );
            fi.modifiedTime = std::chrono::system_clock::to_time_t(sctp);
            fi.modified     = formatTimestamp(fi.modifiedTime);
        }

#ifdef _WIN32
        // ── Windows API로 정밀한 타임스탬프 3개 모두 가져오기 ──
        // std::filesystem은 수정 시각만 제공하지만,
        // Windows API의 GetFileTime은 생성/접근/수정 시각을 모두 제공합니다.

        // CreateFileW : 파일 핸들(handle)을 열어 파일을 제어할 수 있게 함
        //   GENERIC_READ                  : 읽기 전용으로 열기
        //   FILE_SHARE_READ|WRITE|DELETE  : 다른 프로세스도 동시 접근 허용
        //   OPEN_EXISTING                 : 파일이 없으면 실패
        //   FILE_FLAG_BACKUP_SEMANTICS    : 폴더도 열 수 있게 하는 플래그
        HANDLE hFile = CreateFileW(
            path.wstring().c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr
        );

        if (hFile != INVALID_HANDLE_VALUE) { // 파일 열기 성공
            FILETIME ftCreate, ftAccess, ftWrite;

            // GetFileTime : 파일의 3가지 타임스탬프를 FILETIME 구조체로 가져옴
            if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
                fi.createdTime  = filetimeToTimet(ftCreate);  // 생성 시각
                fi.accessedTime = filetimeToTimet(ftAccess);  // 마지막 접근 시각
                fi.modifiedTime = filetimeToTimet(ftWrite);   // 마지막 수정 시각

                fi.created  = filetimeToString(ftCreate);
                fi.accessed = filetimeToString(ftAccess);
                fi.modified = filetimeToString(ftWrite);
            }

            CloseHandle(hFile); // 반드시 핸들을 닫아야 메모리 누수 방지

            // ── 파일 속성(숨김/시스템/읽기전용) 가져오기 ────────
            DWORD attrs = GetFileAttributesW(path.wstring().c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                // 비트 AND 연산으로 특정 속성 플래그가 켜져 있는지 확인
                fi.isHidden   = (attrs & FILE_ATTRIBUTE_HIDDEN)   != 0;
                fi.isSystem   = (attrs & FILE_ATTRIBUTE_SYSTEM)   != 0;
                fi.isReadOnly = (attrs & FILE_ATTRIBUTE_READONLY) != 0;
            }
        }
#else
        // Windows가 아닌 환경에서는 생성/접근 시각을 수정 시각과 동일하게 처리
        fi.created  = fi.modified;
        fi.accessed = fi.modified;
#endif
    }

    // ── 매직 바이트 읽기 ────────────────────────────────────────
    fi.magic = readMagic(path);

    // ── 해시 계산 (선택적, computeHash = true일 때만 수행) ──────
    // 해시 계산은 파일 전체를 읽어야 하므로 대용량 파일에서 느릴 수 있습니다.
    if (computeHash) {
        try {
            fi.md5    = Hash::md5File(path.string());
            fi.sha256 = Hash::sha256File(path.string());
        } catch (...) {
            // 파일 읽기 실패 (권한 없음 등)는 "error"로 표시
            fi.md5 = fi.sha256 = "error";
        }
    }

    return fi; // 완성된 FileInfo 반환
}

// ============================================================
// scanDirectory : 폴더 안의 모든 파일을 수집해서 목록으로 반환
// ============================================================
// 매개변수 dir         : 탐색할 폴더 경로
//           recursive   : true이면 하위 폴더까지 재귀 탐색
//           computeHash : true이면 각 파일의 해시도 계산
std::vector<FileInfo> FileInfoCollector::scanDirectory(const fs::path& dir,
                                                       bool recursive,
                                                       bool computeHash) {
    std::vector<FileInfo> results; // 수집한 파일 정보를 담을 동적 배열
    std::error_code ec;

    // visit : 파일 항목 하나를 처리하는 람다 함수 (지역 함수처럼 사용)
    // [&] : 주변 변수(results, computeHash, ec)를 참조로 캡처
    auto visit = [&](const fs::directory_entry& entry) {
        if (entry.is_regular_file(ec)) // 일반 파일만 처리 (폴더, 링크 제외)
            results.push_back(collect(entry.path(), computeHash));
    };

    // recursive = true이면 하위 폴더도 모두 탐색
    if (recursive) {
        for (auto& entry : fs::recursive_directory_iterator(dir, ec))
            visit(entry);
    } else {
        // 현재 폴더만 탐색
        for (auto& entry : fs::directory_iterator(dir, ec))
            visit(entry);
    }

    // 수정 시각 기준으로 내림차순 정렬 (최근에 수정된 파일이 위에 오도록)
    // 포렌식에서 "최근 활동"을 먼저 보는 것이 일반적입니다.
    std::sort(results.begin(), results.end(),
        [](const FileInfo& a, const FileInfo& b) {
            return a.modifiedTime > b.modifiedTime; // > : 큰 값(최신)이 앞에
        });

    return results;
}

} // namespace forensics
