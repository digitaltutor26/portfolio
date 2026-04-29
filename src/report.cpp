// ============================================================
// report.cpp  -  분석 결과를 Text / CSV / JSON 형식으로 출력
// ============================================================
// 포렌식 보고서는 수사 기록으로 남겨야 하기 때문에 여러 형식을 지원합니다:
//
//   Text : 콘솔에서 바로 읽기 편한 형식 (개인 확인용)
//   CSV  : 엑셀로 열어서 필터링·정렬 가능 (분석·보고서 작성용)
//   JSON : 다른 분석 도구와 연동 가능한 구조화된 형식 (자동화·확장용)
// ============================================================
#include "report.h"
#include "common.h"    // formatTimestamp

#include <algorithm>   // std::sort
#include <iomanip>     // std::setw, std::left (텍스트 정렬)
#include <sstream>     // std::ostringstream (문자열 조합)

namespace forensics {

// ============================================================
// csvEscape : CSV 형식에서 특수문자를 안전하게 처리
// ============================================================
// CSV(Comma-Separated Values)에서는 쉼표(,)가 열 구분자이므로
// 데이터 안에 쉼표나 따옴표가 있으면 올바르게 감싸야 합니다.
//
// 규칙:
//   - 쉼표(,), 큰따옴표("), 줄바꿈이 포함된 필드는 큰따옴표로 감쌈
//   - 데이터 안의 큰따옴표는 두 개("") 로 이스케이프
//
// 예)  He said "hello", world
// →  "He said ""hello"", world"
std::string Report::csvEscape(const std::string& s) {
    // 특수문자가 있는지 먼저 확인 (없으면 그대로 반환해서 성능 절약)
    bool needQuote = s.find_first_of(",\"\r\n") != std::string::npos;
    if (!needQuote) return s;

    std::string out = "\""; // 시작 따옴표
    for (char c : s) {
        if (c == '"') out += "\"\""; // 따옴표 → 두 개의 따옴표로 이스케이프
        else          out += c;
    }
    out += '"'; // 끝 따옴표
    return out;
}

// ============================================================
// jsonEscape : JSON 문자열 안의 특수문자를 이스케이프
// ============================================================
// JSON 표준(RFC 8259)에서 문자열 안에 직접 쓸 수 없는 문자들:
//   "  → \"   (큰따옴표 - JSON 문자열의 경계 기호)
//   \  → \\   (역슬래시 - 이스케이프 시작 기호)
//   개행→ \n  (줄바꿈)
//   탭 → \t  (탭 문자)
//   0x00~0x1F → \u00XX (제어 문자)
std::string Report::jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size()); // 예상 크기 미리 확보 (성능 최적화)

    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break; // " → \"
            case '\\': out += "\\\\"; break; // \ → \\
            case '\n': out += "\\n";  break; // 줄바꿈 → \n
            case '\r': out += "\\r";  break; // 캐리지 리턴 → \r
            case '\t': out += "\\t";  break; // 탭 → \t
            default:
                if (c < 0x20) {
                    // 0x00~0x1F: 출력 불가 제어 문자 → \u00XX 형태로 변환
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c); // 일반 문자는 그대로
                }
        }
    }
    return out;
}

// ============================================================
// jsonString : JSON 문자열 값 완성 (이스케이프 + 양쪽 따옴표)
// ============================================================
// 예) test\npath  →  "test\\npath"
std::string Report::jsonString(const std::string& s) {
    return "\"" + jsonEscape(s) + "\"";
}

// ============================================================
// parseFormat : 문자열 → ReportFormat 열거값
// ============================================================
// 명령줄에서 "--format csv" 입력 시 "csv" 문자열을 ReportFormat::CSV로 변환
ReportFormat Report::parseFormat(const std::string& str) {
    if (str == "csv")  return ReportFormat::CSV;
    if (str == "json") return ReportFormat::JSON;
    return ReportFormat::Text; // 그 외("text" 포함)는 기본값 Text
}

// ============================================================
// writeFileInfo : FileInfo 1개를 지정 형식으로 출력
// ============================================================
// 매개변수 out : 출력 대상 (std::cout이면 화면, std::ofstream이면 파일)
//           fi  : 출력할 파일 정보
//           fmt : 출력 형식
void Report::writeFileInfo(std::ostream& out, const FileInfo& fi, ReportFormat fmt) {
    auto cat = FileInfoCollector::categoryName(fi.category); // 카테고리 문자열

    switch (fmt) {

    // ── 텍스트 형식 ─────────────────────────────────────────────
    case ReportFormat::Text:
        out << "Path     : " << fi.path     << "\n" // 전체 경로
            << "Name     : " << fi.name     << "\n" // 파일명
            << "Size     : " << fi.size     << " bytes\n" // 크기
            << "Category : " << cat         << "\n" // 카테고리
            << "Magic    : " << fi.magic    << "\n" // 매직 바이트 (파일 시그니처)
            << "Created  : " << fi.created  << "\n" // 생성 시각
            << "Modified : " << fi.modified << "\n" // 수정 시각
            << "Accessed : " << fi.accessed << "\n" // 접근 시각
            << "Hidden   : " << (fi.isHidden   ? "Yes" : "No") << "\n"
            << "System   : " << (fi.isSystem   ? "Yes" : "No") << "\n"
            << "ReadOnly : " << (fi.isReadOnly ? "Yes" : "No") << "\n";
        // 해시는 계산한 경우에만 출력 (빈 문자열이면 출력 안 함)
        if (!fi.md5.empty())
            out << "MD5      : " << fi.md5    << "\n"
                << "SHA256   : " << fi.sha256 << "\n";
        out << "\n"; // 파일 간 빈 줄 구분
        break;

    // ── CSV 형식 ─────────────────────────────────────────────────
    // 각 필드를 쉼표로 구분, 줄 끝에 개행
    // 쉼표나 따옴표가 포함된 필드는 csvEscape로 감싸줌
    case ReportFormat::CSV:
        out << csvEscape(fi.path)     << ","  // A열: 경로
            << csvEscape(fi.name)     << ","  // B열: 파일명
            << fi.size                << ","  // C열: 크기 (숫자라서 escape 불필요)
            << csvEscape(cat)         << ","  // D열: 카테고리
            << csvEscape(fi.magic)    << ","  // E열: 매직 바이트
            << csvEscape(fi.created)  << ","  // F열: 생성 시각
            << csvEscape(fi.modified) << ","  // G열: 수정 시각
            << csvEscape(fi.accessed) << ","  // H열: 접근 시각
            << (fi.isHidden   ? "1" : "0") << "," // I열: 숨김 (1=예, 0=아니오)
            << (fi.isSystem   ? "1" : "0") << "," // J열: 시스템
            << (fi.isReadOnly ? "1" : "0") << "," // K열: 읽기전용
            << csvEscape(fi.md5)      << ","  // L열: MD5
            << csvEscape(fi.sha256)   << "\n"; // M열: SHA256
        break;

    // ── JSON 형식 ────────────────────────────────────────────────
    // JSON 객체 { "key": value, ... } 형태로 출력
    case ReportFormat::JSON:
        out << "  {\n"
            << "    \"path\":"     << jsonString(fi.path)     << ",\n"
            << "    \"name\":"     << jsonString(fi.name)     << ",\n"
            << "    \"size\":"     << fi.size                 << ",\n" // 숫자는 따옴표 없이
            << "    \"category\":" << jsonString(cat)         << ",\n"
            << "    \"magic\":"    << jsonString(fi.magic)    << ",\n"
            << "    \"created\":"  << jsonString(fi.created)  << ",\n"
            << "    \"modified\":" << jsonString(fi.modified) << ",\n"
            << "    \"accessed\":" << jsonString(fi.accessed) << ",\n"
            << "    \"hidden\":"   << (fi.isHidden   ? "true" : "false") << ",\n" // JSON 불리언
            << "    \"system\":"   << (fi.isSystem   ? "true" : "false") << ",\n"
            << "    \"readonly\":" << (fi.isReadOnly ? "true" : "false") << ",\n"
            << "    \"md5\":"      << jsonString(fi.md5)      << ",\n"
            << "    \"sha256\":"   << jsonString(fi.sha256)   << "\n"
            << "  }";
        // 주의: JSON 배열 안에서 쓸 때 뒤에 쉼표를 붙여야 할 수 있어
        //       여기서는 개행만 하고 쉼표는 배열 출력 함수에서 처리
        break;
    }
}

// ============================================================
// writeFileInfoList : 파일 목록 전체 출력 (헤더 포함)
// ============================================================
void Report::writeFileInfoList(std::ostream& out,
                               const std::vector<FileInfo>& files,
                               ReportFormat fmt) {
    if (fmt == ReportFormat::Text) {
        // 텍스트: 요약 헤더 + 각 파일 정보
        out << "=== File Analysis Report ===\n"
            << "Total files: " << files.size() << "\n\n";
        for (auto& fi : files) writeFileInfo(out, fi, fmt);
        return;
    }

    if (fmt == ReportFormat::CSV) {
        // CSV: 첫 줄에 컬럼 이름(헤더) 출력 후 각 행 출력
        out << "Path,Name,Size,Category,Magic,Created,Modified,Accessed,"
               "Hidden,System,ReadOnly,MD5,SHA256\n";
        for (auto& fi : files) writeFileInfo(out, fi, fmt);
        return;
    }

    // JSON: 배열 [ {...}, {...}, ... ] 형태
    out << "[\n";
    for (size_t i = 0; i < files.size(); ++i) {
        writeFileInfo(out, files[i], fmt);
        // 마지막 항목이 아니면 쉼표 추가 (JSON 배열 문법)
        if (i + 1 < files.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
}

// ============================================================
// writeArtifacts : 아티팩트 목록 출력
// ============================================================
void Report::writeArtifacts(std::ostream& out,
                             const std::vector<Artifact>& artifacts,
                             ReportFormat fmt) {
    // 수집된 아티팩트가 없을 때 처리
    if (artifacts.empty()) {
        if (fmt == ReportFormat::Text)
            out << "No artifacts collected (Windows required).\n";
        else if (fmt == ReportFormat::JSON)
            out << "[]\n"; // 빈 JSON 배열
        return;
    }

    if (fmt == ReportFormat::Text) {
        out << "=== Windows Artifact Report ===\n"
            << "Total artifacts: " << artifacts.size() << "\n\n";
        for (auto& a : artifacts) {
            // [타입] 형태로 항목 구분
            out << "[" << a.typeName << "]\n"
                << "  Name      : " << a.name         << "\n"
                << "  Path      : " << a.path         << "\n"
                << "  Timestamp : " << a.timestampStr << "\n"
                << "  Size      : " << a.size         << " bytes\n"
                << "  Info      : " << a.description  << "\n\n";
        }
        return;
    }

    if (fmt == ReportFormat::CSV) {
        out << "Type,Name,Path,Timestamp,Size,Description\n";
        for (auto& a : artifacts) {
            out << csvEscape(a.typeName)     << ","
                << csvEscape(a.name)         << ","
                << csvEscape(a.path)         << ","
                << csvEscape(a.timestampStr) << ","
                << a.size                    << ","
                << csvEscape(a.description)  << "\n";
        }
        return;
    }

    // JSON
    out << "[\n";
    for (size_t i = 0; i < artifacts.size(); ++i) {
        auto& a = artifacts[i];
        out << "  {\n"
            << "    \"type\":"        << jsonString(a.typeName)     << ",\n"
            << "    \"name\":"        << jsonString(a.name)         << ",\n"
            << "    \"path\":"        << jsonString(a.path)         << ",\n"
            << "    \"timestamp\":"   << jsonString(a.timestampStr) << ",\n"
            << "    \"size\":"        << a.size                     << ",\n"
            << "    \"description\":" << jsonString(a.description)  << "\n"
            << "  }";
        if (i + 1 < artifacts.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
}

// ============================================================
// buildTimeline : 파일 정보 + 아티팩트를 합쳐 타임라인 이벤트 목록 생성
// ============================================================
// 타임라인이란?
//   여러 소스에서 수집한 이벤트를 시간 순서대로 나열한 것입니다.
//   "2024-07-15 09:10 - 파일 생성"
//   "2024-07-15 09:11 - 프로그램 실행"
//   "2024-07-15 09:15 - 파일 수정"
//   이런 순서로 보면 "무슨 일이 어떤 순서로 일어났는지" 재구성할 수 있습니다.
std::vector<TimelineEvent> Report::buildTimeline(
    const std::vector<FileInfo>&  files,
    const std::vector<Artifact>&  artifacts)
{
    std::vector<TimelineEvent> events;

    // ── 파일 정보에서 이벤트 추출 ───────────────────────────────
    // 파일 1개당 최대 3가지 이벤트(생성/수정/접근)가 생길 수 있습니다.
    for (auto& fi : files) {
        // 생성 이벤트 (타임스탬프가 유효한 경우만)
        if (fi.createdTime > 0)
            events.push_back({
                fi.createdTime,
                formatTimestamp(fi.createdTime),
                "Created",   // 이벤트 종류
                fi.path,
                fi.name      // 설명 = 파일명
            });

        // 수정 이벤트 (생성 시각과 다를 때만 추가 - 중복 방지)
        if (fi.modifiedTime > 0 && fi.modifiedTime != fi.createdTime)
            events.push_back({
                fi.modifiedTime,
                formatTimestamp(fi.modifiedTime),
                "Modified",
                fi.path,
                fi.name
            });

        // 접근 이벤트 (수정 시각과 다를 때만 추가)
        if (fi.accessedTime > 0 && fi.accessedTime != fi.modifiedTime)
            events.push_back({
                fi.accessedTime,
                formatTimestamp(fi.accessedTime),
                "Accessed",
                fi.path,
                fi.name
            });
    }

    // ── 아티팩트에서 이벤트 추출 ────────────────────────────────
    for (auto& a : artifacts) {
        if (a.timestamp > 0) {
            events.push_back({
                a.timestamp,
                a.timestampStr,
                a.typeName,      // "RecentFile", "Prefetch" 등
                a.path,
                a.description    // 예: "Executed: NOTEPAD.EXE"
            });
        }
    }

    // 타임스탬프 내림차순 정렬 (가장 최근 이벤트가 위에)
    std::sort(events.begin(), events.end(),
        [](const TimelineEvent& a, const TimelineEvent& b) {
            return a.timestamp > b.timestamp;
        });

    return events;
}

// ============================================================
// writeTimeline : 타임라인 이벤트 목록 출력
// ============================================================
void Report::writeTimeline(std::ostream& out,
                            const std::vector<TimelineEvent>& events,
                            ReportFormat fmt) {
    if (fmt == ReportFormat::Text) {
        out << "=== Activity Timeline ===\n"
            << "Events: " << events.size() << "\n\n";
        for (auto& e : events) {
            // "2024-07-15 09:10:22  [Created   ]  test.exe"
            out << e.timestampStr
                << "  [" << std::setw(10) << std::left << e.eventType << "]  "
                // std::setw(10): 이벤트 타입 열을 10자리로 고정 (정렬)
                // std::left: 왼쪽 정렬
                << e.description << "\n"
                << "           -> " << e.path << "\n"; // 파일 경로 들여쓰기
        }
        return;
    }

    if (fmt == ReportFormat::CSV) {
        out << "Timestamp,EventType,Path,Description\n";
        for (auto& e : events) {
            out << csvEscape(e.timestampStr) << ","
                << csvEscape(e.eventType)    << ","
                << csvEscape(e.path)         << ","
                << csvEscape(e.description)  << "\n";
        }
        return;
    }

    // JSON 배열로 출력
    out << "[\n";
    for (size_t i = 0; i < events.size(); ++i) {
        auto& e = events[i];
        out << "  {\n"
            << "    \"timestamp\":"   << jsonString(e.timestampStr) << ",\n"
            << "    \"event_type\":"  << jsonString(e.eventType)    << ",\n"
            << "    \"path\":"        << jsonString(e.path)         << ",\n"
            << "    \"description\":" << jsonString(e.description)  << "\n"
            << "  }";
        if (i + 1 < events.size()) out << ","; // 마지막 아니면 쉼표
        out << "\n";
    }
    out << "]\n";
}

} // namespace forensics
