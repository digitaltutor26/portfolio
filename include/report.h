// ============================================================
// report.h  -  분석 결과 보고서 출력 선언
// ============================================================
// 수집한 파일 정보와 아티팩트를 3가지 형식으로 출력합니다:
//
//   Text : 사람이 바로 읽기 좋은 텍스트 형식
//          예) Path     : C:\Users\test.exe
//              Size     : 12345 bytes
//
//   CSV  : 쉼표로 구분된 형식 (엑셀에서 바로 열기 가능)
//          예) Path,Name,Size,...
//              C:\test.exe,test.exe,12345,...
//
//   JSON : 프로그래밍 언어에서 파싱하기 좋은 구조화 형식
//          예) [{"path":"C:\\test.exe","size":12345,...}]
//
// 타임라인(Timeline):
//   파일의 생성/수정/접근 시각과 아티팩트 발생 시각을 한데 모아
//   시간 순서대로 나열하면 "언제 무슨 일이 있었는지" 한눈에 볼 수 있습니다.
//   이것을 '활동 타임라인'이라고 합니다.
// ============================================================
#pragma once

#include "file_info.h"           // FileInfo 구조체
#include "artifact_collector.h"  // Artifact 구조체
#include "lnk_parser.h"          // LnkInfo 구조체
#include "mft_parser.h"          // MftRecord 구조체
#include <string>
#include <vector>
#include <ostream>

namespace forensics {

// ── 출력 형식 열거형 ─────────────────────────────────────────
enum class ReportFormat {
    Text,  // 사람이 읽는 텍스트
    CSV,   // 엑셀 호환 CSV
    JSON   // 프로그래밍 친화적 JSON
};

// ── TimelineEvent 구조체 : 타임라인에 올라가는 이벤트 1건 ────
struct TimelineEvent {
    std::time_t timestamp    = 0;  // 이벤트 발생 시각 (정렬용 숫자)
    std::string timestampStr;      // 시각 문자열 (출력용)
    std::string eventType;         // 이벤트 종류 (예: "Created", "Modified", "Prefetch")
    std::string path;              // 관련 파일 경로
    std::string description;       // 이벤트 설명
};

// ── LnkAnalysis : LNK 파일 1개의 파싱 결과 + MFT 매칭 레코드 ──
struct LnkAnalysis {
    LnkInfo               lnk;
    std::vector<MftRecord> mftRecords;
};

// ── Report 클래스 : 보고서 출력을 담당하는 기능 ────────────────
class Report {
public:
    // writeFileInfo : FileInfo 1개를 지정한 형식으로 출력
    static void writeFileInfo(std::ostream& out,
                              const FileInfo& fi,
                              ReportFormat fmt);

    // writeFileInfoList : FileInfo 목록 전체를 출력 (헤더 포함)
    static void writeFileInfoList(std::ostream& out,
                                  const std::vector<FileInfo>& files,
                                  ReportFormat fmt);

    // writeArtifacts : 아티팩트 목록을 출력
    static void writeArtifacts(std::ostream& out,
                                const std::vector<Artifact>& artifacts,
                                ReportFormat fmt);

    // writeTimeline : 타임라인 이벤트 목록을 출력
    static void writeTimeline(std::ostream& out,
                               const std::vector<TimelineEvent>& events,
                               ReportFormat fmt);

    // buildTimeline : 파일 정보 + 아티팩트를 합쳐 타임라인 이벤트 목록 생성
    //                (시간 역순, 즉 최신 이벤트가 위에 오도록 정렬)
    static std::vector<TimelineEvent> buildTimeline(
        const std::vector<FileInfo>&    files,
        const std::vector<Artifact>&    artifacts);

    // writeLnkAnalysis : LNK 파싱 결과 + $MFT $SI/$FN 타임스탬프 보고서
    static void writeLnkAnalysis(std::ostream& out,
                                  const std::vector<LnkAnalysis>& results,
                                  ReportFormat fmt);

    // parseFormat : "text" / "csv" / "json" 문자열을 ReportFormat 열거값으로 변환
    static ReportFormat parseFormat(const std::string& str);

private:
    // ── 내부 문자열 처리 함수 ───────────────────────────────────

    // csvEscape : CSV에서 쉼표나 따옴표가 포함된 문자열을 안전하게 감싸기
    //            예) He said "hi", world  →  "He said ""hi"", world"
    static std::string csvEscape(const std::string& s);

    // jsonEscape  : JSON 문자열 안에 들어가면 안 되는 특수문자를 이스케이프 처리
    //              예) 역슬래시(\) → \\,  줄바꿈(\n) → \n (문자 2개)
    // jsonString  : jsonEscape를 적용한 후 양쪽에 큰따옴표를 추가한 완성된 JSON 문자열
    //              예) test\n  →  "test\\n"
    static std::string jsonEscape(const std::string& s);
    static std::string jsonString(const std::string& s);
};

} // namespace forensics
