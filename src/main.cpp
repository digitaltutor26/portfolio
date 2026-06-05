// ============================================================
// main.cpp  -  프로그램 진입점 및 명령줄 인터페이스(CLI)
// ============================================================
// 이 파일은 프로그램이 시작될 때 가장 먼저 실행되는 곳입니다.
// 사용자가 입력한 명령줄 옵션을 해석하고, 적절한 분석 함수를 호출합니다.
//
// 지원하는 명령어:
//   analyze  <경로>  : 파일/폴더 메타데이터 분석
//   artifacts        : Windows 컴퓨터 활동 흔적 수집
//   timeline <경로>  : 파일 + 아티팩트 통합 타임라인 생성
//
// 사용 예시:
//   winforensics analyze C:\Users\홍길동\Desktop --hash --recursive
//   winforensics artifacts --prefetch --recent --format csv
//   winforensics timeline C:\Users\홍길동 --all --format json --output 결과.json
// ============================================================
#include "file_info.h"           // 파일 메타데이터 수집
#include "artifact_collector.h"  // Windows 아티팩트 수집
#include "lnk_parser.h"          // LNK 파일 파서
#include "mft_parser.h"          // $MFT 파서
#include "report.h"              // 보고서 출력
#include "common.h"              // 유틸리티 함수

#include <iostream>    // std::cout, std::cerr (화면 출력)
#include <fstream>     // std::ofstream (파일 출력)
#include <string>      // std::string
#include <vector>      // std::vector
#include <filesystem>  // std::filesystem
#include <algorithm>   // std::sort
#include <cstring>     // strcmp 등

namespace fs = std::filesystem;
using namespace forensics; // forensics:: 접두사 없이 사용 가능

// ============================================================
// Options 구조체 : 명령줄에서 읽은 옵션들을 한 곳에 모아 관리
// ============================================================
struct Options {
    std::string  command;         // 실행할 명령 ("analyze", "artifacts", "timeline")
    std::string  path;            // 분석 대상 경로
    ReportFormat format      = ReportFormat::Text; // 출력 형식 (기본: 텍스트)
    std::string  outputFile;      // 결과를 저장할 파일 경로 (비어있으면 화면 출력)
    bool         recursive   = false; // 하위 폴더도 재귀 탐색할지 여부
    bool         computeHash = false; // MD5/SHA256 해시 계산 여부
    bool         recent      = false; // 최근 파일 수집 여부
    bool         prefetch    = false; // 프리패치 수집 여부
    bool         temp        = false; // 임시 파일 수집 여부
    bool         downloads   = false; // 다운로드 폴더 수집 여부
    std::string  mftPath;             // $MFT 원시 파일 경로 (--mft 옵션)
};

// ============================================================
// printHelp : 사용법 안내 메시지 출력
// ============================================================
// --help 옵션 또는 명령 없이 실행 시 출력됩니다.
static void printHelp() {
    std::cout <<
"WinForensics v1.0 - Windows Digital Forensics Toolkit\n"
"\n"
"Usage:\n"
"  winforensics analyze  <path> [options]\n"  // 파일/폴더 분석
"  winforensics artifacts       [options]\n"  // Windows 활동 흔적 수집
"  winforensics timeline <path> [options]\n"  // 통합 타임라인
"\n"
"Commands:\n"
"  analyze <path>   Analyze file or directory (metadata, hashes, categories)\n"
"  artifacts        Collect Windows computer activity artifacts\n"
"  timeline <path>  Build unified activity timeline from files + artifacts\n"
"\n"
"Options:\n"
"  --format <fmt>   Output format: text | csv | json   (default: text)\n"
"  --output <file>  Write report to file (default: stdout)\n"
"  --hash           Compute MD5 + SHA256 hashes        (analyze/timeline)\n"
"  --recursive      Scan subdirectories                (analyze/timeline)\n"
"  --recent         Collect Recent files               (artifacts/timeline)\n"
"  --prefetch       Collect Prefetch entries           (artifacts/timeline)\n"
"  --temp           Collect Temp files                 (artifacts/timeline)\n"
"  --downloads      Collect Downloads folder           (artifacts/timeline)\n"
"  --all            All artifact types                 (default for artifacts)\n"
"  --help           Show this help\n"
"\n"
"Examples:\n"
"  winforensics analyze C:\\Users\\John\\Desktop --hash --recursive\n"
"  winforensics artifacts --prefetch --recent --format csv --output report.csv\n"
"  winforensics timeline C:\\Users\\John --all --format json --output timeline.json\n";
}

// ============================================================
// parseArgs : 명령줄 인자(argv)를 분석해서 Options 구조체로 반환
// ============================================================
// argc : 인자의 개수 (프로그램명 포함)
// argv : 인자 문자열 배열 (argv[0] = 프로그램명, argv[1]부터 사용자 입력)
//
// 예) winforensics analyze C:\test --hash --format csv
//     argc = 5
//     argv[0] = "winforensics"
//     argv[1] = "analyze"
//     argv[2] = "C:\test"
//     argv[3] = "--hash"
//     argv[4] = "--format"
//     argv[5] = "csv"
static Options parseArgs(int argc, char* argv[]) {
    Options opts; // 기본값으로 초기화된 옵션 구조체

    // argv[1]부터 끝까지 하나씩 처리
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i]; // 현재 인자를 string으로 변환

        if (arg == "--help" || arg == "-h") {
            // 도움말 출력 후 즉시 종료
            printHelp();
            std::exit(0);
        }
        else if (arg == "analyze" || arg == "artifacts" ||
                 arg == "timeline" || arg == "lnk") {
            opts.command = arg;
            if (i + 1 < argc && argv[i+1][0] != '-')
                opts.path = argv[++i];
        }
        else if (arg == "--format" && i + 1 < argc) {
            // "--format csv" → opts.format = ReportFormat::CSV
            opts.format = Report::parseFormat(argv[++i]);
        }
        else if (arg == "--output" && i + 1 < argc) {
            // "--output result.csv" → 결과를 파일에 저장
            opts.outputFile = argv[++i];
        }
        else if (arg == "--hash")      opts.computeHash = true; // 해시 계산 활성화
        else if (arg == "--recursive") opts.recursive   = true; // 재귀 탐색 활성화
        else if (arg == "--recent")    opts.recent      = true; // 최근 파일 수집
        else if (arg == "--prefetch")  opts.prefetch    = true; // 프리패치 수집
        else if (arg == "--temp")      opts.temp        = true; // 임시 파일 수집
        else if (arg == "--downloads") opts.downloads   = true;
        else if (arg == "--mft" && i + 1 < argc) opts.mftPath = argv[++i];
        else if (arg == "--all") {
            opts.recent = opts.prefetch = opts.temp = opts.downloads = true;
        }
    }
    return opts;
}

// ============================================================
// cmdAnalyze : "analyze" 명령 실행
// ============================================================
// 지정한 파일 또는 폴더의 메타데이터를 분석해서 출력합니다.
static int cmdAnalyze(std::ostream& out, const Options& opts) {
    // 경로가 없으면 오류 메시지 출력 후 실패 코드(1) 반환
    if (opts.path.empty()) {
        std::cerr << "Error: 'analyze' requires a path.\n";
        return 1;
    }

    fs::path p(opts.path);
    std::error_code ec; // 예외 없이 에러를 처리하기 위한 코드 변수

    // 경로가 실제 존재하는지 확인
    if (!fs::exists(p, ec)) {
        std::cerr << "Error: path not found: " << opts.path << "\n";
        return 1;
    }

    if (fs::is_regular_file(p, ec)) {
        // 단일 파일 분석: FileInfo 1개 수집 후 출력
        auto fi = FileInfoCollector::collect(p, opts.computeHash);
        Report::writeFileInfo(out, fi, opts.format);
    }
    else if (fs::is_directory(p, ec)) {
        // 폴더 분석: 폴더 안의 모든 파일을 수집 후 목록 출력
        auto files = FileInfoCollector::scanDirectory(p, opts.recursive,
                                                      opts.computeHash);
        Report::writeFileInfoList(out, files, opts.format);
    }
    else {
        std::cerr << "Error: path is not a file or directory.\n";
        return 1;
    }
    return 0; // 성공 코드
}

// ============================================================
// cmdArtifacts : "artifacts" 명령 실행
// ============================================================
// 선택한 유형의 Windows 활동 흔적을 수집해서 출력합니다.
static int cmdArtifacts(std::ostream& out, const Options& opts) {
    // 아무 유형도 선택하지 않으면 전체 수집 (기본 동작)
    bool collectAll = !opts.recent && !opts.prefetch &&
                      !opts.temp   && !opts.downloads;

    std::vector<Artifact> artifacts;

    // append : 수집 함수의 결과를 artifacts 벡터에 이어 붙이는 람다 함수
    // std::make_move_iterator : 복사 대신 이동(move)으로 성능 향상
    auto append = [&](std::vector<Artifact> v) {
        artifacts.insert(artifacts.end(),
                         std::make_move_iterator(v.begin()),
                         std::make_move_iterator(v.end()));
    };

    // 선택된 유형만 수집 (collectAll이면 모두 수집)
    if (collectAll || opts.recent)    append(ArtifactCollector::collectRecentFiles());
    if (collectAll || opts.prefetch)  append(ArtifactCollector::collectPrefetch());
    if (collectAll || opts.temp)      append(ArtifactCollector::collectTempFiles());
    if (collectAll || opts.downloads) append(ArtifactCollector::collectDownloads());

    // 최신 순으로 정렬 (timestamp가 클수록 최신)
    std::sort(artifacts.begin(), artifacts.end(),
        [](const Artifact& a, const Artifact& b) {
            return a.timestamp > b.timestamp;
        });

    Report::writeArtifacts(out, artifacts, opts.format);
    return 0;
}

// ============================================================
// cmdTimeline : "timeline" 명령 실행
// ============================================================
// 파일 정보와 아티팩트를 함께 수집해서 통합 타임라인을 만듭니다.
// 예) 파일이 생성된 시각, 프리패치 실행 기록을 시간순으로 나열
static int cmdTimeline(std::ostream& out, const Options& opts) {
    // ── 1단계: 파일 정보 수집 ──────────────────────────────────
    std::vector<FileInfo> files;
    if (!opts.path.empty()) {
        fs::path p(opts.path);
        std::error_code ec;

        if (!fs::exists(p, ec)) {
            std::cerr << "Error: path not found: " << opts.path << "\n";
            return 1;
        }

        if (fs::is_regular_file(p, ec))
            // 파일 1개
            files.push_back(FileInfoCollector::collect(p, opts.computeHash));
        else if (fs::is_directory(p, ec))
            // 폴더 전체
            files = FileInfoCollector::scanDirectory(p, opts.recursive,
                                                     opts.computeHash);
    }

    // ── 2단계: 아티팩트 수집 ────────────────────────────────────
    bool collectAll = !opts.recent && !opts.prefetch &&
                      !opts.temp   && !opts.downloads;

    std::vector<Artifact> artifacts;
    auto append = [&](std::vector<Artifact> v) {
        artifacts.insert(artifacts.end(),
                         std::make_move_iterator(v.begin()),
                         std::make_move_iterator(v.end()));
    };

    if (collectAll || opts.recent)    append(ArtifactCollector::collectRecentFiles());
    if (collectAll || opts.prefetch)  append(ArtifactCollector::collectPrefetch());
    if (collectAll || opts.temp)      append(ArtifactCollector::collectTempFiles());
    if (collectAll || opts.downloads) append(ArtifactCollector::collectDownloads());

    // ── 3단계: 타임라인 생성 및 출력 ────────────────────────────
    // buildTimeline: 파일 이벤트 + 아티팩트 이벤트를 합쳐 시간순 정렬
    auto timeline = Report::buildTimeline(files, artifacts);
    Report::writeTimeline(out, timeline, opts.format);
    return 0;
}

// ============================================================
// cmdLnk : "lnk" 명령 실행
// ============================================================
static int cmdLnk(std::ostream& out, const Options& opts) {
    std::vector<LnkInfo> lnkList;

    if (opts.path.empty()) {
#ifdef _WIN32
        std::string recent = expandEnvVar("%APPDATA%\\Microsoft\\Windows\\Recent");
        lnkList = LnkParser::parseDirectory(recent);
        if (lnkList.empty()) {
            std::cerr << "Error: Recent 폴더에서 LNK 파일 없음: " << recent << "\n";
            return 1;
        }
#else
        std::cerr << "Error: lnk 명령은 경로를 지정하거나 Windows에서 실행하세요.\n";
        return 1;
#endif
    } else {
        fs::path p(opts.path);
        std::error_code ec;
        if (!fs::exists(p, ec)) {
            std::cerr << "Error: 경로 없음: " << opts.path << "\n"; return 1;
        }
        if (fs::is_regular_file(p, ec))
            lnkList.push_back(LnkParser::parse(opts.path));
        else if (fs::is_directory(p, ec))
            lnkList = LnkParser::parseDirectory(opts.path);
        else { std::cerr << "Error: 파일/폴더가 아님\n"; return 1; }
    }

    std::vector<LnkAnalysis> results;
    results.reserve(lnkList.size());
    for (auto& lnk : lnkList) {
        LnkAnalysis analysis;
        analysis.lnk = lnk;
        if (!opts.mftPath.empty() && lnk.success && !lnk.targetName.empty())
            analysis.mftRecords = MftParser::findByName(opts.mftPath, lnk.targetName);
        results.push_back(std::move(analysis));
    }
    Report::writeLnkAnalysis(out, results, opts.format);
    return 0;
}

// ============================================================
// main : 프로그램 시작점
// ============================================================
// C++ 프로그램은 항상 main() 함수에서 시작합니다.
// 반환값: 0 = 성공, 1 이상 = 오류
int main(int argc, char* argv[]) {
    // 인자가 1개뿐이면 (프로그램명만) 사용법 출력 후 종료
    if (argc < 2) {
        printHelp();
        return 1;
    }

    // 명령줄 인자 파싱
    Options opts = parseArgs(argc, argv);

    // 명령어가 인식되지 않으면 오류
    if (opts.command.empty()) {
        std::cerr << "Error: no command specified.\n\n";
        printHelp();
        return 1;
    }

    // ── 출력 대상 설정 ───────────────────────────────────────────
    // std::ostream* : 화면(cout) 또는 파일(ofstream) 중 하나를 가리키는 포인터
    std::ostream*  out = &std::cout; // 기본: 화면 출력
    std::ofstream  outFile;          // 파일 출력 객체 (--output 옵션 시 사용)

    if (!opts.outputFile.empty()) {
        outFile.open(opts.outputFile); // 지정한 파일 열기
        if (!outFile) {
            // 파일을 열 수 없으면 (권한 없음, 경로 오류 등) 오류 메시지
            std::cerr << "Error: cannot write to: " << opts.outputFile << "\n";
            return 1;
        }
        out = &outFile; // 이제부터 out에 쓰면 파일에 저장됨
    }

    // ── 명령어에 따라 적절한 함수 호출 ─────────────────────────
    // *out : out 포인터가 가리키는 스트림 객체를 역참조해서 전달
    if      (opts.command == "analyze")   return cmdAnalyze(*out, opts);
    else if (opts.command == "artifacts") return cmdArtifacts(*out, opts);
    else if (opts.command == "timeline")  return cmdTimeline(*out, opts);
    else if (opts.command == "lnk")       return cmdLnk(*out, opts);

    // 인식 못 한 명령어 (parseArgs 이후에도 걸릴 수 있음)
    std::cerr << "Error: unknown command '" << opts.command << "'\n";
    return 1;
}
