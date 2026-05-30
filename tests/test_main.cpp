// ============================================================
// tests/test_main.cpp  -  WinForensics 단위 테스트
// ============================================================
// 외부 프레임워크 없이 순수 C++17로 작성된 테스트입니다.
// 알려진 벡터값(공식 표준 문서 기준)으로 핵심 모듈을 검증합니다.
// ============================================================
#include "hash.h"
#include "common.h"
#include "report.h"
#include "file_info.h"

#include <iostream>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <vector>

using namespace forensics;

// ── 간이 테스트 프레임워크 ────────────────────────────────────
static int g_pass = 0, g_fail = 0;

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { \
        ++g_pass; \
    } else { \
        ++g_fail; \
        std::cerr << "FAIL [" << __FILE__ << ":" << __LINE__ << "]\n" \
                  << "  expr:     " #a " == " #b "\n" \
                  << "  got:      " << _a << "\n" \
                  << "  expected: " << _b << "\n"; \
    } \
} while(0)

#define CHECK(expr) do { \
    if (expr) { \
        ++g_pass; \
    } else { \
        ++g_fail; \
        std::cerr << "FAIL [" << __FILE__ << ":" << __LINE__ << "] " #expr "\n"; \
    } \
} while(0)

// ── MD5 테스트 (RFC 1321 공식 테스트 벡터) ───────────────────
static void test_md5_known_vectors() {
    const uint8_t* empty = reinterpret_cast<const uint8_t*>("");

    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    CHECK_EQ(Hash::md5Buffer(empty, 0), "d41d8cd98f00b204e9800998ecf8427e");

    // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
    const uint8_t abc[] = {'a','b','c'};
    CHECK_EQ(Hash::md5Buffer(abc, 3), "900150983cd24fb0d6963f7d28e17f72");

    // MD5("message digest") = f96b697d7cb7938d525a2f31aaf161d0
    const char* msg = "message digest";
    CHECK_EQ(Hash::md5Buffer(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg)),
             "f96b697d7cb7938d525a2f31aaf161d0");

    // 결과 길이는 항상 32자리 (128비트 = 16바이트 → 32자 16진수)
    CHECK(Hash::md5Buffer(abc, 3).size() == 32);
}

// ── SHA-256 테스트 (FIPS 180-4 공식 테스트 벡터) ────────────
static void test_sha256_known_vectors() {
    const uint8_t* empty = reinterpret_cast<const uint8_t*>("");

    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    CHECK_EQ(Hash::sha256Buffer(empty, 0),
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // SHA-256("abc") — Python hashlib / OpenSSL 검증값
    const uint8_t abc[] = {'a','b','c'};
    CHECK_EQ(Hash::sha256Buffer(abc, 3),
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // 2블록에 걸치는 긴 메시지 벡터
    const char* longMsg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    CHECK_EQ(Hash::sha256Buffer(reinterpret_cast<const uint8_t*>(longMsg),
                                 std::strlen(longMsg)),
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // 결과 길이는 항상 64자리 (256비트 = 32바이트 → 64자 16진수)
    CHECK(Hash::sha256Buffer(abc, 3).size() == 64);
}

// ── bytesToHex 테스트 ────────────────────────────────────────
static void test_bytes_to_hex() {
    const uint8_t data[] = {0x00, 0xff, 0x4d, 0x5a};
    CHECK_EQ(bytesToHex(data, 4), "00ff4d5a");
    CHECK_EQ(bytesToHex(data, 1), "00");
    CHECK_EQ(bytesToHex(data, 0), "");

    // MZ 헤더 (Windows EXE 시그니처)
    const uint8_t mz[] = {0x4d, 0x5a};
    CHECK_EQ(bytesToHex(mz, 2), "4d5a");
}

// ── formatTimestamp 테스트 ───────────────────────────────────
static void test_format_timestamp() {
    // 0 이하는 "N/A" 반환
    CHECK_EQ(formatTimestamp(0),  "N/A");
    CHECK_EQ(formatTimestamp(-1), "N/A");

    // 유효한 타임스탬프는 "YYYY-MM-DD HH:MM:SS" 형식 (19자)
    std::string s = formatTimestamp(1700000000); // 2023-11-14 근처
    CHECK(s != "N/A");
    CHECK(s.size() == 19);
    CHECK(s[4] == '-' && s[7] == '-' && s[10] == ' ' &&
          s[13] == ':' && s[16] == ':');
}

// ── Report::parseFormat 테스트 ──────────────────────────────
static void test_parse_format() {
    CHECK(Report::parseFormat("text") == ReportFormat::Text);
    CHECK(Report::parseFormat("csv")  == ReportFormat::CSV);
    CHECK(Report::parseFormat("json") == ReportFormat::JSON);
    // 미인식 값은 기본값 Text
    CHECK(Report::parseFormat("XML")  == ReportFormat::Text);
    CHECK(Report::parseFormat("")     == ReportFormat::Text);
}

// ── CSV 이스케이프 동작 테스트 (writeFileInfoList를 통해 간접 검증) ─
static void test_csv_escaping() {
    FileInfo fi;
    fi.path     = "path,with,commas";    // 쉼표 포함 → 따옴표로 감싸야 함
    fi.name     = "file\"quoted\".exe";  // 따옴표 포함 → 내부 따옴표 이중화
    fi.size     = 0;
    fi.category = FileCategory::Unknown;
    fi.magic    = "";
    fi.created = fi.modified = fi.accessed = "N/A";

    std::ostringstream oss;
    std::vector<FileInfo> files = {fi};
    Report::writeFileInfoList(oss, files, ReportFormat::CSV);
    std::string out = oss.str();

    // 헤더 확인
    CHECK(out.find("Path,Name,Size") == 0);
    // 쉼표가 있는 필드는 따옴표로 감싸야 함
    CHECK(out.find("\"path,with,commas\"") != std::string::npos);
    // 따옴표 안의 따옴표는 "" 로 이스케이프
    CHECK(out.find("\"file\"\"quoted\"\".exe\"") != std::string::npos);
}

// ── JSON 이스케이프 동작 테스트 ──────────────────────────────
static void test_json_escaping() {
    FileInfo fi;
    fi.path     = "C:\\test\\path";       // 역슬래시 → \\ 로 이스케이프
    fi.name     = "file\"name\".exe";     // 따옴표 → \" 로 이스케이프
    fi.size     = 0;
    fi.category = FileCategory::Unknown;
    fi.magic    = "";
    fi.created = fi.modified = fi.accessed = "N/A";

    std::ostringstream oss;
    Report::writeFileInfo(oss, fi, ReportFormat::JSON);
    std::string out = oss.str();

    // 역슬래시는 JSON에서 \\ 로 표현됨
    CHECK(out.find("C:\\\\test\\\\path") != std::string::npos);
    // 따옴표는 JSON에서 \" 로 표현됨
    CHECK(out.find("file\\\"name\\\".exe") != std::string::npos);
}

// ── 빈 아티팩트 JSON 출력 테스트 ────────────────────────────
static void test_empty_artifacts_json() {
    std::ostringstream oss;
    std::vector<Artifact> empty;
    Report::writeArtifacts(oss, empty, ReportFormat::JSON);
    CHECK_EQ(oss.str(), "[]\n");
}

// ── 빈 아티팩트 Text 출력 테스트 ────────────────────────────
static void test_empty_artifacts_text() {
    std::ostringstream oss;
    std::vector<Artifact> empty;
    Report::writeArtifacts(oss, empty, ReportFormat::Text);
    CHECK(oss.str().find("No artifacts") != std::string::npos);
}

// ── 타임라인 정렬 테스트 ─────────────────────────────────────
static void test_timeline_sorting() {
    FileInfo newer, older;
    newer.createdTime  = 200; newer.modifiedTime = 200; newer.accessedTime = 0;
    newer.name = "newer.txt";
    newer.created = newer.modified = newer.accessed = "2024-02-01 00:00:00";

    older.createdTime  = 100; older.modifiedTime = 100; older.accessedTime = 0;
    older.name = "older.txt";
    older.created = older.modified = older.accessed = "2024-01-01 00:00:00";

    std::vector<FileInfo> files = {newer, older};
    std::vector<Artifact> arts;
    auto events = Report::buildTimeline(files, arts);

    // 이벤트가 생성됐는지 확인
    CHECK(!events.empty());
    // 내림차순 정렬 확인 (가장 최신 이벤트가 앞에)
    for (size_t i = 1; i < events.size(); ++i)
        CHECK(events[i-1].timestamp >= events[i].timestamp);
}

// ── 타임라인 중복 이벤트 제거 테스트 ─────────────────────────
static void test_timeline_dedup() {
    FileInfo fi;
    // createdTime == modifiedTime 이면 수정 이벤트를 추가하지 않아야 함
    fi.createdTime  = 100;
    fi.modifiedTime = 100; // 생성 시각과 동일
    fi.accessedTime = 0;
    fi.name = "test.txt";
    fi.created = fi.modified = fi.accessed = "2024-01-01 00:00:00";

    std::vector<FileInfo> files = {fi};
    std::vector<Artifact> arts;
    auto events = Report::buildTimeline(files, arts);

    // createdTime == modifiedTime 이므로 이벤트는 1개 (Created만)
    CHECK(events.size() == 1);
}

// ── JSON 배열 형식 검증 ──────────────────────────────────────
static void test_json_array_format() {
    FileInfo fi;
    fi.path = "test.exe"; fi.name = "test.exe";
    fi.size = 100; fi.category = FileCategory::Executable;
    fi.magic = "4d5a";
    fi.created = fi.modified = fi.accessed = "2024-01-01 00:00:00";

    std::vector<FileInfo> files = {fi};
    std::ostringstream oss;
    Report::writeFileInfoList(oss, files, ReportFormat::JSON);
    std::string out = oss.str();

    // JSON 배열로 시작하고 끝나야 함
    CHECK(out.front() == '[');
    CHECK(out.back() == '\n');
    // 마지막 객체 다음에 쉼표가 없어야 함 (유효한 JSON)
    CHECK(out.find("},\n]") == std::string::npos);
}

// ─────────────────────────────────────────────────────────────

int main() {
    std::cout << "Running WinForensics unit tests...\n\n";

    test_md5_known_vectors();
    test_sha256_known_vectors();
    test_bytes_to_hex();
    test_format_timestamp();
    test_parse_format();
    test_csv_escaping();
    test_json_escaping();
    test_empty_artifacts_json();
    test_empty_artifacts_text();
    test_timeline_sorting();
    test_timeline_dedup();
    test_json_array_format();

    int total = g_pass + g_fail;
    std::cout << "\n=== Results: " << g_pass << "/" << total << " passed ===\n";

    if (g_fail > 0) {
        std::cerr << g_fail << " test(s) FAILED.\n";
        return 1;
    }
    std::cout << "All tests passed.\n";
    return 0;
}
