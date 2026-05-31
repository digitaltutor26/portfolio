// ============================================================
// common.cpp  -  공통 유틸리티 함수 구현
// ============================================================
#include "common.h"

#include <sstream>   // std::ostringstream (문자열 스트림 - 숫자→문자열 변환에 사용)
#include <iomanip>   // std::setw, std::setfill, std::hex (출력 형식 조정)
#include <cstring>   // memset 등 C 스타일 메모리 함수

namespace forensics {

// ============================================================
// formatTimestamp : Unix 타임스탬프 → 사람이 읽는 날짜 문자열
// ============================================================
// 매개변수 t : std::time_t 타입의 Unix 타임스탬프
//             (1970-01-01 00:00:00 UTC 부터 현재까지의 경과 초)
// 반환값     : "2024-07-15 13:45:22" 형태의 문자열
std::string formatTimestamp(std::time_t t) {
    // 0 이하이면 유효하지 않은 시각이므로 "N/A" 반환
    if (t <= 0) return "N/A";

    char buf[32];
    struct tm tm_info = {};

    // localtime_s (MSVC) / localtime_r (POSIX) : thread-safe 버전
    // 전역 상태를 공유하는 localtime() 대신 호출자 제공 버퍼에 결과를 씁니다.
#ifdef _WIN32
    localtime_s(&tm_info, &t);
#else
    localtime_r(&t, &tm_info);
#endif

    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    return buf;
}

// ============================================================
// bytesToHex : 바이트 배열 → 16진수 문자열
// ============================================================
// 매개변수 data : 변환할 바이트 배열의 시작 주소
//           len  : 변환할 바이트 수
// 반환값        : 16진수 문자열 (예: {0xFF, 0x4D, 0x5A} → "ff4d5a")
//
// 포렌식에서 해시값이나 매직 바이트를 출력할 때 사용합니다.
std::string bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss; // 문자열을 조금씩 이어붙일 수 있는 스트림

    // std::hex      : 이후 정수를 16진수로 출력하도록 설정
    // std::setfill('0') : 빈 자리를 '0'으로 채우도록 설정
    oss << std::hex << std::setfill('0');

    for (size_t i = 0; i < len; ++i) {
        // std::setw(2)     : 최소 2자리로 출력 (1자리면 앞에 0 추가)
        // static_cast<unsigned> : uint8_t를 unsigned int로 변환해야
        //                        문자가 아닌 숫자로 올바르게 출력됩니다.
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return oss.str(); // 스트림에 쌓인 문자열을 std::string으로 꺼냄
}

// ── 아래는 Windows 전용 함수들 ────────────────────────────────
// #ifdef _WIN32 : Windows에서만 컴파일되는 구역
#ifdef _WIN32

// ============================================================
// wstringToString : 유니코드 문자열(wstring) → UTF-8 문자열(string)
// ============================================================
// Windows API는 파일 경로를 wchar_t(2바이트) 기반의 wstring으로 다룹니다.
// 우리 프로그램은 string(1바이트 기반, UTF-8)을 쓰기 때문에 변환이 필요합니다.
// 이 변환이 없으면 한글 파일명을 올바르게 처리할 수 없습니다.
std::string wstringToString(const std::wstring& ws) {
    if (ws.empty()) return {}; // 빈 문자열이면 바로 빈 string 반환

    // WideCharToMultiByte : Windows API 함수
    //   1단계: nullptr을 넘겨서 결과 문자열이 몇 바이트 필요한지 먼저 계산
    int sz = WideCharToMultiByte(
        CP_UTF8,      // 변환 목표 인코딩: UTF-8
        0,            // 플래그 (기본값)
        ws.c_str(),   // 변환할 원본 wstring
        -1,           // -1이면 null 문자까지 자동으로 길이 계산
        nullptr,      // 출력 버퍼 없음 (크기만 계산)
        0,            // 출력 버퍼 크기 0
        nullptr, nullptr
    );
    if (sz <= 0) return {}; // 변환 실패

    // 2단계: 실제 변환 수행
    std::string result(sz - 1, '\0'); // sz-1 : null 문자 1개를 제외한 크기
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                        result.data(), sz, nullptr, nullptr);
    return result;
}

// ============================================================
// filetimeToTimet : Windows FILETIME → Unix time_t 변환
// ============================================================
// FILETIME 이란?
//   Windows가 파일 시간을 저장하는 구조체입니다.
//   기준점: 1601년 1월 1일 00:00:00 UTC
//   단위  : 100나노초 (1초 = 10,000,000 단위)
//
// time_t 이란?
//   C 표준의 시간 타입.
//   기준점: 1970년 1월 1일 00:00:00 UTC (Unix Epoch)
//   단위  : 1초
//
// 변환 공식:
//   1) FILETIME의 64비트 값을 ULARGE_INTEGER에 담음
//   2) 1601~1970 사이의 차이(116444736000000000 단위)를 뺌
//   3) 10,000,000으로 나눠서 초 단위로 변환
std::time_t filetimeToTimet(const FILETIME& ft) {
    // ULARGE_INTEGER : 32비트 두 개(LowPart, HighPart)를 합쳐
    //                  64비트(QuadPart)로 다룰 수 있는 공용체
    ULARGE_INTEGER ull;
    ull.LowPart  = ft.dwLowDateTime;   // 하위 32비트
    ull.HighPart = ft.dwHighDateTime;  // 상위 32비트

    // 1601~1970년 사이의 차이값 (100나노초 단위)
    // 이 값보다 작으면 1970년 이전이므로 time_t로 표현 불가 → 0 반환
    if (ull.QuadPart < 116444736000000000ULL) return 0;

    return static_cast<std::time_t>(
        (ull.QuadPart - 116444736000000000ULL) / 10000000ULL
    );
    // 10000000ULL = 1초에 해당하는 100나노초 단위 개수
}

// ============================================================
// filetimeToString : FILETIME → 읽기 쉬운 날짜 문자열 (한 번에)
// ============================================================
std::string filetimeToString(const FILETIME& ft) {
    // filetimeToTimet로 time_t로 먼저 바꾸고, formatTimestamp로 문자열화
    return formatTimestamp(filetimeToTimet(ft));
}

// ============================================================
// stringToWstring : UTF-8 string → Windows 유니코드 wstring
// ============================================================
// wstringToString의 역방향 변환입니다.
// 한글 사용자명이 포함된 경로 등을 Windows API에 넘길 때 필요합니다.
std::wstring stringToWstring(const std::string& s) {
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (sz <= 0) return {};
    std::wstring result(sz - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, result.data(), sz);
    return result;
}

// ============================================================
// expandEnvVar : 환경 변수 → 실제 경로 문자열
// ============================================================
// 예) "%APPDATA%\Microsoft\Windows\Recent"
//  →  "C:\Users\홍길동\AppData\Roaming\Microsoft\Windows\Recent"
//
// 환경 변수를 쓰는 이유: 사용자마다 C 드라이브 경로가 다를 수 있기 때문에
// 하드코딩 대신 환경 변수로 경로를 표현합니다.
std::string expandEnvVar(const std::string& path) {
    // Windows API는 wstring을 받으므로 변환 (환경 변수 이름은 ASCII)
    std::wstring wpath = stringToWstring(path);
    wchar_t expanded[MAX_PATH] = {}; // MAX_PATH = 260, Windows 최대 경로 길이

    // ExpandEnvironmentStringsW : 환경 변수를 실제 값으로 치환해주는 API
    DWORD ret = ExpandEnvironmentStringsW(wpath.c_str(), expanded, MAX_PATH);

    // ret > 0 이고 MAX_PATH 이하면 성공
    if (ret > 0 && ret <= MAX_PATH)
        return wstringToString(expanded);

    return path; // 실패하면 원래 문자열 그대로 반환
}

#endif // _WIN32

} // namespace forensics
