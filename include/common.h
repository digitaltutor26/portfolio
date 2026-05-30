// ============================================================
// common.h  -  프로젝트 전체에서 공통으로 쓰는 유틸리티 선언
// ============================================================
// 여러 .cpp 파일에서 같은 함수를 써야 할 때, 그 함수의 이름과
// 사용법만 먼저 "선언"해 두는 파일입니다.
// 실제 구현(코드 본문)은 common.cpp에 있습니다.
// ============================================================

// #pragma once : 이 헤더 파일이 같은 컴파일 단위에 두 번 포함되지
//               않도록 막아주는 지시어입니다. (중복 선언 오류 방지)
#pragma once

#include <string>      // std::string (문자열 타입)
#include <cstdint>     // uint8_t, uint32_t 등 크기가 명확한 정수 타입
#include <ctime>       // std::time_t (시간을 나타내는 정수 타입)
#include <filesystem>  // std::filesystem (파일/폴더 경로 처리)

// ── Windows 전용 헤더 ────────────────────────────────────────
// #ifdef _WIN32 : "지금 Windows 환경에서 컴파일 중이면" 이라는 조건
// Windows가 아닌 Linux/macOS에서는 아래 내용이 무시됩니다.
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN  // windows.h에서 잘 안 쓰는 기능을 제외해 컴파일 속도 향상
#ifndef NOMINMAX
#define NOMINMAX             // windows.h가 min/max 매크로를 덮어쓰지 못하게 방지
#endif
#include <windows.h>         // FILETIME, HANDLE 등 Windows API 타입이 정의된 헤더
#endif
// ─────────────────────────────────────────────────────────────

// namespace forensics : 이 프로젝트의 모든 코드를 "forensics"라는
//                       이름공간 안에 묶어서 다른 라이브러리와 이름
//                       충돌이 생기지 않도록 합니다.
namespace forensics {

// std::filesystem을 fs라는 짧은 이름으로 줄여서 씁니다.
// 예) fs::path  →  std::filesystem::path
namespace fs = std::filesystem;

// ── 함수 선언 (선언만 있고, 구현은 common.cpp에 있음) ───────────

// formatTimestamp : Unix 타임스탬프(1970-01-01 기준 경과 초)를
//                  "2024-07-15 13:45:22" 형태의 문자열로 바꿔줍니다.
std::string formatTimestamp(std::time_t t);

// bytesToHex : 바이너리 데이터(바이트 배열)를 16진수 문자열로 변환합니다.
//             예) {0xFF, 0x4D} → "ff4d"
//             해시값이나 매직 바이트를 사람이 읽을 수 있게 출력할 때 씁니다.
std::string bytesToHex(const uint8_t* data, size_t len);

// ── Windows 전용 함수 선언 ────────────────────────────────────
#ifdef _WIN32

// wstringToString : Windows 유니코드 wstring → UTF-8 string 변환
std::string wstringToString(const std::wstring& ws);

// stringToWstring : UTF-8 string → Windows 유니코드 wstring 변환
//                  한글 경로 등 비ASCII 경로를 Windows API에 넘길 때 사용
std::wstring stringToWstring(const std::string& s);

// filetimeToTimet : Windows의 FILETIME(1601-01-01 기준 100나노초 단위)을
//                  C 표준 time_t(1970-01-01 기준 초 단위)로 변환합니다.
//                  두 시간 기준이 다르기 때문에 변환 계산이 필요합니다.
std::time_t filetimeToTimet(const FILETIME& ft);

// filetimeToString : FILETIME을 바로 읽기 쉬운 문자열로 변환합니다.
//                   (내부적으로 filetimeToTimet → formatTimestamp 를 순서대로 호출)
std::string filetimeToString(const FILETIME& ft);

// expandEnvVar : 환경 변수가 포함된 경로를 실제 경로로 바꿔줍니다.
//               예) "%APPDATA%\Recent"  →  "C:\Users\홍길동\AppData\Roaming\Recent"
std::string expandEnvVar(const std::string& path);

#endif // _WIN32

} // namespace forensics
