// ============================================================
// hash.h  -  MD5 / SHA-256 해시 알고리즘 선언
// ============================================================
// 해시(Hash)란?
//   파일 내용 전체를 계산해서 만드는 '디지털 지문'입니다.
//   파일이 1바이트라도 바뀌면 해시값이 완전히 달라지기 때문에
//   포렌식에서 "이 파일이 원본 그대로인지" 확인할 때 사용합니다.
//
//   예) notepad.exe의 MD5    = "a8b7c6d5e4f3..."
//       해당 파일이 변조되면  = "ff00112233..."  (완전히 다른 값)
//
// 이 파일에서 구현하는 알고리즘:
//   - MD5    : 128비트(16바이트) 해시값 생성. 빠르지만 충돌 취약점 있음.
//              (포렌식 현장에서는 무결성 확인용으로 여전히 많이 씀)
//   - SHA-256: 256비트(32바이트) 해시값 생성. 더 안전하고 신뢰도 높음.
//              (현재 포렌식/보안 업계 표준)
// ============================================================
#pragma once

#include <string>   // std::string
#include <cstdint>  // uint8_t (1바이트 정수), uint32_t (4바이트 정수)

namespace forensics {

// Hash 클래스 : MD5와 SHA-256 계산 기능을 묶어놓은 클래스
// 모든 함수가 static이므로 Hash h; 처럼 객체를 만들 필요 없이
// Hash::md5File(...) 형태로 바로 호출할 수 있습니다.
class Hash {
public:
    // ── 외부에서 사용하는 함수 (public) ─────────────────────────

    // md5File   : 파일 경로를 받아 MD5 해시값을 16진수 문자열(32글자)로 반환
    // sha256File : 파일 경로를 받아 SHA-256 해시값을 16진수 문자열(64글자)로 반환
    static std::string md5File(const std::string& filepath);
    static std::string sha256File(const std::string& filepath);

    // md5Buffer   : 메모리의 바이트 배열에 대해 MD5 계산
    // sha256Buffer: 메모리의 바이트 배열에 대해 SHA-256 계산
    static std::string md5Buffer(const uint8_t* data, size_t len);
    static std::string sha256Buffer(const uint8_t* data, size_t len);

private:
    // ── MD5 내부 상태 구조체 (RFC 1321 표준 정의) ────────────────
    // MD5는 4개의 32비트 레지스터(a,b,c,d)를 이용해 계산합니다.
    struct MD5State {
        uint32_t a, b, c, d; // 현재 해시 계산 중인 4개 레지스터
        uint64_t count;      // 지금까지 처리한 바이트 수 (패딩 계산에 필요)
        uint8_t  buf[64];    // 아직 처리 안 된 데이터를 임시로 저장하는 64바이트 버퍼
        size_t   bufLen;     // buf에 현재 몇 바이트가 들어있는지
    };
    // md5Init    : 레지스터를 RFC 표준 초기값으로 설정
    // md5Process : 64바이트 블록 1개를 처리해서 상태를 업데이트
    // md5Update  : 임의 길이의 데이터를 받아 64바이트씩 잘라 Process에 전달
    // md5Finish  : 패딩 추가 후 최종 16바이트 해시값(digest) 출력
    static void md5Init(MD5State& s);
    static void md5Process(MD5State& s, const uint8_t block[64]);
    static void md5Update(MD5State& s, const uint8_t* data, size_t len);
    static void md5Finish(MD5State& s, uint8_t digest[16]);

    // ── SHA-256 내부 상태 구조체 (FIPS 180-4 표준 정의) ──────────
    // SHA-256은 8개의 32비트 레지스터(h[0]~h[7])를 이용합니다.
    struct SHA256State {
        uint32_t h[8];    // 8개의 해시 레지스터
        uint64_t count;   // 처리한 바이트 수
        uint8_t  buf[64]; // 64바이트 임시 버퍼
        size_t   bufLen;  // 버퍼에 쌓인 데이터 크기
    };
    // 역할은 MD5와 동일하나 알고리즘 내부 연산이 더 복잡하고 안전합니다.
    static void sha256Init(SHA256State& s);
    static void sha256Process(SHA256State& s, const uint8_t block[64]);
    static void sha256Update(SHA256State& s, const uint8_t* data, size_t len);
    static void sha256Finish(SHA256State& s, uint8_t digest[32]);
};

} // namespace forensics
