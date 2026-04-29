// ============================================================
// hash.cpp  -  MD5 / SHA-256 해시 알고리즘 구현
// ============================================================
// 외부 라이브러리 없이 표준 규격만으로 직접 구현한 버전입니다.
//   - MD5    : RFC 1321  (1992년)
//   - SHA-256: FIPS 180-4 (미국 국립표준기술원 표준)
//
// [해시 알고리즘의 작동 원리 - 간단 요약]
//   1) 입력 데이터를 64바이트(512비트) 블록으로 잘라냄
//   2) 마지막 블록에 패딩(빈 공간 채우기 + 원본 길이 정보) 추가
//   3) 각 블록을 복잡한 비트 연산으로 압축해 내부 상태를 업데이트
//   4) 모든 블록 처리 후 내부 상태를 이어 붙이면 최종 해시값
// ============================================================
#include "hash.h"
#include "common.h"   // bytesToHex 함수 사용

#include <fstream>    // std::ifstream (파일 읽기)
#include <cstring>    // std::memcpy, std::memset
#include <stdexcept>  // std::runtime_error (파일 열기 실패 예외)

namespace forensics {

// ============================================================
// 비트 회전 연산 헬퍼 함수
// ============================================================
// 해시 알고리즘에서 가장 자주 쓰는 비트 조작입니다.
//
// rotl32 (left rotate, 왼쪽 회전):
//   비트를 왼쪽으로 n칸 밀고, 밀려난 비트는 오른쪽 끝에 붙입니다.
//   예) x = 0b10110001, n = 2
//       밀기: 0b11000100  (왼쪽 2비트 "10"이 오른쪽으로 이동)
//       결과: 0b11000110
//
// rotr32 (right rotate, 오른쪽 회전):
//   반대 방향으로 회전합니다. SHA-256에서 주로 사용합니다.
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
    // (x << n)       : 왼쪽으로 n비트 이동 (오른쪽에 0이 채워짐)
    // (x >> (32 - n)): 오른쪽으로 (32-n)비트 이동 (왼쪽에 0이 채워짐)
    // 두 결과를 OR로 합치면 회전 효과
}

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n)); // rotl32와 방향만 반대
}

// ============================================================
//  MD5 알고리즘 구현  (RFC 1321)
// ============================================================

// ── MD5 상수 테이블 ──────────────────────────────────────────
// MD5_T[i] = floor(abs(sin(i+1)) * 2^32) 로 계산된 값들
// sin 함수에서 유도된 난수처럼 보이는 상수로, 0과 1이 균일하게
// 섞이도록 만들어 역산을 어렵게 합니다.
// 라운드별로 4개씩 묶어서 총 64개 = 4라운드 × 16스텝
static const uint32_t MD5_T[64] = {
    // 라운드 1 (F 함수 사용, 스텝 0~15)
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    // 라운드 2 (G 함수 사용, 스텝 16~31)
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    // 라운드 3 (H 함수 사용, 스텝 32~47)
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    // 라운드 4 (I 함수 사용, 스텝 48~63)
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// ── MD5 회전량 테이블 ────────────────────────────────────────
// 각 스텝마다 몇 비트를 회전할지 정해둔 표입니다.
// 라운드마다 4가지 회전량이 반복됩니다.
static const uint32_t MD5_S[64] = {
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, // 라운드1
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20, // 라운드2
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23, // 라운드3
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21  // 라운드4
};

// ============================================================
// md5Init : MD5 내부 상태를 초기값으로 설정
// ============================================================
// a, b, c, d는 RFC 1321에서 정해진 고정 초기값입니다.
// 이 값들이 초기 "씨앗"이 되어 데이터를 처리할수록 바뀌어 갑니다.
void Hash::md5Init(MD5State& s) {
    s.a = 0x67452301; // 리틀 엔디언으로 표현하면 01 23 45 67
    s.b = 0xefcdab89; //                            89 ab cd ef
    s.c = 0x98badcfe; //                            fe dc ba 98
    s.d = 0x10325476; //                            76 54 32 10
    s.count  = 0;     // 처리한 바이트 수 초기화
    s.bufLen = 0;     // 임시 버퍼에 쌓인 데이터 크기 초기화
    std::memset(s.buf, 0, sizeof(s.buf)); // 버퍼를 0으로 클리어
}

// ============================================================
// md5Process : 64바이트(512비트) 블록 1개를 처리해서 상태 업데이트
// ============================================================
// MD5의 핵심 연산입니다. 64스텝 × 4라운드의 비트 연산을 수행합니다.
void Hash::md5Process(MD5State& s, const uint8_t blk[64]) {
    // ① 64바이트 블록을 16개의 32비트 워드(M[0]~M[15])로 변환
    //    MD5는 리틀 엔디언(Little-Endian)을 사용합니다.
    //    리틀 엔디언: 낮은 주소에 낮은 바이트가 옴
    //    예) 4바이트 [0x78, 0x56, 0x34, 0x12] → M[i] = 0x12345678
    uint32_t M[16];
    for (int i = 0; i < 16; ++i)
        M[i] = uint32_t(blk[i*4])              // 첫 번째 바이트 (비트 0~7)
             | (uint32_t(blk[i*4+1]) <<  8)    // 두 번째 바이트 (비트 8~15)
             | (uint32_t(blk[i*4+2]) << 16)    // 세 번째 바이트 (비트 16~23)
             | (uint32_t(blk[i*4+3]) << 24);   // 네 번째 바이트 (비트 24~31)

    // ② 현재 상태를 a,b,c,d에 복사 (원본 상태는 나중에 더하기 위해 유지)
    uint32_t a = s.a, b = s.b, c = s.c, d = s.d;

    // ③ 64스텝 메인 루프
    for (int i = 0; i < 64; ++i) {
        uint32_t F; // 라운드 함수 결과값
        int g;      // 이번 스텝에서 사용할 메시지 워드 인덱스

        // 라운드에 따라 다른 보조 함수(F, G, H, I)와 인덱스 계산식 사용
        if (i < 16) {
            // 라운드 1 - F 함수: (b AND c) OR (NOT b AND d)
            // b가 1이면 c를, 0이면 d를 선택하는 '선택 함수'
            F = (b & c) | (~b & d);
            g = i; // 순서대로
        } else if (i < 32) {
            // 라운드 2 - G 함수: (d AND b) OR (NOT d AND c)
            // F와 비슷하지만 d, b, c 순서가 다름
            F = (d & b) | (~d & c);
            g = (5*i + 1) % 16; // 불규칙한 순서로 메시지 워드 접근
        } else if (i < 48) {
            // 라운드 3 - H 함수: b XOR c XOR d (XOR 연산)
            F = b ^ c ^ d;
            g = (3*i + 5) % 16;
        } else {
            // 라운드 4 - I 함수: c XOR (b OR NOT d)
            F = c ^ (b | ~d);
            g = (7*i) % 16;
        }

        // 핵심 계산: F에 a, 상수, 메시지 워드를 모두 더함
        F += a + MD5_T[i] + M[g];

        // 레지스터 순환: d→a, c→d, b→c, 새값→b
        a = d;
        d = c;
        c = b;
        b += rotl32(F, MD5_S[i]); // F를 MD5_S[i]비트 왼쪽 회전 후 b에 더함
    }

    // ④ 원래 상태에 이번 블록 처리 결과를 더함 (누적)
    //    모든 블록에 걸쳐 이 누적이 반복됩니다.
    s.a += a; s.b += b; s.c += c; s.d += d;
}

// ============================================================
// md5Update : 임의 크기의 데이터를 64바이트 단위로 잘라 처리
// ============================================================
// 파일이 클 경우 한 번에 읽지 않고 조금씩 읽어 이 함수를 반복 호출합니다.
// 내부 버퍼에 64바이트가 모이면 md5Process를 호출합니다.
void Hash::md5Update(MD5State& s, const uint8_t* data, size_t len) {
    s.count += len; // 총 처리 바이트 수 누적 (패딩 계산에 필요)

    while (len > 0) {
        size_t space = 64 - s.bufLen;             // 버퍼의 남은 공간
        size_t take  = (len < space) ? len : space; // 이번에 채울 바이트 수

        // 데이터를 버퍼에 복사
        std::memcpy(s.buf + s.bufLen, data, take);
        s.bufLen += take; // 버퍼 사용량 증가
        data     += take; // 포인터를 이동해 다음 데이터 위치 가리킴
        len      -= take; // 남은 처리량 감소

        // 버퍼가 꽉 찼으면(64바이트) 블록 처리 후 버퍼 비우기
        if (s.bufLen == 64) {
            md5Process(s, s.buf);
            s.bufLen = 0;
        }
    }
}

// ============================================================
// md5Finish : 패딩 추가 후 최종 해시값(16바이트) 출력
// ============================================================
// MD5 패딩 규칙:
//   1) 메시지 끝에 0x80 바이트 1개 추가 (이진수로 10000000)
//   2) 버퍼 내 사용량이 56바이트가 될 때까지 0x00 바이트 추가
//   3) 원본 메시지 길이를 비트 단위(바이트 수 × 8)로
//      리틀 엔디언 64비트 정수로 마지막 8바이트에 추가
//   → 총 블록이 정확히 64바이트 배수가 됨
void Hash::md5Finish(MD5State& s, uint8_t digest[16]) {
    // 패딩 전에 원본 데이터 길이를 비트 단위로 저장
    uint64_t bitLen = s.count * 8;

    // 1) 0x80 (이진: 1000 0000) 추가 → "메시지 끝"을 알리는 마커
    uint8_t pad = 0x80;
    md5Update(s, &pad, 1);

    // 2) 버퍼 위치가 56바이트가 될 때까지 0x00 패딩
    //    (56바이트 = 64바이트 블록에서 길이 정보 8바이트를 위한 공간 확보)
    //    bufLen이 56 이상이면 한 바퀴 돌아 다음 블록의 56바이트 위치까지 채움
    uint8_t zero = 0;
    while (s.bufLen != 56) md5Update(s, &zero, 1);

    // 3) 원본 길이(비트 단위)를 리틀 엔디언으로 8바이트 추가
    //    리틀 엔디언: 낮은 바이트부터 저장
    //    예) bitLen = 0x0000000000000040 (64비트)
    //        저장 순서: 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    for (int i = 0; i < 8; ++i) {
        uint8_t b = static_cast<uint8_t>(bitLen >> (i * 8));
        md5Update(s, &b, 1);
    }

    // ④ 최종 상태 a,b,c,d를 리틀 엔디언으로 digest[0~15]에 씀
    //    put32le: 32비트 값을 리틀 엔디언 바이트 4개로 변환하는 람다 함수
    auto put32le = [](uint32_t v, uint8_t* p) {
        p[0] = v & 0xff;         // 최하위 8비트
        p[1] = (v >>  8) & 0xff; // 다음 8비트
        p[2] = (v >> 16) & 0xff; // 다음 8비트
        p[3] = (v >> 24) & 0xff; // 최상위 8비트
    };
    put32le(s.a, digest +  0); // digest[0~3]
    put32le(s.b, digest +  4); // digest[4~7]
    put32le(s.c, digest +  8); // digest[8~11]
    put32le(s.d, digest + 12); // digest[12~15]
}

// ============================================================
//  SHA-256 알고리즘 구현  (FIPS 180-4)
// ============================================================

// ── SHA-256 라운드 상수 K[0~63] ──────────────────────────────
// K[i] = 처음 64개 소수의 세제곱근의 소수 부분 × 2^32
// 예) 소수 2의 세제곱근 ≈ 1.2599..., 소수 부분 0.2599... × 2^32 ≈ 0x428a2f98
// 이 상수들도 MD5_T처럼 비트 패턴을 '예측하기 어렵게' 만들어줍니다.
static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, // 소수 2, 3, 5, 7
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, // 소수 11, 13, 17, 19
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, // 소수 23, 29, 31, 37
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ============================================================
// sha256Init : SHA-256 내부 상태를 초기값으로 설정
// ============================================================
// h[0]~h[7] = 처음 8개 소수(2,3,5,7,11,13,17,19)의 제곱근의 소수 부분 × 2^32
// 예) sqrt(2) ≈ 1.41421356..., 소수 부분 0.41421356... × 2^32 ≈ 0x6a09e667
void Hash::sha256Init(SHA256State& s) {
    s.h[0] = 0x6a09e667; // sqrt(2)
    s.h[1] = 0xbb67ae85; // sqrt(3)
    s.h[2] = 0x3c6ef372; // sqrt(5)
    s.h[3] = 0xa54ff53a; // sqrt(7)
    s.h[4] = 0x510e527f; // sqrt(11)
    s.h[5] = 0x9b05688c; // sqrt(13)
    s.h[6] = 0x1f83d9ab; // sqrt(17)
    s.h[7] = 0x5be0cd19; // sqrt(19)
    s.count  = 0;
    s.bufLen = 0;
    std::memset(s.buf, 0, sizeof(s.buf));
}

// ============================================================
// sha256Process : 64바이트 블록 1개를 처리 (SHA-256 핵심 연산)
// ============================================================
void Hash::sha256Process(SHA256State& s, const uint8_t blk[64]) {
    // ① 64바이트 블록을 16개의 32비트 워드로 변환 (빅 엔디언)
    //    빅 엔디언: 높은 주소에 낮은 바이트 → 첫 바이트가 최상위 바이트
    //    MD5(리틀 엔디언)과 반대 방향입니다.
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(blk[i*4])   << 24)  // 첫 바이트 → 최상위 8비트
             | (uint32_t(blk[i*4+1]) << 16)  // 두 번째 바이트
             | (uint32_t(blk[i*4+2]) <<  8)  // 세 번째 바이트
             |  uint32_t(blk[i*4+3]);         // 네 번째 바이트 → 최하위 8비트

    // ② 메시지 확장: w[16]~w[63]을 이전 워드들로 계산해서 채움
    //    이렇게 하면 64바이트 입력이 256바이트(64×4)의 '확장된 메시지 스케줄'이 됩니다.
    for (int i = 16; i < 64; ++i) {
        // sigma0: w[i-15]에 대한 혼합 함수 (회전 + 시프트)
        uint32_t s0 = rotr32(w[i-15],  7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        // sigma1: w[i-2]에 대한 혼합 함수
        uint32_t s1 = rotr32(w[i- 2], 17) ^ rotr32(w[i- 2], 19) ^ (w[i- 2] >> 10);
        // 새 워드 = 이전 워드들의 합 (모두 mod 2^32 덧셈)
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    // ③ 현재 해시 상태를 a~h에 복사 (이 값들이 64라운드 동안 변함)
    uint32_t a = s.h[0], b = s.h[1], c = s.h[2], d = s.h[3];
    uint32_t e = s.h[4], f = s.h[5], g = s.h[6], h = s.h[7];

    // ④ 64라운드 압축 함수
    for (int i = 0; i < 64; ++i) {
        // Sigma1(e): e에 대한 큰 시그마1 함수 (3가지 회전값의 XOR)
        uint32_t S1    = rotr32(e,  6) ^ rotr32(e, 11) ^ rotr32(e, 25);

        // Ch(e,f,g): e의 비트가 1이면 f를, 0이면 g를 선택하는 '선택 함수'
        //            (e & f): e가 1인 비트 위치에서 f의 값 선택
        //            (~e & g): e가 0인 비트 위치에서 g의 값 선택
        uint32_t ch    = (e & f) ^ (~e & g);

        // temp1: h, S1, Ch, 라운드 상수, 메시지 워드를 모두 더한 임시값
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];

        // Sigma0(a): a에 대한 큰 시그마0 함수
        uint32_t S0    = rotr32(a,  2) ^ rotr32(a, 13) ^ rotr32(a, 22);

        // Maj(a,b,c): 세 값 중 다수결(2개 이상이 1이면 1) 함수
        //             (a & b): a, b 모두 1인 위치
        //             (a & c): a, c 모두 1인 위치
        //             (b & c): b, c 모두 1인 위치
        uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);

        // temp2: S0과 다수결 함수의 합
        uint32_t temp2 = S0 + maj;

        // 레지스터 순환 (h←g←f←e, e에 temp1 더함, d←c←b←a, a에 temp1+temp2 설정)
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    // ⑤ 원래 상태에 이번 블록 결과를 누적
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d;
    s.h[4] += e; s.h[5] += f; s.h[6] += g; s.h[7] += h;
}

// ============================================================
// sha256Update : 임의 크기의 데이터를 64바이트 단위로 처리
// ============================================================
// MD5와 동일한 구조이며, 버퍼가 64바이트 차면 sha256Process 호출
void Hash::sha256Update(SHA256State& s, const uint8_t* data, size_t len) {
    s.count += len; // 총 처리 바이트 수 누적

    while (len > 0) {
        size_t space = 64 - s.bufLen;             // 버퍼 남은 공간
        size_t take  = (len < space) ? len : space; // 이번에 채울 양

        std::memcpy(s.buf + s.bufLen, data, take);
        s.bufLen += take;
        data     += take;
        len      -= take;

        if (s.bufLen == 64) { // 버퍼가 꽉 찼으면 처리
            sha256Process(s, s.buf);
            s.bufLen = 0;
        }
    }
}

// ============================================================
// sha256Finish : SHA-256 패딩 추가 후 최종 32바이트 해시 출력
// ============================================================
// MD5와 패딩 방법은 같지만 두 가지 차이가 있습니다:
//   1) 길이를 빅 엔디언으로 추가 (MD5는 리틀 엔디언)
//   2) 결과를 빅 엔디언으로 출력 (MD5는 리틀 엔디언)
void Hash::sha256Finish(SHA256State& s, uint8_t digest[32]) {
    uint64_t bitLen = s.count * 8; // 원본 길이를 비트 단위로

    // 1) 0x80 패딩 추가
    uint8_t pad = 0x80;
    sha256Update(s, &pad, 1);

    // 2) 0x00으로 56바이트 위치까지 패딩
    uint8_t zero = 0;
    while (s.bufLen != 56) sha256Update(s, &zero, 1);

    // 3) 원본 길이를 빅 엔디언 8바이트로 추가
    //    빅 엔디언: i=7에서 최상위 바이트(MSB)부터 저장
    //    예) bitLen = 0x0000000000000040
    //        저장 순서: 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
    for (int i = 7; i >= 0; --i) {
        uint8_t b = static_cast<uint8_t>(bitLen >> (i * 8));
        sha256Update(s, &b, 1);
    }

    // ④ 8개의 32비트 상태를 빅 엔디언으로 32바이트 digest에 출력
    for (int i = 0; i < 8; ++i) {
        digest[i*4+0] = static_cast<uint8_t>(s.h[i] >> 24); // 최상위 바이트
        digest[i*4+1] = static_cast<uint8_t>(s.h[i] >> 16);
        digest[i*4+2] = static_cast<uint8_t>(s.h[i] >>  8);
        digest[i*4+3] = static_cast<uint8_t>(s.h[i]);        // 최하위 바이트
    }
}

// ============================================================
// 공개 인터페이스 (외부에서 직접 호출하는 함수들)
// ============================================================

// md5Buffer : 메모리의 데이터 블록에 대해 MD5 계산
std::string Hash::md5Buffer(const uint8_t* data, size_t len) {
    MD5State s;
    md5Init(s);               // 상태 초기화
    md5Update(s, data, len);  // 데이터 처리
    uint8_t digest[16];
    md5Finish(s, digest);     // 최종 해시 계산
    return bytesToHex(digest, 16); // 16진수 문자열로 변환
}

// sha256Buffer : 메모리의 데이터 블록에 대해 SHA-256 계산
std::string Hash::sha256Buffer(const uint8_t* data, size_t len) {
    SHA256State s;
    sha256Init(s);
    sha256Update(s, data, len);
    uint8_t digest[32];
    sha256Finish(s, digest);
    return bytesToHex(digest, 32); // 32바이트 → 64자리 16진수 문자열
}

// md5File : 파일 전체를 읽어 MD5 계산
// 8192바이트(8KB)씩 조금씩 읽어서 처리하므로 대용량 파일도 가능합니다.
std::string Hash::md5File(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary); // 바이너리 모드로 파일 열기
    if (!f) throw std::runtime_error("Cannot open: " + filepath);

    MD5State s;
    md5Init(s);

    uint8_t buf[8192]; // 8KB 읽기 버퍼
    while (f) {
        f.read(reinterpret_cast<char*>(buf), sizeof(buf)); // 최대 8KB 읽기
        auto n = static_cast<size_t>(f.gcount()); // 실제로 읽은 바이트 수
        if (n > 0) md5Update(s, buf, n);
    }

    uint8_t digest[16];
    md5Finish(s, digest);
    return bytesToHex(digest, 16); // "d41d8cd98f00b204..." 형태의 32자리 문자열
}

// sha256File : 파일 전체를 읽어 SHA-256 계산
std::string Hash::sha256File(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open: " + filepath);

    SHA256State s;
    sha256Init(s);

    uint8_t buf[8192];
    while (f) {
        f.read(reinterpret_cast<char*>(buf), sizeof(buf));
        auto n = static_cast<size_t>(f.gcount());
        if (n > 0) sha256Update(s, buf, n);
    }

    uint8_t digest[32];
    sha256Finish(s, digest);
    return bytesToHex(digest, 32); // 64자리 16진수 문자열
}

} // namespace forensics
