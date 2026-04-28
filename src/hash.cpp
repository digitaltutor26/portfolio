#include "hash.h"
#include "common.h"

#include <fstream>
#include <cstring>
#include <stdexcept>

namespace forensics {

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

// ─────────────────────────────────────────────────────────────────────────────
// MD5  (RFC 1321)
// ─────────────────────────────────────────────────────────────────────────────

static const uint32_t MD5_T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t MD5_S[64] = {
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

void Hash::md5Init(MD5State& s) {
    s.a = 0x67452301;
    s.b = 0xefcdab89;
    s.c = 0x98badcfe;
    s.d = 0x10325476;
    s.count  = 0;
    s.bufLen = 0;
    std::memset(s.buf, 0, sizeof(s.buf));
}

void Hash::md5Process(MD5State& s, const uint8_t blk[64]) {
    uint32_t M[16];
    for (int i = 0; i < 16; ++i)
        M[i] = uint32_t(blk[i*4])
             | (uint32_t(blk[i*4+1]) <<  8)
             | (uint32_t(blk[i*4+2]) << 16)
             | (uint32_t(blk[i*4+3]) << 24);

    uint32_t a = s.a, b = s.b, c = s.c, d = s.d;
    for (int i = 0; i < 64; ++i) {
        uint32_t F; int g;
        if      (i < 16) { F = (b & c) | (~b & d); g = i; }
        else if (i < 32) { F = (d & b) | (~d & c); g = (5*i + 1) % 16; }
        else if (i < 48) { F = b ^ c ^ d;           g = (3*i + 5) % 16; }
        else             { F = c ^ (b | ~d);         g = (7*i)     % 16; }
        F += a + MD5_T[i] + M[g];
        a = d; d = c; c = b;
        b += rotl32(F, MD5_S[i]);
    }
    s.a += a; s.b += b; s.c += c; s.d += d;
}

void Hash::md5Update(MD5State& s, const uint8_t* data, size_t len) {
    s.count += len;
    while (len > 0) {
        size_t space = 64 - s.bufLen;
        size_t take  = (len < space) ? len : space;
        std::memcpy(s.buf + s.bufLen, data, take);
        s.bufLen += take;
        data     += take;
        len      -= take;
        if (s.bufLen == 64) {
            md5Process(s, s.buf);
            s.bufLen = 0;
        }
    }
}

void Hash::md5Finish(MD5State& s, uint8_t digest[16]) {
    uint64_t bitLen = s.count * 8;

    uint8_t pad = 0x80;
    md5Update(s, &pad, 1);
    uint8_t zero = 0;
    while (s.bufLen != 56) md5Update(s, &zero, 1);

    // Append bit-length as little-endian 64-bit integer
    for (int i = 0; i < 8; ++i) {
        uint8_t b = static_cast<uint8_t>(bitLen >> (i * 8));
        md5Update(s, &b, 1);
    }

    // Write state words in little-endian order
    auto put32le = [](uint32_t v, uint8_t* p) {
        p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
        p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
    };
    put32le(s.a, digest +  0);
    put32le(s.b, digest +  4);
    put32le(s.c, digest +  8);
    put32le(s.d, digest + 12);
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256  (FIPS 180-4)
// ─────────────────────────────────────────────────────────────────────────────

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
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

void Hash::sha256Init(SHA256State& s) {
    s.h[0] = 0x6a09e667; s.h[1] = 0xbb67ae85;
    s.h[2] = 0x3c6ef372; s.h[3] = 0xa54ff53a;
    s.h[4] = 0x510e527f; s.h[5] = 0x9b05688c;
    s.h[6] = 0x1f83d9ab; s.h[7] = 0x5be0cd19;
    s.count  = 0;
    s.bufLen = 0;
    std::memset(s.buf, 0, sizeof(s.buf));
}

void Hash::sha256Process(SHA256State& s, const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(blk[i*4]) << 24)
             | (uint32_t(blk[i*4+1]) << 16)
             | (uint32_t(blk[i*4+2]) <<  8)
             |  uint32_t(blk[i*4+3]);

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i- 2],17) ^ rotr32(w[i- 2], 19) ^ (w[i- 2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a = s.h[0], b = s.h[1], c = s.h[2], d = s.h[3];
    uint32_t e = s.h[4], f = s.h[5], g = s.h[6], h = s.h[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1    = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch    = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0    = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    s.h[0]+=a; s.h[1]+=b; s.h[2]+=c; s.h[3]+=d;
    s.h[4]+=e; s.h[5]+=f; s.h[6]+=g; s.h[7]+=h;
}

void Hash::sha256Update(SHA256State& s, const uint8_t* data, size_t len) {
    s.count += len;
    while (len > 0) {
        size_t space = 64 - s.bufLen;
        size_t take  = (len < space) ? len : space;
        std::memcpy(s.buf + s.bufLen, data, take);
        s.bufLen += take;
        data     += take;
        len      -= take;
        if (s.bufLen == 64) {
            sha256Process(s, s.buf);
            s.bufLen = 0;
        }
    }
}

void Hash::sha256Finish(SHA256State& s, uint8_t digest[32]) {
    uint64_t bitLen = s.count * 8;

    uint8_t pad = 0x80;
    sha256Update(s, &pad, 1);
    uint8_t zero = 0;
    while (s.bufLen != 56) sha256Update(s, &zero, 1);

    // Append bit-length as big-endian 64-bit integer
    for (int i = 7; i >= 0; --i) {
        uint8_t b = static_cast<uint8_t>(bitLen >> (i * 8));
        sha256Update(s, &b, 1);
    }

    // Write state words in big-endian order
    for (int i = 0; i < 8; ++i) {
        digest[i*4+0] = static_cast<uint8_t>(s.h[i] >> 24);
        digest[i*4+1] = static_cast<uint8_t>(s.h[i] >> 16);
        digest[i*4+2] = static_cast<uint8_t>(s.h[i] >>  8);
        digest[i*4+3] = static_cast<uint8_t>(s.h[i]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public interface
// ─────────────────────────────────────────────────────────────────────────────

std::string Hash::md5Buffer(const uint8_t* data, size_t len) {
    MD5State s;
    md5Init(s);
    md5Update(s, data, len);
    uint8_t digest[16];
    md5Finish(s, digest);
    return bytesToHex(digest, 16);
}

std::string Hash::sha256Buffer(const uint8_t* data, size_t len) {
    SHA256State s;
    sha256Init(s);
    sha256Update(s, data, len);
    uint8_t digest[32];
    sha256Finish(s, digest);
    return bytesToHex(digest, 32);
}

std::string Hash::md5File(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open: " + filepath);
    MD5State s;
    md5Init(s);
    uint8_t buf[8192];
    while (f) {
        f.read(reinterpret_cast<char*>(buf), sizeof(buf));
        auto n = static_cast<size_t>(f.gcount());
        if (n > 0) md5Update(s, buf, n);
    }
    uint8_t digest[16];
    md5Finish(s, digest);
    return bytesToHex(digest, 16);
}

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
    return bytesToHex(digest, 32);
}

} // namespace forensics
