#pragma once

#include <string>
#include <cstdint>

namespace forensics {

class Hash {
public:
    static std::string md5File(const std::string& filepath);
    static std::string sha256File(const std::string& filepath);

    static std::string md5Buffer(const uint8_t* data, size_t len);
    static std::string sha256Buffer(const uint8_t* data, size_t len);

private:
    // ── MD5 (RFC 1321) ──────────────────────────────────────────────────────
    struct MD5State {
        uint32_t a, b, c, d;
        uint64_t count;  // bytes processed
        uint8_t  buf[64];
        size_t   bufLen;
    };
    static void md5Init(MD5State& s);
    static void md5Process(MD5State& s, const uint8_t block[64]);
    static void md5Update(MD5State& s, const uint8_t* data, size_t len);
    static void md5Finish(MD5State& s, uint8_t digest[16]);

    // ── SHA-256 (FIPS 180-4) ─────────────────────────────────────────────────
    struct SHA256State {
        uint32_t h[8];
        uint64_t count;  // bytes processed
        uint8_t  buf[64];
        size_t   bufLen;
    };
    static void sha256Init(SHA256State& s);
    static void sha256Process(SHA256State& s, const uint8_t block[64]);
    static void sha256Update(SHA256State& s, const uint8_t* data, size_t len);
    static void sha256Finish(SHA256State& s, uint8_t digest[32]);
};

} // namespace forensics
