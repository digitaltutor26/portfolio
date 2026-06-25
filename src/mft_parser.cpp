#include "mft_parser.h"
#include "common.h"
#include <fstream>
#include <algorithm>
#include <cstring>
#include <sstream>

namespace forensics {

uint16_t MftParser::read16(const uint8_t* p) { return static_cast<uint16_t>(p[0])|(static_cast<uint16_t>(p[1])<<8); }
uint32_t MftParser::read32(const uint8_t* p) { return static_cast<uint32_t>(p[0])|(static_cast<uint32_t>(p[1])<<8)|(static_cast<uint32_t>(p[2])<<16)|(static_cast<uint32_t>(p[3])<<24); }
uint64_t MftParser::read64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0])|(static_cast<uint64_t>(p[1])<<8)|(static_cast<uint64_t>(p[2])<<16)|(static_cast<uint64_t>(p[3])<<24)
          |(static_cast<uint64_t>(p[4])<<32)|(static_cast<uint64_t>(p[5])<<40)|(static_cast<uint64_t>(p[6])<<48)|(static_cast<uint64_t>(p[7])<<56);
}

std::time_t MftParser::filetimeToTimet(uint64_t ft) {
    if (ft == 0) return 0;
    uint64_t sec = ft / 10000000ULL;
    if (sec <= 11644473600ULL) return 0;
    return static_cast<std::time_t>(sec - 11644473600ULL);
}

std::string MftParser::utf16leToUtf8(const uint8_t* data, size_t charCount) {
    std::string result;
    result.reserve(charCount);
    for (size_t i = 0; i < charCount; ++i) {
        uint16_t c = read16(data + i * 2);
        if (c == 0) break;
        if (c < 0x80)       result += static_cast<char>(c);
        else if (c < 0x800) { result += static_cast<char>(0xC0|(c>>6)); result += static_cast<char>(0x80|(c&0x3F)); }
        else                { result += static_cast<char>(0xE0|(c>>12)); result += static_cast<char>(0x80|((c>>6)&0x3F)); result += static_cast<char>(0x80|(c&0x3F)); }
    }
    return result;
}

bool MftParser::fixUsn(std::vector<uint8_t>& rec) {
    if (rec.size() < 48) return false;
    uint16_t usaOff   = read16(rec.data() + 0x04);
    uint16_t usaCount = read16(rec.data() + 0x06);
    if (usaOff + static_cast<size_t>(usaCount) * 2 > rec.size() || usaCount < 2) return false;
    for (uint16_t i = 1; i < usaCount; ++i) {
        size_t sectorEnd = static_cast<size_t>(i) * 512 - 2;
        if (sectorEnd + 2 > rec.size()) break;
        uint16_t original = read16(rec.data() + usaOff + i * 2);
        rec[sectorEnd]     = static_cast<uint8_t>(original & 0xFF);
        rec[sectorEnd + 1] = static_cast<uint8_t>((original >> 8) & 0xFF);
    }
    return true;
}

bool MftParser::parseSiAttribute(const uint8_t* content, size_t contentSize, MftMacTimes& times) {
    if (contentSize < 32) return false;
    times.created     = filetimeToTimet(read64(content + 0x00));
    times.modified    = filetimeToTimet(read64(content + 0x08));
    times.mftModified = filetimeToTimet(read64(content + 0x10));
    times.accessed    = filetimeToTimet(read64(content + 0x18));
    times.createdStr     = formatTimestamp(times.created);
    times.modifiedStr    = formatTimestamp(times.modified);
    times.mftModifiedStr = formatTimestamp(times.mftModified);
    times.accessedStr    = formatTimestamp(times.accessed);
    return true;
}

bool MftParser::parseFnAttribute(const uint8_t* content, size_t contentSize,
                                  MftMacTimes& times, std::string& fileName, uint32_t& fileNameSpace) {
    if (contentSize < 66) return false;
    times.created     = filetimeToTimet(read64(content + 0x08));
    times.modified    = filetimeToTimet(read64(content + 0x10));
    times.mftModified = filetimeToTimet(read64(content + 0x18));
    times.accessed    = filetimeToTimet(read64(content + 0x20));
    times.createdStr     = formatTimestamp(times.created);
    times.modifiedStr    = formatTimestamp(times.modified);
    times.mftModifiedStr = formatTimestamp(times.mftModified);
    times.accessedStr    = formatTimestamp(times.accessed);
    uint8_t fnLen = content[0x40];
    fileNameSpace = content[0x41];
    if (contentSize >= 0x42 + static_cast<size_t>(fnLen) * 2)
        fileName = utf16leToUtf8(content + 0x42, fnLen);
    return true;
}

bool MftParser::parseRecord(const uint8_t* data, size_t size, uint64_t recordNum, MftRecord& out) {
    if (size < 48 || std::memcmp(data, "FILE", 4) != 0) return false;
    out.recordNumber = recordNum;
    uint16_t flags   = read16(data + 0x16);
    out.isDeleted    = !(flags & 0x01);
    out.isDirectory  =  (flags & 0x02) != 0;
    uint16_t firstAttrOff = read16(data + 0x14);
    if (firstAttrOff >= size) return false;

    size_t attrPos = firstAttrOff;
    while (attrPos + 8 <= size) {
        uint32_t attrType = read32(data + attrPos);
        if (attrType == ATTR_END) break;
        uint32_t attrLen  = read32(data + attrPos + 0x04);
        if (attrLen < 8 || attrPos + attrLen > size) break;
        if (data[attrPos + 0x08] == 0 && attrPos + 0x16 <= size) {
            uint32_t cSz = read32(data + attrPos + 0x10);
            uint16_t cOff = read16(data + attrPos + 0x14);
            if (attrPos + cOff + cSz <= size) {
                const uint8_t* content = data + attrPos + cOff;
                if (attrType == ATTR_STANDARD_INFORMATION) {
                    if (parseSiAttribute(content, cSz, out.siTimes)) out.hasSi = true;
                } else if (attrType == ATTR_FILE_NAME) {
                    MftMacTimes times; std::string name; uint32_t ns = 0;
                    if (parseFnAttribute(content, cSz, times, name, ns) && !name.empty()) {
                        if (out.fileName.empty() || ns == 1 || ns == 3) {
                            out.fnTimes = times; out.fileName = name; out.fileNameSpace = ns; out.hasFn = true;
                        }
                    }
                }
            }
        }
        attrPos += attrLen;
    }
    return out.hasSi || out.hasFn;
}

void MftParser::detectAnomaly(MftRecord& record) {
    if (!record.hasSi || !record.hasFn) { record.timestampAnomaly = false; return; }
    bool anomaly = false; std::string details;
    const int64_t THRESHOLD = 2;
    auto check = [&](const char* label, std::time_t si, std::time_t fn) {
        if (si == 0 || fn == 0) return;
        int64_t diff = static_cast<int64_t>(si) - static_cast<int64_t>(fn);
        if (diff < -THRESHOLD) { anomaly = true; details += std::string(label) + "($SI가 $FN보다 " + std::to_string(-diff) + "초 이전); "; }
    };
    check("Created",  record.siTimes.created,    record.fnTimes.created);
    check("Modified", record.siTimes.modified,   record.fnTimes.modified);
    check("MFT-Mod",  record.siTimes.mftModified,record.fnTimes.mftModified);
    check("Accessed", record.siTimes.accessed,   record.fnTimes.accessed);
    record.timestampAnomaly = anomaly;
    record.anomalyDetail    = details;
}

std::vector<MftRecord> MftParser::findByName(const std::string& mftPath, const std::string& targetName) {
    std::vector<MftRecord> results;
    std::ifstream f(mftPath, std::ios::binary);
    if (!f) return results;
    std::string lowerTarget = targetName;
    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
    std::vector<uint8_t> buf(MFT_RECORD_SIZE);
    uint64_t recordNum = 0;
    while (f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(MFT_RECORD_SIZE))) {
        if (std::memcmp(buf.data(), "FILE", 4) != 0) { ++recordNum; continue; }
        auto rec = buf; fixUsn(rec);
        MftRecord record;
        if (parseRecord(rec.data(), rec.size(), recordNum, record)) {
            std::string lowerName = record.fileName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
            if (lowerName.find(lowerTarget) != std::string::npos) { detectAnomaly(record); results.push_back(record); }
        }
        ++recordNum;
    }
    return results;
}

} // namespace forensics
