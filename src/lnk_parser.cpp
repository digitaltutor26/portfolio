#include "lnk_parser.h"
#include "common.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace forensics {
namespace fs = std::filesystem;

uint16_t LnkParser::read16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
uint32_t LnkParser::read32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint64_t LnkParser::read64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8)
         | (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 24)
         | (static_cast<uint64_t>(p[4]) << 32) | (static_cast<uint64_t>(p[5]) << 40)
         | (static_cast<uint64_t>(p[6]) << 48) | (static_cast<uint64_t>(p[7]) << 56);
}

std::time_t LnkParser::filetimeToTimet(uint64_t ft) {
    if (ft == 0) return 0;
    uint64_t sec = ft / 10000000ULL;
    if (sec <= 11644473600ULL) return 0;
    return static_cast<std::time_t>(sec - 11644473600ULL);
}

std::string LnkParser::utf16leToUtf8(const uint8_t* data, size_t charCount) {
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

std::string LnkParser::driveTypeName(DriveType dt) {
    switch (dt) {
        case DriveType::Removable: return "Removable (USB/Floppy)";
        case DriveType::Fixed:     return "Fixed (HDD/SSD)";
        case DriveType::Remote:    return "Remote (Network)";
        case DriveType::CdRom:     return "CD-ROM";
        case DriveType::RamDisk:   return "RAM Disk";
        case DriveType::NoRootDir: return "No Root Directory";
        default:                   return "Unknown";
    }
}

std::string LnkParser::formatSerial(uint32_t serial) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0')
        << std::setw(4) << ((serial >> 16) & 0xFFFF) << "-"
        << std::setw(4) << (serial & 0xFFFF);
    return oss.str();
}

std::vector<uint8_t> LnkParser::readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = f.tellg();
    if (sz <= 0) return {};
    f.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

void LnkParser::parseTrackerData(const uint8_t* data, size_t size, LnkInfo& info) {
    size_t pos = 0;
    while (pos + 8 <= size) {
        uint32_t blockSize = read32(data + pos);
        uint32_t blockSig  = read32(data + pos + 4);
        if (blockSize < 8 || pos + blockSize > size) break;
        if (blockSig == 0xA0000003 && blockSize >= 0x60) {
            const auto* mid = data + pos + 0x10;
            info.machineName = std::string(reinterpret_cast<const char*>(mid),
                                           ::strnlen(reinterpret_cast<const char*>(mid), 16));
            const uint8_t* g = data + pos + 0x20;
            std::ostringstream oss;
            oss << std::uppercase << std::hex << std::setfill('0') << "{"
                << std::setw(8) << read32(g) << "-"
                << std::setw(4) << read16(g+4) << "-"
                << std::setw(4) << read16(g+6) << "-";
            for (int i=8; i<10; ++i) oss << std::setw(2) << static_cast<unsigned>(g[i]);
            oss << "-";
            for (int i=10; i<16; ++i) oss << std::setw(2) << static_cast<unsigned>(g[i]);
            oss << "}";
            info.machineGuid = oss.str();
            return;
        }
        pos += blockSize;
    }
}

LnkInfo LnkParser::parse(const std::string& lnkPath) {
    LnkInfo info;
    info.lnkPath = lnkPath;
    info.lnkName = fs::path(lnkPath).filename().string();

    auto buf = readFile(lnkPath);
    if (buf.size() < 76) { info.errorMsg = "File too small"; return info; }

    const uint8_t* data = buf.data();
    const size_t   size = buf.size();

    if (read32(data + 0x00) != 0x0000004C) { info.errorMsg = "Invalid LNK signature"; return info; }

    uint32_t linkFlags = read32(data + 0x14);
    info.targetSize              = static_cast<uint64_t>(read32(data + 0x34));
    info.targetTimes.created     = filetimeToTimet(read64(data + 0x1C));
    info.targetTimes.accessed    = filetimeToTimet(read64(data + 0x24));
    info.targetTimes.modified    = filetimeToTimet(read64(data + 0x2C));
    info.targetTimes.createdStr  = formatTimestamp(info.targetTimes.created);
    info.targetTimes.accessedStr = formatTimestamp(info.targetTimes.accessed);
    info.targetTimes.modifiedStr = formatTimestamp(info.targetTimes.modified);

    const bool hasIDList   = (linkFlags & 0x01) != 0;
    const bool hasLinkInfo = (linkFlags & 0x02) != 0;
    const bool isUnicode   = (linkFlags & 0x80) != 0;
    size_t pos = 76;

    if (hasIDList) {
        if (pos + 2 > size) { info.errorMsg = "Truncated IDList"; return info; }
        pos += 2 + read16(data + pos);
    }

    size_t linkInfoStart = pos;
    if (hasLinkInfo && pos + 28 <= size) {
        uint32_t liSize   = read32(data + pos + 0x00);
        uint32_t liHdrSz  = read32(data + pos + 0x04);
        uint32_t liFlags  = read32(data + pos + 0x08);
        uint32_t vidOff   = read32(data + pos + 0x0C);
        uint32_t lpOff    = read32(data + pos + 0x10);
        uint32_t netOff   = read32(data + pos + 0x14);
        if (pos + liSize > size) { info.errorMsg = "Truncated LinkInfo"; return info; }

        uint32_t lpOffU = 0;
        if (liHdrSz >= 0x24 && pos + 0x24 <= size) lpOffU = read32(data + pos + 0x1C);

        bool hasVol    = (liFlags & 0x01) != 0;
        bool hasNet    = (liFlags & 0x02) != 0;

        if (hasVol && vidOff > 0) {
            size_t vo = linkInfoStart + vidOff;
            if (vo + 16 <= size) {
                uint32_t vsz   = read32(data + vo + 0x00);
                info.volume.driveType    = static_cast<DriveType>(read32(data + vo + 0x04));
                info.volume.driveTypeStr = driveTypeName(info.volume.driveType);
                info.volume.serialNumber = read32(data + vo + 0x08);
                info.volume.serialStr    = formatSerial(info.volume.serialNumber);
                uint32_t lbOff = read32(data + vo + 0x0C);
                if (lbOff == 0x14 && vo + 0x14 <= size) {
                    uint32_t uOff = read32(data + vo + 0x10);
                    size_t lp = vo + uOff;
                    if (lp < size) info.volume.label = utf16leToUtf8(data + lp, (size - lp) / 2);
                } else if (vo + lbOff < size) {
                    size_t lp = vo + lbOff;
                    size_t ml = std::min(size - lp, (size_t)(vsz - lbOff));
                    info.volume.label = std::string(reinterpret_cast<const char*>(data + lp),
                                                    ::strnlen(reinterpret_cast<const char*>(data + lp), ml));
                }
            }
        }

        if (hasVol && lpOff > 0) {
            if (lpOffU > 0) {
                size_t pp = linkInfoStart + lpOffU;
                if (pp < size) info.targetPath = utf16leToUtf8(data + pp, (size - pp) / 2);
            }
            if (info.targetPath.empty()) {
                size_t pp = linkInfoStart + lpOff;
                if (pp < size) info.targetPath = std::string(
                    reinterpret_cast<const char*>(data + pp),
                    ::strnlen(reinterpret_cast<const char*>(data + pp), size - pp));
            }
        }

        if (hasNet && netOff > 0) {
            size_t no = linkInfoStart + netOff;
            if (no + 20 <= size) {
                uint32_t nhsz = read32(data + no + 0x04);
                uint32_t snOff = read32(data + no + 0x0C);
                uint32_t snOffU = 0;
                if (nhsz >= 0x1C && no + 0x1C <= size) snOffU = read32(data + no + 0x14);
                if (snOffU > 0) {
                    size_t pp = no + snOffU;
                    if (pp < size) info.networkShare = utf16leToUtf8(data + pp, (size - pp) / 2);
                }
                if (info.networkShare.empty() && no + snOff < size) {
                    size_t pp = no + snOff;
                    info.networkShare = std::string(reinterpret_cast<const char*>(data + pp),
                                                    ::strnlen(reinterpret_cast<const char*>(data + pp), size - pp));
                }
            }
        }
        pos = linkInfoStart + liSize;
    }

    auto skipString = [&]() -> bool {
        if (pos + 2 > size) return false;
        uint16_t count = read16(data + pos);
        pos += 2;
        size_t bl = isUnicode ? (size_t)count * 2 : (size_t)count;
        if (pos + bl > size) return false;
        pos += bl;
        return true;
    };
    for (int bit = 2; bit <= 6; ++bit)
        if ((linkFlags >> bit) & 0x01) if (!skipString()) break;

    if (pos < size) parseTrackerData(data + pos, size - pos, info);

    if (!info.targetPath.empty()) {
        size_t sep = info.targetPath.find_last_of("/\\");
        info.targetName = (sep == std::string::npos) ? info.targetPath : info.targetPath.substr(sep + 1);
    } else {
        info.targetName = info.lnkName;
        if (info.targetName.size() > 4) {
            std::string ext = info.targetName.substr(info.targetName.size() - 4);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".lnk") info.targetName = info.targetName.substr(0, info.targetName.size() - 4);
        }
    }
    info.success = true;
    return info;
}

std::vector<LnkInfo> LnkParser::parseDirectory(const std::string& dirPath) {
    std::vector<LnkInfo> results;
    std::error_code ec;
    if (!fs::is_directory(dirPath, ec)) return results;
    for (const auto& entry : fs::directory_iterator(dirPath, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        std::string ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".lnk") results.push_back(parse(entry.path().string()));
    }
    return results;
}

} // namespace forensics
