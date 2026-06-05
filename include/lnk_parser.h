#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>

namespace forensics {

enum class DriveType : uint32_t {
    Unknown   = 0,
    NoRootDir = 1,
    Removable = 2,
    Fixed     = 3,
    Remote    = 4,
    CdRom     = 5,
    RamDisk   = 6
};

struct LnkVolumeInfo {
    DriveType   driveType    = DriveType::Unknown;
    std::string driveTypeStr;
    uint32_t    serialNumber = 0;
    std::string serialStr;
    std::string label;
};

struct LnkTimestamps {
    std::time_t created  = 0;
    std::time_t modified = 0;
    std::time_t accessed = 0;
    std::string createdStr;
    std::string modifiedStr;
    std::string accessedStr;
};

struct LnkInfo {
    std::string   lnkPath;
    std::string   lnkName;
    std::string   targetPath;
    std::string   targetName;
    uint64_t      targetSize = 0;
    LnkVolumeInfo volume;
    LnkTimestamps targetTimes;
    std::string   networkShare;
    std::string   machineName;
    std::string   machineGuid;
    bool          success  = false;
    std::string   errorMsg;
};

class LnkParser {
public:
    static LnkInfo              parse(const std::string& lnkPath);
    static std::vector<LnkInfo> parseDirectory(const std::string& dirPath);
private:
    static std::vector<uint8_t> readFile(const std::string& path);
    static uint16_t    read16(const uint8_t* p);
    static uint32_t    read32(const uint8_t* p);
    static uint64_t    read64(const uint8_t* p);
    static std::time_t filetimeToTimet(uint64_t ft);
    static std::string utf16leToUtf8(const uint8_t* data, size_t charCount);
    static std::string driveTypeName(DriveType dt);
    static std::string formatSerial(uint32_t serial);
    static void        parseTrackerData(const uint8_t* data, size_t size, LnkInfo& info);
};

} // namespace forensics
