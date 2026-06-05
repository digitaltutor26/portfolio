#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>

namespace forensics {

struct MftMacTimes {
    std::time_t created     = 0;
    std::time_t modified    = 0;
    std::time_t mftModified = 0;
    std::time_t accessed    = 0;
    std::string createdStr;
    std::string modifiedStr;
    std::string mftModifiedStr;
    std::string accessedStr;
};

struct MftRecord {
    uint64_t    recordNumber  = 0;
    std::string fileName;
    uint32_t    fileNameSpace = 0;
    MftMacTimes siTimes;
    MftMacTimes fnTimes;
    bool        isDirectory       = false;
    bool        isDeleted         = false;
    bool        hasSi             = false;
    bool        hasFn             = false;
    bool        timestampAnomaly  = false;
    std::string anomalyDetail;
};

class MftParser {
public:
    static std::vector<MftRecord> findByName(const std::string& mftPath,
                                              const std::string& targetName);
    static void detectAnomaly(MftRecord& record);
private:
    static const uint32_t ATTR_STANDARD_INFORMATION = 0x10;
    static const uint32_t ATTR_FILE_NAME            = 0x30;
    static const uint32_t ATTR_END                  = 0xFFFFFFFF;
    static const size_t   MFT_RECORD_SIZE           = 1024;
    static bool fixUsn(std::vector<uint8_t>& record);
    static bool parseRecord(const uint8_t* data, size_t size,
                            uint64_t recordNum, MftRecord& out);
    static bool parseSiAttribute(const uint8_t* content, size_t contentSize,
                                 MftMacTimes& times);
    static bool parseFnAttribute(const uint8_t* content, size_t contentSize,
                                 MftMacTimes& times, std::string& fileName,
                                 uint32_t& fileNameSpace);
    static uint16_t    read16(const uint8_t* p);
    static uint32_t    read32(const uint8_t* p);
    static uint64_t    read64(const uint8_t* p);
    static std::time_t filetimeToTimet(uint64_t ft);
    static std::string utf16leToUtf8(const uint8_t* data, size_t charCount);
};

} // namespace forensics
