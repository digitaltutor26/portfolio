#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <filesystem>

namespace forensics {

namespace fs = std::filesystem;

enum class FileCategory {
    Executable,
    Script,
    Document,
    Image,
    Video,
    Audio,
    Archive,
    Database,
    Log,
    Unknown
};

struct FileInfo {
    std::string  path;
    std::string  name;
    std::string  extension;
    uint64_t     size        = 0;
    std::time_t  createdTime = 0;
    std::time_t  modifiedTime = 0;
    std::time_t  accessedTime = 0;
    std::string  created;
    std::string  modified;
    std::string  accessed;
    std::string  md5;
    std::string  sha256;
    std::string  magic;       // first 8 bytes as hex
    FileCategory category    = FileCategory::Unknown;
    bool         isHidden    = false;
    bool         isSystem    = false;
    bool         isReadOnly  = false;
};

class FileInfoCollector {
public:
    static FileInfo              collect(const fs::path& path, bool computeHash = false);
    static std::vector<FileInfo> scanDirectory(const fs::path& dir,
                                               bool recursive   = false,
                                               bool computeHash = false);

    static FileCategory categorize(const std::string& lowerExt);
    static std::string  categoryName(FileCategory cat);

private:
    static std::string readMagic(const fs::path& path);
};

} // namespace forensics
