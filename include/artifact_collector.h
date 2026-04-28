#pragma once

#include <string>
#include <vector>
#include <ctime>

namespace forensics {

enum class ArtifactType {
    RecentFile,
    PrefetchEntry,
    TempFile,
    DownloadedFile
};

struct Artifact {
    ArtifactType type;
    std::string  typeName;
    std::string  path;
    std::string  name;
    std::string  description;
    std::time_t  timestamp    = 0;
    std::string  timestampStr;
    uint64_t     size         = 0;
};

class ArtifactCollector {
public:
    // Windows-specific collections (return empty on non-Windows)
    static std::vector<Artifact> collectRecentFiles();
    static std::vector<Artifact> collectPrefetch();
    static std::vector<Artifact> collectTempFiles();
    static std::vector<Artifact> collectDownloads();
    static std::vector<Artifact> collectAll();

private:
    static std::string typeName(ArtifactType t);

#ifdef _WIN32
    static std::vector<Artifact> scanDir(const std::string& dirPath,
                                         ArtifactType       type,
                                         const std::string& description,
                                         const std::string& extFilter = "");
#endif
};

} // namespace forensics
