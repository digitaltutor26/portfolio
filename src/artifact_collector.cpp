#include "artifact_collector.h"
#include "common.h"

#include <algorithm>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#endif

namespace forensics {

namespace fs = std::filesystem;

std::string ArtifactCollector::typeName(ArtifactType t) {
    switch (t) {
        case ArtifactType::RecentFile:    return "RecentFile";
        case ArtifactType::PrefetchEntry: return "Prefetch";
        case ArtifactType::TempFile:      return "TempFile";
        case ArtifactType::DownloadedFile:return "Download";
        default:                          return "Unknown";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows implementation
// ─────────────────────────────────────────────────────────────────────────────

#ifdef _WIN32

std::vector<Artifact> ArtifactCollector::scanDir(const std::string& dirPath,
                                                  ArtifactType       type,
                                                  const std::string& description,
                                                  const std::string& extFilter) {
    std::vector<Artifact> results;

    std::wstring wDirPath(dirPath.begin(), dirPath.end());
    std::wstring searchPath = wDirPath + L"\\*";

    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return results;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        std::string fileName = wstringToString(ffd.cFileName);
        std::string filePath = dirPath + "\\" + fileName;

        // Extension filter (case-insensitive)
        if (!extFilter.empty()) {
            fs::path p(fileName);
            std::string ext = p.extension().string();
            if (!ext.empty() && ext[0] == '.') ext = ext.substr(1);
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (ext != extFilter) continue;
        }

        Artifact a;
        a.type        = type;
        a.typeName    = typeName(type);
        a.path        = filePath;
        a.name        = fileName;
        a.description = description;

        // Prefer last-write time as the event timestamp
        a.timestamp    = filetimeToTimet(ffd.ftLastWriteTime);
        a.timestampStr = filetimeToString(ffd.ftLastWriteTime);

        ULARGE_INTEGER fileSize;
        fileSize.LowPart  = ffd.nFileSizeLow;
        fileSize.HighPart = ffd.nFileSizeHigh;
        a.size = fileSize.QuadPart;

        results.push_back(std::move(a));
    } while (FindNextFileW(hFind, &ffd));

    FindClose(hFind);
    return results;
}

std::vector<Artifact> ArtifactCollector::collectRecentFiles() {
    // %APPDATA%\Microsoft\Windows\Recent
    std::string recentPath = expandEnvVar("%APPDATA%\\Microsoft\\Windows\\Recent");
    return scanDir(recentPath, ArtifactType::RecentFile,
                   "Recently accessed file (LNK shortcut)", "lnk");
}

std::vector<Artifact> ArtifactCollector::collectPrefetch() {
    // C:\Windows\Prefetch - requires elevated privileges on some systems
    // Filename format: PROGRAM-HASHVALUE.pf
    std::string prefetchPath = expandEnvVar("%SystemRoot%\\Prefetch");
    auto results = scanDir(prefetchPath, ArtifactType::PrefetchEntry,
                           "Program execution record", "pf");

    // Extract program name from prefetch filename (e.g., NOTEPAD.EXE-1234ABCD.pf)
    for (auto& a : results) {
        fs::path p(a.name);
        std::string stem = p.stem().string();
        auto dashPos = stem.rfind('-');
        if (dashPos != std::string::npos) {
            a.description = "Executed: " + stem.substr(0, dashPos);
        }
    }
    return results;
}

std::vector<Artifact> ArtifactCollector::collectTempFiles() {
    std::string tempPath = expandEnvVar("%TEMP%");
    return scanDir(tempPath, ArtifactType::TempFile,
                   "Temporary file", "");
}

std::vector<Artifact> ArtifactCollector::collectDownloads() {
    std::string dlPath = expandEnvVar("%USERPROFILE%\\Downloads");
    return scanDir(dlPath, ArtifactType::DownloadedFile,
                   "Downloaded file", "");
}

#else // ─── Non-Windows stubs ─────────────────────────────────────────────────

std::vector<Artifact> ArtifactCollector::collectRecentFiles()  { return {}; }
std::vector<Artifact> ArtifactCollector::collectPrefetch()     { return {}; }
std::vector<Artifact> ArtifactCollector::collectTempFiles()    { return {}; }
std::vector<Artifact> ArtifactCollector::collectDownloads()    { return {}; }

#endif

// ─────────────────────────────────────────────────────────────────────────────
// Collect all artifacts, sorted newest-first
// ─────────────────────────────────────────────────────────────────────────────

std::vector<Artifact> ArtifactCollector::collectAll() {
    std::vector<Artifact> all;
    for (auto& v : { collectRecentFiles(), collectPrefetch(),
                     collectTempFiles(),   collectDownloads() })
        all.insert(all.end(), v.begin(), v.end());

    std::sort(all.begin(), all.end(),
        [](const Artifact& a, const Artifact& b) {
            return a.timestamp > b.timestamp;
        });
    return all;
}

} // namespace forensics
