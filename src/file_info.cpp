#include "file_info.h"
#include "hash.h"
#include "common.h"

#include <fstream>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#endif

namespace forensics {

// ─────────────────────────────────────────────────────────────────────────────
// Extension → category mapping
// ─────────────────────────────────────────────────────────────────────────────

FileCategory FileInfoCollector::categorize(const std::string& ext) {
    static const struct { const char* e; FileCategory c; } table[] = {
        // Executables & binaries
        {"exe", FileCategory::Executable}, {"dll", FileCategory::Executable},
        {"sys", FileCategory::Executable}, {"scr", FileCategory::Executable},
        {"com", FileCategory::Executable}, {"msi", FileCategory::Executable},
        {"drv", FileCategory::Executable},
        // Scripts
        {"bat", FileCategory::Script}, {"cmd", FileCategory::Script},
        {"ps1", FileCategory::Script}, {"vbs", FileCategory::Script},
        {"js",  FileCategory::Script}, {"jse", FileCategory::Script},
        {"wsf", FileCategory::Script}, {"wsh", FileCategory::Script},
        {"py",  FileCategory::Script}, {"rb",  FileCategory::Script},
        {"sh",  FileCategory::Script},
        // Documents
        {"doc",  FileCategory::Document}, {"docx", FileCategory::Document},
        {"xls",  FileCategory::Document}, {"xlsx", FileCategory::Document},
        {"ppt",  FileCategory::Document}, {"pptx", FileCategory::Document},
        {"pdf",  FileCategory::Document}, {"txt",  FileCategory::Document},
        {"rtf",  FileCategory::Document}, {"odt",  FileCategory::Document},
        {"csv",  FileCategory::Document}, {"xml",  FileCategory::Document},
        {"html", FileCategory::Document}, {"htm",  FileCategory::Document},
        // Images
        {"jpg",  FileCategory::Image}, {"jpeg", FileCategory::Image},
        {"png",  FileCategory::Image}, {"bmp",  FileCategory::Image},
        {"gif",  FileCategory::Image}, {"tif",  FileCategory::Image},
        {"tiff", FileCategory::Image}, {"ico",  FileCategory::Image},
        {"webp", FileCategory::Image},
        // Video
        {"mp4",  FileCategory::Video}, {"avi",  FileCategory::Video},
        {"mkv",  FileCategory::Video}, {"mov",  FileCategory::Video},
        {"wmv",  FileCategory::Video}, {"flv",  FileCategory::Video},
        // Audio
        {"mp3",  FileCategory::Audio}, {"wav",  FileCategory::Audio},
        {"flac", FileCategory::Audio}, {"aac",  FileCategory::Audio},
        {"wma",  FileCategory::Audio},
        // Archives
        {"zip",  FileCategory::Archive}, {"rar", FileCategory::Archive},
        {"7z",   FileCategory::Archive}, {"tar", FileCategory::Archive},
        {"gz",   FileCategory::Archive}, {"bz2", FileCategory::Archive},
        {"cab",  FileCategory::Archive},
        // Databases
        {"db",   FileCategory::Database}, {"sqlite", FileCategory::Database},
        {"mdb",  FileCategory::Database}, {"accdb",  FileCategory::Database},
        {"ldb",  FileCategory::Database},
        // Logs
        {"log",  FileCategory::Log}, {"evtx", FileCategory::Log},
        {"evt",  FileCategory::Log},
    };
    for (auto& row : table)
        if (ext == row.e) return row.c;
    return FileCategory::Unknown;
}

std::string FileInfoCollector::categoryName(FileCategory cat) {
    switch (cat) {
        case FileCategory::Executable: return "Executable";
        case FileCategory::Script:     return "Script";
        case FileCategory::Document:   return "Document";
        case FileCategory::Image:      return "Image";
        case FileCategory::Video:      return "Video";
        case FileCategory::Audio:      return "Audio";
        case FileCategory::Archive:    return "Archive";
        case FileCategory::Database:   return "Database";
        case FileCategory::Log:        return "Log";
        default:                       return "Unknown";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Magic bytes (first 8 bytes as hex)
// ─────────────────────────────────────────────────────────────────────────────

std::string FileInfoCollector::readMagic(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    uint8_t buf[8] = {};
    f.read(reinterpret_cast<char*>(buf), sizeof(buf));
    auto n = static_cast<size_t>(f.gcount());
    return bytesToHex(buf, n);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single file collection
// ─────────────────────────────────────────────────────────────────────────────

FileInfo FileInfoCollector::collect(const fs::path& path, bool computeHash) {
    FileInfo fi;
    fi.path = path.string();
    fi.name = path.filename().string();

    std::string rawExt = path.extension().string();
    if (!rawExt.empty() && rawExt[0] == '.') rawExt = rawExt.substr(1);
    // Lowercase extension for comparison
    std::string ext = rawExt;
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    fi.extension = ext;
    fi.category  = categorize(ext);

    std::error_code ec;
    if (fs::exists(path, ec)) {
        fi.size = fs::file_size(path, ec);

        auto modTime = fs::last_write_time(path, ec);
        if (!ec) {
            // Convert fs::file_time_type to time_t
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                modTime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
            );
            fi.modifiedTime = std::chrono::system_clock::to_time_t(sctp);
            fi.modified     = formatTimestamp(fi.modifiedTime);
        }

#ifdef _WIN32
        // Use Win32 API for more precise timestamps (Created, Accessed)
        HANDLE hFile = CreateFileW(
            path.wstring().c_str(),
            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, nullptr);

        if (hFile != INVALID_HANDLE_VALUE) {
            FILETIME ftCreate, ftAccess, ftWrite;
            if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
                fi.createdTime  = filetimeToTimet(ftCreate);
                fi.accessedTime = filetimeToTimet(ftAccess);
                fi.modifiedTime = filetimeToTimet(ftWrite);
                fi.created  = filetimeToString(ftCreate);
                fi.accessed = filetimeToString(ftAccess);
                fi.modified = filetimeToString(ftWrite);
            }
            CloseHandle(hFile);

            DWORD attrs = GetFileAttributesW(path.wstring().c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                fi.isHidden   = (attrs & FILE_ATTRIBUTE_HIDDEN)   != 0;
                fi.isSystem   = (attrs & FILE_ATTRIBUTE_SYSTEM)   != 0;
                fi.isReadOnly = (attrs & FILE_ATTRIBUTE_READONLY) != 0;
            }
        }
#else
        fi.created  = fi.modified;
        fi.accessed = fi.modified;
#endif
    }

    fi.magic = readMagic(path);

    if (computeHash) {
        try {
            fi.md5    = Hash::md5File(path.string());
            fi.sha256 = Hash::sha256File(path.string());
        } catch (...) {
            fi.md5 = fi.sha256 = "error";
        }
    }

    return fi;
}

// ─────────────────────────────────────────────────────────────────────────────
// Directory scan
// ─────────────────────────────────────────────────────────────────────────────

std::vector<FileInfo> FileInfoCollector::scanDirectory(const fs::path& dir,
                                                       bool recursive,
                                                       bool computeHash) {
    std::vector<FileInfo> results;
    std::error_code ec;

    auto visit = [&](const fs::directory_entry& entry) {
        if (entry.is_regular_file(ec))
            results.push_back(collect(entry.path(), computeHash));
    };

    if (recursive) {
        for (auto& entry : fs::recursive_directory_iterator(dir, ec))
            visit(entry);
    } else {
        for (auto& entry : fs::directory_iterator(dir, ec))
            visit(entry);
    }

    // Sort by modified time (newest first)
    std::sort(results.begin(), results.end(),
        [](const FileInfo& a, const FileInfo& b) {
            return a.modifiedTime > b.modifiedTime;
        });

    return results;
}

} // namespace forensics
