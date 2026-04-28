#include "common.h"

#include <sstream>
#include <iomanip>
#include <cstring>

namespace forensics {

std::string formatTimestamp(std::time_t t) {
    if (t <= 0) return "N/A";
    char buf[32];
    struct tm* tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

std::string bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    return oss.str();
}

#ifdef _WIN32

std::string wstringToString(const std::wstring& ws) {
    if (ws.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                 nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return {};
    std::string result(sz - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                        result.data(), sz, nullptr, nullptr);
    return result;
}

std::time_t filetimeToTimet(const FILETIME& ft) {
    ULARGE_INTEGER ull;
    ull.LowPart  = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    // FILETIME: 100-nanosecond intervals since 1601-01-01
    // Subtract epoch offset between 1601 and 1970
    if (ull.QuadPart < 116444736000000000ULL) return 0;
    return static_cast<std::time_t>(
        (ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

std::string filetimeToString(const FILETIME& ft) {
    return formatTimestamp(filetimeToTimet(ft));
}

std::string expandEnvVar(const std::string& path) {
    std::wstring wpath(path.begin(), path.end());
    wchar_t expanded[MAX_PATH] = {};
    DWORD ret = ExpandEnvironmentStringsW(wpath.c_str(), expanded, MAX_PATH);
    if (ret > 0 && ret <= MAX_PATH)
        return wstringToString(expanded);
    return path;
}

#endif // _WIN32

} // namespace forensics
