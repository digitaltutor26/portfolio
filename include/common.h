#pragma once

#include <string>
#include <cstdint>
#include <ctime>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace forensics {

namespace fs = std::filesystem;

std::string formatTimestamp(std::time_t t);
std::string bytesToHex(const uint8_t* data, size_t len);

#ifdef _WIN32
std::string      wstringToString(const std::wstring& ws);
std::time_t      filetimeToTimet(const FILETIME& ft);
std::string      filetimeToString(const FILETIME& ft);
std::string      expandEnvVar(const std::string& path);
#endif

} // namespace forensics
