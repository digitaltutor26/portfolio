#include "report.h"
#include "common.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace forensics {

// ─────────────────────────────────────────────────────────────────────────────
// String helpers
// ─────────────────────────────────────────────────────────────────────────────

std::string Report::csvEscape(const std::string& s) {
    bool needQuote = s.find_first_of(",\"\r\n") != std::string::npos;
    if (!needQuote) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else          out += c;
    }
    out += '"';
    return out;
}

std::string Report::jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

std::string Report::jsonString(const std::string& s) {
    return "\"" + jsonEscape(s) + "\"";
}

ReportFormat Report::parseFormat(const std::string& str) {
    if (str == "csv")  return ReportFormat::CSV;
    if (str == "json") return ReportFormat::JSON;
    return ReportFormat::Text;
}

// ─────────────────────────────────────────────────────────────────────────────
// FileInfo output
// ─────────────────────────────────────────────────────────────────────────────

void Report::writeFileInfo(std::ostream& out, const FileInfo& fi, ReportFormat fmt) {
    auto cat = FileInfoCollector::categoryName(fi.category);
    switch (fmt) {
    case ReportFormat::Text:
        out << "Path     : " << fi.path      << "\n"
            << "Name     : " << fi.name      << "\n"
            << "Size     : " << fi.size << " bytes\n"
            << "Category : " << cat          << "\n"
            << "Magic    : " << fi.magic     << "\n"
            << "Created  : " << fi.created   << "\n"
            << "Modified : " << fi.modified  << "\n"
            << "Accessed : " << fi.accessed  << "\n"
            << "Hidden   : " << (fi.isHidden   ? "Yes" : "No") << "\n"
            << "System   : " << (fi.isSystem   ? "Yes" : "No") << "\n"
            << "ReadOnly : " << (fi.isReadOnly ? "Yes" : "No") << "\n";
        if (!fi.md5.empty())
            out << "MD5      : " << fi.md5    << "\n"
                << "SHA256   : " << fi.sha256 << "\n";
        out << "\n";
        break;

    case ReportFormat::CSV:
        out << csvEscape(fi.path)     << ","
            << csvEscape(fi.name)     << ","
            << fi.size                << ","
            << csvEscape(cat)         << ","
            << csvEscape(fi.magic)    << ","
            << csvEscape(fi.created)  << ","
            << csvEscape(fi.modified) << ","
            << csvEscape(fi.accessed) << ","
            << (fi.isHidden   ? "1" : "0") << ","
            << (fi.isSystem   ? "1" : "0") << ","
            << (fi.isReadOnly ? "1" : "0") << ","
            << csvEscape(fi.md5)      << ","
            << csvEscape(fi.sha256)   << "\n";
        break;

    case ReportFormat::JSON:
        out << "  {\n"
            << "    \"path\":"     << jsonString(fi.path)     << ",\n"
            << "    \"name\":"     << jsonString(fi.name)     << ",\n"
            << "    \"size\":"     << fi.size                 << ",\n"
            << "    \"category\":" << jsonString(cat)         << ",\n"
            << "    \"magic\":"    << jsonString(fi.magic)    << ",\n"
            << "    \"created\":"  << jsonString(fi.created)  << ",\n"
            << "    \"modified\":" << jsonString(fi.modified) << ",\n"
            << "    \"accessed\":" << jsonString(fi.accessed) << ",\n"
            << "    \"hidden\":"   << (fi.isHidden   ? "true" : "false") << ",\n"
            << "    \"system\":"   << (fi.isSystem   ? "true" : "false") << ",\n"
            << "    \"readonly\":" << (fi.isReadOnly ? "true" : "false") << ",\n"
            << "    \"md5\":"      << jsonString(fi.md5)      << ",\n"
            << "    \"sha256\":"   << jsonString(fi.sha256)   << "\n"
            << "  }";
        break;
    }
}

void Report::writeFileInfoList(std::ostream& out,
                               const std::vector<FileInfo>& files,
                               ReportFormat fmt) {
    if (fmt == ReportFormat::Text) {
        out << "=== File Analysis Report ===\n"
            << "Total files: " << files.size() << "\n\n";
        for (auto& fi : files) writeFileInfo(out, fi, fmt);
        return;
    }
    if (fmt == ReportFormat::CSV) {
        out << "Path,Name,Size,Category,Magic,Created,Modified,Accessed,"
               "Hidden,System,ReadOnly,MD5,SHA256\n";
        for (auto& fi : files) writeFileInfo(out, fi, fmt);
        return;
    }
    // JSON
    out << "[\n";
    for (size_t i = 0; i < files.size(); ++i) {
        writeFileInfo(out, files[i], fmt);
        if (i + 1 < files.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Artifact output
// ─────────────────────────────────────────────────────────────────────────────

void Report::writeArtifacts(std::ostream& out,
                             const std::vector<Artifact>& artifacts,
                             ReportFormat fmt) {
    if (artifacts.empty()) {
        if (fmt == ReportFormat::Text)
            out << "No artifacts collected (Windows required).\n";
        else if (fmt == ReportFormat::JSON)
            out << "[]\n";
        return;
    }

    if (fmt == ReportFormat::Text) {
        out << "=== Windows Artifact Report ===\n"
            << "Total artifacts: " << artifacts.size() << "\n\n";
        for (auto& a : artifacts) {
            out << "[" << a.typeName << "]\n"
                << "  Name      : " << a.name        << "\n"
                << "  Path      : " << a.path        << "\n"
                << "  Timestamp : " << a.timestampStr << "\n"
                << "  Size      : " << a.size        << " bytes\n"
                << "  Info      : " << a.description << "\n\n";
        }
        return;
    }
    if (fmt == ReportFormat::CSV) {
        out << "Type,Name,Path,Timestamp,Size,Description\n";
        for (auto& a : artifacts) {
            out << csvEscape(a.typeName)    << ","
                << csvEscape(a.name)        << ","
                << csvEscape(a.path)        << ","
                << csvEscape(a.timestampStr)<< ","
                << a.size                   << ","
                << csvEscape(a.description) << "\n";
        }
        return;
    }
    // JSON
    out << "[\n";
    for (size_t i = 0; i < artifacts.size(); ++i) {
        auto& a = artifacts[i];
        out << "  {\n"
            << "    \"type\":"        << jsonString(a.typeName)    << ",\n"
            << "    \"name\":"        << jsonString(a.name)        << ",\n"
            << "    \"path\":"        << jsonString(a.path)        << ",\n"
            << "    \"timestamp\":"   << jsonString(a.timestampStr)<< ",\n"
            << "    \"size\":"        << a.size                    << ",\n"
            << "    \"description\":" << jsonString(a.description) << "\n"
            << "  }";
        if (i + 1 < artifacts.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeline
// ─────────────────────────────────────────────────────────────────────────────

std::vector<TimelineEvent> Report::buildTimeline(
    const std::vector<FileInfo>&  files,
    const std::vector<Artifact>&  artifacts)
{
    std::vector<TimelineEvent> events;

    for (auto& fi : files) {
        if (fi.createdTime > 0)
            events.push_back({fi.createdTime,
                              formatTimestamp(fi.createdTime),
                              "Created",  fi.path, fi.name});
        if (fi.modifiedTime > 0 && fi.modifiedTime != fi.createdTime)
            events.push_back({fi.modifiedTime,
                              formatTimestamp(fi.modifiedTime),
                              "Modified", fi.path, fi.name});
        if (fi.accessedTime > 0 && fi.accessedTime != fi.modifiedTime)
            events.push_back({fi.accessedTime,
                              formatTimestamp(fi.accessedTime),
                              "Accessed", fi.path, fi.name});
    }

    for (auto& a : artifacts) {
        if (a.timestamp > 0)
            events.push_back({a.timestamp, a.timestampStr,
                              a.typeName, a.path, a.description});
    }

    std::sort(events.begin(), events.end(),
        [](const TimelineEvent& a, const TimelineEvent& b) {
            return a.timestamp > b.timestamp; // newest first
        });
    return events;
}

void Report::writeTimeline(std::ostream& out,
                            const std::vector<TimelineEvent>& events,
                            ReportFormat fmt) {
    if (fmt == ReportFormat::Text) {
        out << "=== Activity Timeline ===\n"
            << "Events: " << events.size() << "\n\n";
        for (auto& e : events) {
            out << e.timestampStr
                << "  [" << std::setw(10) << std::left << e.eventType << "]  "
                << e.description << "\n"
                << "           -> " << e.path << "\n";
        }
        return;
    }
    if (fmt == ReportFormat::CSV) {
        out << "Timestamp,EventType,Path,Description\n";
        for (auto& e : events) {
            out << csvEscape(e.timestampStr) << ","
                << csvEscape(e.eventType)    << ","
                << csvEscape(e.path)         << ","
                << csvEscape(e.description)  << "\n";
        }
        return;
    }
    // JSON
    out << "[\n";
    for (size_t i = 0; i < events.size(); ++i) {
        auto& e = events[i];
        out << "  {\n"
            << "    \"timestamp\":"   << jsonString(e.timestampStr) << ",\n"
            << "    \"event_type\":"  << jsonString(e.eventType)    << ",\n"
            << "    \"path\":"        << jsonString(e.path)         << ",\n"
            << "    \"description\":" << jsonString(e.description)  << "\n"
            << "  }";
        if (i + 1 < events.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
}

} // namespace forensics
