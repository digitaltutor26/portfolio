#pragma once

#include "file_info.h"
#include "artifact_collector.h"
#include <string>
#include <vector>
#include <ostream>

namespace forensics {

enum class ReportFormat { Text, CSV, JSON };

struct TimelineEvent {
    std::time_t timestamp    = 0;
    std::string timestampStr;
    std::string eventType;   // Created / Modified / Accessed / Artifact
    std::string path;
    std::string description;
};

class Report {
public:
    static void writeFileInfo(std::ostream& out,
                              const FileInfo& fi,
                              ReportFormat fmt);

    static void writeFileInfoList(std::ostream& out,
                                  const std::vector<FileInfo>& files,
                                  ReportFormat fmt);

    static void writeArtifacts(std::ostream& out,
                                const std::vector<Artifact>& artifacts,
                                ReportFormat fmt);

    static void writeTimeline(std::ostream& out,
                               const std::vector<TimelineEvent>& events,
                               ReportFormat fmt);

    static std::vector<TimelineEvent> buildTimeline(
        const std::vector<FileInfo>&    files,
        const std::vector<Artifact>&    artifacts);

    static ReportFormat parseFormat(const std::string& str);

private:
    static std::string csvEscape(const std::string& s);
    static std::string jsonEscape(const std::string& s);
    static std::string jsonString(const std::string& s);
};

} // namespace forensics
