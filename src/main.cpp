#include "file_info.h"
#include "artifact_collector.h"
#include "report.h"
#include "common.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cstring>

namespace fs = std::filesystem;
using namespace forensics;

// ─────────────────────────────────────────────────────────────────────────────
// CLI options
// ─────────────────────────────────────────────────────────────────────────────

struct Options {
    std::string  command;       // analyze | artifacts | timeline
    std::string  path;
    ReportFormat format      = ReportFormat::Text;
    std::string  outputFile;
    bool         recursive   = false;
    bool         computeHash = false;
    bool         recent      = false;
    bool         prefetch    = false;
    bool         temp        = false;
    bool         downloads   = false;
};

static void printHelp() {
    std::cout <<
"WinForensics v1.0 - Windows Digital Forensics Toolkit\n"
"\n"
"Usage:\n"
"  winforensics analyze  <path> [options]\n"
"  winforensics artifacts       [options]\n"
"  winforensics timeline <path> [options]\n"
"\n"
"Commands:\n"
"  analyze <path>   Analyze file or directory (metadata, hashes, categories)\n"
"  artifacts        Collect Windows computer activity artifacts\n"
"  timeline <path>  Build unified activity timeline from files + artifacts\n"
"\n"
"Options:\n"
"  --format <fmt>   Output format: text | csv | json   (default: text)\n"
"  --output <file>  Write report to file (default: stdout)\n"
"  --hash           Compute MD5 + SHA256 hashes        (analyze/timeline)\n"
"  --recursive      Scan subdirectories                (analyze/timeline)\n"
"  --recent         Collect Recent files               (artifacts/timeline)\n"
"  --prefetch       Collect Prefetch entries           (artifacts/timeline)\n"
"  --temp           Collect Temp files                 (artifacts/timeline)\n"
"  --downloads      Collect Downloads folder           (artifacts/timeline)\n"
"  --all            All artifact types                 (default for artifacts)\n"
"  --help           Show this help\n"
"\n"
"Examples:\n"
"  winforensics analyze C:\\Users\\John\\Desktop --hash --recursive\n"
"  winforensics artifacts --prefetch --recent --format csv --output report.csv\n"
"  winforensics timeline C:\\Users\\John --all --format json --output timeline.json\n";
}

static Options parseArgs(int argc, char* argv[]) {
    Options opts;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") { printHelp(); std::exit(0); }
        else if (arg == "analyze" || arg == "artifacts" || arg == "timeline") {
            opts.command = arg;
            // Next positional argument (if not a flag) is the path
            if (i + 1 < argc && argv[i+1][0] != '-')
                opts.path = argv[++i];
        }
        else if (arg == "--format" && i + 1 < argc)
            opts.format = Report::parseFormat(argv[++i]);
        else if (arg == "--output" && i + 1 < argc)
            opts.outputFile = argv[++i];
        else if (arg == "--hash")      opts.computeHash = true;
        else if (arg == "--recursive") opts.recursive   = true;
        else if (arg == "--recent")    opts.recent      = true;
        else if (arg == "--prefetch")  opts.prefetch    = true;
        else if (arg == "--temp")      opts.temp        = true;
        else if (arg == "--downloads") opts.downloads   = true;
        else if (arg == "--all") {
            opts.recent = opts.prefetch = opts.temp = opts.downloads = true;
        }
    }
    return opts;
}

// ─────────────────────────────────────────────────────────────────────────────
// Command handlers
// ─────────────────────────────────────────────────────────────────────────────

static int cmdAnalyze(std::ostream& out, const Options& opts) {
    if (opts.path.empty()) {
        std::cerr << "Error: 'analyze' requires a path.\n";
        return 1;
    }
    fs::path p(opts.path);
    std::error_code ec;
    if (!fs::exists(p, ec)) {
        std::cerr << "Error: path not found: " << opts.path << "\n";
        return 1;
    }

    if (fs::is_regular_file(p, ec)) {
        auto fi = FileInfoCollector::collect(p, opts.computeHash);
        Report::writeFileInfo(out, fi, opts.format);
    } else if (fs::is_directory(p, ec)) {
        auto files = FileInfoCollector::scanDirectory(p, opts.recursive,
                                                      opts.computeHash);
        Report::writeFileInfoList(out, files, opts.format);
    } else {
        std::cerr << "Error: path is not a file or directory.\n";
        return 1;
    }
    return 0;
}

static int cmdArtifacts(std::ostream& out, const Options& opts) {
    // Default: collect all artifact types when none specified
    bool collectAll = !opts.recent && !opts.prefetch &&
                      !opts.temp   && !opts.downloads;

    std::vector<Artifact> artifacts;
    auto append = [&](std::vector<Artifact> v) {
        artifacts.insert(artifacts.end(),
                         std::make_move_iterator(v.begin()),
                         std::make_move_iterator(v.end()));
    };

    if (collectAll || opts.recent)    append(ArtifactCollector::collectRecentFiles());
    if (collectAll || opts.prefetch)  append(ArtifactCollector::collectPrefetch());
    if (collectAll || opts.temp)      append(ArtifactCollector::collectTempFiles());
    if (collectAll || opts.downloads) append(ArtifactCollector::collectDownloads());

    std::sort(artifacts.begin(), artifacts.end(),
        [](const Artifact& a, const Artifact& b) {
            return a.timestamp > b.timestamp;
        });

    Report::writeArtifacts(out, artifacts, opts.format);
    return 0;
}

static int cmdTimeline(std::ostream& out, const Options& opts) {
    // Collect file info
    std::vector<FileInfo> files;
    if (!opts.path.empty()) {
        fs::path p(opts.path);
        std::error_code ec;
        if (!fs::exists(p, ec)) {
            std::cerr << "Error: path not found: " << opts.path << "\n";
            return 1;
        }
        if (fs::is_regular_file(p, ec))
            files.push_back(FileInfoCollector::collect(p, opts.computeHash));
        else if (fs::is_directory(p, ec))
            files = FileInfoCollector::scanDirectory(p, opts.recursive,
                                                     opts.computeHash);
    }

    // Collect artifacts
    bool collectAll = !opts.recent && !opts.prefetch &&
                      !opts.temp   && !opts.downloads;
    std::vector<Artifact> artifacts;
    auto append = [&](std::vector<Artifact> v) {
        artifacts.insert(artifacts.end(),
                         std::make_move_iterator(v.begin()),
                         std::make_move_iterator(v.end()));
    };
    if (collectAll || opts.recent)    append(ArtifactCollector::collectRecentFiles());
    if (collectAll || opts.prefetch)  append(ArtifactCollector::collectPrefetch());
    if (collectAll || opts.temp)      append(ArtifactCollector::collectTempFiles());
    if (collectAll || opts.downloads) append(ArtifactCollector::collectDownloads());

    auto timeline = Report::buildTimeline(files, artifacts);
    Report::writeTimeline(out, timeline, opts.format);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp();
        return 1;
    }

    Options opts = parseArgs(argc, argv);

    if (opts.command.empty()) {
        std::cerr << "Error: no command specified.\n\n";
        printHelp();
        return 1;
    }

    // Set up output stream
    std::ostream*  out = &std::cout;
    std::ofstream  outFile;
    if (!opts.outputFile.empty()) {
        outFile.open(opts.outputFile);
        if (!outFile) {
            std::cerr << "Error: cannot write to: " << opts.outputFile << "\n";
            return 1;
        }
        out = &outFile;
    }

    if      (opts.command == "analyze")   return cmdAnalyze(*out, opts);
    else if (opts.command == "artifacts") return cmdArtifacts(*out, opts);
    else if (opts.command == "timeline")  return cmdTimeline(*out, opts);

    std::cerr << "Error: unknown command '" << opts.command << "'\n";
    return 1;
}
