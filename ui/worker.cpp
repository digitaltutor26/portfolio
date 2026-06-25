#include "worker.h"
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

namespace forensics {

void AnalyzeWorker::run() {
    try {
        emit status(QStringLiteral("분석 중..."));
        fs::path p(path.toStdString());
        std::error_code ec;
        if (fs::is_regular_file(p, ec))
            results.push_back(FileInfoCollector::collect(p, computeHash));
        else if (fs::is_directory(p, ec))
            results = FileInfoCollector::scanDirectory(p, recursive, computeHash);
        emit status(QStringLiteral("완료: %1개 파일").arg(results.size()));
    } catch (const std::exception& e) { emit error(QString::fromStdString(e.what())); return; }
    emit finished();
}

void ArtifactsWorker::run() {
    try {
        emit status(QStringLiteral("아티팩트 수집 중..."));
        bool all = !recent && !prefetch && !temp && !downloads;
        auto append = [&](std::vector<Artifact> v) {
            results.insert(results.end(), std::make_move_iterator(v.begin()), std::make_move_iterator(v.end()));
        };
        if (all || recent)    append(ArtifactCollector::collectRecentFiles());
        if (all || prefetch)  append(ArtifactCollector::collectPrefetch());
        if (all || temp)      append(ArtifactCollector::collectTempFiles());
        if (all || downloads) append(ArtifactCollector::collectDownloads());
        std::sort(results.begin(), results.end(), [](const Artifact& a, const Artifact& b){ return a.timestamp > b.timestamp; });
        emit status(QStringLiteral("완료: %1개 아티팩트").arg(results.size()));
    } catch (const std::exception& e) { emit error(QString::fromStdString(e.what())); return; }
    emit finished();
}

void TimelineWorker::run() {
    try {
        emit status(QStringLiteral("타임라인 생성 중..."));
        std::vector<FileInfo> files;
        if (!path.isEmpty()) {
            fs::path p(path.toStdString()); std::error_code ec;
            if (fs::is_regular_file(p, ec))    files.push_back(FileInfoCollector::collect(p, computeHash));
            else if (fs::is_directory(p, ec))  files = FileInfoCollector::scanDirectory(p, recursive, computeHash);
        }
        bool all = !recent && !prefetch && !temp && !downloads;
        std::vector<Artifact> artifacts;
        auto append = [&](std::vector<Artifact> v) {
            artifacts.insert(artifacts.end(), std::make_move_iterator(v.begin()), std::make_move_iterator(v.end()));
        };
        if (all || recent)    append(ArtifactCollector::collectRecentFiles());
        if (all || prefetch)  append(ArtifactCollector::collectPrefetch());
        if (all || temp)      append(ArtifactCollector::collectTempFiles());
        if (all || downloads) append(ArtifactCollector::collectDownloads());
        results = Report::buildTimeline(files, artifacts);
        emit status(QStringLiteral("완료: %1개 이벤트").arg(results.size()));
    } catch (const std::exception& e) { emit error(QString::fromStdString(e.what())); return; }
    emit finished();
}

void LnkWorker::run() {
    try {
        emit status(QStringLiteral("LNK 파일 파싱 중..."));
        std::vector<LnkInfo> lnkList;
        fs::path p(lnkPath.toStdString()); std::error_code ec;
        if (fs::is_regular_file(p, ec))      lnkList.push_back(LnkParser::parse(lnkPath.toStdString()));
        else if (fs::is_directory(p, ec))    lnkList = LnkParser::parseDirectory(lnkPath.toStdString());
        results.reserve(lnkList.size());
        for (auto& lnk : lnkList) {
            LnkAnalysis analysis;
            analysis.lnk = lnk;
            if (!mftPath.isEmpty() && lnk.success && !lnk.targetName.empty()) {
                emit status(QStringLiteral("$MFT 검색 중: %1").arg(QString::fromStdString(lnk.targetName)));
                analysis.mftRecords = MftParser::findByName(mftPath.toStdString(), lnk.targetName);
            }
            results.push_back(std::move(analysis));
        }
        emit status(QStringLiteral("완료: %1개 LNK 파일").arg(results.size()));
    } catch (const std::exception& e) { emit error(QString::fromStdString(e.what())); return; }
    emit finished();
}

} // namespace forensics
