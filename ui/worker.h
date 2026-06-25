#pragma once
#include <QObject>
#include <QString>
#include "file_info.h"
#include "artifact_collector.h"
#include "report.h"
#include "lnk_parser.h"
#include "mft_parser.h"
#include <vector>

namespace forensics {

class AnalyzeWorker : public QObject {
    Q_OBJECT
public:
    QString path;
    bool    recursive   = false;
    bool    computeHash = false;
    std::vector<FileInfo> results;
public slots:
    void run();
signals:
    void finished();
    void error(QString msg);
    void status(QString msg);
};

class ArtifactsWorker : public QObject {
    Q_OBJECT
public:
    bool recent    = false;
    bool prefetch  = false;
    bool temp      = false;
    bool downloads = false;
    std::vector<Artifact> results;
public slots:
    void run();
signals:
    void finished();
    void error(QString msg);
    void status(QString msg);
};

class TimelineWorker : public QObject {
    Q_OBJECT
public:
    QString path;
    bool    recursive   = false;
    bool    computeHash = false;
    bool    recent      = false;
    bool    prefetch    = false;
    bool    temp        = false;
    bool    downloads   = false;
    std::vector<TimelineEvent> results;
public slots:
    void run();
signals:
    void finished();
    void error(QString msg);
    void status(QString msg);
};

class LnkWorker : public QObject {
    Q_OBJECT
public:
    QString lnkPath;
    QString mftPath;
    std::vector<LnkAnalysis> results;
public slots:
    void run();
signals:
    void finished();
    void error(QString msg);
    void status(QString msg);
};

} // namespace forensics
