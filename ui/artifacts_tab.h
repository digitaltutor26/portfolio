#pragma once
#include <QWidget>
#include "worker.h"

class QCheckBox; class QPushButton; class QProgressBar;
class QLabel; class QTableWidget; class QThread;

class ArtifactsTab : public QWidget {
    Q_OBJECT
public:
    explicit ArtifactsTab(QWidget* parent = nullptr);
private slots:
    void onCollect(); void onFinished();
    void onError(QString msg); void onStatus(QString msg);
    void onExportCsv(); void onExportJson();
private:
    void setupUi();
    void populateTable(const std::vector<forensics::Artifact>& artifacts);
    void setRunning(bool running);
    QCheckBox* m_recentCheck; QCheckBox* m_prefetchCheck;
    QCheckBox* m_tempCheck; QCheckBox* m_downloadsCheck;
    QPushButton* m_collectBtn; QProgressBar* m_progress;
    QLabel* m_statusLabel; QTableWidget* m_table;
    QPushButton* m_exportCsvBtn; QPushButton* m_exportJsonBtn;
    forensics::ArtifactsWorker* m_worker = nullptr; QThread* m_thread = nullptr;
};
