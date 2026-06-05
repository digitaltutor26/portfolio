#pragma once
#include <QWidget>
#include "worker.h"

class QLineEdit; class QCheckBox; class QPushButton;
class QProgressBar; class QLabel; class QTableWidget; class QThread;

class TimelineTab : public QWidget {
    Q_OBJECT
public:
    explicit TimelineTab(QWidget* parent = nullptr);
private slots:
    void onBrowse(); void onGenerate(); void onFinished();
    void onError(QString msg); void onStatus(QString msg);
    void onExportCsv(); void onExportJson();
private:
    void setupUi();
    void populateTable(const std::vector<forensics::TimelineEvent>& events);
    void setRunning(bool running);
    QLineEdit* m_pathEdit; QCheckBox* m_hashCheck; QCheckBox* m_recursiveCheck;
    QCheckBox* m_recentCheck; QCheckBox* m_prefetchCheck;
    QCheckBox* m_tempCheck; QCheckBox* m_downloadsCheck;
    QPushButton* m_browseBtn; QPushButton* m_generateBtn;
    QProgressBar* m_progress; QLabel* m_statusLabel; QTableWidget* m_table;
    QPushButton* m_exportCsvBtn; QPushButton* m_exportJsonBtn;
    forensics::TimelineWorker* m_worker = nullptr; QThread* m_thread = nullptr;
};
