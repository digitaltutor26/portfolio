#pragma once
#include <QWidget>
#include "worker.h"

class QLineEdit; class QCheckBox; class QPushButton;
class QProgressBar; class QLabel; class QTableWidget; class QThread;

class AnalyzeTab : public QWidget {
    Q_OBJECT
public:
    explicit AnalyzeTab(QWidget* parent = nullptr);
private slots:
    void onBrowse(); void onAnalyze(); void onFinished();
    void onError(QString msg); void onStatus(QString msg);
    void onExportCsv(); void onExportJson();
private:
    void setupUi();
    void populateTable(const std::vector<forensics::FileInfo>& files);
    void setRunning(bool running);
    QLineEdit* m_pathEdit; QCheckBox* m_hashCheck; QCheckBox* m_recursiveCheck;
    QPushButton* m_browseBtn; QPushButton* m_analyzeBtn;
    QProgressBar* m_progress; QLabel* m_statusLabel; QTableWidget* m_table;
    QPushButton* m_exportCsvBtn; QPushButton* m_exportJsonBtn;
    forensics::AnalyzeWorker* m_worker = nullptr; QThread* m_thread = nullptr;
};
