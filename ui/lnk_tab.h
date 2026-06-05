#pragma once
#include <QWidget>
#include "worker.h"

class QLineEdit; class QPushButton; class QProgressBar;
class QLabel; class QTableWidget; class QSplitter; class QThread;

class LnkTab : public QWidget {
    Q_OBJECT
public:
    explicit LnkTab(QWidget* parent = nullptr);
private slots:
    void onBrowseLnk(); void onBrowseMft(); void onAnalyze(); void onFinished();
    void onError(QString msg); void onStatus(QString msg);
    void onExportCsv(); void onExportJson(); void onLnkSelectionChanged();
private:
    void setupUi();
    void populateLnkTable(const std::vector<forensics::LnkAnalysis>& results);
    void populateMftTable(const forensics::LnkAnalysis& analysis);
    void setRunning(bool running);
    QLineEdit* m_lnkPathEdit; QLineEdit* m_mftPathEdit;
    QPushButton* m_browseLnkBtn; QPushButton* m_browseMftBtn; QPushButton* m_analyzeBtn;
    QProgressBar* m_progress; QLabel* m_statusLabel;
    QTableWidget* m_lnkTable; QTableWidget* m_mftTable;
    QPushButton* m_exportCsvBtn; QPushButton* m_exportJsonBtn;
    forensics::LnkWorker* m_worker = nullptr; QThread* m_thread = nullptr;
    std::vector<forensics::LnkAnalysis> m_results;
};
