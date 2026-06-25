#include "analyze_tab.h"
#include "file_info.h"
#include "report.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QProgressBar>
#include <QLabel>
#include <QTableWidget>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QThread>
#include <fstream>
using namespace forensics;

AnalyzeTab::AnalyzeTab(QWidget* parent) : QWidget(parent) { setupUi(); }

void AnalyzeTab::setupUi() {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(8,8,8,8); root->setSpacing(6);
    auto* pathRow = new QHBoxLayout;
    pathRow->addWidget(new QLabel(QStringLiteral("경로:")));
    m_pathEdit = new QLineEdit; m_pathEdit->setPlaceholderText(QStringLiteral("파일 또는 폴더 경로..."));
    pathRow->addWidget(m_pathEdit);
    m_browseBtn = new QPushButton(QStringLiteral("찾아보기...")); pathRow->addWidget(m_browseBtn);
    root->addLayout(pathRow);
    auto* optRow = new QHBoxLayout;
    m_hashCheck      = new QCheckBox(QStringLiteral("해시 계산 (MD5+SHA256)"));
    m_recursiveCheck = new QCheckBox(QStringLiteral("재귀 탐색"));
    m_analyzeBtn     = new QPushButton(QStringLiteral("분석 시작")); m_analyzeBtn->setDefault(true);
    optRow->addWidget(m_hashCheck); optRow->addWidget(m_recursiveCheck);
    optRow->addStretch(); optRow->addWidget(m_analyzeBtn);
    root->addLayout(optRow);
    m_progress = new QProgressBar; m_progress->setRange(0,0); m_progress->setVisible(false);
    root->addWidget(m_progress);
    m_statusLabel = new QLabel(QStringLiteral("준비")); root->addWidget(m_statusLabel);
    m_table = new QTableWidget(0, 12);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("파일명"), QStringLiteral("크기(B)"), QStringLiteral("카테고리"),
        QStringLiteral("매직"), QStringLiteral("생성"), QStringLiteral("수정"), QStringLiteral("접근"),
        QStringLiteral("숨김"), QStringLiteral("시스템"), QStringLiteral("읽기전용"),
        QStringLiteral("MD5"), QStringLiteral("SHA256")
    });
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true);
    root->addWidget(m_table);
    auto* exportRow = new QHBoxLayout;
    m_exportCsvBtn  = new QPushButton(QStringLiteral("CSV 저장")); m_exportCsvBtn->setEnabled(false);
    m_exportJsonBtn = new QPushButton(QStringLiteral("JSON 저장")); m_exportJsonBtn->setEnabled(false);
    exportRow->addStretch(); exportRow->addWidget(m_exportCsvBtn); exportRow->addWidget(m_exportJsonBtn);
    root->addLayout(exportRow);
    connect(m_browseBtn,    &QPushButton::clicked, this, &AnalyzeTab::onBrowse);
    connect(m_analyzeBtn,   &QPushButton::clicked, this, &AnalyzeTab::onAnalyze);
    connect(m_exportCsvBtn, &QPushButton::clicked, this, &AnalyzeTab::onExportCsv);
    connect(m_exportJsonBtn,&QPushButton::clicked, this, &AnalyzeTab::onExportJson);
}

void AnalyzeTab::onBrowse() {
    QString path = QFileDialog::getExistingDirectory(this,QStringLiteral("폴더 선택"),{},QFileDialog::ShowDirsOnly);
    if (path.isEmpty()) path = QFileDialog::getOpenFileName(this,QStringLiteral("파일 선택"));
    if (!path.isEmpty()) m_pathEdit->setText(path);
}

void AnalyzeTab::onAnalyze() {
    if (m_pathEdit->text().trimmed().isEmpty()) { QMessageBox::warning(this,QStringLiteral("경고"),QStringLiteral("경로를 입력하세요.")); return; }
    if (m_thread && m_thread->isRunning()) return;
    m_table->setRowCount(0); m_exportCsvBtn->setEnabled(false); m_exportJsonBtn->setEnabled(false);
    m_worker = new AnalyzeWorker;
    m_worker->path = m_pathEdit->text().trimmed();
    m_worker->recursive = m_recursiveCheck->isChecked();
    m_worker->computeHash = m_hashCheck->isChecked();
    m_thread = new QThread(this);
    m_worker->moveToThread(m_thread);
    connect(m_thread,&QThread::started,        m_worker,&AnalyzeWorker::run);
    connect(m_worker,&AnalyzeWorker::finished, this,    &AnalyzeTab::onFinished);
    connect(m_worker,&AnalyzeWorker::error,    this,    &AnalyzeTab::onError);
    connect(m_worker,&AnalyzeWorker::status,   this,    &AnalyzeTab::onStatus);
    connect(m_worker,&AnalyzeWorker::finished, m_thread,&QThread::quit);
    connect(m_thread,&QThread::finished,       m_worker,&QObject::deleteLater);
    connect(m_thread,&QThread::finished,       m_thread,&QObject::deleteLater);
    setRunning(true); m_thread->start();
}

void AnalyzeTab::onFinished() {
    populateTable(m_worker->results); setRunning(false);
    m_exportCsvBtn->setEnabled(m_table->rowCount()>0);
    m_exportJsonBtn->setEnabled(m_table->rowCount()>0);
}
void AnalyzeTab::onError(QString msg)  { setRunning(false); QMessageBox::critical(this,QStringLiteral("오류"),msg); }
void AnalyzeTab::onStatus(QString msg) { m_statusLabel->setText(msg); }

void AnalyzeTab::populateTable(const std::vector<FileInfo>& files) {
    m_table->setSortingEnabled(false);
    m_table->setRowCount(static_cast<int>(files.size()));
    for (int r = 0; r < static_cast<int>(files.size()); ++r) {
        const auto& f = files[r];
        auto set = [&](int col, const QString& val) { m_table->setItem(r,col,new QTableWidgetItem(val)); };
        set(0, QString::fromStdString(f.name)); set(1, QString::number(f.size));
        set(2, QString::fromStdString(FileInfoCollector::categoryName(f.category)));
        set(3, QString::fromStdString(f.magic)); set(4, QString::fromStdString(f.created));
        set(5, QString::fromStdString(f.modified)); set(6, QString::fromStdString(f.accessed));
        set(7, f.isHidden?QStringLiteral("예"):QStringLiteral("아니오"));
        set(8, f.isSystem?QStringLiteral("예"):QStringLiteral("아니오"));
        set(9, f.isReadOnly?QStringLiteral("예"):QStringLiteral("아니오"));
        set(10,QString::fromStdString(f.md5)); set(11,QString::fromStdString(f.sha256));
        m_table->item(r,0)->setToolTip(QString::fromStdString(f.path));
    }
    m_table->setSortingEnabled(true); m_table->resizeColumnsToContents();
}

void AnalyzeTab::setRunning(bool running) {
    m_analyzeBtn->setEnabled(!running); m_browseBtn->setEnabled(!running);
    m_progress->setVisible(running);
}

void AnalyzeTab::onExportCsv() {
    if (!m_worker) return;
    QString path = QFileDialog::getSaveFileName(this,QStringLiteral("CSV 저장"),QStringLiteral("analyze_report.csv"),QStringLiteral("CSV (*.csv)"));
    if (path.isEmpty()) return;
    std::ofstream f(path.toStdString());
    if (!f) { QMessageBox::critical(this,QStringLiteral("오류"),QStringLiteral("저장 실패")); return; }
    Report::writeFileInfoList(f, m_worker->results, ReportFormat::CSV);
    m_statusLabel->setText(QStringLiteral("CSV 저장: ") + path);
}

void AnalyzeTab::onExportJson() {
    if (!m_worker) return;
    QString path = QFileDialog::getSaveFileName(this,QStringLiteral("JSON 저장"),QStringLiteral("analyze_report.json"),QStringLiteral("JSON (*.json)"));
    if (path.isEmpty()) return;
    std::ofstream f(path.toStdString());
    if (!f) { QMessageBox::critical(this,QStringLiteral("오류"),QStringLiteral("저장 실패")); return; }
    Report::writeFileInfoList(f, m_worker->results, ReportFormat::JSON);
    m_statusLabel->setText(QStringLiteral("JSON 저장: ") + path);
}
