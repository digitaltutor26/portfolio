#include "artifacts_tab.h"
#include "report.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
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

ArtifactsTab::ArtifactsTab(QWidget* parent) : QWidget(parent) { setupUi(); }

void ArtifactsTab::setupUi() {
    auto* root = new QVBoxLayout(this); root->setContentsMargins(8,8,8,8); root->setSpacing(6);
    auto* grp = new QGroupBox(QStringLiteral("수집 항목")); auto* optRow = new QHBoxLayout(grp);
    m_recentCheck    = new QCheckBox(QStringLiteral("Recent")); m_recentCheck->setChecked(true);
    m_prefetchCheck  = new QCheckBox(QStringLiteral("Prefetch")); m_prefetchCheck->setChecked(true);
    m_tempCheck      = new QCheckBox(QStringLiteral("Temp")); m_tempCheck->setChecked(true);
    m_downloadsCheck = new QCheckBox(QStringLiteral("Downloads")); m_downloadsCheck->setChecked(true);
    m_collectBtn     = new QPushButton(QStringLiteral("수집 시작")); m_collectBtn->setDefault(true);
    optRow->addWidget(m_recentCheck); optRow->addWidget(m_prefetchCheck);
    optRow->addWidget(m_tempCheck); optRow->addWidget(m_downloadsCheck);
    optRow->addStretch(); optRow->addWidget(m_collectBtn);
    root->addWidget(grp);
    m_progress = new QProgressBar; m_progress->setRange(0,0); m_progress->setVisible(false);
    root->addWidget(m_progress);
    m_statusLabel = new QLabel(QStringLiteral("준비  (Windows에서만 실제 데이터 수집)")); root->addWidget(m_statusLabel);
    m_table = new QTableWidget(0, 6);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("종류"), QStringLiteral("이름"), QStringLiteral("경로"),
        QStringLiteral("시각"), QStringLiteral("크기(B)"), QStringLiteral("설명")
    });
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true); root->addWidget(m_table);
    auto* exportRow = new QHBoxLayout;
    m_exportCsvBtn  = new QPushButton(QStringLiteral("CSV 저장")); m_exportCsvBtn->setEnabled(false);
    m_exportJsonBtn = new QPushButton(QStringLiteral("JSON 저장")); m_exportJsonBtn->setEnabled(false);
    exportRow->addStretch(); exportRow->addWidget(m_exportCsvBtn); exportRow->addWidget(m_exportJsonBtn);
    root->addLayout(exportRow);
    connect(m_collectBtn,   &QPushButton::clicked, this, &ArtifactsTab::onCollect);
    connect(m_exportCsvBtn, &QPushButton::clicked, this, &ArtifactsTab::onExportCsv);
    connect(m_exportJsonBtn,&QPushButton::clicked, this, &ArtifactsTab::onExportJson);
}

void ArtifactsTab::onCollect() {
    if (m_thread && m_thread->isRunning()) return;
    m_table->setRowCount(0); m_exportCsvBtn->setEnabled(false); m_exportJsonBtn->setEnabled(false);
    m_worker = new ArtifactsWorker;
    m_worker->recent=m_recentCheck->isChecked(); m_worker->prefetch=m_prefetchCheck->isChecked();
    m_worker->temp=m_tempCheck->isChecked(); m_worker->downloads=m_downloadsCheck->isChecked();
    m_thread = new QThread(this); m_worker->moveToThread(m_thread);
    connect(m_thread,&QThread::started,           m_worker,&ArtifactsWorker::run);
    connect(m_worker,&ArtifactsWorker::finished,  this,    &ArtifactsTab::onFinished);
    connect(m_worker,&ArtifactsWorker::error,     this,    &ArtifactsTab::onError);
    connect(m_worker,&ArtifactsWorker::status,    this,    &ArtifactsTab::onStatus);
    connect(m_worker,&ArtifactsWorker::finished,  m_thread,&QThread::quit);
    connect(m_thread,&QThread::finished,          m_worker,&QObject::deleteLater);
    connect(m_thread,&QThread::finished,          m_thread,&QObject::deleteLater);
    setRunning(true); m_thread->start();
}

void ArtifactsTab::onFinished() {
    populateTable(m_worker->results); setRunning(false);
    m_exportCsvBtn->setEnabled(m_table->rowCount()>0);
    m_exportJsonBtn->setEnabled(m_table->rowCount()>0);
}
void ArtifactsTab::onError(QString msg)  { setRunning(false); QMessageBox::critical(this,QStringLiteral("오류"),msg); }
void ArtifactsTab::onStatus(QString msg) { m_statusLabel->setText(msg); }

void ArtifactsTab::populateTable(const std::vector<Artifact>& artifacts) {
    m_table->setSortingEnabled(false);
    m_table->setRowCount(static_cast<int>(artifacts.size()));
    for (int r=0; r<static_cast<int>(artifacts.size()); ++r) {
        const auto& a = artifacts[r];
        auto set = [&](int col, const QString& val){ m_table->setItem(r,col,new QTableWidgetItem(val)); };
        set(0,QString::fromStdString(a.typeName)); set(1,QString::fromStdString(a.name));
        set(2,QString::fromStdString(a.path));     set(3,QString::fromStdString(a.timestampStr));
        set(4,QString::number(a.size));            set(5,QString::fromStdString(a.description));
    }
    m_table->setSortingEnabled(true); m_table->resizeColumnsToContents();
}

void ArtifactsTab::setRunning(bool running) { m_collectBtn->setEnabled(!running); m_progress->setVisible(running); }

void ArtifactsTab::onExportCsv() {
    if (!m_worker) return;
    QString path = QFileDialog::getSaveFileName(this,QStringLiteral("CSV 저장"),QStringLiteral("artifacts.csv"),QStringLiteral("CSV (*.csv)"));
    if (path.isEmpty()) return;
    std::ofstream f(path.toStdString()); if (!f) { QMessageBox::critical(this,QStringLiteral("오류"),QStringLiteral("저장 실패")); return; }
    Report::writeArtifacts(f, m_worker->results, ReportFormat::CSV);
    m_statusLabel->setText(QStringLiteral("CSV 저장: ") + path);
}

void ArtifactsTab::onExportJson() {
    if (!m_worker) return;
    QString path = QFileDialog::getSaveFileName(this,QStringLiteral("JSON 저장"),QStringLiteral("artifacts.json"),QStringLiteral("JSON (*.json)"));
    if (path.isEmpty()) return;
    std::ofstream f(path.toStdString()); if (!f) { QMessageBox::critical(this,QStringLiteral("오류"),QStringLiteral("저장 실패")); return; }
    Report::writeArtifacts(f, m_worker->results, ReportFormat::JSON);
    m_statusLabel->setText(QStringLiteral("JSON 저장: ") + path);
}
