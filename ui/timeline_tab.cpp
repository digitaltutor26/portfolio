#include "timeline_tab.h"
#include "report.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
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
#include <QColor>
#include <fstream>
using namespace forensics;

TimelineTab::TimelineTab(QWidget* parent) : QWidget(parent) { setupUi(); }

void TimelineTab::setupUi() {
    auto* root = new QVBoxLayout(this); root->setContentsMargins(8,8,8,8); root->setSpacing(6);
    auto* pathRow = new QHBoxLayout;
    pathRow->addWidget(new QLabel(QStringLiteral("경로(선택):")));
    m_pathEdit = new QLineEdit; m_pathEdit->setPlaceholderText(QStringLiteral("비워두면 아티팩트만 수집"));
    pathRow->addWidget(m_pathEdit);
    m_browseBtn = new QPushButton(QStringLiteral("찾아보기...")); pathRow->addWidget(m_browseBtn);
    root->addLayout(pathRow);
    auto* grp = new QGroupBox(QStringLiteral("옵션")); auto* optLayout = new QHBoxLayout(grp);
    m_hashCheck=new QCheckBox(QStringLiteral("해시")); m_recursiveCheck=new QCheckBox(QStringLiteral("재귀"));
    m_recentCheck=new QCheckBox(QStringLiteral("Recent")); m_recentCheck->setChecked(true);
    m_prefetchCheck=new QCheckBox(QStringLiteral("Prefetch")); m_prefetchCheck->setChecked(true);
    m_tempCheck=new QCheckBox(QStringLiteral("Temp")); m_downloadsCheck=new QCheckBox(QStringLiteral("Downloads"));
    m_generateBtn=new QPushButton(QStringLiteral("타임라인 생성")); m_generateBtn->setDefault(true);
    optLayout->addWidget(m_hashCheck); optLayout->addWidget(m_recursiveCheck); optLayout->addSpacing(8);
    optLayout->addWidget(m_recentCheck); optLayout->addWidget(m_prefetchCheck);
    optLayout->addWidget(m_tempCheck); optLayout->addWidget(m_downloadsCheck);
    optLayout->addStretch(); optLayout->addWidget(m_generateBtn);
    root->addWidget(grp);
    m_progress = new QProgressBar; m_progress->setRange(0,0); m_progress->setVisible(false); root->addWidget(m_progress);
    m_statusLabel = new QLabel(QStringLiteral("준비")); root->addWidget(m_statusLabel);
    m_table = new QTableWidget(0,4);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("시각"), QStringLiteral("이벤트 종류"),
        QStringLiteral("설명"), QStringLiteral("경로")
    });
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers); root->addWidget(m_table);
    auto* exportRow = new QHBoxLayout;
    m_exportCsvBtn=new QPushButton(QStringLiteral("CSV 저장")); m_exportCsvBtn->setEnabled(false);
    m_exportJsonBtn=new QPushButton(QStringLiteral("JSON 저장")); m_exportJsonBtn->setEnabled(false);
    exportRow->addStretch(); exportRow->addWidget(m_exportCsvBtn); exportRow->addWidget(m_exportJsonBtn);
    root->addLayout(exportRow);
    connect(m_browseBtn,   &QPushButton::clicked, this, &TimelineTab::onBrowse);
    connect(m_generateBtn, &QPushButton::clicked, this, &TimelineTab::onGenerate);
    connect(m_exportCsvBtn,&QPushButton::clicked, this, &TimelineTab::onExportCsv);
    connect(m_exportJsonBtn,&QPushButton::clicked,this, &TimelineTab::onExportJson);
}

void TimelineTab::onBrowse() {
    QString p = QFileDialog::getExistingDirectory(this,QStringLiteral("폴더 선택"),{},QFileDialog::ShowDirsOnly);
    if (p.isEmpty()) p = QFileDialog::getOpenFileName(this,QStringLiteral("파일 선택"));
    if (!p.isEmpty()) m_pathEdit->setText(p);
}

void TimelineTab::onGenerate() {
    if (m_thread && m_thread->isRunning()) return;
    m_table->setRowCount(0); m_exportCsvBtn->setEnabled(false); m_exportJsonBtn->setEnabled(false);
    m_worker = new TimelineWorker;
    m_worker->path=m_pathEdit->text().trimmed(); m_worker->recursive=m_recursiveCheck->isChecked();
    m_worker->computeHash=m_hashCheck->isChecked(); m_worker->recent=m_recentCheck->isChecked();
    m_worker->prefetch=m_prefetchCheck->isChecked(); m_worker->temp=m_tempCheck->isChecked();
    m_worker->downloads=m_downloadsCheck->isChecked();
    m_thread = new QThread(this); m_worker->moveToThread(m_thread);
    connect(m_thread,&QThread::started,          m_worker,&TimelineWorker::run);
    connect(m_worker,&TimelineWorker::finished,  this,    &TimelineTab::onFinished);
    connect(m_worker,&TimelineWorker::error,     this,    &TimelineTab::onError);
    connect(m_worker,&TimelineWorker::status,    this,    &TimelineTab::onStatus);
    connect(m_worker,&TimelineWorker::finished,  m_thread,&QThread::quit);
    connect(m_thread,&QThread::finished,         m_worker,&QObject::deleteLater);
    connect(m_thread,&QThread::finished,         m_thread,&QObject::deleteLater);
    setRunning(true); m_thread->start();
}

void TimelineTab::onFinished() {
    populateTable(m_worker->results); setRunning(false);
    m_exportCsvBtn->setEnabled(m_table->rowCount()>0);
    m_exportJsonBtn->setEnabled(m_table->rowCount()>0);
}
void TimelineTab::onError(QString msg)  { setRunning(false); QMessageBox::critical(this,QStringLiteral("오류"),msg); }
void TimelineTab::onStatus(QString msg) { m_statusLabel->setText(msg); }

void TimelineTab::populateTable(const std::vector<TimelineEvent>& events) {
    static const QMap<QString,QColor> colorMap{
        {QStringLiteral("Created"),QColor(220,255,220)},{QStringLiteral("Modified"),QColor(255,240,200)},
        {QStringLiteral("Accessed"),QColor(220,235,255)},{QStringLiteral("RecentFile"),QColor(255,220,255)},
        {QStringLiteral("Prefetch"),QColor(255,235,220)}
    };
    m_table->setRowCount(static_cast<int>(events.size()));
    for (int r=0; r<static_cast<int>(events.size()); ++r) {
        const auto& e=events[r];
        QString type=QString::fromStdString(e.eventType);
        QColor bg=colorMap.value(type,QColor(245,245,245));
        auto set=[&](int col, const QString& val){ auto* item=new QTableWidgetItem(val); item->setBackground(bg); m_table->setItem(r,col,item); };
        set(0,QString::fromStdString(e.timestampStr)); set(1,type);
        set(2,QString::fromStdString(e.description)); set(3,QString::fromStdString(e.path));
    }
    m_table->resizeColumnsToContents();
}

void TimelineTab::setRunning(bool r) { m_generateBtn->setEnabled(!r); m_browseBtn->setEnabled(!r); m_progress->setVisible(r); }

void TimelineTab::onExportCsv() {
    if (!m_worker) return;
    QString path=QFileDialog::getSaveFileName(this,QStringLiteral("CSV 저장"),QStringLiteral("timeline.csv"),QStringLiteral("CSV (*.csv)"));
    if (path.isEmpty()) return;
    std::ofstream f(path.toStdString()); if (!f) { QMessageBox::critical(this,QStringLiteral("오류"),QStringLiteral("저장 실패")); return; }
    Report::writeTimeline(f, m_worker->results, ReportFormat::CSV);
    m_statusLabel->setText(QStringLiteral("CSV 저장: ")+path);
}
void TimelineTab::onExportJson() {
    if (!m_worker) return;
    QString path=QFileDialog::getSaveFileName(this,QStringLiteral("JSON 저장"),QStringLiteral("timeline.json"),QStringLiteral("JSON (*.json)"));
    if (path.isEmpty()) return;
    std::ofstream f(path.toStdString()); if (!f) { QMessageBox::critical(this,QStringLiteral("오류"),QStringLiteral("저장 실패")); return; }
    Report::writeTimeline(f, m_worker->results, ReportFormat::JSON);
    m_statusLabel->setText(QStringLiteral("JSON 저장: ")+path);
}
