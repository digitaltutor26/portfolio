#include "lnk_tab.h"
#include "report.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QLabel>
#include <QTableWidget>
#include <QHeaderView>
#include <QSplitter>
#include <QFileDialog>
#include <QMessageBox>
#include <QThread>
#include <QColor>
#include <QFont>
#include <fstream>
using namespace forensics;

LnkTab::LnkTab(QWidget* parent) : QWidget(parent) { setupUi(); }

void LnkTab::setupUi() {
    auto* root = new QVBoxLayout(this); root->setContentsMargins(8,8,8,8); root->setSpacing(6);
    auto* grp = new QGroupBox("입력"); auto* gl = new QVBoxLayout(grp);
    auto* lnkRow = new QHBoxLayout;
    lnkRow->addWidget(new QLabel("LNK 경로:"));
    m_lnkPathEdit = new QLineEdit; m_lnkPathEdit->setPlaceholderText(".lnk 파일 또는 폴더 (Recent 등)");
    lnkRow->addWidget(m_lnkPathEdit);
    m_browseLnkBtn = new QPushButton("찾아보기..."); lnkRow->addWidget(m_browseLnkBtn);
    gl->addLayout(lnkRow);
    auto* mftRow = new QHBoxLayout;
    mftRow->addWidget(new QLabel("$MFT 경로:"));
    m_mftPathEdit = new QLineEdit; m_mftPathEdit->setPlaceholderText("(선택) 원시 $MFT 파일 — $SI/$FN 비교");
    mftRow->addWidget(m_mftPathEdit);
    m_browseMftBtn = new QPushButton("찾아보기..."); mftRow->addWidget(m_browseMftBtn);
    gl->addLayout(mftRow);
    auto* btnRow = new QHBoxLayout; btnRow->addStretch();
    m_analyzeBtn = new QPushButton("분석 시작"); m_analyzeBtn->setDefault(true);
    btnRow->addWidget(m_analyzeBtn); gl->addLayout(btnRow);
    root->addWidget(grp);
    m_progress = new QProgressBar; m_progress->setRange(0,0); m_progress->setVisible(false); root->addWidget(m_progress);
    m_statusLabel = new QLabel("준비"); root->addWidget(m_statusLabel);

    auto* splitter = new QSplitter(Qt::Vertical);
    auto* lnkGrp = new QGroupBox("LNK 파일 목록 (선택하면 $SI/$FN 표시)");
    auto* lgl = new QVBoxLayout(lnkGrp);
    m_lnkTable = new QTableWidget(0,9);
    m_lnkTable->setHorizontalHeaderLabels({"LNK 파일","대상 경로","드라이브","시리얼","레이블","컴퓨터","생성","수정","접근"});
    m_lnkTable->horizontalHeader()->setSectionResizeMode(1,QHeaderView::Stretch);
    m_lnkTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_lnkTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    lgl->addWidget(m_lnkTable); splitter->addWidget(lnkGrp);

    auto* mftGrp = new QGroupBox("$MFT 타임스탬프 ($SI vs $FN)");
    auto* mgl = new QVBoxLayout(mftGrp);
    m_mftTable = new QTableWidget(0,11);
    m_mftTable->setHorizontalHeaderLabels({"레코드#","파일명","상태","$SI 생성","$SI 수정","$SI MFT수정","$SI 접근","$FN 생성","$FN 수정","$FN MFT수정","$FN 접근"});
    m_mftTable->horizontalHeader()->setStretchLastSection(true);
    m_mftTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_mftTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mgl->addWidget(m_mftTable); splitter->addWidget(mftGrp);
    root->addWidget(splitter);

    auto* exportRow = new QHBoxLayout;
    m_exportCsvBtn=new QPushButton("CSV 저장"); m_exportCsvBtn->setEnabled(false);
    m_exportJsonBtn=new QPushButton("JSON 저장"); m_exportJsonBtn->setEnabled(false);
    exportRow->addStretch(); exportRow->addWidget(m_exportCsvBtn); exportRow->addWidget(m_exportJsonBtn);
    root->addLayout(exportRow);

    connect(m_browseLnkBtn,&QPushButton::clicked, this,&LnkTab::onBrowseLnk);
    connect(m_browseMftBtn,&QPushButton::clicked, this,&LnkTab::onBrowseMft);
    connect(m_analyzeBtn,  &QPushButton::clicked, this,&LnkTab::onAnalyze);
    connect(m_exportCsvBtn,&QPushButton::clicked, this,&LnkTab::onExportCsv);
    connect(m_exportJsonBtn,&QPushButton::clicked,this,&LnkTab::onExportJson);
    connect(m_lnkTable,&QTableWidget::currentRowChanged,this,[this](int row){
        if (row>=0 && row<static_cast<int>(m_results.size())) populateMftTable(m_results[row]);
        else m_mftTable->setRowCount(0);
    });
}

void LnkTab::onBrowseLnk() {
    QString p=QFileDialog::getExistingDirectory(this,"LNK 폴더");
    if (p.isEmpty()) p=QFileDialog::getOpenFileName(this,"LNK 파일",{},"LNK (*.lnk);;전체 (*)");
    if (!p.isEmpty()) m_lnkPathEdit->setText(p);
}
void LnkTab::onBrowseMft() {
    QString p=QFileDialog::getOpenFileName(this,"$MFT 파일",{},"전체 (*)");
    if (!p.isEmpty()) m_mftPathEdit->setText(p);
}

void LnkTab::onAnalyze() {
    if (m_lnkPathEdit->text().trimmed().isEmpty()) { QMessageBox::warning(this,"경고","LNK 경로를 입력하세요."); return; }
    if (m_thread && m_thread->isRunning()) return;
    m_lnkTable->setRowCount(0); m_mftTable->setRowCount(0);
    m_exportCsvBtn->setEnabled(false); m_exportJsonBtn->setEnabled(false); m_results.clear();
    m_worker = new LnkWorker;
    m_worker->lnkPath=m_lnkPathEdit->text().trimmed(); m_worker->mftPath=m_mftPathEdit->text().trimmed();
    m_thread = new QThread(this); m_worker->moveToThread(m_thread);
    connect(m_thread,&QThread::started,       m_worker,&LnkWorker::run);
    connect(m_worker,&LnkWorker::finished,    this,    &LnkTab::onFinished);
    connect(m_worker,&LnkWorker::error,       this,    &LnkTab::onError);
    connect(m_worker,&LnkWorker::status,      this,    &LnkTab::onStatus);
    connect(m_worker,&LnkWorker::finished,    m_thread,&QThread::quit);
    connect(m_thread,&QThread::finished,      m_worker,&QObject::deleteLater);
    connect(m_thread,&QThread::finished,      m_thread,&QObject::deleteLater);
    setRunning(true); m_thread->start();
}

void LnkTab::onFinished() {
    m_results=m_worker->results; populateLnkTable(m_results); setRunning(false);
    m_exportCsvBtn->setEnabled(!m_results.empty()); m_exportJsonBtn->setEnabled(!m_results.empty());
}
void LnkTab::onError(QString msg)  { setRunning(false); QMessageBox::critical(this,"오류",msg); }
void LnkTab::onStatus(QString msg) { m_statusLabel->setText(msg); }

void LnkTab::populateLnkTable(const std::vector<LnkAnalysis>& results) {
    m_lnkTable->setRowCount(static_cast<int>(results.size()));
    for (int r=0; r<static_cast<int>(results.size()); ++r) {
        const LnkInfo& lnk=results[r].lnk;
        bool anomaly=false;
        for (auto& rec:results[r].mftRecords) if (rec.timestampAnomaly) { anomaly=true; break; }
        bool hasMft=!results[r].mftRecords.empty();
        QColor bg=anomaly?QColor(255,200,200):hasMft?QColor(220,255,220):QColor(255,255,255);
        auto set=[&](int col, const QString& val){
            auto* item=new QTableWidgetItem(val); item->setBackground(bg);
            if(anomaly){QFont f=item->font();f.setBold(true);item->setFont(f);}
            m_lnkTable->setItem(r,col,item);
        };
        set(0,QString::fromStdString(lnk.lnkName)); set(1,QString::fromStdString(lnk.targetPath));
        set(2,QString::fromStdString(lnk.volume.driveTypeStr)); set(3,QString::fromStdString(lnk.volume.serialStr));
        set(4,QString::fromStdString(lnk.volume.label)); set(5,QString::fromStdString(lnk.machineName));
        set(6,QString::fromStdString(lnk.targetTimes.createdStr)); set(7,QString::fromStdString(lnk.targetTimes.modifiedStr));
        set(8,QString::fromStdString(lnk.targetTimes.accessedStr));
        m_lnkTable->item(r,0)->setToolTip(QString::fromStdString(lnk.lnkPath));
    }
    m_lnkTable->resizeColumnsToContents();
    if (!results.empty()) { m_lnkTable->selectRow(0); populateMftTable(results[0]); }
}

void LnkTab::populateMftTable(const LnkAnalysis& analysis) {
    const auto& recs=analysis.mftRecords;
    if (recs.empty()) {
        m_mftTable->clearSpans(); m_mftTable->setRowCount(1); m_mftTable->setSpan(0,0,1,11);
        auto* item=new QTableWidgetItem(m_mftPathEdit->text().isEmpty()?"$MFT 경로 미지정":"매칭 레코드 없음");
        item->setTextAlignment(Qt::AlignCenter); item->setForeground(QColor(120,120,120));
        m_mftTable->setItem(0,0,item); return;
    }
    m_mftTable->clearSpans(); m_mftTable->setRowCount(static_cast<int>(recs.size()));
    for (int r=0; r<static_cast<int>(recs.size()); ++r) {
        const MftRecord& rec=recs[r];
        QColor bg=rec.timestampAnomaly?QColor(255,200,200):QColor(220,255,220);
        auto set=[&](int col,const QString& val){ auto* item=new QTableWidgetItem(val); item->setBackground(bg); m_mftTable->setItem(r,col,item); };
        set(0,QString::number(rec.recordNumber)); set(1,QString::fromStdString(rec.fileName));
        QString st=rec.isDeleted?"삭제됨":"활성"; if(rec.isDirectory)st+="/폴더"; if(rec.timestampAnomaly)st+=" ⚠";
        set(2,st);
        set(3,QString::fromStdString(rec.siTimes.createdStr)); set(4,QString::fromStdString(rec.siTimes.modifiedStr));
        set(5,QString::fromStdString(rec.siTimes.mftModifiedStr)); set(6,QString::fromStdString(rec.siTimes.accessedStr));
        set(7,QString::fromStdString(rec.fnTimes.createdStr)); set(8,QString::fromStdString(rec.fnTimes.modifiedStr));
        set(9,QString::fromStdString(rec.fnTimes.mftModifiedStr)); set(10,QString::fromStdString(rec.fnTimes.accessedStr));
        if (rec.timestampAnomaly) m_mftTable->item(r,2)->setToolTip(QString::fromStdString(rec.anomalyDetail));
    }
    m_mftTable->resizeColumnsToContents();
}

void LnkTab::setRunning(bool r) {
    m_analyzeBtn->setEnabled(!r); m_browseLnkBtn->setEnabled(!r); m_browseMftBtn->setEnabled(!r);
    m_progress->setVisible(r);
}

void LnkTab::onExportCsv() {
    QString path=QFileDialog::getSaveFileName(this,"CSV 저장","lnk_report.csv","CSV (*.csv)");
    if (path.isEmpty()) return;
    std::ofstream f(path.toStdString()); if (!f) { QMessageBox::critical(this,"오류","저장 실패"); return; }
    Report::writeLnkAnalysis(f, m_results, ReportFormat::CSV);
    m_statusLabel->setText("CSV 저장: "+path);
}
void LnkTab::onExportJson() {
    QString path=QFileDialog::getSaveFileName(this,"JSON 저장","lnk_report.json","JSON (*.json)");
    if (path.isEmpty()) return;
    std::ofstream f(path.toStdString()); if (!f) { QMessageBox::critical(this,"오류","저장 실패"); return; }
    Report::writeLnkAnalysis(f, m_results, ReportFormat::JSON);
    m_statusLabel->setText("JSON 저장: "+path);
}
void LnkTab::onLnkSelectionChanged() {}
