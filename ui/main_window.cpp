#include "main_window.h"
#include "analyze_tab.h"
#include "artifacts_tab.h"
#include "timeline_tab.h"
#include "lnk_tab.h"
#include <QTabWidget>
#include <QMenuBar>
#include <QStatusBar>
#include <QApplication>
#include <QMessageBox>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("WinForensics v1.0"));
    setMinimumSize(900, 650);
    m_tabs         = new QTabWidget(this);
    m_analyzeTab   = new AnalyzeTab(this);
    m_artifactsTab = new ArtifactsTab(this);
    m_timelineTab  = new TimelineTab(this);
    m_lnkTab       = new LnkTab(this);
    m_tabs->addTab(m_analyzeTab,   QStringLiteral("파일 분석"));
    m_tabs->addTab(m_artifactsTab, QStringLiteral("아티팩트"));
    m_tabs->addTab(m_timelineTab,  QStringLiteral("타임라인"));
    m_tabs->addTab(m_lnkTab,       QStringLiteral("LNK / $MFT"));
    setCentralWidget(m_tabs);
    setupMenuBar();
    statusBar()->showMessage(QStringLiteral("준비"));
}

void MainWindow::setupMenuBar() {
    auto* fileMenu = menuBar()->addMenu(QStringLiteral("파일(&F)"));
    fileMenu->addAction(QStringLiteral("종료(&X)"), qApp, &QApplication::quit);
    auto* helpMenu = menuBar()->addMenu(QStringLiteral("도움말(&H)"));
    helpMenu->addAction(QStringLiteral("정보(&A)"), this, [this] {
        QMessageBox::about(this, QStringLiteral("WinForensics"),
            QStringLiteral("<b>WinForensics v1.0</b><br>Windows 디지털 포렌식 툴킷<br><br>"
            "· 파일/폴더 메타데이터 분석<br>"
            "· Windows 아티팩트 수집<br>"
            "· 활동 타임라인 생성<br>"
            "· LNK 파일 파싱 + $MFT $SI/$FN 타임스탬프 비교"));
    });
}
