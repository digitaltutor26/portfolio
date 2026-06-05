#pragma once
#include <QMainWindow>

class QTabWidget;
class AnalyzeTab;
class ArtifactsTab;
class TimelineTab;
class LnkTab;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
private:
    void setupMenuBar();
    QTabWidget*   m_tabs;
    AnalyzeTab*   m_analyzeTab;
    ArtifactsTab* m_artifactsTab;
    TimelineTab*  m_timelineTab;
    LnkTab*       m_lnkTab;
};
