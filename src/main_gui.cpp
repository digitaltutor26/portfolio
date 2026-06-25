#include <QApplication>
#include "main_window.h"
#ifdef _WIN32
#include <clocale>
#endif
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#include <QTextCodec>
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Windows 10 1803+: UTF-8을 프로세스 코드페이지로 설정
    // std::filesystem::path::string() 등이 UTF-8을 반환하게 됨
    setlocale(LC_ALL, ".UTF-8");
#endif
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QTextCodec::setCodecForLocale(QTextCodec::codecForName("UTF-8"));
#endif
    QApplication app(argc, argv);
    app.setApplicationName("WinForensics");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("WinForensics");

    MainWindow win;
    win.show();
    return app.exec();
}
