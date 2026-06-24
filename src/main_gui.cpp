#include <QApplication>
#include "main_window.h"
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#include <QTextCodec>
#endif

int main(int argc, char* argv[]) {
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
