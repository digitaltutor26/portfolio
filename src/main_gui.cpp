#include <QApplication>
#include "main_window.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("WinForensics");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("WinForensics");

    MainWindow win;
    win.show();
    return app.exec();
}
