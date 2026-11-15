#include <QApplication>
#include <QTextStream>
#include <QTimer>

#include "capture/device.h"
#include "ui/mainwindow.h"

int main(int argc, char* argv[])
{
    // Listing devices also works without a graphical desktop session.
    for (int i = 1; i < argc; ++i) {
        if (QString::fromLocal8Bit(argv[i]) == QStringLiteral("--list-devices")) {
            const auto result = enumerateDevices();
            if (!result.error.isEmpty()) {
                QTextStream(stderr) << result.error << '\n';
                return 1;
            }
            QTextStream out(stdout);
            for (const auto& device : result.devices) {
                out << device.name << '\t' << device.description << '\t'
                    << device.addresses.join(QStringLiteral(", ")) << '\n';
            }
            return 0;
        }
    }

    QApplication app(argc, argv);
    QApplication::setApplicationName("netsniffer");
    QApplication::setApplicationVersion("0.1.0");

    MainWindow window;
    window.show();

    // Allow an unattended startup check to exercise the event loop and exit.
    if (app.arguments().contains(QStringLiteral("--smoke-test"))) {
        QTimer::singleShot(250, &app, &QApplication::quit);
    }

    return app.exec();
}
