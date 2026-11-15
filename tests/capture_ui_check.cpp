#include "ui/mainwindow.h"

#include <QApplication>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QPushButton>
#include <QStatusBar>
#include <QTableWidget>
#include <QTextStream>
#include <QThread>
#include <QTimer>
#include <functional>

// Isolate GUI lifecycle from the host's interface-enumeration permissions.
DeviceList enumerateDevices()
{
    DeviceList result;
    result.devices.append(CaptureDevice{QStringLiteral("test"), {}, {}, false});
    return result;
}

static bool waitUntil(const std::function<bool()>& condition)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (!condition() && elapsed.elapsed() < 4000) {
        QEventLoop tick;
        QTimer::singleShot(10, &tick, &QEventLoop::quit);
        tick.exec();
    }
    return condition();
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    if (argc != 2) {
        return 2;
    }
    MainWindow window(QString::fromLocal8Bit(argv[1]));
    window.show();
    auto* selector = window.findChild<QComboBox*>();
    auto* table = window.findChild<QTableWidget*>();
    QPushButton* start = nullptr;
    QPushButton* stop = nullptr;
    QPushButton* refresh = nullptr;
    for (auto* button : window.findChildren<QPushButton*>()) {
        if (button->text() == QStringLiteral("开始抓包")) start = button;
        if (button->text() == QStringLiteral("停止抓包")) stop = button;
        if (button->text() == QStringLiteral("刷新网卡")) refresh = button;
    }
    if (!selector || !table || !start || !stop || !refresh) {
        return 1;
    }
    // Synthetic device entries exercise UI lifecycle without capture privileges.
    selector->clear();
    selector->addItem(QStringLiteral("test"), QStringLiteral("fragmented"));
    start->setEnabled(true);
    for (int round = 0; round < 3; ++round) {
        start->click();
        if (!waitUntil([&] { return table->rowCount() == 1; })
            || start->isEnabled() || selector->isEnabled() || refresh->isEnabled()) {
            return 1;
        }
        stop->click();
        if (!waitUntil([&] { return start->isEnabled() && !stop->isEnabled(); })) {
            return 1;
        }
    }
    selector->setItemData(0, QStringLiteral("error"));
    start->click();
    if (!waitUntil([&] { return start->isEnabled(); })
        || !window.statusBar()->currentMessage().contains(QStringLiteral("test permission denied"))) {
        return 1;
    }
    selector->setItemData(0, QStringLiteral("fragmented"));
    start->click();
    if (!waitUntil([&] { return table->rowCount() == 1; })) {
        return 1;
    }
    window.close();
    if (!waitUntil([&] { return !window.isVisible(); })) {
        return 1;
    }
    for (auto* thread : window.findChildren<QThread*>()) {
        if (thread->isRunning()) {
            return 1;
        }
    }
    QTextStream(stdout) << "PASS UI start/stop, retry after error, close while capturing\n";
    return 0;
}
