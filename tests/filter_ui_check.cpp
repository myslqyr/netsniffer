#include "ui/mainwindow.h"

#include <QApplication>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStatusBar>
#include <QTableWidget>
#include <QTextStream>
#include <QTimer>
#include <QTreeWidget>
#include <cstdlib>
#include <functional>

DeviceList enumerateDevices()
{
    DeviceList result;
    result.devices.append(CaptureDevice{QStringLiteral("test"), {}, {}, false});
    return result;
}

static void require(bool valid, const char* name)
{
    if (!valid) {
        QTextStream(stderr) << "FAIL " << name << Qt::endl;
        std::_Exit(1);
    }
}

static bool waitUntil(const std::function<bool()>& condition)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (!condition() && elapsed.elapsed() < 8000) {
        QEventLoop tick;
        QTimer::singleShot(10, &tick, &QEventLoop::quit);
        tick.exec();
    }
    return condition();
}

static int visibleRows(QTableWidget* table)
{
    int count = 0;
    for (int row = 0; row < table->rowCount(); ++row) if (!table->isRowHidden(row)) ++count;
    return count;
}

static int rowForId(QTableWidget* table, quint64 id)
{
    for (int row = 0; row < table->rowCount(); ++row) {
        if (table->item(row, 0)->data(Qt::UserRole).toULongLong() == id) return row;
    }
    return -1;
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    if (argc != 2) return 2;
    MainWindow window(QString::fromLocal8Bit(argv[1]));
    window.show();
    auto* device = window.findChild<QComboBox*>(QStringLiteral("captureDevice"));
    auto* protocol = window.findChild<QComboBox*>(QStringLiteral("protocolFilter"));
    auto* ip = window.findChild<QLineEdit*>(QStringLiteral("addressFilter"));
    auto* port = window.findChild<QLineEdit*>(QStringLiteral("portFilter"));
    auto* capture = window.findChild<QLineEdit*>(QStringLiteral("captureFilter"));
    auto* apply = window.findChild<QPushButton*>(QStringLiteral("applyDisplayFilter"));
    auto* clear = window.findChild<QPushButton*>(QStringLiteral("clearDisplayFilter"));
    auto* error = window.findChild<QLabel*>(QStringLiteral("filterError"));
    auto* table = window.findChild<QTableWidget*>();
    auto* tree = window.findChild<QTreeWidget*>(QStringLiteral("protocolDetails"));
    auto* bytes = window.findChild<QPlainTextEdit*>(QStringLiteral("packetBytes"));
    auto* summary = window.findChild<QLabel*>(QStringLiteral("packetSummary"));
    QPushButton* start = nullptr;
    QPushButton* stop = nullptr;
    for (auto* button : window.findChildren<QPushButton*>()) {
        if (button->text() == QStringLiteral("开始抓包")) start = button;
        if (button->text() == QStringLiteral("停止抓包")) stop = button;
    }
    require(device && protocol && ip && port && capture && apply && clear && error
        && table && tree && bytes && summary && start && stop, "filter widgets exist");
    device->setItemData(0, QStringLiteral("filter-pair"));
    start->click();
    require(waitUntil([&] { return table->rowCount() == 2; }), "TCP and UDP are captured");
    require(!capture->isEnabled(), "capture filter cannot change during capture");
    table->selectRow(rowForId(table, 1));
    require(!bytes->toPlainText().isEmpty(), "selected TCP has details");
    protocol->setCurrentIndex(protocol->findData(QStringLiteral("UDP")));
    require(visibleRows(table) == 1 && table->isRowHidden(rowForId(table, 1))
        && tree->topLevelItemCount() == 0 && bytes->toPlainText().isEmpty(), "excluding selection clears details");
    table->selectRow(rowForId(table, 2));
    const auto udpBytes = bytes->toPlainText();
    ip->setText(QStringLiteral("9.2.3.4"));
    port->setText(QStringLiteral("5353"));
    apply->click();
    require(visibleRows(table) == 1 && bytes->toPlainText() == udpBytes
        && summary->text().contains(QStringLiteral("目的端口 5353")), "combined filter preserves a matching selection");
    const auto screenshot = qEnvironmentVariable("NETSNIFFER_FILTER_SCREENSHOT");
    if (!screenshot.isEmpty()) {
        QApplication::processEvents();
        require(window.grab().save(screenshot), "save filter preview");
    }
    table->setSortingEnabled(true);
    table->sortItems(2, Qt::DescendingOrder);
    require(visibleRows(table) == 1 && table->isRowHidden(rowForId(table, 1))
        && !table->isRowHidden(rowForId(table, 2)) && bytes->toPlainText() == udpBytes,
            "sorting reassigns hidden rows by packet identity");
    ip->setText(QStringLiteral("not an address"));
    apply->click();
    require(!error->isHidden() && visibleRows(table) == 1 && bytes->toPlainText() == udpBytes,
            "invalid IP preserves previous filter and details");
    ip->setText(QStringLiteral("9.2.3.4"));
    port->setText(QStringLiteral("70000"));
    apply->click();
    require(!error->isHidden() && visibleRows(table) == 1, "invalid port preserves previous filter");
    port->setText(QStringLiteral("80"));
    apply->click();
    require(error->isHidden() && visibleRows(table) == 0 && bytes->toPlainText().isEmpty(), "valid zero-result filter");
    clear->click();
    require(visibleRows(table) == 2 && ip->text().isEmpty() && port->text().isEmpty(), "clear restores cached packets");
    protocol->setCurrentIndex(protocol->findData(QStringLiteral("IPv4")));
    require(visibleRows(table) == 2, "network-layer filter matches both transports");
    protocol->setCurrentIndex(protocol->findData(QStringLiteral("IPv6")));
    require(visibleRows(table) == 0, "different IP version has no matches");
    clear->click();
    stop->click();
    require(waitUntil([&] { return start->isEnabled(); }) && capture->isEnabled(), "stop restores capture editing");
    port->setText(QStringLiteral("5353"));
    apply->click();
    require(visibleRows(table) == 1 && table->rowCount() == 2
        && window.statusBar()->currentMessage().contains(QStringLiteral("缓存 2 · 显示 1")), "filtering works after stop with distinct counts");
    clear->click();

    capture->setText(QStringLiteral("udp port 5353"));
    start->click();
    require(waitUntil([&] { return table->rowCount() == 1; }) && table->item(0, 4)->text() == "UDP",
            "BPF filters before packets enter the GUI cache");
    stop->click();
    require(waitUntil([&] { return start->isEnabled(); }), "stop filtered capture");
    capture->setText(QStringLiteral("tcp and ("));
    start->click();
    require(waitUntil([&] { return start->isEnabled(); })
        && window.statusBar()->currentMessage().contains(QStringLiteral("捕获过滤条件错误")), "BPF error reaches the GUI");
    capture->setText(QStringLiteral("tcp and (port 80 or port 443)"));
    start->click();
    require(waitUntil([&] { return table->rowCount() == 1; }) && table->item(0, 4)->text() == "TCP",
            "space and parentheses survive process arguments; retry after BPF error");
    stop->click();
    require(waitUntil([&] { return start->isEnabled(); }), "stop retry capture");
    device->setItemData(0, QStringLiteral("legacy-filter"));
    start->click();
    require(waitUntil([&] { return start->isEnabled(); })
        && window.statusBar()->currentMessage().contains(QStringLiteral("辅助程序需要更新")), "old helper reports update requirement");

    table->setSortingEnabled(false);
    device->setItemData(0, QStringLiteral("detail-stream"));
    capture->clear();
    protocol->setCurrentIndex(protocol->findData(QStringLiteral("UDP")));
    start->click();
    require(waitUntil([&] { return table->rowCount() >= 2; }) && visibleRows(table) == 1,
            "new packets use active display filter");
    table->selectRow(rowForId(table, 2));
    require(!bytes->toPlainText().isEmpty(), "select matching live packet");
    require(waitUntil([&] { return table->rowCount() == 2000 && rowForId(table, 2102) >= 0; })
        && visibleRows(table) == 0 && bytes->toPlainText().isEmpty(), "hidden packets still count towards cache eviction");
    clear->click();
    require(visibleRows(table) == 2000, "clear restores surviving packets after eviction");
    stop->click();
    require(waitUntil([&] { return start->isEnabled(); }), "final capture stops");
    window.close();
    QTextStream(stdout) << "PASS display filtering, BPF IPC, invalid conditions, sorting, cache and details\n";
    return 0;
}
