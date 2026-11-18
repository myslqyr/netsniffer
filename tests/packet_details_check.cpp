#include "ui/mainwindow.h"
#include "ui/packetbytesview.h"

#include <QApplication>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QLabel>
#include <QPushButton>
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

static QTreeWidgetItem* field(QTreeWidget* tree, const QString& group, const QString& name)
{
    for (int index = 0; index < tree->topLevelItemCount(); ++index) {
        auto* parent = tree->topLevelItem(index);
        if (parent->text(0) != group) continue;
        if (name.isEmpty()) return parent;
        for (int child = 0; child < parent->childCount(); ++child) {
            if (parent->child(child)->text(0) == name) return parent->child(child);
        }
    }
    return nullptr;
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

    PacketBytesView standalone;
    QByteArray sample(20, 'x');
    sample.replace(14, 4, "ABCD");
    standalone.setBytes(sample);
    standalone.highlightBytes(14, 4);
    const auto ranges = standalone.extraSelections();
    require(ranges.size() == 4 && ranges[0].cursor.selectedText() == "41 42"
        && ranges[1].cursor.selectedText() == "AB" && ranges[2].cursor.selectedText() == "43 44"
        && ranges[3].cursor.selectedText() == "CD", "Hex/ASCII highlight across line boundary");
    standalone.highlightBytes(18, 3);
    require(standalone.extraSelections().isEmpty(), "reject out-of-range highlights");
    standalone.setBytes(QByteArray::fromHex("610a09003c3e"));
    require(standalone.toPlainText().contains("61 0a 09 00 3c 3e")
        && standalone.toPlainText().contains("a...<>"), "nonprintable bytes remain dots in ASCII");
    standalone.setBytes({});
    require(standalone.toPlainText().isEmpty() && standalone.extraSelections().isEmpty(), "clear byte view state");

    MainWindow window(QString::fromLocal8Bit(argv[1]));
    window.show();
    auto* selector = window.findChild<QComboBox*>();
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
    require(selector && table && tree && bytes && summary && start && stop, "detail widgets exist");
    selector->setItemData(0, QStringLiteral("detail-stream"));
    start->click();
    require(waitUntil([&] { return table->rowCount() >= 2; }), "two distinct packets arrive");
    table->selectRow(rowForId(table, 1));
    auto* port = field(tree, "TCP", "源端口");
    require(port && port->text(1) == "12345" && port->data(0, Qt::UserRole).toLongLong() == 34
        && port->data(0, Qt::UserRole + 1).toLongLong() == 2, "TCP field has correct value and byte range");
    tree->setCurrentItem(port);
    require(bytes->extraSelections().size() == 2
        && bytes->extraSelections()[0].cursor.selectedText() == "30 39", "TCP port highlights actual bytes");
    tree->setCurrentItem(field(tree, "帧", "捕获时间"));
    require(bytes->extraSelections().isEmpty(), "metadata clears byte highlights");

    table->selectRow(rowForId(table, 2));
    require(!field(tree, "TCP", {}) && field(tree, "UDP", "源端口")
        && field(tree, "UDP", "源端口")->text(1) == "12346"
        && summary->text().contains("目的端口 5353"), "switch to a different UDP packet");
    auto* payload = field(tree, "UDP 载荷", {});
    require(payload, "UDP payload node exists");
    tree->setCurrentItem(payload);
    tree->scrollToItem(payload);
    require(bytes->extraSelections().size() == 2
        && bytes->extraSelections()[0].cursor.selectedText() == "41 0a 00 5a"
        && bytes->extraSelections()[1].cursor.selectedText() == "A..Z", "UDP payload Hex and ASCII match");
    const auto screenshot = qEnvironmentVariable("NETSNIFFER_UI_SCREENSHOT");
    if (!screenshot.isEmpty()) {
        QApplication::processEvents();
        require(window.grab().save(screenshot), "save offscreen detail preview");
    }

    table->setSortingEnabled(true);
    table->sortItems(2, Qt::DescendingOrder);
    table->selectRow(rowForId(table, 1));
    require(field(tree, "TCP", "源端口") && !field(tree, "UDP", {})
        && field(tree, "IPv4", "源 IP 地址")->text(1) == "1.2.3.4", "sorting preserves packet identity");
    require(waitUntil([&] { return table->rowCount() == 2000 && rowForId(table, 2102) >= 0; }),
            "packet-count cache limit evicts oldest records");
    require(rowForId(table, 1) < 0 && summary->text().isEmpty()
        && tree->topLevelItemCount() == 0 && bytes->toPlainText().isEmpty(), "evicted selection clears all panes");
    table->selectRow(rowForId(table, 2102));
    require(field(tree, "TCP", "序列号") && field(tree, "TCP", "序列号")->text(1) == "53",
            "retained raw packet still matches its stable ID");
    const auto retainedHex = bytes->toPlainText();
    stop->click();
    require(waitUntil([&] { return start->isEnabled(); }) && bytes->toPlainText() == retainedHex,
            "stopping preserves cached packet details");

    table->setSortingEnabled(false);
    selector->setItemData(0, QStringLiteral("detail-budget"));
    start->click();
    require(tree->topLevelItemCount() == 0 && bytes->toPlainText().isEmpty() && summary->text().isEmpty(),
            "new capture clears old detail state");
    require(waitUntil([&] { return rowForId(table, 1) >= 0; }), "large packets arrive");
    table->selectRow(rowForId(table, 1));
    require(!bytes->toPlainText().isEmpty(), "large raw packet can be displayed");
    require(waitUntil([&] { return table->rowCount() == 1024 && rowForId(table, 1050) >= 0; }),
            "64 MiB raw-byte budget applies before 2000-row limit");
    require(tree->topLevelItemCount() == 0 && bytes->toPlainText().isEmpty() && summary->text().isEmpty(),
            "byte-budget eviction clears selected packet details");
    stop->click();
    require(waitUntil([&] { return start->isEnabled(); }), "capture stops after eviction");
    window.close();
    require(waitUntil([&] { return !window.isVisible(); }), "window closes cleanly");
    QTextStream(stdout) << "PASS packet details, byte ranges, sorting, stop/restart and cache eviction\n";
    return 0;
}
