#include "ui/mainwindow.h"
#include "storage/pcapfile.h"

#include <QApplication>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStatusBar>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTextStream>
#include <QThread>
#include <QTimer>
#include <QTreeWidget>
#include <cstdlib>
#include <functional>
#include <pcap/dlt.h>

static bool haveDevice = true;

DeviceList enumerateDevices()
{
    DeviceList result;
    if (haveDevice) result.devices.append(CaptureDevice{QStringLiteral("parsed"), {}, {}, false});
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

static int rowForId(QTableWidget* table, quint64 id)
{
    for (int row = 0; row < table->rowCount(); ++row) {
        if (table->item(row, 0)->data(Qt::UserRole).toULongLong() == id) return row;
    }
    return -1;
}

static int visibleRows(QTableWidget* table)
{
    int count = 0;
    for (int row = 0; row < table->rowCount(); ++row) if (!table->isRowHidden(row)) ++count;
    return count;
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    if (argc != 2) return 2;
    QTemporaryDir directory;
    require(directory.isValid(), "temporary directory");
    const auto tcp = QByteArray::fromHex("00112233445566778899aabb0800"
        "4500002800010000400600000102030405060708"
        "3039005000000001000000005002200000000000");
    const auto udp = QByteArray::fromHex("00112233445566778899aabb0800"
        "4500002000010000401100000902030405060708"
        "303a14e9000c0000410a005a");
    const CapturedPacket first{1700000000123456, quint32(tcp.size()), quint32(tcp.size()), DLT_EN10MB, tcp};
    const CapturedPacket second{1700000001123456, quint32(udp.size()), quint32(udp.size()) + 10, DLT_EN10MB, udp, 789};
    const auto input = directory.filePath(QStringLiteral("input.pcap"));
    const auto output = directory.filePath(QStringLiteral("output.pcap"));
    require(PcapFile::write(input, {first, second}).error.isEmpty(), "prepare external input");

    MainWindow window(QString::fromLocal8Bit(argv[1]));
    window.show();
    auto* table = window.findChild<QTableWidget*>();
    auto* tree = window.findChild<QTreeWidget*>(QStringLiteral("protocolDetails"));
    auto* bytes = window.findChild<QPlainTextEdit*>(QStringLiteral("packetBytes"));
    auto* summary = window.findChild<QLabel*>(QStringLiteral("packetSummary"));
    auto* protocol = window.findChild<QComboBox*>(QStringLiteral("protocolFilter"));
    auto* capture = window.findChild<QLineEdit*>(QStringLiteral("captureFilter"));
    auto* clear = window.findChild<QPushButton*>(QStringLiteral("clearDisplayFilter"));
    auto* open = window.findChild<QPushButton*>(QStringLiteral("openPcap"));
    auto* save = window.findChild<QPushButton*>(QStringLiteral("savePcap"));
    auto* cancel = window.findChild<QPushButton*>(QStringLiteral("cancelFileOperation"));
    QPushButton* start = nullptr;
    QPushButton* stop = nullptr;
    for (auto* button : window.findChildren<QPushButton*>()) {
        if (button->text() == QStringLiteral("开始抓包")) start = button;
        if (button->text() == QStringLiteral("停止抓包")) stop = button;
    }
    require(table && tree && bytes && summary && protocol && capture && clear && open && save && cancel && start && stop,
            "file controls exist");
    require(!save->isEnabled(), "empty cache cannot be saved");
    capture->setText(QStringLiteral("tcp and ("));
    require(window.openPcapFile(input) && !start->isEnabled() && !open->isEnabled() && !cancel->isHidden(),
            "background import locks conflicting operations");
    require(!window.openPcapFile(input) && !window.savePcapFile(output), "only one file job at a time");
    require(waitUntil([&] { return open->isEnabled(); }) && table->rowCount() == 2 && save->isEnabled(),
            "file loads without applying live capture filter");
    require(table->item(rowForId(table, 2), 1)->text().endsWith(QStringLiteral(".123456789"))
        && table->item(rowForId(table, 2), 5)->text() == QString::number(udp.size())
        && table->item(rowForId(table, 2), 6)->text() == QString::number(udp.size() + 10),
            "nanosecond time and captured/original lengths appear in the list");
    protocol->setCurrentIndex(protocol->findData(QStringLiteral("UDP")));
    table->setSortingEnabled(true);
    table->sortItems(2, Qt::DescendingOrder);
    table->selectRow(rowForId(table, 2));
    require(visibleRows(table) == 1 && !bytes->toPlainText().isEmpty()
        && summary->text().contains(QStringLiteral("目的端口 5353")), "loaded packet filtering and details work");
    QTreeWidgetItem* payload = nullptr;
    for (int i = 0; i < tree->topLevelItemCount(); ++i) {
        if (tree->topLevelItem(i)->text(0) == QStringLiteral("UDP 载荷")) payload = tree->topLevelItem(i);
    }
    require(payload, "loaded payload field exists");
    tree->setCurrentItem(payload);
    tree->scrollToItem(payload);
    require(bytes->extraSelections().size() == 2
        && bytes->extraSelections()[0].cursor.selectedText() == "41 0a 00 5a", "loaded fields highlight original bytes");
    const auto screenshot = qEnvironmentVariable("NETSNIFFER_PCAP_SCREENSHOT");
    if (!screenshot.isEmpty()) {
        QApplication::processEvents();
        require(window.grab().save(screenshot), "save PCAP interface preview");
    }
    require(window.savePcapFile(output) && waitUntil([&] { return open->isEnabled(); }), "save imported cache");
    auto result = PcapFile::read(output);
    require(result.error.isEmpty() && result.packets.size() == 2 && result.packets[0].bytes == tcp
        && result.packets[1].bytes == udp && result.packets[1].timestampSubMicroNs == 789,
            "save includes hidden packets in original capture order");
    const auto previousBytes = bytes->toPlainText();
    const auto previousSummary = summary->text();
    const auto bad = directory.filePath(QStringLiteral("bad.pcap"));
    { QFile file(bad); require(file.open(QIODevice::WriteOnly) && file.write("broken") == 6, "prepare bad file"); }
    require(window.openPcapFile(bad) && waitUntil([&] { return open->isEnabled(); })
        && window.statusBar()->currentMessage().contains(QStringLiteral("读取失败"))
        && table->rowCount() == 2 && bytes->toPlainText() == previousBytes && summary->text() == previousSummary,
            "failed read preserves previous list, selection and details");
    require(window.savePcapFile(directory.path()) && waitUntil([&] { return open->isEnabled(); })
        && window.statusBar()->currentMessage().contains(QStringLiteral("保存失败"))
        && bytes->toPlainText() == previousBytes, "failed save preserves displayed data");

    clear->click();
    capture->clear();
    start->click();
    require(!open->isEnabled() && !save->isEnabled() && !window.openPcapFile(input), "live capture excludes file operations");
    require(waitUntil([&] { return table->rowCount() == 1; }) && table->item(0, 4)->text() == "TCP",
            "new live capture replaces offline session");
    stop->click();
    require(waitUntil([&] { return start->isEnabled(); }) && save->isEnabled(), "stop enables cache export");
    table->selectRow(0);
    const auto liveBytes = bytes->toPlainText();
    require(window.savePcapFile(output) && waitUntil([&] { return open->isEnabled(); }), "save live capture");
    result = PcapFile::read(output);
    require(result.error.isEmpty() && result.packets.size() == 1 && result.packets[0].timestampUs == first.timestampUs,
            "live capture export preserves timestamp");

    QVector<CapturedPacket> many;
    many.reserve(100000);
    for (int index = 0; index < 100000; ++index) {
        auto packet = first;
        packet.timestampUs += index;
        many.append(packet);
    }
    const auto large = directory.filePath(QStringLiteral("large.pcap"));
    require(PcapFile::write(large, many).error.isEmpty(), "prepare longer input");
    require(window.openPcapFile(large), "start cancellable read");
    cancel->click();
    require(waitUntil([&] { return open->isEnabled(); })
        && window.statusBar()->currentMessage().contains(QStringLiteral("已取消读取"))
        && table->rowCount() == 1 && bytes->toPlainText() == liveBytes, "cancelled read keeps old live cache");
    require(window.openPcapFile(large) && waitUntil([&] { return open->isEnabled(); })
        && table->rowCount() == 2000 && rowForId(table, 98001) >= 0 && rowForId(table, 100000) >= 0
        && window.statusBar()->currentMessage().contains(QStringLiteral("已读取 100000")), "large input has bounded cache and original record numbers");
    require(window.savePcapFile(output) && waitUntil([&] { return open->isEnabled(); }), "export retained suffix");
    result = PcapFile::read(output);
    require(result.packetCount == 2000 && result.packets.first().timestampUs == first.timestampUs + 98000,
            "export does not claim to include evicted packets");

    haveDevice = false;
    MainWindow noDevice;
    noDevice.show();
    auto* offlineOpen = noDevice.findChild<QPushButton*>(QStringLiteral("openPcap"));
    auto* offlineTable = noDevice.findChild<QTableWidget*>();
    require(noDevice.openPcapFile(input) && waitUntil([&] { return offlineOpen->isEnabled(); })
        && offlineTable->rowCount() == 2, "offline analysis works without capture devices or helper");
    noDevice.close();
    require(window.openPcapFile(large), "start final background read");
    window.close();
    require(waitUntil([&] { return !window.isVisible(); }), "closing cancels file operation and releases thread");
    for (auto* thread : window.findChildren<QThread*>()) require(!thread->isRunning(), "no running file thread after close");
    QTextStream(stdout) << "PASS PCAP import/export, details, filtering, cancellation, errors and session transitions\n";
    return 0;
}
