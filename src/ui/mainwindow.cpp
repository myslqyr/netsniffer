#include "mainwindow.h"
#include "../capture/captureworker.h"
#include "../parser/packetparser.h"
#include "packetbytesview.h"

#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QStatusBar>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QTimer>
#include <utility>

MainWindow::MainWindow(QString helperPath) : helperPath_(std::move(helperPath))
{
    setWindowTitle(QStringLiteral("网络嗅探器 · 实验 1A"));
    resize(1280, 900);

    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);
    auto* controls = new QHBoxLayout;
    controls->addWidget(new QLabel(QStringLiteral("捕获网卡："), central));
    deviceSelector_ = new QComboBox(central);
    controls->addWidget(deviceSelector_, 1);
    refresh_ = new QPushButton(QStringLiteral("刷新网卡"), central);
    controls->addWidget(refresh_);
    start_ = new QPushButton(QStringLiteral("开始抓包"), central);
    stop_ = new QPushButton(QStringLiteral("停止抓包"), central);
    stop_->setEnabled(false);
    controls->addWidget(start_);
    controls->addWidget(stop_);
    layout->addLayout(controls);

    details_ = new QLabel(central);
    details_->setTextFormat(Qt::PlainText);
    details_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    details_->setWordWrap(true);
    layout->addWidget(details_);
    auto* panes = new QSplitter(Qt::Vertical, central);
    panes->setChildrenCollapsible(false);
    auto* listPane = new QWidget(panes);
    auto* listLayout = new QVBoxLayout(listPane);
    listLayout->setContentsMargins(0, 0, 0, 0);
    table_ = new QTableWidget(0, 8, central);
    table_->setHorizontalHeaderLabels({QStringLiteral("序号"), QStringLiteral("捕获时间"),
                                      QStringLiteral("源地址"), QStringLiteral("目的地址"),
                                      QStringLiteral("协议"), QStringLiteral("捕获长度"),
                                      QStringLiteral("原始长度"), QStringLiteral("摘要")});
    table_->horizontalHeader()->setStretchLastSection(true);
    const int widths[] = {65, 145, 210, 210, 85, 85, 85, 400};
    for (int column = 0; column < 8; ++column) table_->setColumnWidth(column, widths[column]);
    table_->setWordWrap(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->verticalHeader()->hide();
    table_->setMinimumHeight(100);
    listLayout->addWidget(table_, 1);
    summary_ = new QLabel(listPane);
    summary_->setObjectName(QStringLiteral("packetSummary"));
    summary_->setTextFormat(Qt::PlainText);
    summary_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    summary_->setWordWrap(true);
    listLayout->addWidget(summary_);
    protocolTree_ = new QTreeWidget(panes);
    protocolTree_->setObjectName(QStringLiteral("protocolDetails"));
    protocolTree_->setHeaderLabels({QStringLiteral("协议 / 字段"), QStringLiteral("值")});
    protocolTree_->setColumnWidth(0, 300);
    protocolTree_->setMinimumHeight(90);
    bytesView_ = new PacketBytesView(panes);
    bytesView_->setMinimumHeight(90);
    panes->setSizes({300, 220, 180});
    panes->setStretchFactor(0, 3);
    panes->setStretchFactor(1, 2);
    panes->setStretchFactor(2, 2);
    layout->addWidget(panes, 1);
    connect(table_, &QTableWidget::itemSelectionChanged, this, &MainWindow::showSelectedPacket);
    connect(protocolTree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item) {
        bytesView_->highlightBytes(item && item->data(0, Qt::UserRole).isValid()
                                       ? item->data(0, Qt::UserRole).toLongLong() : -1,
                                   item ? item->data(0, Qt::UserRole + 1).toLongLong() : 0);
    });
    setCentralWidget(central);

    timer_ = new QTimer(this);
    timer_->setInterval(100);
    connect(timer_, &QTimer::timeout, this, &MainWindow::drainPackets);
    connect(start_, &QPushButton::clicked, this, &MainWindow::startCapture);
    connect(stop_, &QPushButton::clicked, this, &MainWindow::stopCapture);
    connect(refresh_, &QPushButton::clicked, this, &MainWindow::refreshDevices);
    connect(deviceSelector_, &QComboBox::currentIndexChanged,
            this, &MainWindow::showSelectedDevice);
    refreshDevices();
}

void MainWindow::refreshDevices()
{
    const QString previousName = deviceSelector_->currentData().toString();
    auto result = enumerateDevices();
    deviceSelector_->blockSignals(true);
    deviceSelector_->clear();
    devices_ = std::move(result.devices);
    for (const auto& device : devices_) {
        QString label = device.name;
        if (!device.description.isEmpty()) {
            label += QStringLiteral(" — ") + device.description;
        }
        deviceSelector_->addItem(label, device.name);
    }
    const int previousIndex = deviceSelector_->findData(previousName);
    if (previousIndex >= 0) {
        deviceSelector_->setCurrentIndex(previousIndex);
    }
    deviceSelector_->setEnabled(!devices_.isEmpty());
    start_->setEnabled(!devices_.isEmpty());
    deviceSelector_->blockSignals(false);
    showSelectedDevice();
    if (!result.error.isEmpty()) {
        details_->setText(QStringLiteral("网卡枚举失败：\n") + result.error);
        statusBar()->showMessage(QStringLiteral("无法读取网卡，请刷新重试"));
    } else {
        statusBar()->showMessage(QStringLiteral("发现 %1 个捕获设备").arg(devices_.size()));
    }
}

void MainWindow::startCapture()
{
    if (worker_ || deviceSelector_->currentIndex() < 0) {
        return;
    }
    table_->setRowCount(0);
    packets_.clear();
    packetOrder_.clear();
    storedBytes_ = 0;
    clearPacketDetails();
    packetCount_ = 0;
    captureError_.clear();
    worker_ = new CaptureWorker(deviceSelector_->currentData().toString(), this, helperPath_);
    deviceSelector_->setEnabled(false);
    refresh_->setEnabled(false);
    start_->setEnabled(false);
    stop_->setEnabled(true);
    statusBar()->showMessage(QStringLiteral("正在启动抓包…"));
    connect(worker_, &CaptureWorker::captureStarted, this, [this] {
        if (stop_->isEnabled()) {
            statusBar()->showMessage(QStringLiteral("正在抓包"));
        }
    });
    connect(worker_, &CaptureWorker::captureError, this, [this](const QString& error) {
        captureError_ = error;
        statusBar()->showMessage(QStringLiteral("抓包失败：") + error);
    });
    connect(worker_, &QThread::finished, this, [this] {
        drainPackets();
        timer_->stop();
        worker_->deleteLater();
        worker_ = nullptr;
        deviceSelector_->setEnabled(!devices_.isEmpty());
        refresh_->setEnabled(true);
        start_->setEnabled(!devices_.isEmpty());
        stop_->setEnabled(false);
        if (!captureError_.isEmpty()) {
            statusBar()->showMessage(QStringLiteral("抓包失败：") + captureError_);
        } else {
            statusBar()->showMessage(QStringLiteral("已停止，共接收 %1 个包").arg(packetCount_));
        }
        if (closing_) {
            close();
        }
    });
    timer_->start();
    worker_->start();
}

void MainWindow::stopCapture()
{
    if (worker_) {
        worker_->requestInterruption();
        stop_->setEnabled(false);
        statusBar()->showMessage(QStringLiteral("正在停止…"));
    }
}

void MainWindow::drainPackets()
{
    if (!worker_) {
        return;
    }
    const auto packets = worker_->takePackets();
    const QSignalBlocker selectionBlocker(table_);
    table_->setUpdatesEnabled(false);
    const bool sorting = table_->isSortingEnabled();
    table_->setSortingEnabled(false);
    // IDs stay stable when rows move; retain at most 2000 packets / 64 MiB of bytes.
    constexpr int maxRows = 2000;
    constexpr qsizetype maxBytes = 64 * 1024 * 1024;
    for (const auto& packet : packets) {
        const int row = table_->rowCount();
        table_->insertRow(row);
        const auto time = QDateTime::fromMSecsSinceEpoch(packet.timestampUs / 1000)
            .toString(QStringLiteral("HH:mm:ss"))
            + QStringLiteral(".%1").arg(packet.timestampUs % 1000000, 6, 10, QLatin1Char('0'));
        const auto parsed = parsePacket(packet);
        const QStringList values{QString::number(++packetCount_), time,
                                 parsed.source.isEmpty() ? QStringLiteral("—") : parsed.source,
                                 parsed.destination.isEmpty() ? QStringLiteral("—") : parsed.destination,
                                 parsed.protocol,
                                 QString::number(packet.capturedLength),
                                 QString::number(packet.originalLength), parsed.summary};
        for (int column = 0; column < values.size(); ++column) {
            auto* item = new QTableWidgetItem(values[column]);
            item->setToolTip(values[column]);
            table_->setItem(row, column, item);
        }
        auto* rowItem = table_->item(row, 0);
        rowItem->setData(Qt::UserRole, QVariant::fromValue(packetCount_));
        packets_.insert(packetCount_, {packet, rowItem});
        packetOrder_.push_back(packetCount_);
        storedBytes_ += packet.bytes.size();
        while (packetOrder_.size() > maxRows || storedBytes_ > maxBytes) {
            const auto id = packetOrder_.front();
            packetOrder_.pop_front();
            const auto oldest = packets_.find(id);
            storedBytes_ -= oldest->packet.bytes.size();
            table_->removeRow(table_->row(oldest->rowItem));
            packets_.erase(oldest);
        }
    }
    if (selectedPacketId_ != 0 && !packets_.contains(selectedPacketId_)) {
        table_->clearSelection();
        table_->setCurrentCell(-1, -1);
    }
    table_->setSortingEnabled(sorting);
    table_->setUpdatesEnabled(true);
    // Signals were blocked during insertion/eviction. Refresh once from stable IDs.
    showSelectedPacket();
    if (captureError_.isEmpty() && stop_->isEnabled()) {
        statusBar()->showMessage(QStringLiteral("正在抓包 · 接收 %1 · 队列丢弃 %2 · 显示 %3")
            .arg(packetCount_).arg(worker_->droppedPackets()).arg(table_->rowCount()));
    }
}

void MainWindow::clearPacketDetails()
{
    selectedPacketId_ = 0;
    protocolTree_->clear();
    bytesView_->setBytes({});
    summary_->clear();
}

void MainWindow::showSelectedPacket()
{
    const auto selection = table_->selectedItems();
    const auto* item = selection.isEmpty() ? nullptr : table_->item(selection.first()->row(), 0);
    const auto id = item ? item->data(Qt::UserRole).toULongLong() : 0;
    const auto stored = packets_.constFind(id);
    if (stored == packets_.cend()) {
        clearPacketDetails();
        return;
    }
    if (selectedPacketId_ == id) return;
    selectedPacketId_ = id;
    const auto parsed = parsePacket(stored->packet, true);
    summary_->setText(parsed.summary);
    const QSignalBlocker blocker(protocolTree_);
    protocolTree_->clear();
    bytesView_->setBytes(stored->packet.bytes);
    const auto addField = [&](const auto& self, const ProtocolField& field, QTreeWidgetItem* parent) -> void {
        auto* node = parent ? new QTreeWidgetItem(parent) : new QTreeWidgetItem(protocolTree_);
        node->setText(0, field.name);
        node->setText(1, field.value);
        node->setToolTip(1, field.value);
        if (field.offset >= 0 && field.length > 0) {
            node->setData(0, Qt::UserRole, qlonglong(field.offset));
            node->setData(0, Qt::UserRole + 1, qlonglong(field.length));
        }
        for (const auto& child : field.children) self(self, child, node);
    };
    for (const auto& field : parsed.fields) addField(addField, field, nullptr);
    protocolTree_->expandAll();
    protocolTree_->setCurrentItem(nullptr);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (worker_) {
        closing_ = true;
        event->ignore();
        stopCapture();
        return;
    }
    QMainWindow::closeEvent(event);
}

void MainWindow::showSelectedDevice()
{
    const int index = deviceSelector_->currentIndex();
    if (index < 0 || index >= devices_.size()) {
        details_->setText(QStringLiteral("没有可用的捕获设备，请检查网络环境后刷新。"));
        return;
    }
    const auto& device = devices_[index];
    details_->setText(QStringLiteral("名称：%1\n描述：%2\n回环设备：%3\nIP 地址：\n%4")
        .arg(device.name,
             device.description.isEmpty() ? QStringLiteral("未提供") : device.description,
             device.loopback ? QStringLiteral("是") : QStringLiteral("否"),
             device.addresses.isEmpty() ? QStringLiteral("未提供 IPv4/IPv6 地址")
                                        : device.addresses.join(QLatin1Char('\n'))));
}
