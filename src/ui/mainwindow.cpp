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
#include <QLineEdit>
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
    deviceSelector_->setObjectName(QStringLiteral("captureDevice"));
    controls->addWidget(deviceSelector_, 1);
    refresh_ = new QPushButton(QStringLiteral("刷新网卡"), central);
    controls->addWidget(refresh_);
    start_ = new QPushButton(QStringLiteral("开始抓包"), central);
    stop_ = new QPushButton(QStringLiteral("停止抓包"), central);
    stop_->setEnabled(false);
    controls->addWidget(start_);
    controls->addWidget(stop_);
    layout->addLayout(controls);

    auto* captureControls = new QHBoxLayout;
    captureControls->addWidget(new QLabel(QStringLiteral("捕获过滤："), central));
    captureFilter_ = new QLineEdit(central);
    captureFilter_->setObjectName(QStringLiteral("captureFilter"));
    captureFilter_->setMaxLength(4096);
    captureControls->addWidget(captureFilter_, 1);
    layout->addLayout(captureControls);

    auto* displayControls = new QHBoxLayout;
    displayControls->addWidget(new QLabel(QStringLiteral("显示过滤："), central));
    protocolFilter_ = new QComboBox(central);
    protocolFilter_->setObjectName(QStringLiteral("protocolFilter"));
    protocolFilter_->addItem(QStringLiteral("全部协议"), QString());
    for (const auto& protocol : {"TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6", "ARP", "IGMP"}) {
        protocolFilter_->addItem(QString::fromLatin1(protocol), QString::fromLatin1(protocol));
    }
    displayControls->addWidget(protocolFilter_);
    displayControls->addWidget(new QLabel(QStringLiteral("IP 地址："), central));
    addressFilter_ = new QLineEdit(central);
    addressFilter_->setObjectName(QStringLiteral("addressFilter"));
    addressFilter_->setMaxLength(64);
    displayControls->addWidget(addressFilter_, 1);
    displayControls->addWidget(new QLabel(QStringLiteral("端口："), central));
    portFilter_ = new QLineEdit(central);
    portFilter_->setObjectName(QStringLiteral("portFilter"));
    portFilter_->setMaxLength(10);
    portFilter_->setMaximumWidth(100);
    displayControls->addWidget(portFilter_);
    auto* apply = new QPushButton(QStringLiteral("应用"), central);
    apply->setObjectName(QStringLiteral("applyDisplayFilter"));
    auto* clear = new QPushButton(QStringLiteral("清除"), central);
    clear->setObjectName(QStringLiteral("clearDisplayFilter"));
    displayControls->addWidget(apply);
    displayControls->addWidget(clear);
    layout->addLayout(displayControls);
    filterError_ = new QLabel(central);
    filterError_->setObjectName(QStringLiteral("filterError"));
    filterError_->setTextFormat(Qt::PlainText);
    filterError_->hide();
    layout->addWidget(filterError_);
    connect(apply, &QPushButton::clicked, this, &MainWindow::applyDisplayFilter);
    connect(addressFilter_, &QLineEdit::returnPressed, this, &MainWindow::applyDisplayFilter);
    connect(portFilter_, &QLineEdit::returnPressed, this, &MainWindow::applyDisplayFilter);
    connect(protocolFilter_, &QComboBox::currentIndexChanged, this, &MainWindow::applyDisplayFilter);
    connect(clear, &QPushButton::clicked, this, [this] {
        const QSignalBlocker blocker(protocolFilter_);
        protocolFilter_->setCurrentIndex(0);
        addressFilter_->clear();
        portFilter_->clear();
        applyDisplayFilter();
    });

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
    connect(table_->model(), &QAbstractItemModel::layoutChanged, this, [this] {
        if (!updatingPackets_) refreshDisplayFilter();
    });
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
    visiblePacketCount_ = 0;
    lastDroppedPackets_ = 0;
    captureReady_ = false;
    captureError_.clear();
    worker_ = new CaptureWorker(deviceSelector_->currentData().toString(), this, helperPath_, captureFilter_->text());
    captureFilter_->setEnabled(false);
    deviceSelector_->setEnabled(false);
    refresh_->setEnabled(false);
    start_->setEnabled(false);
    stop_->setEnabled(true);
    statusBar()->showMessage(QStringLiteral("正在启动抓包…"));
    connect(worker_, &CaptureWorker::captureStarted, this, [this] {
        captureReady_ = true;
        if (stop_->isEnabled()) {
            updateCaptureStatus();
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
        captureReady_ = false;
        captureFilter_->setEnabled(true);
        deviceSelector_->setEnabled(!devices_.isEmpty());
        refresh_->setEnabled(true);
        start_->setEnabled(!devices_.isEmpty());
        stop_->setEnabled(false);
        updateCaptureStatus();
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
    lastDroppedPackets_ = worker_->droppedPackets();
    if (packets.isEmpty()) return;
    const QSignalBlocker selectionBlocker(table_);
    updatingPackets_ = true;
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
        packets_.insert(packetCount_, {packet, rowItem, parsed});
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
    updatingPackets_ = false;
    table_->setUpdatesEnabled(true);
    // Signals were blocked during insertion/eviction. Refresh once from stable IDs.
    refreshDisplayFilter();
}

void MainWindow::applyDisplayFilter()
{
    QString error;
    auto next = DisplayFilter::create(protocolFilter_->currentData().toString(),
                                      addressFilter_->text(), portFilter_->text(), error);
    filterError_->setText(error);
    filterError_->setVisible(!error.isEmpty());
    if (!next) return;
    displayFilter_ = std::move(*next);
    refreshDisplayFilter();
}

void MainWindow::refreshDisplayFilter()
{
    const QSignalBlocker blocker(table_);
    visiblePacketCount_ = 0;
    for (int row = 0; row < table_->rowCount(); ++row) {
        const auto id = table_->item(row, 0)->data(Qt::UserRole).toULongLong();
        const auto stored = packets_.constFind(id);
        const bool visible = stored != packets_.cend() && displayFilter_.matches(stored->parsed);
        table_->setRowHidden(row, !visible);
        if (visible) ++visiblePacketCount_;
    }
    const auto selected = table_->selectedItems();
    if (!selected.isEmpty() && table_->isRowHidden(selected.first()->row())) {
        table_->clearSelection();
        table_->setCurrentCell(-1, -1);
    }
    showSelectedPacket();
    updateCaptureStatus();
}

void MainWindow::updateCaptureStatus()
{
    if (!captureError_.isEmpty()) {
        statusBar()->showMessage(QStringLiteral("抓包失败：") + captureError_);
        return;
    }
    const auto state = !worker_ ? QStringLiteral("已停止") : !stop_->isEnabled() ? QStringLiteral("正在停止…")
        : captureReady_ ? QStringLiteral("正在抓包") : QStringLiteral("正在启动抓包…");
    statusBar()->showMessage(QStringLiteral("%1 · 接收 %2 · 缓存 %3 · 显示 %4 · 队列丢弃 %5")
        .arg(state).arg(packetCount_).arg(packets_.size()).arg(visiblePacketCount_).arg(lastDroppedPackets_));
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
