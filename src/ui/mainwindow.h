#pragma once

#include "../capture/device.h"
#include "../packet/packet.h"

#include <QHash>
#include <QMainWindow>
#include <deque>

class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;
class QTimer;
class QCloseEvent;
class CaptureWorker;
class QTreeWidget;
class QTableWidgetItem;
class PacketBytesView;

class MainWindow : public QMainWindow {
public:
    explicit MainWindow(QString helperPath = {});

private:
    void refreshDevices();
    void showSelectedDevice();
    void startCapture();
    void stopCapture();
    void drainPackets();
    void showSelectedPacket();
    void clearPacketDetails();
    void closeEvent(QCloseEvent* event) override;

    QVector<CaptureDevice> devices_;
    QComboBox* deviceSelector_;
    QLabel* details_;
    QPushButton* refresh_;
    QPushButton* start_;
    QPushButton* stop_;
    QTableWidget* table_;
    QTimer* timer_;
    CaptureWorker* worker_ = nullptr;
    quint64 packetCount_ = 0;
    bool closing_ = false;
    QString captureError_;
    QString helperPath_;
    QTreeWidget* protocolTree_;
    PacketBytesView* bytesView_;
    QLabel* summary_;
    struct StoredPacket {
        CapturedPacket packet;
        QTableWidgetItem* rowItem;
    };
    QHash<quint64, StoredPacket> packets_;
    std::deque<quint64> packetOrder_;
    qsizetype storedBytes_ = 0;
    quint64 selectedPacketId_ = 0;
};
