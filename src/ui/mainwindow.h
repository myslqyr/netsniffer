#pragma once

#include "../capture/device.h"
#include "../packet/packet.h"
#include "../filter/displayfilter.h"

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
class QLineEdit;
class PcapFileWorker;

class MainWindow : public QMainWindow {
public:
    explicit MainWindow(QString helperPath = {});
    bool openPcapFile(const QString& path);
    bool savePcapFile(const QString& path);

private:
    void refreshDevices();
    void showSelectedDevice();
    void startCapture();
    void stopCapture();
    void drainPackets();
    void showSelectedPacket();
    void clearPacketDetails();
    void applyDisplayFilter();
    void refreshDisplayFilter();
    void updateCaptureStatus();
    void appendPackets(const QVector<CapturedPacket>& packets);
    void resetPackets();
    void startFileOperation(PcapFileWorker* operation);
    void setFileBusy(bool busy);
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
        ParsedPacket parsed;
    };
    QHash<quint64, StoredPacket> packets_;
    std::deque<quint64> packetOrder_;
    qsizetype storedBytes_ = 0;
    quint64 selectedPacketId_ = 0;
    QComboBox* protocolFilter_;
    QLineEdit* addressFilter_;
    QLineEdit* portFilter_;
    QLineEdit* captureFilter_;
    QLabel* filterError_;
    DisplayFilter displayFilter_;
    int visiblePacketCount_ = 0;
    quint64 lastDroppedPackets_ = 0;
    bool updatingPackets_ = false;
    bool captureReady_ = false;
    QPushButton* openFile_;
    QPushButton* saveFile_;
    QPushButton* cancelFile_;
    PcapFileWorker* fileWorker_ = nullptr;
    quint64 fileProgress_ = 0;
    QString sourcePath_;
    QString fileError_;
    QString fileNotice_;
};
