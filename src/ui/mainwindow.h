#pragma once

#include "../capture/device.h"

#include <QMainWindow>

class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;
class QTimer;
class QCloseEvent;
class CaptureWorker;

class MainWindow : public QMainWindow {
public:
    explicit MainWindow(QString helperPath = {});

private:
    void refreshDevices();
    void showSelectedDevice();
    void startCapture();
    void stopCapture();
    void drainPackets();
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
};
