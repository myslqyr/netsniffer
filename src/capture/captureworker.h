#pragma once

#include "../packet/packet.h"
#include <QMutex>
#include <QThread>
#include <QVector>

class CaptureWorker : public QThread {
    Q_OBJECT
public:
    explicit CaptureWorker(QString device, QObject* parent = nullptr, QString helperPath = {},
                           QString captureFilter = {});
    QVector<CapturedPacket> takePackets();
    quint64 droppedPackets();

signals:
    void captureStarted();
    void captureError(const QString& message);

protected:
    void run() override;

private:
    QString device_;
    QString helperPath_;
    QString captureFilter_;
    QMutex mutex_;
    QVector<CapturedPacket> pending_;
    quint64 dropped_ = 0;
};
