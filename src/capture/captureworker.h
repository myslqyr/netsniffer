#pragma once

#include <QByteArray>
#include <QMutex>
#include <QThread>
#include <QVector>

struct CapturedPacket {
    qint64 timestampUs;
    quint32 capturedLength;
    quint32 originalLength;
    int linkType;
    QByteArray bytes;
};

class CaptureWorker : public QThread {
    Q_OBJECT
public:
    explicit CaptureWorker(QString device, QObject* parent = nullptr, QString helperPath = {});
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
    QMutex mutex_;
    QVector<CapturedPacket> pending_;
    quint64 dropped_ = 0;
};
