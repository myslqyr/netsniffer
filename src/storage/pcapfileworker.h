#pragma once

#include "pcapfile.h"

#include <QThread>

class PcapFileWorker : public QThread {
    Q_OBJECT
public:
    enum class Operation { Read, Write };
    PcapFileWorker(Operation operation, QString path, QVector<CapturedPacket> packets = {}, QObject* parent = nullptr);
    const PcapFile::Result& result() const { return result_; }
    Operation operation() const { return operation_; }
    const QString& path() const { return path_; }

signals:
    void progress(quint64 packetCount);

protected:
    void run() override;

private:
    Operation operation_;
    QString path_;
    QVector<CapturedPacket> packets_;
    PcapFile::Result result_;
};
