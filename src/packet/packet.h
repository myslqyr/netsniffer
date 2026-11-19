#pragma once

#include <QByteArray>
#include <QString>

struct CapturedPacket {
    qint64 timestampUs = 0;
    quint32 capturedLength = 0;
    quint32 originalLength = 0;
    int linkType = 0;
    QByteArray bytes;
    quint16 timestampSubMicroNs = 0;
};

QString packetTimestamp(const CapturedPacket& packet, bool includeDate = false);
