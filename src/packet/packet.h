#pragma once

#include <QByteArray>

struct CapturedPacket {
    qint64 timestampUs = 0;
    quint32 capturedLength = 0;
    quint32 originalLength = 0;
    int linkType = 0;
    QByteArray bytes;
};
