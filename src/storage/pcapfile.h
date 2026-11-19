#pragma once

#include "../packet/packet.h"

#include <QVector>
#include <functional>

namespace PcapFile {
constexpr qsizetype maxCachedPackets = 2000;
constexpr qsizetype maxCachedBytes = 64 * 1024 * 1024;
constexpr quint32 maxPacketBytes = 256 * 1024;

struct Result {
    QVector<CapturedPacket> packets;
    quint64 packetCount = 0;
    QString error;
    bool cancelled = false;
};

using Cancelled = std::function<bool()>;
using Progress = std::function<void(quint64)>;

Result read(const QString& path, const Cancelled& cancelled = {}, const Progress& progress = {});
Result write(const QString& path, const QVector<CapturedPacket>& packets,
             const Cancelled& cancelled = {}, const Progress& progress = {});
}
