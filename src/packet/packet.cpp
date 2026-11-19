#include "packet.h"

#include <QDateTime>

QString packetTimestamp(const CapturedPacket& packet, bool includeDate)
{
    const auto base = QDateTime::fromMSecsSinceEpoch(packet.timestampUs / 1000)
        .toString(includeDate ? QStringLiteral("yyyy-MM-dd HH:mm:ss") : QStringLiteral("HH:mm:ss"));
    const auto fraction = packet.timestampUs % 1000000;
    if (packet.timestampSubMicroNs != 0) {
        return base + QStringLiteral(".%1").arg(fraction * 1000 + packet.timestampSubMicroNs, 9, 10, QLatin1Char('0'));
    }
    return base + QStringLiteral(".%1").arg(fraction, 6, 10, QLatin1Char('0'));
}
