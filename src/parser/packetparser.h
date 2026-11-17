#pragma once

#include "../packet/packet.h"

#include <QString>
#include <QStringList>
#include <optional>

enum class ParseStatus { Complete, Unsupported, Truncated, Malformed };

struct ParsedPacket {
    QString source;
    QString destination;
    QString sourceMac;
    QString destinationMac;
    std::optional<quint16> sourcePort;
    std::optional<quint16> destinationPort;
    QString protocol = QStringLiteral("未知");
    QStringList protocols;
    QString summary;
    ParseStatus status = ParseStatus::Complete;
    bool fragmented = false;
};

ParsedPacket parsePacket(const CapturedPacket& packet);
