#pragma once

#include "../parser/packetparser.h"

#include <optional>

class DisplayFilter {
public:
    static std::optional<DisplayFilter> create(const QString& protocol, const QString& address,
                                               const QString& port, QString& error);
    bool matches(const ParsedPacket& packet) const;

private:
    QString protocol_;
    QByteArray address_;
    std::optional<quint16> port_;
};
