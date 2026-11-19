#include "displayfilter.h"

#include <arpa/inet.h>

namespace {
QByteArray normalizedAddress(const QString& text)
{
    const auto input = text.toLatin1();
    // inet_pton accepts C strings; reject embedded NULs and lossy conversions.
    if (input.contains('\0') || QString::fromLatin1(input) != text) return {};
    in_addr ipv4{};
    if (inet_pton(AF_INET, input.constData(), &ipv4) == 1) {
        return QByteArray(reinterpret_cast<const char*>(&ipv4), sizeof(ipv4));
    }
    in6_addr ipv6{};
    if (inet_pton(AF_INET6, input.constData(), &ipv6) == 1) {
        return QByteArray(reinterpret_cast<const char*>(&ipv6), sizeof(ipv6));
    }
    return {};
}
}

std::optional<DisplayFilter> DisplayFilter::create(const QString& protocol, const QString& address,
                                                   const QString& port, QString& error)
{
    error.clear();
    DisplayFilter filter;
    filter.protocol_ = protocol.trimmed().toUpper();
    const QStringList protocols{"TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6", "ARP", "IGMP"};
    if (!filter.protocol_.isEmpty()) {
        bool found = false;
        for (const auto& known : protocols) {
            if (filter.protocol_ == known.toUpper()) {
                filter.protocol_ = known;
                found = true;
                break;
            }
        }
        if (!found) {
            error = QStringLiteral("协议条件不正确");
            return std::nullopt;
        }
    }
    const auto ip = address.trimmed();
    if (!ip.isEmpty()) {
        filter.address_ = normalizedAddress(ip);
        if (filter.address_.isEmpty()) {
            error = QStringLiteral("IP 地址格式不正确");
            return std::nullopt;
        }
    }
    const auto portText = port.trimmed();
    if (!portText.isEmpty()) {
        bool digits = portText.size() <= 5;
        for (const auto character : portText) digits &= character >= QLatin1Char('0') && character <= QLatin1Char('9');
        bool valid = false;
        const auto number = portText.toUInt(&valid);
        if (!digits || !valid || number > 65535) {
            error = QStringLiteral("端口必须是 0 至 65535 的整数");
            return std::nullopt;
        }
        filter.port_ = quint16(number);
    }
    return filter;
}

bool DisplayFilter::matches(const ParsedPacket& packet) const
{
    if (!protocol_.isEmpty() && !packet.protocols.contains(protocol_)) return false;
    if (!address_.isEmpty() && normalizedAddress(packet.source) != address_
        && normalizedAddress(packet.destination) != address_) return false;
    if (port_ && packet.sourcePort != port_ && packet.destinationPort != port_) return false;
    return true;
}
