#include "packetparser.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <pcap/dlt.h>
#include <sys/socket.h>

namespace {
class Parser {
public:
    explicit Parser(const CapturedPacket& packet)
        : bytes_(packet.bytes), end_(std::min<qsizetype>(bytes_.size(), packet.capturedLength))
    {
        if (packet.capturedLength > packet.originalLength
            || qsizetype(packet.capturedLength) != bytes_.size()) {
            note(ParseStatus::Malformed, QStringLiteral("捕获长度记录异常"));
        }
        if (packet.capturedLength < packet.originalLength) {
            note(ParseStatus::Truncated, QStringLiteral("捕获数据截断"));
        }
    }

    ParsedPacket run(int linkType)
    {
        switch (linkType) {
        case DLT_EN10MB:
            ethernet();
            break;
        case DLT_LINUX_SLL:
            layer(QStringLiteral("Linux SLL"));
            if (need(0, 16, end_)) network(16, u16(14));
            break;
        case DLT_LINUX_SLL2:
            layer(QStringLiteral("Linux SLL2"));
            if (need(0, 20, end_)) network(20, u16(0));
            break;
        case DLT_NULL:
        case DLT_LOOP:
            loopback(linkType);
            break;
        case DLT_RAW:
            if (need(0, 1, end_)) {
                if ((u8(0) >> 4) == 4) ipv4(0);
                else if ((u8(0) >> 4) == 6) ipv6(0);
                else note(ParseStatus::Malformed, QStringLiteral("无效 IP 版本"));
            }
            break;
        case DLT_IPV4:
            ipv4(0);
            break;
        case DLT_IPV6:
            ipv6(0);
            break;
        default:
            note(ParseStatus::Unsupported, QStringLiteral("暂不支持链路类型 %1").arg(linkType));
            break;
        }
        if (result_.summary.isEmpty()) result_.summary = result_.protocol;
        if (!notes_.isEmpty()) result_.summary += QStringLiteral(" · ") + notes_.join(QStringLiteral(" · "));
        return result_;
    }

private:
    quint8 u8(qsizetype at) const { return static_cast<quint8>(bytes_[at]); }
    quint16 u16(qsizetype at) const { return (quint16(u8(at)) << 8) | u8(at + 1); }
    quint32 u32(qsizetype at) const { return (quint32(u16(at)) << 16) | u16(at + 2); }

    void note(ParseStatus status, const QString& text)
    {
        if (int(status) > int(result_.status)) result_.status = status;
        if (!notes_.contains(text)) notes_.append(text);
    }

    void layer(const QString& protocol)
    {
        result_.protocol = protocol;
        if (!result_.protocols.contains(protocol)) result_.protocols.append(protocol);
    }

    bool need(qsizetype at, qsizetype count, qsizetype end)
    {
        if (at < 0 || count < 0 || at > end || count > end - at) {
            note(ParseStatus::Truncated, QStringLiteral("协议头或数据截断"));
            return false;
        }
        return true;
    }

    QString ip(qsizetype at, int family) const
    {
        char text[INET6_ADDRSTRLEN] = {};
        inet_ntop(family, bytes_.constData() + at, text, sizeof(text));
        return QString::fromLatin1(text);
    }

    QString mac(qsizetype at) const
    {
        QStringList parts;
        for (int i = 0; i < 6; ++i) parts.append(QStringLiteral("%1").arg(u8(at + i), 2, 16, QLatin1Char('0')));
        return parts.join(QLatin1Char(':'));
    }

    void ethernet()
    {
        layer(QStringLiteral("Ethernet"));
        if (!need(0, 14, end_)) return;
        result_.sourceMac = mac(6);
        result_.destinationMac = mac(0);
        result_.source = result_.sourceMac;
        result_.destination = result_.destinationMac;
        network(14, u16(12));
    }

    void loopback(int type)
    {
        layer(QStringLiteral("Loopback"));
        if (!need(0, 4, end_)) return;
        quint32 family = 0;
        std::memcpy(&family, bytes_.constData(), sizeof(family));
        const auto known = [](quint32 value) {
            return value == 2 || value == 10 || value == 24 || value == 28 || value == 30;
        };
        if (type == DLT_LOOP || !known(family)) family = u32(0);
        if (family == 2) ipv4(4);
        else if (family == 10 || family == 24 || family == 28 || family == 30) ipv6(4);
        else note(ParseStatus::Unsupported, QStringLiteral("未知回环地址族 %1").arg(family));
    }

    void network(qsizetype offset, quint16 type)
    {
        int tags = 0;
        while (type == 0x8100 || type == 0x88a8 || type == 0x9100) {
            if (++tags > 4) {
                note(ParseStatus::Unsupported, QStringLiteral("VLAN 层数超出限制"));
                return;
            }
            layer(QStringLiteral("802.1Q"));
            if (!need(offset, 4, end_)) return;
            notes_.append(QStringLiteral("VLAN %1").arg(u16(offset) & 0x0fff));
            type = u16(offset + 2);
            offset += 4;
        }
        if (type == 0x0800) ipv4(offset);
        else if (type == 0x86dd) ipv6(offset);
        else if (type == 0x0806) arp(offset);
        else note(ParseStatus::Unsupported, QStringLiteral("EtherType 0x%1 暂不支持").arg(type, 4, 16, QLatin1Char('0')));
    }

    void ipv4(qsizetype offset)
    {
        layer(QStringLiteral("IPv4"));
        if (!need(offset, 20, end_)) return;
        const int headerLength = (u8(offset) & 0x0f) * 4;
        const int totalLength = u16(offset + 2);
        if ((u8(offset) >> 4) != 4 || headerLength < 20 || totalLength < headerLength) {
            note(ParseStatus::Malformed, QStringLiteral("无效 IPv4 版本或长度"));
            return;
        }
        result_.source = ip(offset + 12, AF_INET);
        result_.destination = ip(offset + 16, AF_INET);
        if (!need(offset, headerLength, end_)) return;
        if (totalLength > end_ - offset) note(ParseStatus::Truncated, QStringLiteral("IPv4 数据截断"));
        const auto end = std::min(end_, offset + totalLength);
        const auto fragment = u16(offset + 6);
        const int fragmentOffset = (fragment & 0x1fff) * 8;
        const bool more = (fragment & 0x2000) != 0;
        result_.fragmented = more || fragmentOffset != 0;
        if (result_.fragmented) {
            notes_.append(QStringLiteral("IPv4 分片 ID=%1 Offset=%2 MF=%3")
                .arg(u16(offset + 4)).arg(fragmentOffset).arg(more ? 1 : 0));
        }
        if (fragmentOffset != 0) return;
        transport(offset + headerLength, end, totalLength - headerLength, u8(offset + 9), more, false);
    }

    void ipv6(qsizetype offset)
    {
        layer(QStringLiteral("IPv6"));
        if (!need(offset, 40, end_)) return;
        if ((u8(offset) >> 4) != 6) {
            note(ParseStatus::Malformed, QStringLiteral("无效 IPv6 版本"));
            return;
        }
        result_.source = ip(offset + 8, AF_INET6);
        result_.destination = ip(offset + 24, AF_INET6);
        const int payloadLength = u16(offset + 4);
        int next = u8(offset + 6);
        if (payloadLength == 0 && next != 59) {
            note(ParseStatus::Unsupported, QStringLiteral("IPv6 零长度载荷或巨型报文暂不解析"));
            return;
        }
        const auto declaredEnd = offset + 40 + payloadLength;
        const auto end = std::min(end_, declaredEnd);
        if (declaredEnd > end_) note(ParseStatus::Truncated, QStringLiteral("IPv6 数据截断"));
        auto cursor = offset + 40;
        bool more = false;
        int extensions = 0;
        while (next == 0 || next == 43 || next == 60 || next == 51 || next == 44) {
            if (++extensions > 16) {
                note(ParseStatus::Unsupported, QStringLiteral("IPv6 扩展头数量超出限制"));
                return;
            }
            if (declaredEnd - cursor < 2) {
                note(ParseStatus::Malformed, QStringLiteral("IPv6 扩展头长度异常"));
                return;
            }
            if (!need(cursor, 2, end)) return;
            const int size = next == 44 ? 8 : next == 51 ? (u8(cursor + 1) + 2) * 4 : (u8(cursor + 1) + 1) * 8;
            if (size > declaredEnd - cursor || (next == 51 && size < 12)) {
                note(ParseStatus::Malformed, QStringLiteral("IPv6 扩展头长度异常"));
                return;
            }
            if (!need(cursor, size, end)) return;
            if (next == 44) {
                const auto fragment = u16(cursor + 2);
                const int fragmentOffset = fragment & 0xfff8;
                more = (fragment & 1) != 0;
                result_.fragmented = true;
                notes_.append(QStringLiteral("IPv6 分片 ID=%1 Offset=%2 M=%3")
                    .arg(u32(cursor + 4)).arg(fragmentOffset).arg(more ? 1 : 0));
                if (fragmentOffset != 0) return;
            }
            next = u8(cursor);
            cursor += size;
        }
        if (next == 59) {
            result_.summary = QStringLiteral("无下一头部");
            return;
        }
        transport(cursor, end, declaredEnd - cursor, next, more, true);
    }

    void transport(qsizetype offset, qsizetype end, qsizetype declaredLength,
                   int protocol, bool moreFragments, bool ipv6)
    {
        int minimum = 0;
        if (protocol == 6) { layer(QStringLiteral("TCP")); minimum = 20; }
        else if (protocol == 17) { layer(QStringLiteral("UDP")); minimum = 8; }
        else if (protocol == 1 && !ipv6) { layer(QStringLiteral("ICMP")); minimum = 4; }
        else if (protocol == 58 && ipv6) { layer(QStringLiteral("ICMPv6")); minimum = 4; }
        else {
            note(ParseStatus::Unsupported, protocol == 50 ? QStringLiteral("ESP 加密载荷")
                : QStringLiteral("上层协议 %1 暂不支持").arg(protocol));
            return;
        }
        const auto transportHeader = [&](qsizetype size) {
            if (declaredLength < size) {
                note(moreFragments ? ParseStatus::Unsupported : ParseStatus::Malformed,
                     moreFragments ? QStringLiteral("首片传输层头不完整，需分片重组")
                                   : QStringLiteral("传输层长度异常"));
                return false;
            }
            return need(offset, size, end);
        };
        if (!transportHeader(minimum)) return;
        if (protocol == 6 || protocol == 17) {
            if (protocol == 6) {
                const int size = (u8(offset + 12) >> 4) * 4;
                if (size < 20) {
                    note(ParseStatus::Malformed, QStringLiteral("TCP 头部长度异常"));
                    return;
                }
                if (!transportHeader(size)) return;
                QStringList flags;
                const char* names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
                for (int bit = 0; bit < 8; ++bit) {
                    if (u8(offset + 13) & (1 << bit)) flags.append(QString::fromLatin1(names[bit]));
                }
                const auto bits = u8(offset + 13);
                QString action;
                if (bits & 0x04) action = QStringLiteral("重置连接");
                else if (bits & 0x02) action = (bits & 0x10) ? QStringLiteral("回应连接请求") : QStringLiteral("发起连接");
                else if (bits & 0x01) action = QStringLiteral("结束本方向发送");
                else if (declaredLength > size) action = QStringLiteral("传输数据");
                else if (bits & 0x10) action = QStringLiteral("确认应答");
                else action = QStringLiteral("控制报文");
                result_.summary = QStringLiteral("源端口 %1 → 目的端口 %2；%3 [%4]；%5 %6 字节；序列号 %7")
                    .arg(u16(offset)).arg(u16(offset + 2)).arg(action,
                        flags.isEmpty() ? QStringLiteral("无标志") : flags.join(QStringLiteral(", ")),
                        moreFragments ? QStringLiteral("本分片载荷") : QStringLiteral("载荷"))
                    .arg(declaredLength - size).arg(u32(offset + 4));
                if (bits & 0x10) result_.summary += QStringLiteral("；确认号 %1").arg(u32(offset + 8));
                result_.summary += QStringLiteral("；通告窗口字段 %1 字节").arg(u16(offset + 14));
            } else {
                const int length = u16(offset + 4);
                if (length < 8 || (!moreFragments && length > declaredLength)) {
                    note(ParseStatus::Malformed, QStringLiteral("UDP 长度异常"));
                    return;
                }
                if (length > end - offset && !moreFragments) note(ParseStatus::Truncated, QStringLiteral("UDP 数据截断"));
                result_.summary = QStringLiteral("源端口 %1 → 目的端口 %2；%3 %4 字节；UDP 报文 %5 字节")
                    .arg(u16(offset)).arg(u16(offset + 2))
                    .arg(moreFragments ? QStringLiteral("重组后载荷") : QStringLiteral("载荷"))
                    .arg(length - 8).arg(length);
                if (u16(offset) == 5353 || u16(offset + 2) == 5353) {
                    result_.summary += QStringLiteral("；含 mDNS 常用端口（5353），内容未验证");
                }
            }
            result_.sourcePort = u16(offset);
            result_.destinationPort = u16(offset + 2);
        } else {
            const int type = u8(offset);
            const int code = u8(offset + 1);
            const bool request = ipv6 ? type == 128 : type == 8;
            const bool reply = ipv6 ? type == 129 : type == 0;
            if (request || reply) {
                if (!transportHeader(8)) return;
                result_.summary = QStringLiteral("%1；标识符 %2；序号 %3；代码 %4")
                    .arg(request ? QStringLiteral("回显请求（Ping 请求）") : QStringLiteral("回显应答（Ping 回复）"))
                    .arg(u16(offset + 4)).arg(u16(offset + 6)).arg(code);
            } else {
                QString meaning;
                if ((!ipv6 && type == 3) || (ipv6 && type == 1)) meaning = QStringLiteral("目的不可达");
                else if ((!ipv6 && type == 11) || (ipv6 && type == 3)) meaning = QStringLiteral("传输超时");
                else if (ipv6 && type == 2) meaning = QStringLiteral("数据包过大");
                else if (ipv6 && type == 135) meaning = QStringLiteral("邻居请求");
                else if (ipv6 && type == 136) meaning = QStringLiteral("邻居通告");
                else if (ipv6 && type == 133) meaning = QStringLiteral("路由器请求");
                else if (ipv6 && type == 134) meaning = QStringLiteral("路由器通告");
                else meaning = QStringLiteral("控制消息");
                result_.summary = QStringLiteral("%1；类型 %2；代码 %3").arg(meaning).arg(type).arg(code);
            }
        }
    }

    void arp(qsizetype offset)
    {
        layer(QStringLiteral("ARP"));
        if (!need(offset, 8, end_)) return;
        const int hardwareLength = u8(offset + 4);
        const int protocolLength = u8(offset + 5);
        if (hardwareLength == 0 || protocolLength == 0) {
            note(ParseStatus::Malformed, QStringLiteral("ARP 地址长度异常"));
            return;
        }
        if (!need(offset, 8 + 2 * (hardwareLength + protocolLength), end_)) return;
        if (u16(offset) != 1 || u16(offset + 2) != 0x0800 || hardwareLength != 6 || protocolLength != 4) {
            note(ParseStatus::Unsupported, QStringLiteral("暂不支持此 ARP 地址格式"));
            return;
        }
        result_.source = ip(offset + 14, AF_INET);
        result_.destination = ip(offset + 24, AF_INET);
        const int operation = u16(offset + 6);
        if (operation == 1) result_.summary = QStringLiteral("ARP 请求：%1 查询 %2 的 MAC 地址").arg(result_.source, result_.destination);
        else if (operation == 2) result_.summary = QStringLiteral("ARP 应答：%1 的 MAC 地址为 %2").arg(result_.source, mac(offset + 8));
        else result_.summary = QStringLiteral("ARP 操作码 %1").arg(operation);
    }

    const QByteArray& bytes_;
    qsizetype end_;
    ParsedPacket result_;
    QStringList notes_;
};
}

ParsedPacket parsePacket(const CapturedPacket& packet)
{
    return Parser(packet).run(packet.linkType);
}
