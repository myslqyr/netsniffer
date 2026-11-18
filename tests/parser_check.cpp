#include "parser/packetparser.h"

#include <QRandomGenerator>
#include <QTextStream>
#include <cstring>
#include <pcap/dlt.h>
#include <sys/socket.h>

namespace {
int checks = 0;
int failures = 0;

void check(bool valid, const char* name)
{
    ++checks;
    if (!valid) {
        ++failures;
        QTextStream(stderr) << "FAIL " << name << '\n';
    }
}

void put16(QByteArray& bytes, int at, int value)
{
    bytes[at] = char(value >> 8);
    bytes[at + 1] = char(value);
}

QByteArray ipv4(const QByteArray& payload, int protocol, int headerLength = 20)
{
    QByteArray header(headerLength, '\0');
    header[0] = char(0x40 | (headerLength / 4));
    put16(header, 2, headerLength + payload.size());
    header[8] = 64;
    header[9] = char(protocol);
    header.replace(12, 8, QByteArray::fromHex("0102030405060708"));
    return header + payload;
}

QByteArray ipv6(const QByteArray& payload, int protocol)
{
    QByteArray header(40, '\0');
    header[0] = 0x60;
    put16(header, 4, payload.size());
    header[6] = char(protocol);
    header[7] = 64;
    header.replace(8, 16, QByteArray::fromHex("20010db8000000000000000000000001"));
    header.replace(24, 16, QByteArray::fromHex("20010db8000000000000000000000002"));
    return header + payload;
}

ParsedPacket parse(const QByteArray& bytes, int link = DLT_RAW, int originalLength = -1)
{
    return parsePacket({0, quint32(bytes.size()),
        quint32(originalLength < 0 ? bytes.size() : originalLength), link, bytes}, true);
}

const ProtocolField* findField(const ParsedPacket& packet, const QString& group, const QString& name)
{
    for (const auto& parent : packet.fields) {
        if (parent.name != group) continue;
        for (const auto& child : parent.children) if (child.name == name) return &child;
    }
    return nullptr;
}

bool rangeIs(const ParsedPacket& packet, const QString& group, const QString& name,
             qsizetype offset, qsizetype length, const QString& value = {})
{
    const auto* field = findField(packet, group, name);
    return field && field->offset == offset && field->length == length
        && (value.isEmpty() || field->value == value);
}

bool validRanges(const QVector<ProtocolField>& fields, qsizetype capturedSize)
{
    for (const auto& field : fields) {
        if (field.offset >= 0 && (field.offset > capturedSize || field.length < 0
                                  || field.length > capturedSize - field.offset)) return false;
        if (!validRanges(field.children, capturedSize)) return false;
    }
    return true;
}
}

int main()
{
    const auto tcp = QByteArray::fromHex("3039005000000001000000005002200000000000");
    const auto udp = QByteArray::fromHex("04d2003500080000");
    const auto tcp4 = ipv4(tcp, 6);
    const auto ethernet = QByteArray::fromHex("00112233445566778899aabb0800") + tcp4;
    auto result = parse(ethernet, DLT_EN10MB);
    check(result.status == ParseStatus::Complete && result.protocol == "TCP"
        && result.source == "1.2.3.4" && result.destination == "5.6.7.8"
        && result.sourcePort == 12345 && result.destinationPort == 80
        && result.sourceMac == "66:77:88:99:aa:bb" && result.destinationMac == "00:11:22:33:44:55"
        && result.protocols == QStringList({"Ethernet", "IPv4", "TCP"})
        && result.summary.contains("SYN") && result.summary.contains("序列号 1"), "Ethernet IPv4 TCP SYN");
    check(rangeIs(result, "Ethernet II", "源 MAC 地址", 6, 6, "66:77:88:99:aa:bb")
        && rangeIs(result, "IPv4", "源 IP 地址", 26, 4, "1.2.3.4")
        && rangeIs(result, "TCP", "源端口", 34, 2, "12345")
        && rangeIs(result, "TCP", "标志位（低 8 位）", 47, 1), "Ethernet/IP/TCP byte ranges");
    check(parsePacket({0, quint32(ethernet.size()), quint32(ethernet.size()), DLT_EN10MB, ethernet}).fields.isEmpty(),
          "list parsing does not retain detail trees");

    auto tcpOptions = tcp;
    tcpOptions[12] = 0x60;
    tcpOptions.append(4, '\0');
    result = parse(ipv4(tcpOptions, 6, 24));
    check(result.status == ParseStatus::Complete && result.summary.contains("载荷 0 字节"), "variable IP and TCP headers");
    check(rangeIs(result, "IPv4", "IP 选项", 20, 4)
        && rangeIs(result, "TCP", "源端口", 24, 2)
        && rangeIs(result, "TCP", "TCP 选项", 44, 4), "variable header byte ranges");
    auto badTcp = tcp;
    badTcp[12] = 0x40;
    check(parse(ipv4(badTcp, 6)).status == ParseStatus::Malformed, "TCP invalid data offset");
    auto badIP = tcp4;
    badIP[0] = 0x44;
    check(parse(badIP).status == ParseStatus::Malformed, "IPv4 invalid IHL");
    badIP = tcp4;
    put16(badIP, 2, 19);
    check(parse(badIP).status == ParseStatus::Malformed, "IPv4 invalid total length");
    put16(badIP, 2, 20);
    check(parse(badIP).status == ParseStatus::Malformed, "IP padding not parsed as TCP header");
    check(parse(tcp4.left(30), DLT_RAW, 40).status == ParseStatus::Truncated, "truncated TCP capture");

    for (int length = 0; length < ethernet.size(); ++length) {
        check(parse(ethernet.left(length), DLT_EN10MB, ethernet.size()).status == ParseStatus::Truncated,
              "all truncated Ethernet/TCP prefixes");
    }
    auto fragment = tcp4;
    put16(fragment, 6, 1);
    result = parse(fragment);
    check(result.fragmented && result.protocol == "IPv4" && !result.sourcePort, "IPv4 noninitial fragment");
    auto firstFragment = ipv4(udp, 17);
    put16(firstFragment, 6, 0x2000);
    put16(firstFragment, 24, 100);
    result = parse(firstFragment);
    check(result.fragmented && result.status == ParseStatus::Complete && result.sourcePort == 1234,
          "first UDP fragment may declare full datagram length");
    firstFragment = ipv4(tcp.left(8), 6);
    put16(firstFragment, 6, 0x2000);
    check(parse(firstFragment).status == ParseStatus::Unsupported, "TCP header split across IP fragments");

    result = parse(ipv4(udp, 17));
    check(result.status == ParseStatus::Complete && result.protocol == "UDP" && result.sourcePort == 1234
        && result.destinationPort == 53 && result.summary.contains("载荷 0 字节"), "IPv4 UDP");
    auto mdns = udp;
    put16(mdns, 2, 5353);
    mdns.append(360, '\0');
    put16(mdns, 4, mdns.size());
    result = parse(ipv4(mdns, 17));
    check(result.protocol == "UDP" && result.summary.contains("源端口 1234 → 目的端口 5353")
        && result.summary.contains("载荷 360 字节") && result.summary.contains("UDP 报文 368 字节")
        && !result.summary.contains("mDNS") && !result.summary.contains("未验证"), "UDP summary contains factual packet fields only");
    result = parse(ipv4(QByteArray::fromHex("1600000000000000"), 2));
    check(result.protocol == "IGMP" && result.summary == QStringLiteral("IGMP；载荷 8 字节")
        && result.status == ParseStatus::Unsupported, "IGMP protocol identity without implementation commentary");
    result = parse(ipv4(udp, 253));
    check(result.summary == QStringLiteral("IP 协议 253；载荷 8 字节")
        && !result.summary.contains("暂不支持"), "unknown IP protocol retains numeric identity");
    auto ack = tcp;
    ack[13] = 0x10;
    check(parse(ipv4(ack, 6)).summary.contains("确认应答 [ACK]"), "TCP ACK intent");
    check(!parse(tcp4).summary.contains("确认号"), "SYN does not claim an effective acknowledgment number");
    auto badUdp = udp;
    put16(badUdp, 4, 7);
    check(parse(ipv4(badUdp, 17)).status == ParseStatus::Malformed, "UDP too short");
    put16(badUdp, 4, 100);
    check(parse(ipv4(badUdp, 17)).status == ParseStatus::Malformed, "UDP exceeds IP payload");

    result = parse(ipv4(QByteArray::fromHex("0800000012340001"), 1));
    check(result.status == ParseStatus::Complete && result.protocol == "ICMP"
        && result.summary.contains("Ping 请求") && result.summary.contains("标识符 4660"), "ICMP echo request");
    check(parse(ipv4(QByteArray::fromHex("03010000"), 1)).summary.contains("目的不可达；类型 3；代码 1"), "ICMP other types");
    check(parse(ipv4(QByteArray::fromHex("08000000"), 1)).status == ParseStatus::Malformed, "short ICMP echo");

    result = parse(ipv6(udp, 17));
    check(result.status == ParseStatus::Complete && result.protocol == "UDP"
        && result.source == "2001:db8::1" && result.destination == "2001:db8::2"
        && result.protocols.contains("IPv6"), "IPv6 UDP");
    check(rangeIs(result, "IPv6", "源 IP 地址", 8, 16, "2001:db8::1")
        && rangeIs(result, "UDP", "目的端口", 42, 2, "53"), "IPv6 byte ranges");
    result = parse(ipv6(QByteArray::fromHex("8100000012340001"), 58));
    check(result.protocol == "ICMPv6" && result.summary.contains("Ping 回复"), "ICMPv6 echo reply");
    check(parse(ipv6(tcp, 6)).protocol == "TCP", "IPv6 TCP");
    check(parse(ipv6({}, 59)).status == ParseStatus::Complete, "IPv6 no next header");
    check(parse(ipv6({}, 0)).status == ParseStatus::Unsupported, "IPv6 jumbogram unsupported");
    auto extension = QByteArray::fromHex("1100000000000000");
    result = parse(ipv6(extension + udp, 0));
    check(result.status == ParseStatus::Complete && result.destinationPort == 53, "IPv6 hop-by-hop traversal");
    check(rangeIs(result, "IPv6 扩展头：逐跳选项", "下一头部", 40, 1, "17")
        && rangeIs(result, "UDP", "源端口", 48, 2), "IPv6 extension byte ranges");
    extension[1] = 2;
    check(parse(ipv6(extension + udp, 0)).status == ParseStatus::Malformed, "IPv6 extension exceeds declared length");
    auto fragment6 = QByteArray::fromHex("1100000900000001");
    result = parse(ipv6(fragment6 + udp, 44));
    check(result.fragmented && result.protocol == "IPv6" && !result.sourcePort, "IPv6 noninitial fragment");
    fragment6[3] = 0;
    result = parse(ipv6(fragment6 + udp, 44));
    check(result.fragmented && result.protocol == "UDP", "IPv6 atomic fragment");
    QByteArray extensions;
    for (int index = 0; index < 17; ++index) extensions += QByteArray(8, '\0');
    check(parse(ipv6(extensions, 0)).status == ParseStatus::Unsupported, "IPv6 extension traversal bound");
    check(parse(ipv6(udp, 50)).status == ParseStatus::Unsupported, "ESP opaque payload");

    auto vlan = ethernet;
    vlan.replace(12, 2, QByteArray::fromHex("8100002a0800"));
    result = parse(vlan, DLT_EN10MB);
    check(result.protocol == "TCP" && result.summary.contains("VLAN 42"), "VLAN Ethernet");
    check(rangeIs(result, "802.1Q VLAN", "VLAN ID", 14, 2, "42")
        && rangeIs(result, "IPv4", "源 IP 地址", 30, 4), "VLAN byte ranges");
    QByteArray sll(16, '\0');
    put16(sll, 14, 0x0800);
    check(parse(sll + tcp4, DLT_LINUX_SLL).sourcePort == 12345, "Linux SLL");
    QByteArray sll2(20, '\0');
    put16(sll2, 0, 0x86dd);
    result = parse(sll2 + ipv6(udp, 17), DLT_LINUX_SLL2);
    check(result.destinationPort == 53, "Linux SLL2 any device");
    check(rangeIs(result, "Linux SLL2", "协议类型", 0, 2, "0x86dd")
        && rangeIs(result, "IPv6", "源 IP 地址", 28, 16), "SLL2 byte ranges");
    quint32 family = AF_INET;
    QByteArray nullHeader(reinterpret_cast<const char*>(&family), sizeof(family));
    check(parse(nullHeader + tcp4, DLT_NULL).sourcePort == 12345, "native loopback header");
    check(parse(QByteArray::fromHex("00000002") + tcp4, DLT_LOOP).sourcePort == 12345, "network-order loopback header");
    check(parse(tcp4, DLT_IPV4).protocol == "TCP", "dedicated IPv4 link type");
    check(parse(ipv6(udp, 17), DLT_IPV6).protocol == "UDP", "dedicated IPv6 link type");

    const auto arp = QByteArray::fromHex("00112233445566778899aabb0806"
        "000108000604000166778899aabb0102030400000000000005060708");
    result = parse(arp, DLT_EN10MB);
    check(result.status == ParseStatus::Complete && result.protocol == "ARP"
        && result.source == "1.2.3.4" && result.destination == "5.6.7.8"
        && result.summary.contains("查询 5.6.7.8 的 MAC 地址"), "ARP request");
    check(rangeIs(result, "ARP", "发送方 IP 地址", 28, 4, "1.2.3.4")
        && rangeIs(result, "ARP", "目标 IP 地址", 38, 4, "5.6.7.8"), "ARP byte ranges");
    auto arpReply = arp;
    put16(arpReply, 20, 2);
    check(parse(arpReply, DLT_EN10MB).summary.contains("MAC 地址为 66:77:88:99:aa:bb"), "ARP reply");
    check(parse(ethernet, 99999).status == ParseStatus::Unsupported, "unknown link type");
    auto unknownEthernet = ethernet;
    put16(unknownEthernet, 12, 0x1234);
    check(parse(unknownEthernet, DLT_EN10MB).status == ParseStatus::Unsupported, "unknown EtherType");
    check(parsePacket({0, 100, 100, DLT_EN10MB, QByteArray(1, '\0')}).status == ParseStatus::Malformed,
          "inconsistent captured byte count");

    // Exercise bounded reads on deterministic random data across supported link types.
    QRandomGenerator random(12345);
    const int links[] = {DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_NULL, DLT_LOOP, DLT_RAW, DLT_IPV4, DLT_IPV6};
    for (int sample = 0; sample < 4000; ++sample) {
        QByteArray bytes(random.bounded(128), '\0');
        for (auto& byte : bytes) byte = char(random.generate());
        check(validRanges(parse(bytes, links[sample % 8]).fields, bytes.size()), "random input detail bounds");
    }
    QTextStream(stdout) << "checks=" << checks << " failures=" << failures << " random_inputs=4000\n";
    return failures == 0 ? 0 : 1;
}
