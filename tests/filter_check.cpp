#include "filter/displayfilter.h"
#include "capture/capturefilter.h"

#include <QTextStream>
#include <memory>

static int checks = 0;
static int failures = 0;

static void check(bool valid, const char* name)
{
    ++checks;
    if (!valid) {
        ++failures;
        QTextStream(stderr) << "FAIL " << name << '\n';
    }
}

int main()
{
    const auto tcp = QByteArray::fromHex("00112233445566778899aabb0800"
        "4500002800010000400600000102030405060708"
        "3039005000000001000000005002200000000000");
    const auto udp = QByteArray::fromHex("00112233445566778899aabb86dd"
        "6000000000081140"
        "20010db8000000000000000000000001"
        "20010db8000000000000000000000002"
        "04d214e900080000");
    const auto parse = [](const QByteArray& bytes) {
        return parsePacket({0, quint32(bytes.size()), quint32(bytes.size()), DLT_EN10MB, bytes});
    };
    const auto tcpPacket = parse(tcp);
    const auto udpPacket = parse(udp);
    QString error;
    auto filter = DisplayFilter::create({}, {}, {}, error);
    check(filter && filter->matches(tcpPacket) && filter->matches(udpPacket), "empty display filter");
    filter = DisplayFilter::create("TCP", "1.2.3.4", "80", error);
    check(filter && filter->matches(tcpPacket) && !filter->matches(udpPacket), "protocol/IP/port use AND semantics");
    filter = DisplayFilter::create("IPv4", "5.6.7.8", "12345", error);
    check(filter && filter->matches(tcpPacket), "layer and either endpoint matching");
    filter = DisplayFilter::create("ipv6", "2001:0DB8:0000:0000:0000:0000:0000:0001", "5353", error);
    check(filter && filter->matches(udpPacket) && !filter->matches(tcpPacket), "IPv6 canonical binary matching");
    filter = DisplayFilter::create("UDP", {}, "0", error);
    auto zeroPort = udpPacket;
    zeroPort.sourcePort = 0;
    auto noPorts = udpPacket;
    noPorts.sourcePort.reset();
    noPorts.destinationPort.reset();
    check(filter && filter->matches(zeroPort) && !filter->matches(noPorts), "port zero differs from absent port");
    filter = DisplayFilter::create("TCP", {}, "5353", error);
    check(filter && !filter->matches(tcpPacket) && !filter->matches(udpPacket), "combined conditions may match nothing");
    for (const auto& address : {"1.2.3.999", "2001:::1", "00:11:22:33:44:55", "127.0.0.1/24"}) {
        check(!DisplayFilter::create({}, address, {}, error) && !error.isEmpty(), "reject invalid IP condition");
    }
    for (const auto& port : {"-1", "+53", "65536", "1.5", "80 or 443", "abc"}) {
        check(!DisplayFilter::create({}, {}, port, error) && !error.isEmpty(), "reject invalid port condition");
    }
    check(!DisplayFilter::create("nonsense", {}, {}, error), "reject unsupported filter protocol");
    filter = DisplayFilter::create(" ICMPv6 ", {}, {}, error);
    auto control = udpPacket;
    control.protocols = {"IPv6", "ICMPv6"};
    check(filter && filter->matches(control) && error.isEmpty(), "ICMPv6 filter and error reset");

    std::unique_ptr<pcap_t, decltype(&pcap_close)> dead(pcap_open_dead(DLT_EN10MB, 65535), &pcap_close);
    check(bool(dead), "create offline BPF context");
    if (!dead) return 1;
    CaptureFilter bpf;
    std::string bpfError;
    const auto accepts = [&](const QByteArray& bytes) {
        pcap_pkthdr header{};
        header.caplen = bytes.size();
        header.len = bytes.size();
        return bpf.program() && pcap_offline_filter(bpf.program(), &header,
            reinterpret_cast<const unsigned char*>(bytes.constData())) != 0;
    };
    check(bpf.compile(dead.get(), "tcp and (port 80 or port 443)", bpfError)
        && accepts(tcp) && !accepts(udp), "BPF TCP logical expression");
    check(bpf.compile(dead.get(), "ip6 and udp port 5353", bpfError)
        && accepts(udp) && !accepts(tcp), "BPF IPv6 UDP port");
    check(bpf.compile(dead.get(), "host 1.2.3.4", bpfError)
        && accepts(tcp) && !accepts(udp), "BPF address filter");
    check(bpf.compile(dead.get(), "tcp and port 81", bpfError)
        && !accepts(tcp) && !accepts(udp), "BPF empty match set");
    check(!bpf.compile(dead.get(), "tcp and (", bpfError) && !bpfError.empty()
        && !bpf.program(), "invalid expression discards previous compiled code");
    check(!bpf.compile(dead.get(), std::string(4097, 't'), bpfError), "bounded BPF expression");
    check(!bpf.compile(dead.get(), std::string("tcp\0or udp", 10), bpfError), "reject embedded NUL");
    check(bpf.compile(dead.get(), "", bpfError) && accepts(tcp) && accepts(udp), "empty BPF matches all");
    check(!bpf.install(dead.get(), bpfError) && !bpfError.empty(), "report BPF installation failure");
    QTextStream(stdout) << "checks=" << checks << " failures=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
