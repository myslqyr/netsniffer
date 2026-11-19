#include "storage/pcapfile.h"
#include "parser/packetparser.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QFile>
#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTextStream>
#include <pcap/dlt.h>

static int failures = 0;
static int checks = 0;

static void check(bool valid, const char* name)
{
    ++checks;
    if (!valid) {
        ++failures;
        QTextStream(stderr) << "FAIL " << name << '\n';
    }
}

static QByteArray readAll(const QString& path)
{
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

static void putFile(const QString& path, const QByteArray& bytes)
{
    QFile file(path);
    check(file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size(), "prepare test file");
}

static QByteArray independentPcap(const QVector<CapturedPacket>& packets, bool nano, bool little,
                                  quint32 snapshot = 65535, quint32 linkType = 1)
{
    QByteArray bytes;
    QDataStream data(&bytes, QIODevice::WriteOnly);
    data.setByteOrder(little ? QDataStream::LittleEndian : QDataStream::BigEndian);
    data << quint32(nano ? 0xa1b23c4d : 0xa1b2c3d4) << quint16(2) << quint16(4)
         << quint32(0) << quint32(0) << snapshot << linkType;
    for (const auto& packet : packets) {
        const auto fraction = packet.timestampUs % 1000000;
        data << quint32(packet.timestampUs / 1000000)
             << quint32(nano ? fraction * 1000 + packet.timestampSubMicroNs : fraction)
             << packet.capturedLength << packet.originalLength;
        data.writeRawData(packet.bytes.constData(), packet.bytes.size());
    }
    return bytes;
}

static bool samePacket(const CapturedPacket& left, const CapturedPacket& right)
{
    return left.timestampUs == right.timestampUs && left.timestampSubMicroNs == right.timestampSubMicroNs
        && left.linkType == right.linkType && left.capturedLength == right.capturedLength
        && left.originalLength == right.originalLength && left.bytes == right.bytes;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir directory;
    check(directory.isValid(), "temporary directory");
    if (!directory.isValid()) return 1;
    const auto tcp = QByteArray::fromHex("00112233445566778899aabb0800"
        "4500002800010000400600000102030405060708"
        "3039005000000001000000005002200000000000");
    const CapturedPacket first{1700000000123456, quint32(tcp.size()), quint32(tcp.size()), DLT_EN10MB, tcp};
    auto second = first;
    second.timestampUs += 1234567;
    second.originalLength += 10;
    second.timestampSubMicroNs = 789;
    const QVector<CapturedPacket> records{first, second};
    const auto path = directory.filePath(QStringLiteral("测试 capture.pcap"));
    auto result = PcapFile::write(path, records);
    check(result.error.isEmpty() && result.packetCount == 2 && !result.cancelled, "save PCAP");
    result = PcapFile::read(path);
    check(result.error.isEmpty() && result.packetCount == 2 && result.packets.size() == 2
        && samePacket(result.packets[0], first) && samePacket(result.packets[1], second), "raw bytes, lengths and nanoseconds round trip");
    check(packetTimestamp(second).endsWith(QStringLiteral(".358023789")), "nanosecond timestamp display");
    check(packetTimestamp(first).endsWith(QStringLiteral(".123456")), "live microsecond timestamp display unchanged");
    check(parsePacket(result.packets.first()).sourcePort == 12345, "import reuses protocol parsing");

    const auto tcpdump = QStandardPaths::findExecutable(QStringLiteral("tcpdump"));
    if (!tcpdump.isEmpty()) {
        QProcess reader;
        reader.start(tcpdump, {QStringLiteral("-nn"), QStringLiteral("-r"), path});
        const bool success = reader.waitForStarted() && reader.waitForFinished(5000)
            && reader.exitStatus() == QProcess::NormalExit && reader.exitCode() == 0;
        check(success && reader.readAllStandardOutput().contains("1.2.3.4.12345 > 5.6.7.8.80"), "independent tcpdump interoperability");
    }

    for (const bool nano : {false, true}) {
        for (const bool little : {false, true}) {
            const auto file = directory.filePath(QStringLiteral("external-%1-%2.pcap").arg(nano).arg(little));
            putFile(file, independentPcap(records, nano, little));
            result = PcapFile::read(file);
            auto expected = second;
            if (!nano) expected.timestampSubMicroNs = 0;
            check(result.error.isEmpty() && result.packets.size() == 2
                && samePacket(result.packets[0], first) && samePacket(result.packets[1], expected),
                "independent little/big endian micro/nano fixtures");
        }
    }
    auto raw = first;
    raw.bytes = tcp.mid(14);
    raw.capturedLength = raw.bytes.size();
    raw.originalLength = raw.bytes.size();
    raw.linkType = DLT_RAW;
    const auto rawPath = directory.filePath(QStringLiteral("raw.pcap"));
    check(PcapFile::write(rawPath, {raw}).error.isEmpty(), "export non-Ethernet link type");
    result = PcapFile::read(rawPath);
    check(result.error.isEmpty() && result.packets.size() == 1 && samePacket(result.packets.first(), raw), "DLT and LINKTYPE mapping preserved");

    const auto baseline = readAll(path);
    auto invalid = first;
    invalid.capturedLength += 1;
    check(!PcapFile::write(path, {invalid}).error.isEmpty() && readAll(path) == baseline, "bad length does not overwrite original");
    invalid = first;
    invalid.timestampSubMicroNs = 1000;
    check(!PcapFile::write(path, {invalid}).error.isEmpty() && readAll(path) == baseline, "invalid nanosecond remainder");
    invalid = first;
    invalid.timestampUs = -1;
    check(!PcapFile::write(path, {invalid}).error.isEmpty(), "negative classic-PCAP timestamp rejected");
    invalid.timestampUs = (qint64(0xffffffff) + 1) * 1000000;
    check(!PcapFile::write(path, {invalid}).error.isEmpty(), "timestamp exceeds classic-PCAP seconds field");
    check(!PcapFile::write(path, {first, raw}).error.isEmpty() && readAll(path) == baseline, "mixed link types rejected before overwrite");
    invalid = first;
    invalid.linkType = 99999;
    check(!PcapFile::write(path, {invalid}).error.isEmpty() && readAll(path) == baseline, "dumper failure leaves original intact");
    check(!PcapFile::write(path, {}).error.isEmpty(), "empty save rejected");
    check(!PcapFile::write(directory.path(), records).error.isEmpty(), "directory output error");
    check(!PcapFile::read(directory.filePath(QStringLiteral("missing.pcap"))).error.isEmpty(), "missing input error");

    const auto bad = directory.filePath(QStringLiteral("bad.pcap"));
    putFile(bad, independentPcap(records, true, true).chopped(1));
    result = PcapFile::read(bad);
    check(!result.error.isEmpty() && result.packets.isEmpty(), "truncated file returns no partial dataset");
    putFile(bad, "not a pcap file");
    check(!PcapFile::read(bad).error.isEmpty(), "invalid file header");
    putFile(bad, independentPcap({}, false, true));
    result = PcapFile::read(bad);
    check(result.error.isEmpty() && result.packetCount == 0 && result.packets.isEmpty(), "valid empty PCAP");
    putFile(bad, independentPcap({}, false, true, PcapFile::maxPacketBytes + 1));
    check(!PcapFile::read(bad).error.isEmpty(), "bound file snapshot length before parsing records");
    invalid = first;
    invalid.originalLength = 1;
    putFile(bad, independentPcap({invalid}, false, true));
    check(!PcapFile::read(bad).error.isEmpty(), "invalid original length in input");

    bool cancel = false;
    result = PcapFile::write(path, records, [&] { return cancel; }, [&](quint64) { cancel = true; });
    check(result.cancelled && readAll(path) == baseline, "cancelled save is atomic");
    cancel = false;
    result = PcapFile::read(path, [&] { return cancel; }, [&](quint64) { cancel = true; });
    check(result.cancelled && result.packets.isEmpty(), "cancelled read returns no partial dataset");

    QVector<CapturedPacket> many;
    for (int index = 0; index < 2105; ++index) {
        auto packet = first;
        packet.timestampUs += index;
        many.append(packet);
    }
    const auto manyPath = directory.filePath(QStringLiteral("many.pcap"));
    check(PcapFile::write(manyPath, many).error.isEmpty(), "write larger capture fixture");
    result = PcapFile::read(manyPath);
    check(result.error.isEmpty() && result.packetCount == 2105 && result.packets.size() == 2000
        && result.packets.first().timestampUs == first.timestampUs + 105, "reader retains bounded chronological suffix");

    auto large = first;
    large.bytes.resize(262144, '\0');
    large.capturedLength = large.bytes.size();
    large.originalLength = large.bytes.size();
    const auto largePath = directory.filePath(QStringLiteral("large.pcap"));
    check(PcapFile::write(largePath, QVector<CapturedPacket>(258, large)).error.isEmpty(), "write raw byte budget fixture");
    result = PcapFile::read(largePath);
    check(result.error.isEmpty() && result.packetCount == 258 && result.packets.size() == 256,
          "reader applies 64 MiB byte budget before row limit");
    auto maximum = first;
    maximum.bytes.resize(PcapFile::maxPacketBytes, '\0');
    maximum.capturedLength = maximum.bytes.size();
    maximum.originalLength = maximum.bytes.size();
    const auto maximumPath = directory.filePath(QStringLiteral("maximum.pcap"));
    check(PcapFile::write(maximumPath, {maximum}).error.isEmpty(), "save maximum supported packet");
    result = PcapFile::read(maximumPath);
    check(result.error.isEmpty() && result.packets.size() == 1
        && samePacket(result.packets.first(), maximum), "maximum supported packet round trip");
    const auto exportedFixture = qEnvironmentVariable("NETSNIFFER_TEST_PCAP");
    if (!exportedFixture.isEmpty()) check(PcapFile::write(exportedFixture, records).error.isEmpty(), "export inspection fixture");
    QTextStream(stdout) << "checks=" << checks << " failures=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
