#include "pcapfile.h"

#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QtEndian>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <pcap/pcap.h>
#include <unistd.h>

namespace {
struct CloseStream {
    void operator()(FILE* stream) const { std::fclose(stream); }
};
using Stream = std::unique_ptr<FILE, CloseStream>;
using Handle = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
using Dumper = std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)>;

Stream duplicateStream(int descriptor, const char* mode)
{
    const int duplicate = dup(descriptor);
    FILE* stream = duplicate < 0 ? nullptr : fdopen(duplicate, mode);
    if (!stream && duplicate >= 0) close(duplicate);
    return Stream(stream);
}

bool isCancelled(const PcapFile::Cancelled& cancelled)
{
    return cancelled && cancelled();
}
}

PcapFile::Result PcapFile::read(const QString& path, const Cancelled& cancelled, const Progress& progress)
{
    Result result;
    if (isCancelled(cancelled)) { result.cancelled = true; return result; }
    if (!QFileInfo(path).isFile()) {
        result.error = QStringLiteral("请选择有效的 PCAP 文件");
        return result;
    }
    QFile source(path);
    if (!source.open(QIODevice::ReadOnly | QIODevice::Unbuffered)) {
        result.error = source.errorString();
        return result;
    }
    const auto header = source.read(24);
    const auto magic = header.left(4).toHex();
    const bool little = magic == "d4c3b2a1" || magic == "4d3cb2a1";
    const bool big = magic == "a1b2c3d4" || magic == "a1b23c4d";
    if (header.size() != 24 || (!little && !big)) {
        result.error = QStringLiteral("文件不是有效的 PCAP 格式");
        return result;
    }
    const auto* snapshot = reinterpret_cast<const unsigned char*>(header.constData() + 16);
    const auto snapLength = little ? qFromLittleEndian<quint32>(snapshot) : qFromBigEndian<quint32>(snapshot);
    if (snapLength == 0 || snapLength > maxPacketBytes) {
        result.error = QStringLiteral("PCAP 单包捕获上限无效或超过 256 KiB");
        return result;
    }
    if (!source.seek(0)) {
        result.error = source.errorString();
        return result;
    }
    auto stream = duplicateStream(source.handle(), "rb");
    if (!stream) {
        result.error = QString::fromLocal8Bit(std::strerror(errno));
        return result;
    }
    char error[PCAP_ERRBUF_SIZE] = {};
    Handle handle(pcap_fopen_offline_with_tstamp_precision(stream.get(), PCAP_TSTAMP_PRECISION_NANO, error), &pcap_close);
    if (!handle) {
        result.error = QString::fromLocal8Bit(error);
        return result;
    }
    stream.release(); // libpcap now owns the duplicate FILE; QFile keeps its own descriptor.
    const int linkType = pcap_datalink(handle.get());
    if (linkType < 0) {
        result.error = QStringLiteral("PCAP 链路类型无效");
        return result;
    }
    std::deque<CapturedPacket> cached;
    qsizetype cachedBytes = 0;
    while (true) {
        if (isCancelled(cancelled)) { result.cancelled = true; return result; }
        pcap_pkthdr* record = nullptr;
        const unsigned char* data = nullptr;
        const int state = pcap_next_ex(handle.get(), &record, &data);
        if (state == PCAP_ERROR_BREAK) break;
        if (state < 0) {
            result.error = QString::fromLocal8Bit(pcap_geterr(handle.get()));
            return result;
        }
        if (state == 0) continue;
        if (record->caplen > maxPacketBytes || record->caplen > record->len
            || record->ts.tv_sec < 0 || quint64(record->ts.tv_sec) > std::numeric_limits<quint32>::max()
            || record->ts.tv_usec < 0 || record->ts.tv_usec >= 1000000000) {
            result.error = QStringLiteral("PCAP 数据包长度或时间戳无效");
            return result;
        }
        CapturedPacket packet{qint64(record->ts.tv_sec) * 1000000 + record->ts.tv_usec / 1000,
            record->caplen, record->len, linkType,
            QByteArray(reinterpret_cast<const char*>(data), int(record->caplen)),
            quint16(record->ts.tv_usec % 1000)};
        cachedBytes += packet.bytes.size();
        cached.push_back(std::move(packet));
        ++result.packetCount;
        while (cached.size() > std::size_t(maxCachedPackets) || cachedBytes > maxCachedBytes) {
            cachedBytes -= cached.front().bytes.size();
            cached.pop_front();
        }
        if (progress) progress(result.packetCount);
    }
    if (isCancelled(cancelled)) { result.cancelled = true; return result; }
    result.packets.reserve(cached.size());
    for (auto& packet : cached) result.packets.append(std::move(packet));
    return result;
}

PcapFile::Result PcapFile::write(const QString& path, const QVector<CapturedPacket>& packets,
                               const Cancelled& cancelled, const Progress& progress)
{
    Result result;
    if (isCancelled(cancelled)) { result.cancelled = true; return result; }
    if (packets.isEmpty()) {
        result.error = QStringLiteral("缓存中没有可保存的数据包");
        return result;
    }
    const int linkType = packets.first().linkType;
    quint32 snapshot = 65535;
    for (const auto& packet : packets) {
        if (isCancelled(cancelled)) { result.cancelled = true; return result; }
        if (packet.linkType != linkType) {
            result.error = QStringLiteral("同一 PCAP 文件中的链路类型必须一致");
            return result;
        }
        if (packet.capturedLength != packet.bytes.size() || packet.capturedLength > packet.originalLength
            || packet.capturedLength > maxPacketBytes || packet.timestampUs < 0
            || quint64(packet.timestampUs / 1000000) > std::numeric_limits<quint32>::max()
            || packet.timestampSubMicroNs > 999) {
            result.error = QStringLiteral("数据包长度或时间戳无效");
            return result;
        }
        snapshot = std::max(snapshot, packet.capturedLength);
    }
    Handle handle(pcap_open_dead_with_tstamp_precision(linkType, int(snapshot), PCAP_TSTAMP_PRECISION_NANO), &pcap_close);
    if (!handle) {
        result.error = QStringLiteral("无法创建 PCAP 文件头");
        return result;
    }
    QSaveFile target(path);
    target.setDirectWriteFallback(false);
    if (!target.open(QIODevice::WriteOnly)) {
        result.error = target.errorString();
        return result;
    }
    auto stream = duplicateStream(target.handle(), "wb");
    if (!stream) {
        result.error = QString::fromLocal8Bit(std::strerror(errno));
        return result;
    }
    Dumper dumper(pcap_dump_fopen(handle.get(), stream.get()), &pcap_dump_close);
    if (!dumper) {
        result.error = QString::fromLocal8Bit(pcap_geterr(handle.get()));
        return result;
    }
    stream.release();
    for (const auto& packet : packets) {
        if (isCancelled(cancelled)) { result.cancelled = true; return result; }
        pcap_pkthdr record{};
        record.ts.tv_sec = packet.timestampUs / 1000000;
        record.ts.tv_usec = (packet.timestampUs % 1000000) * 1000 + packet.timestampSubMicroNs;
        record.caplen = packet.capturedLength;
        record.len = packet.originalLength;
        pcap_dump(reinterpret_cast<unsigned char*>(dumper.get()), &record,
                  reinterpret_cast<const unsigned char*>(packet.bytes.constData()));
        ++result.packetCount;
        if (std::ferror(pcap_dump_file(dumper.get()))) {
            result.error = QStringLiteral("写入 PCAP 文件失败");
            return result;
        }
        if (progress) progress(result.packetCount);
    }
    if (pcap_dump_flush(dumper.get()) != 0) {
        result.error = QStringLiteral("写入 PCAP 文件失败");
        return result;
    }
    dumper.reset();
    if (isCancelled(cancelled)) { result.cancelled = true; return result; }
    if (!target.commit()) result.error = target.errorString();
    return result;
}
