#include "captureworker.h"
#include "protocol.h"

#include <QElapsedTimer>
#include <QFileInfo>
#include <QMutexLocker>
#include <QProcess>
#include <limits>
#include <utility>

CaptureWorker::CaptureWorker(QString device, QObject* parent, QString helperPath)
    : QThread(parent), device_(std::move(device)),
      helperPath_(helperPath.isEmpty() ? QString::fromLatin1(CaptureProtocol::installedHelper)
                                       : std::move(helperPath))
{
}

QVector<CapturedPacket> CaptureWorker::takePackets()
{
    QMutexLocker lock(&mutex_);
    QVector<CapturedPacket> result;
    result.swap(pending_);
    return result;
}

quint64 CaptureWorker::droppedPackets()
{
    QMutexLocker lock(&mutex_);
    return dropped_;
}

void CaptureWorker::run()
{
    if (isInterruptionRequested()) {
        return;
    }
    if (!QFileInfo(helperPath_).isExecutable()) {
        emit captureError(QStringLiteral("抓包辅助程序未安装或不可执行"));
        return;
    }
    QProcess process;
    process.setProgram(helperPath_);
    process.setArguments({QStringLiteral("--interface"), device_});
    process.start();
    if (!process.waitForStarted(3000)) {
        emit captureError(QStringLiteral("无法启动抓包辅助程序：") + process.errorString());
        return;
    }

    QByteArray buffer;
    QElapsedTimer startup;
    QElapsedTimer stopping;
    startup.start();
    bool ready = false;
    bool failed = false;
    int linkType = 0;
    auto fail = [&](const QString& message) {
        if (!failed) {
            failed = true;
            emit captureError(message);
        }
    };
    while (true) {
        if (isInterruptionRequested() && !stopping.isValid()) {
            process.closeWriteChannel();
            stopping.start();
        }
        if (stopping.isValid() && stopping.elapsed() > 1000) {
            process.terminate();
        }
        if (stopping.isValid() && stopping.elapsed() > 2000) {
            process.kill();
            break;
        }
        process.waitForReadyRead(20);
        buffer += process.read(65536);
        process.readAllStandardError();
        while (buffer.size() >= qsizetype(CaptureProtocol::headerSize)) {
            const auto* header = reinterpret_cast<const unsigned char*>(buffer.constData());
            const auto size = CaptureProtocol::read32(header + 8);
            if (CaptureProtocol::read32(header) != CaptureProtocol::magic
                || CaptureProtocol::read16(header + 4) != CaptureProtocol::version
                || size > CaptureProtocol::maxPayload) {
                fail(QStringLiteral("抓包辅助程序返回了无效数据"));
                break;
            }
            const auto frameSize = qsizetype(CaptureProtocol::headerSize + size);
            if (buffer.size() < frameSize) {
                break;
            }
            const auto type = static_cast<CaptureProtocol::Type>(CaptureProtocol::read16(header + 6));
            const auto* payload = header + CaptureProtocol::headerSize;
            if (type == CaptureProtocol::Type::Ready && !ready && size == 4
                && CaptureProtocol::read32(payload) <= std::uint32_t(std::numeric_limits<int>::max())) {
                linkType = static_cast<int>(CaptureProtocol::read32(payload));
                ready = true;
                emit captureStarted();
            } else if (type == CaptureProtocol::Type::Packet && ready && size >= 16) {
                const auto timestamp = CaptureProtocol::read64(payload);
                const auto capturedLength = CaptureProtocol::read32(payload + 8);
                const auto originalLength = CaptureProtocol::read32(payload + 12);
                if (capturedLength != size - 16 || capturedLength > originalLength
                    || timestamp > std::uint64_t(std::numeric_limits<qint64>::max())) {
                    fail(QStringLiteral("抓包辅助程序返回了无效数据包"));
                    break;
                }
                QMutexLocker lock(&mutex_);
                if (pending_.size() >= 2000) {
                    ++dropped_;
                } else {
                    pending_.append({static_cast<qint64>(timestamp), capturedLength,
                        originalLength, linkType,
                        QByteArray(reinterpret_cast<const char*>(payload + 16), int(capturedLength))});
                }
            } else if (type == CaptureProtocol::Type::Error && size > 0 && size <= 4096) {
                fail(QString::fromUtf8(reinterpret_cast<const char*>(payload), int(size)));
            } else {
                fail(QStringLiteral("抓包辅助程序通信协议错误"));
            }
            buffer.remove(0, frameSize);
            if (failed) {
                break;
            }
        }
        if (failed) {
            break;
        }
        if (process.state() == QProcess::NotRunning && process.bytesAvailable() == 0) {
            if (!stopping.isValid()) {
                fail(QStringLiteral("抓包辅助程序意外退出"));
            }
            break;
        }
        if (!ready && !stopping.isValid() && startup.elapsed() > 5000) {
            fail(QStringLiteral("抓包辅助程序启动超时"));
            break;
        }
    }
    process.closeWriteChannel();
    if (process.state() != QProcess::NotRunning && !process.waitForFinished(500)) {
        process.kill();
        process.waitForFinished(1000);
    }
}
