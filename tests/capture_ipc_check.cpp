#include "capture/captureworker.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QTextStream>
#include <QTimer>
#include <cstdlib>

static bool check(const QString& helper, const QString& mode, bool expectError,
                  int expectedPackets, quint64 expectedDrops = 0)
{
    CaptureWorker worker(mode, nullptr, helper);
    QEventLoop loop;
    QElapsedTimer elapsed;
    elapsed.start();
    bool started = false;
    bool error = false;
    bool timeout = false;
    QObject::connect(&worker, &CaptureWorker::captureStarted, &loop, [&] {
        started = true;
        QTimer::singleShot(mode == QStringLiteral("flood") ? 600 : 200, &loop,
                          [&] { worker.requestInterruption(); });
    });
    QObject::connect(&worker, &CaptureWorker::captureError, &loop, [&](const QString&) {
        error = true;
    });
    QObject::connect(&worker, &QThread::finished, &loop, &QEventLoop::quit);
    QTimer watchdog;
    watchdog.setSingleShot(true);
    QObject::connect(&watchdog, &QTimer::timeout, &loop, [&] {
        timeout = true;
        worker.requestInterruption();
        loop.quit();
    });
    watchdog.start(5000);
    worker.start();
    loop.exec();
    if (!worker.wait(3000)) {
        std::_Exit(2);
    }
    const auto packets = worker.takePackets();
    bool valid = !timeout && error == expectError && packets.size() == expectedPackets
        && worker.droppedPackets() == expectedDrops;
    if (!expectError) {
        valid &= started;
    }
    for (const auto& packet : packets) {
        valid &= packet.bytes == QByteArray("test") && packet.capturedLength == 4
            && packet.originalLength == 8 && packet.linkType == 1
            && packet.timestampUs == 1700000000123456;
    }
    QTextStream(stdout) << (valid ? "PASS " : "FAIL ") << mode
        << " packets=" << packets.size() << " dropped=" << worker.droppedPackets()
        << " elapsed_ms=" << elapsed.elapsed() << '\n';
    return valid;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2) {
        return 2;
    }
    const QString helper = QString::fromLocal8Bit(argv[1]);
    bool valid = true;
    for (int round = 0; round < 3; ++round) {
        valid &= check(helper, QStringLiteral("fragmented"), false, 1);
        valid &= check(helper, QStringLiteral("idle"), false, 0);
    }
    valid &= check(helper, QStringLiteral("flood"), false, 2000, 100);
    valid &= check(helper, QStringLiteral("stubborn"), false, 0);
    for (const auto& mode : {"error", "oversized", "truncated", "packet-before-ready",
                             "invalid-length", "crash", "early-exit"}) {
        valid &= check(helper, QString::fromLatin1(mode), true, 0);
    }
    valid &= check(QStringLiteral("/nonexistent/netsniffer-capture"),
                   QStringLiteral("missing-helper"), true, 0);
    return valid ? 0 : 1;
}
