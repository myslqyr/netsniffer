#include "capture/captureworker.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QTextStream>
#include <QTimer>
#include <arpa/inet.h>
#include <cstdlib>
#include <sys/socket.h>
#include <unistd.h>

static QString helperPath;
static QString captureExpression;

static bool checkSession(const QString& device, bool sendTraffic, bool expectError)
{
    CaptureWorker worker(device, nullptr, helperPath, captureExpression);
    QEventLoop loop;
    bool started = false;
    bool error = false;
    bool timedOut = false;
    bool stopRequested = false;
    QElapsedTimer stopping;
    QTimer traffic;
    traffic.setInterval(10);
    QObject::connect(&traffic, &QTimer::timeout, &loop, [] {
        const int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            sockaddr_in destination{};
            destination.sin_family = AF_INET;
            destination.sin_port = htons(43891);
            destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            const char message[] = "netsniffer-capture-check";
            sendto(fd, message, sizeof(message), 0,
                   reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));
            close(fd);
        }
    });
    QObject::connect(&worker, &CaptureWorker::captureStarted, &loop, [&] {
        started = true;
        if (sendTraffic) {
            traffic.start();
        }
        QTimer::singleShot(400, &loop, [&] {
            traffic.stop();
            stopRequested = true;
            stopping.start();
            worker.requestInterruption();
        });
    });
    QObject::connect(&worker, &CaptureWorker::captureError, &loop, [&](const QString& message) {
        error = true;
        QTextStream(stdout) << "capture error: " << message << '\n';
    });
    QObject::connect(&worker, &QThread::finished, &loop, &QEventLoop::quit);
    QTimer watchdog;
    watchdog.setSingleShot(true);
    QObject::connect(&watchdog, &QTimer::timeout, &loop, [&] {
        timedOut = true;
        worker.requestInterruption();
        loop.quit();
    });
    watchdog.start(5000);
    worker.start();
    loop.exec();
    if (!worker.wait(2000)) {
        QTextStream(stderr) << "FAIL: capture thread failed to stop\n";
        std::_Exit(2);
    }
    if (expectError) {
        return error && !started && !timedOut;
    }
    const auto packets = worker.takePackets();
    bool foundPayload = false;
    for (const auto& packet : packets) {
        if (packet.bytes.size() != int(packet.capturedLength)
            || packet.originalLength < packet.capturedLength || packet.timestampUs <= 0) {
            return false;
        }
        foundPayload |= packet.bytes.contains("netsniffer-capture-check");
    }
    QTextStream(stdout) << "packets=" << packets.size()
                        << " stop_ms=" << (stopRequested ? stopping.elapsed() : -1) << '\n';
    return started && !error && !timedOut && stopRequested
        && stopping.elapsed() < 1000 && (!sendTraffic || foundPayload);
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const int helperIndex = app.arguments().indexOf(QStringLiteral("--helper"));
    if (helperIndex >= 0 && helperIndex + 1 < app.arguments().size()) {
        helperPath = app.arguments().at(helperIndex + 1);
    }
    const int filterIndex = app.arguments().indexOf(QStringLiteral("--filter"));
    if (filterIndex >= 0 && filterIndex + 1 < app.arguments().size()) {
        captureExpression = app.arguments().at(filterIndex + 1);
    }
    if (app.arguments().contains(QStringLiteral("--expect-error"))) {
        return checkSession(QStringLiteral("netsniffer-nonexistent-device"), false, true) ? 0 : 1;
    }
    for (int round = 0; round < 3; ++round) {
        if (!checkSession(QStringLiteral("lo"), true, false)
            || !checkSession(QStringLiteral("lo"), false, false)) {
            return 1;
        }
    }
    return checkSession(QStringLiteral("netsniffer-nonexistent-device"), false, true) ? 0 : 1;
}
