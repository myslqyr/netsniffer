#include "pcapfileworker.h"

#include <QElapsedTimer>
#include <utility>

PcapFileWorker::PcapFileWorker(Operation operation, QString path, QVector<CapturedPacket> packets, QObject* parent)
    : QThread(parent), operation_(operation), path_(std::move(path)), packets_(std::move(packets))
{
}

void PcapFileWorker::run()
{
    QElapsedTimer timer;
    timer.start();
    const auto cancelled = [this] { return isInterruptionRequested(); };
    const auto notify = [this, &timer](quint64 count) {
        if (timer.elapsed() >= 100) {
            emit progress(count);
            timer.restart();
        }
    };
    result_ = operation_ == Operation::Read ? PcapFile::read(path_, cancelled, notify)
                                           : PcapFile::write(path_, packets_, cancelled, notify);
}
