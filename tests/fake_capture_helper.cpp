#include "capture/protocol.h"
#include "capture/capturefilter.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <memory>
#include <poll.h>
#include <string>
#include <unistd.h>

static bool sendBytes(const std::vector<unsigned char>& bytes, bool fragmented = false)
{
    std::size_t position = 0;
    while (position < bytes.size()) {
        const auto count = write(STDOUT_FILENO, bytes.data() + position,
                                 fragmented ? 1 : bytes.size() - position);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        position += static_cast<std::size_t>(count);
        if (fragmented) {
            usleep(1000);
        }
    }
    return true;
}

int main(int argc, char** argv)
{
    if ((argc != 3 && argc != 5) || std::strcmp(argv[1], "--interface") != 0
        || (argc == 5 && std::strcmp(argv[3], "--filter") != 0)) {
        return 2;
    }
    std::signal(SIGPIPE, SIG_IGN);
    const std::string mode(argv[2]);
    if (mode == "legacy-filter" && argc == 5) return 2;
    std::unique_ptr<pcap_t, decltype(&pcap_close)> dead(
        pcap_open_dead(DLT_EN10MB, CaptureProtocol::snapLength), &pcap_close);
    CaptureFilter filter;
    if (argc == 5) {
        std::string error;
        if (!dead || !filter.compile(dead.get(), argv[4], error)) {
            const auto message = std::string("捕获过滤条件错误：") + error;
            sendBytes(CaptureProtocol::frame(CaptureProtocol::Type::Error, {message.begin(), message.end()}));
            return 1;
        }
    }
    if (mode == "error") {
        const std::string message = "test permission denied";
        sendBytes(CaptureProtocol::frame(CaptureProtocol::Type::Error,
                                         {message.begin(), message.end()}));
        return 1;
    }
    if (mode == "oversized") {
        auto header = CaptureProtocol::frame(CaptureProtocol::Type::Ready, {});
        header.resize(8);
        CaptureProtocol::append32(header, CaptureProtocol::maxPayload + 1);
        sendBytes(header);
        return 0;
    }
    std::vector<unsigned char> ready;
    CaptureProtocol::append32(ready, 1);
    const auto readyFrame = CaptureProtocol::frame(CaptureProtocol::Type::Ready, ready);
    if (mode == "truncated") {
        sendBytes({readyFrame.begin(), readyFrame.begin() + 5});
        return 0;
    }
    if (mode == "packet-before-ready") {
        sendBytes(CaptureProtocol::frame(CaptureProtocol::Type::Packet, {}));
        return 0;
    }
    if (!sendBytes(readyFrame, mode == "fragmented")) {
        return 0;
    }
    if (mode == "crash") {
        return 3;
    }
    if (mode == "early-exit") {
        return 0;
    }
    if (mode == "stubborn") {
        std::signal(SIGTERM, SIG_IGN);
        sleep(10);
        return 0;
    }
    if (mode != "idle") {
        const bool detailStream = mode == "detail-stream";
        const bool detailBudget = mode == "detail-budget";
        const bool pair = mode == "filter-pair";
        const int count = mode == "flood" ? 2100 : detailStream ? 2102 : detailBudget ? 1050 : pair ? 2 : 1;
        for (int index = 0; index < count; ++index) {
            if ((detailStream || detailBudget) && (index == 2 || (index > 2 && index % 100 == 0))) {
                pollfd input{STDIN_FILENO, POLLIN, 0};
                if (poll(&input, 1, index == 2 ? 400 : 80) > 0) return 0;
            }
            std::vector<unsigned char> data{'t', 'e', 's', 't'};
            if (mode == "parsed" || detailStream || detailBudget || pair) {
                data.assign(detailBudget ? 65535 : 54, 0);
                data[12] = 0x08;
                data[14] = 0x45;
                data[17] = 40;
                data[22] = 64;
                data[23] = 6;
                for (int byte = 0; byte < 8; ++byte) data[26 + byte] = byte + 1;
                data[34] = 0x30;
                data[35] = 0x39;
                data[37] = 80;
                data[41] = 1;
                data[46] = 0x50;
                data[47] = 0x02;
                if (detailStream || detailBudget) {
                    data[41] = static_cast<unsigned char>(index);
                }
                if ((detailStream || pair) && index == 1) {
                    data.resize(46);
                    data[17] = 32;
                    data[23] = 17;
                    data[26] = 9;
                    data[35] = 0x3a;
                    data[36] = 0x14;
                    data[37] = 0xe9;
                    data[38] = 0;
                    data[39] = 12;
                    data[40] = 0;
                    data[41] = 0;
                    data[42] = 'A';
                    data[43] = '\n';
                    data[44] = 0;
                    data[45] = 'Z';
                }
            }
            if (filter.program()) {
                pcap_pkthdr header{};
                header.caplen = data.size();
                header.len = data.size();
                if (pcap_offline_filter(filter.program(), &header, data.data()) == 0) continue;
            }
            std::vector<unsigned char> payload;
            CaptureProtocol::append64(payload, 1700000000123456);
            CaptureProtocol::append32(payload, mode == "invalid-length" ? 5 : data.size());
            CaptureProtocol::append32(payload, mode == "parsed" || detailStream || detailBudget || pair ? data.size() : 8);
            payload.insert(payload.end(), data.begin(), data.end());
            if (!sendBytes(CaptureProtocol::frame(CaptureProtocol::Type::Packet, payload),
                           mode == "fragmented")) {
                return 0;
            }
        }
    }
    pollfd input{STDIN_FILENO, POLLIN, 0};
    poll(&input, 1, 5000);
    return 0;
}
