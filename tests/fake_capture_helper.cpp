#include "capture/protocol.h"

#include <cerrno>
#include <csignal>
#include <cstring>
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
    if (argc != 3 || std::strcmp(argv[1], "--interface") != 0) {
        return 2;
    }
    std::signal(SIGPIPE, SIG_IGN);
    const std::string mode(argv[2]);
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
        const int count = mode == "flood" ? 2100 : 1;
        for (int index = 0; index < count; ++index) {
            std::vector<unsigned char> payload;
            CaptureProtocol::append64(payload, 1700000000123456);
            CaptureProtocol::append32(payload, mode == "invalid-length" ? 5 : 4);
            CaptureProtocol::append32(payload, 8);
            payload.insert(payload.end(), {'t', 'e', 's', 't'});
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
