#include "../capture/protocol.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <linux/capability.h>
#include <memory>
#include <pcap/pcap.h>
#include <poll.h>
#include <string>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
volatile sig_atomic_t stopping = 0;

void requestStop(int)
{
    stopping = 1;
}

bool parentStopped()
{
    pollfd input{STDIN_FILENO, POLLIN, 0};
    if (poll(&input, 1, 0) > 0 && (input.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
        return true; // Closing stdin requests stop. No commands are accepted.
    }
    return stopping != 0;
}

bool sendFrame(CaptureProtocol::Type type, const std::vector<unsigned char>& payload)
{
    const auto bytes = CaptureProtocol::frame(type, payload);
    std::size_t offset = 0;
    while (offset < bytes.size() && !parentStopped()) {
        const auto written = write(STDOUT_FILENO, bytes.data() + offset, bytes.size() - offset);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd descriptors[] = {{STDOUT_FILENO, POLLOUT, 0}, {STDIN_FILENO, POLLIN, 0}};
            if (poll(descriptors, 2, 50) < 0 && errno != EINTR) {
                return false;
            }
            if (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                return false;
            }
        } else {
            return false;
        }
    }
    return offset == bytes.size();
}

int fail(const std::string& message)
{
    const auto text = message.substr(0, 4096);
    sendFrame(CaptureProtocol::Type::Error, {text.begin(), text.end()});
    return 1;
}

bool dropCapabilities()
{
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    __user_cap_data_struct data[2]{};
    return syscall(SYS_capset, &header, data) == 0
        && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
}
}

int main(int argc, char** argv)
{
    if (argc != 3 || std::strcmp(argv[1], "--interface") != 0 || argv[2][0] == '\0') {
        return 2;
    }
    const auto parent = getppid();
    if (parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() != parent) {
        return 2;
    }
    std::signal(SIGTERM, requestStop);
    std::signal(SIGINT, requestStop);
    std::signal(SIGPIPE, SIG_IGN);
    const int flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) < 0) {
        return 2;
    }

    char error[PCAP_ERRBUF_SIZE] = {};
    std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(
        pcap_create(argv[2], error), &pcap_close);
    if (!handle) {
        return fail(error);
    }
    if (pcap_set_snaplen(handle.get(), CaptureProtocol::snapLength) != 0
        || pcap_set_promisc(handle.get(), 0) != 0
        || pcap_set_timeout(handle.get(), 100) != 0) {
        return fail(pcap_geterr(handle.get()));
    }
    if (pcap_activate(handle.get()) < 0) {
        return fail(pcap_geterr(handle.get()));
    }
    if (pcap_setnonblock(handle.get(), 1, error) != 0) {
        return fail(error);
    }
    const int linkType = pcap_datalink(handle.get());
    // The packet socket is open; the running helper needs no retained capabilities.
    if (linkType < 0 || !dropCapabilities()) {
        return fail("Unable to finish capture initialization");
    }
    std::vector<unsigned char> ready;
    CaptureProtocol::append32(ready, static_cast<std::uint32_t>(linkType));
    if (!sendFrame(CaptureProtocol::Type::Ready, ready)) {
        return 0;
    }
    while (!parentStopped()) {
        pcap_pkthdr* header = nullptr;
        const unsigned char* bytes = nullptr;
        const int status = pcap_next_ex(handle.get(), &header, &bytes);
        if (status == 0) {
            pollfd input{STDIN_FILENO, POLLIN, 0};
            poll(&input, 1, 20);
            continue;
        }
        if (status == PCAP_ERROR_BREAK) {
            break;
        }
        if (status < 0) {
            return fail(pcap_geterr(handle.get()));
        }
        if (header->caplen > CaptureProtocol::snapLength || header->caplen > header->len) {
            return fail("Invalid packet length");
        }
        std::vector<unsigned char> payload;
        payload.reserve(16 + header->caplen);
        CaptureProtocol::append64(payload,
            std::uint64_t(header->ts.tv_sec) * 1000000 + header->ts.tv_usec);
        CaptureProtocol::append32(payload, header->caplen);
        CaptureProtocol::append32(payload, header->len);
        payload.insert(payload.end(), bytes, bytes + header->caplen);
        if (!sendFrame(CaptureProtocol::Type::Packet, payload)) {
            break;
        }
    }
    return 0;
}
