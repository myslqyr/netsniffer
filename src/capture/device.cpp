#include "device.h"

#include <arpa/inet.h>
#include <memory>
#include <netinet/in.h>
#include <pcap/pcap.h>

DeviceList enumerateDevices()
{
    DeviceList result;
    char error[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* rawDevices = nullptr;
    if (pcap_findalldevs(&rawDevices, error) == -1) {
        result.error = QString::fromLocal8Bit(error);
        return result;
    }

    const std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)>
        devices(rawDevices, &pcap_freealldevs);
    for (auto* entry = devices.get(); entry; entry = entry->next) {
        if (!entry->name) {
            continue;
        }
        CaptureDevice device;
        device.name = QString::fromLocal8Bit(entry->name);
        if (entry->description) {
            device.description = QString::fromLocal8Bit(entry->description);
        }
        device.loopback = (entry->flags & PCAP_IF_LOOPBACK) != 0;

        for (auto* address = entry->addresses; address; address = address->next) {
            if (!address->addr) {
                continue;
            }
            const auto* socketAddress = address->addr;
            const void* bytes = nullptr;
            QString suffix;
            QString type;
            if (socketAddress->sa_family == AF_INET) {
                bytes = &reinterpret_cast<const sockaddr_in*>(socketAddress)->sin_addr;
                type = QStringLiteral("IPv4");
            } else if (socketAddress->sa_family == AF_INET6) {
                const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(socketAddress);
                bytes = &ipv6->sin6_addr;
                if (IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr)) {
                    type = QStringLiteral("IPv6（链路本地）");
                } else if (IN6_IS_ADDR_LOOPBACK(&ipv6->sin6_addr)) {
                    type = QStringLiteral("IPv6（回环）");
                } else if ((ipv6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc) {
                    type = QStringLiteral("IPv6（唯一本地）");
                } else if ((ipv6->sin6_addr.s6_addr[0] & 0xe0) == 0x20) {
                    type = QStringLiteral("IPv6（全局单播）");
                } else {
                    type = QStringLiteral("IPv6");
                }
                if (ipv6->sin6_scope_id != 0) {
                    suffix = QStringLiteral("%") + QString::number(ipv6->sin6_scope_id);
                }
            } else {
                continue;
            }
            char text[INET6_ADDRSTRLEN] = {};
            if (inet_ntop(socketAddress->sa_family, bytes, text, sizeof(text))) {
                const auto formatted = type + QStringLiteral("：")
                    + QString::fromLatin1(text) + suffix;
                if (!device.addresses.contains(formatted)) {
                    device.addresses.append(formatted);
                }
            }
        }
        result.devices.append(device);
    }
    return result;
}
