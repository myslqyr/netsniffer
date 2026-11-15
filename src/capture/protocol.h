#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace CaptureProtocol {
constexpr const char* installedHelper = "/usr/local/libexec/netsniffer/netsniffer-capture";
constexpr std::uint32_t magic = 0x4e534350; // NSCP
constexpr std::uint16_t version = 1;
constexpr std::size_t headerSize = 12;
constexpr std::uint32_t snapLength = 65535;
constexpr std::uint32_t maxPayload = snapLength + 16;
enum class Type : std::uint16_t { Ready = 1, Packet = 2, Error = 3 };

inline std::uint16_t read16(const unsigned char* data)
{
    return (std::uint16_t(data[0]) << 8) | data[1];
}

inline std::uint32_t read32(const unsigned char* data)
{
    return (std::uint32_t(read16(data)) << 16) | read16(data + 2);
}

inline std::uint64_t read64(const unsigned char* data)
{
    return (std::uint64_t(read32(data)) << 32) | read32(data + 4);
}

inline void append32(std::vector<unsigned char>& bytes, std::uint32_t value)
{
    for (int shift = 24; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<unsigned char>(value >> shift));
    }
}

inline void append64(std::vector<unsigned char>& bytes, std::uint64_t value)
{
    append32(bytes, static_cast<std::uint32_t>(value >> 32));
    append32(bytes, static_cast<std::uint32_t>(value));
}

inline std::vector<unsigned char> frame(Type type, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> bytes;
    bytes.reserve(headerSize + payload.size());
    append32(bytes, magic);
    bytes.push_back(0);
    bytes.push_back(version);
    bytes.push_back(0);
    bytes.push_back(static_cast<unsigned char>(type));
    append32(bytes, static_cast<std::uint32_t>(payload.size()));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}
}
