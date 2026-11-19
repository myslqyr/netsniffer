#pragma once

#include <pcap/pcap.h>
#include <string>

class CaptureFilter {
public:
    CaptureFilter() = default;
    ~CaptureFilter();
    CaptureFilter(const CaptureFilter&) = delete;
    CaptureFilter& operator=(const CaptureFilter&) = delete;

    bool compile(pcap_t* handle, const std::string& expression, std::string& error,
                 bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN);
    bool install(pcap_t* handle, std::string& error);
    const bpf_program* program() const { return compiled_ ? &program_ : nullptr; }

private:
    bpf_program program_{};
    bool compiled_ = false;
};
