#include "capturefilter.h"

CaptureFilter::~CaptureFilter()
{
    if (compiled_) pcap_freecode(&program_);
}

bool CaptureFilter::compile(pcap_t* handle, const std::string& expression, std::string& error,
                            bpf_u_int32 netmask)
{
    error.clear();
    if (compiled_) {
        pcap_freecode(&program_);
        compiled_ = false;
        program_ = {};
    }
    if (expression.size() > 4096 || expression.find('\0') != std::string::npos) {
        error = "Invalid filter length or embedded NUL";
        return false;
    }
    if (pcap_compile(handle, &program_, expression.c_str(), 1, netmask) != 0) {
        error = pcap_geterr(handle);
        return false;
    }
    compiled_ = true;
    return true;
}

bool CaptureFilter::install(pcap_t* handle, std::string& error)
{
    error.clear();
    if (!compiled_) {
        error = "Filter has not been compiled";
        return false;
    }
    if (pcap_setfilter(handle, &program_) != 0) {
        error = pcap_geterr(handle);
        return false;
    }
    return true;
}
