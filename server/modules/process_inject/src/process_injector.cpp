#include "process_injector.hpp"

#include <mutex>

#ifdef _WIN32
#include "injector_main.hpp"
#endif

namespace clink::hook::inject {

namespace {
std::mutex g_sink_mutex;
InjectorLogSink g_sink;

void emit_log(bool is_error, const std::string& message) {
    InjectorLogSink sink_copy;
    {
        std::lock_guard<std::mutex> lock(g_sink_mutex);
        sink_copy = g_sink;
    }
    if (sink_copy) {
        sink_copy(is_error, message);
    }
}
} // namespace

void SetLogSink(InjectorLogSink sink) {
    {
        std::lock_guard<std::mutex> lock(g_sink_mutex);
        g_sink = std::move(sink);
    }
#ifdef _WIN32
    clink::hook::SetInjectorLogSink([](bool is_error, const std::string& message) {
        emit_log(is_error, message);
    });
#endif
}

bool IsSupported() {
#ifdef _WIN32
    return true;
#else
    return false;
#endif
}

const char* BackendName() {
#ifdef _WIN32
    return "windows-createremotethread";
#else
    return "linux-not-implemented";
#endif
}

const char* InjectErrorToString(InjectError code) {
    switch (code) {
        case InjectError::None:
            return "none";
        case InjectError::NotSupported:
            return "not_supported";
        case InjectError::InvalidArgument:
            return "invalid_argument";
        case InjectError::AccessDenied:
            return "access_denied";
        case InjectError::ProcessNotFound:
            return "process_not_found";
        case InjectError::BackendFailure:
            return "backend_failure";
        default:
            return "unknown";
    }
}

bool InjectLibrary(uint32_t process_id, const std::string& library_path, std::string* error, InjectError* error_code) {
    auto set_error = [&](InjectError code, const std::string& msg) {
        if (error) {
            *error = msg;
        }
        if (error_code) {
            *error_code = code;
        }
    };

    if (process_id == 0 || library_path.empty()) {
        set_error(InjectError::InvalidArgument, "Invalid injection arguments");
        return false;
    }

#ifdef _WIN32
    const bool ok = clink::hook::InjectDLL(static_cast<DWORD>(process_id), library_path);
    if (!ok) {
        set_error(InjectError::BackendFailure, "Windows injector failed");
        return false;
    }

    set_error(InjectError::None, "");
    return true;
#else
    (void)process_id;
    (void)library_path;
    set_error(InjectError::NotSupported, "Process injection is not implemented on Linux yet");
    emit_log(true, "[injector] Linux backend placeholder called (not implemented)");
    return false;
#endif
}

} // namespace clink::hook::inject
