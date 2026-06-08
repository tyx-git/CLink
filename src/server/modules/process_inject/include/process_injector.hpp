#pragma once

#include <cstdint>
#include <functional>
#include <string>

#if defined(_WIN32)
  #if defined(clink_inject_EXPORTS) || defined(clink_process_server_EXPORTS)
    #define CLINK_PROCESS_INJECT_EXPORT __declspec(dllexport)
  #else
    #define CLINK_PROCESS_INJECT_EXPORT __declspec(dllimport)
  #endif
#else
  #define CLINK_PROCESS_INJECT_EXPORT
#endif

namespace clink::hook::inject {

using InjectorLogSink = std::function<void(bool is_error, const std::string& message)>;

CLINK_PROCESS_INJECT_EXPORT void SetLogSink(InjectorLogSink sink);
CLINK_PROCESS_INJECT_EXPORT bool IsSupported();
CLINK_PROCESS_INJECT_EXPORT const char* BackendName();
enum class InjectError {
    None = 0,
    NotSupported,
    InvalidArgument,
    AccessDenied,
    ProcessNotFound,
    BackendFailure
};

CLINK_PROCESS_INJECT_EXPORT const char* InjectErrorToString(InjectError code);

CLINK_PROCESS_INJECT_EXPORT bool InjectLibrary(uint32_t process_id, const std::string& library_path, std::string* error = nullptr, InjectError* error_code = nullptr);

} // namespace clink::hook::inject
