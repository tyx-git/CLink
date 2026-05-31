#pragma once

#include <functional>
#include <string>
#include <windows.h>

namespace clink::hook {

using InjectorLogSink = std::function<void(bool is_error, const std::string& message)>;

void SetInjectorLogSink(InjectorLogSink sink);
bool InjectDLL(DWORD processId, const std::string& dllPath);

} // namespace clink::hook
