#pragma once

#include <functional>
#include <string>
#include <windows.h>

// 进程注入器：Windows CreateRemoteThread 方式将 DLL 注入目标进程
// OpenProcess(最小权限) → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibraryA)
namespace clink::hook {

using InjectorLogSink = std::function<void(bool is_error, const std::string& message)>;

void SetInjectorLogSink(InjectorLogSink sink);  // 设置日志回调
bool InjectDLL(DWORD processId, const std::string& dllPath);  // 将 dllPath 注入 processId 进程

} // namespace clink::hook
