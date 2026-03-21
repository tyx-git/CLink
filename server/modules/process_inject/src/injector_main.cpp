#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <mutex>
#include <cstdio>

#include "injector_main.hpp"

namespace clink::hook {

namespace {
std::mutex g_injector_log_mutex;
InjectorLogSink g_injector_log_sink;

std::string hex_u64(unsigned long long value) {
    char buf[32] = {0};
    std::snprintf(buf, sizeof(buf), "0x%llX", value);
    return std::string(buf);
}

std::string format_last_error(DWORD err) {
    if (err == 0) return "0";

    LPSTR msg_buf = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;

    const DWORD len = FormatMessageA(
        flags,
        nullptr,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&msg_buf),
        0,
        nullptr);

    std::string msg;
    if (len > 0 && msg_buf) {
        msg.assign(msg_buf, len);
        while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n')) {
            msg.pop_back();
        }
        LocalFree(msg_buf);
    }

    if (msg.empty()) {
        return std::to_string(err);
    }
    return std::to_string(err) + " (" + msg + ")";
}

void emit_inject_log(bool is_error, const std::string& message) {
    InjectorLogSink sink_copy;
    {
        std::lock_guard<std::mutex> lock(g_injector_log_mutex);
        sink_copy = g_injector_log_sink;
    }

    if (sink_copy) {
        sink_copy(is_error, message);
        return;
    }

    if (is_error) {
        std::cerr << "[injector][error] " << message << std::endl;
    } else {
        std::cerr << "[injector] " << message << std::endl;
    }
}

void log_inject(const std::string& message) {
    emit_inject_log(false, message);
}

void log_inject_error(const std::string& message) {
    emit_inject_log(true, message);
}
} // namespace

void SetInjectorLogSink(InjectorLogSink sink) {
    std::lock_guard<std::mutex> lock(g_injector_log_mutex);
    g_injector_log_sink = std::move(sink);
}

bool InjectDLL(DWORD processId, const std::string& dllPath) {
    log_inject("pid=" + std::to_string(GetCurrentProcessId()) +
               " tid=" + std::to_string(GetCurrentThreadId()) +
               " begin target_pid=" + std::to_string(processId) +
               " dll='" + dllPath + "'");

    if (dllPath.empty()) {
        log_inject_error("InjectDLL failed: empty dll path");
        return false;
    }

    constexpr DWORD kRequiredAccess = PROCESS_CREATE_THREAD |
                                      PROCESS_QUERY_INFORMATION |
                                      PROCESS_VM_OPERATION |
                                      PROCESS_VM_WRITE |
                                      PROCESS_VM_READ;

    HANDLE hProcess = OpenProcess(kRequiredAccess, FALSE, processId);
    if (!hProcess) {
        const DWORD err = GetLastError();
        log_inject_error("OpenProcess failed pid=" + std::to_string(processId) +
                         " access=" + hex_u64(static_cast<unsigned long long>(kRequiredAccess)) +
                         " err=" + format_last_error(err));
        return false;
    }
    log_inject("OpenProcess ok");

    void* pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        const DWORD err = GetLastError();
        log_inject_error("VirtualAllocEx failed err=" + format_last_error(err));
        CloseHandle(hProcess);
        return false;
    }
    log_inject("VirtualAllocEx ok bytes=" + std::to_string(dllPath.size() + 1));

    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        const DWORD err = GetLastError();
        log_inject_error("WriteProcessMemory failed err=" + format_last_error(err));
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    log_inject("WriteProcessMemory ok");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        const DWORD err = GetLastError();
        log_inject_error("GetModuleHandleA(kernel32.dll) failed err=" + format_last_error(err));
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(hKernel32, "LoadLibraryA"));
    if (!pLoadLibrary) {
        const DWORD err = GetLastError();
        log_inject_error("GetProcAddress(LoadLibraryA) failed err=" + format_last_error(err));
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    log_inject("resolved LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteBuf, 0, NULL);
    if (!hThread) {
        const DWORD err = GetLastError();
        log_inject_error("CreateRemoteThread failed err=" + format_last_error(err));
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    log_inject("CreateRemoteThread ok");

    const DWORD wait_rc = WaitForSingleObject(hThread, 15000);
    bool wait_ok = false;
    if (wait_rc == WAIT_TIMEOUT) {
        log_inject_error("WaitForSingleObject timeout (15s)");
    } else if (wait_rc == WAIT_FAILED) {
        const DWORD err = GetLastError();
        log_inject_error("WaitForSingleObject failed err=" + format_last_error(err));
    } else {
        wait_ok = true;
        log_inject("WaitForSingleObject completed rc=" + std::to_string(wait_rc));
    }

    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        const DWORD err = GetLastError();
        log_inject_error("GetExitCodeThread failed err=" + format_last_error(err));
    } else {
        log_inject("remote LoadLibraryA exit_code=" + hex_u64(static_cast<unsigned long long>(exitCode)));
    }

    CloseHandle(hThread);

    if (!VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE)) {
        const DWORD err = GetLastError();
        log_inject_error("VirtualFreeEx warning err=" + format_last_error(err));
    }

    CloseHandle(hProcess);

    const bool ok = wait_ok && (exitCode != 0);
    log_inject(std::string("end result=") + (ok ? "success" : "failed"));
    return ok;
}

} // namespace clink::hook
