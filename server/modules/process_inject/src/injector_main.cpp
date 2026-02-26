#include <windows.h>
#include <string>
#include <iostream>
#include <vector>

namespace clink::hook {

bool InjectDLL(DWORD processId, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Failed to open process " << processId << std::endl;
        return false;
    }

    void* pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        std::cerr << "Failed to allocate memory in remote process" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        std::cerr << "Failed to write to remote process memory" << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteBuf, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread" << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return exitCode != 0;
}

} // namespace clink::hook
