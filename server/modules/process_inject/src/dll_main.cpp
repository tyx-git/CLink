#include <winsock2.h>
#include <windows.h>
#include "hook_manager.hpp"

// Global thread handle
HANDLE g_hInitThread = NULL;

DWORD WINAPI InitThread(LPVOID lpParam) {
    clink::hook::HookManager::instance().initialize();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Disable thread library calls if not needed
        DisableThreadLibraryCalls(hModule);
        
        // Create a thread to initialize hooks and connect to IPC
        // This avoids doing heavy work in DllMain which can cause deadlocks
        g_hInitThread = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (g_hInitThread) {
            CloseHandle(g_hInitThread);
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        clink::hook::HookManager::instance().shutdown();
        break;
    }
    return TRUE;
}
