#include <Windows.h>

HINSTANCE g_hInstance = NULL;
bool g_running = true;

DWORD WINAPI HotkeyThread(LPVOID lpParam) {
    while (g_running) {
        if (GetAsyncKeyState(VK_END) & 0x8000) {
            MessageBoxA(NULL, "Hotkey Pressed!", "TestDLL", MB_OK | MB_ICONINFORMATION);
            
            while (GetAsyncKeyState(VK_END) & 0x8000) {
                Sleep(10);
            }
        }
        Sleep(50);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        g_hInstance = hModule;
        
        CreateThread(NULL, 0, HotkeyThread, NULL, 0, NULL);
        break;
        
    case DLL_PROCESS_DETACH:
        g_running = false;
        break;
    }
    return TRUE;
}
