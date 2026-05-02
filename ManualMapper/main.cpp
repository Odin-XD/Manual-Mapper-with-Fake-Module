#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <thread>
#include <chrono>
#include <string>

using namespace std;

void SetConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void SlowPrint(const string& text, int delayMs = 1) {
    for (char c : text) {
        cout << c << flush;
        this_thread::sleep_for(chrono::milliseconds(delayMs));
    }
}

void PrintBanner() {
    SetConsoleColor(13);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SlowPrint("    ___  ____  ___ _   _ \n", 0);
    SlowPrint("   / _ \\|  _ \\|_ _| \\ | |\n", 0);
    SlowPrint("  | | | | | | || ||  \\| |\n", 0);
    SlowPrint("  | |_| | |_| || || |\\  |\n", 0);
    SlowPrint("   \\___/|____/___|_| \\_|\n", 0);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SetConsoleColor(7);
    cout << endl;
    SetConsoleColor(8);
    SlowPrint("                        DEV BY ODIN\n", 0);
    SetConsoleColor(7);
    cout << endl;
    SetConsoleColor(13);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SetConsoleColor(7);
    cout << endl;
}

string GetInput(const string& prompt) {
    SetConsoleColor(10);
    cout << prompt;
    SetConsoleColor(7);
    string input;
    getline(cin, input);
    
    if (!input.empty() && input.front() == '"' && input.back() == '"') {
        input = input.substr(1, input.length() - 2);
    }
    
    return input;
}

void PrintStatus(const string& message, int color = 7) {
    SetConsoleColor(color);
    cout << message << endl;
    SetConsoleColor(7);
}

void PrintProgress(const string& message) {
    SetConsoleColor(11);
    cout << "[*] " << message;
    SetConsoleColor(7);
    for (int i = 0; i < 3; i++) {
        this_thread::sleep_for(chrono::milliseconds(300));
        cout << "." << flush;
    }
    cout << endl;
}

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

struct MANUAL_MAPPING_DATA {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
    f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
    BYTE* pbase;
    HINSTANCE hMod;
    DWORD fdwReasonParam;
    LPVOID reservedParam;
    BOOL SEHSupport;
};

#define LOG_SUCCESS(text, ...) { SetConsoleColor(COLOR_SUCCESS); printf("[+] "); printf(text, __VA_ARGS__); SetConsoleColor(COLOR_DEFAULT); }
#define LOG_ERROR(text, ...) { SetConsoleColor(COLOR_ERROR); printf("[-] "); printf(text, __VA_ARGS__); SetConsoleColor(COLOR_DEFAULT); }
#define LOG_WARNING(text, ...) { SetConsoleColor(COLOR_WARNING); printf("[!] "); printf(text, __VA_ARGS__); SetConsoleColor(COLOR_DEFAULT); }
#define LOG_INFO(text, ...) { SetConsoleColor(COLOR_INFO); printf("[*] "); printf(text, __VA_ARGS__); SetConsoleColor(COLOR_DEFAULT); }

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#endif

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
DWORD GetProcessIdByName(const wstring& name);
bool IsCorrectTargetArchitecture(HANDLE hProc);
void EnsureAdminPrivileges();
void EnableDebugPrivileges();
BYTE* ReadDllFile(const wstring& path, SIZE_T& fileSize);
bool AddToPebModuleList(HANDLE hProc, BYTE* pImageBase, const wstring& dllPath, SIZE_T imageSize);

#pragma runtime_checks("", off)
#pragma optimize("", off)

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) return;

    BYTE* pBase = pData->pbase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif

    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>((BYTE*)pRelocData + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
            UINT count = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
            for (UINT i = 0; i < count; ++i) {
                if (RELOC_FLAG(pRelativeInfo[i])) {
                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + (pRelativeInfo[i] & 0xFFF));
                    *pPatch += (UINT_PTR)LocationDelta;
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>((BYTE*)pRelocData + pRelocData->SizeOfBlock);
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDesc->Name) {
            char* szMod = (char*)(pBase + pImportDesc->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDesc->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDesc->FirstThunk);
            if (!pThunkRef) pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
                }
                else {
                    auto* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDesc;
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

#ifdef _WIN64
    if (pData->SEHSupport && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        _RtlAddFunctionTable(
            (PRUNTIME_FUNCTION)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
            pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
            (DWORD64)pBase);
    }
#endif

    auto DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);
    DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);
}

#pragma runtime_checks("", restore)
#pragma optimize("", on)

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)pSrcData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        PrintStatus("[!] Invalid DOS signature", 12);
        return false;
    }

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(pSrcData + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        PrintStatus("[!] Invalid NT signature", 12);
        return false;
    }

    if (ntHeader->FileHeader.Machine != CURRENT_ARCH) {
        PrintStatus("[!] Architecture mismatch", 12);
        return false;
    }

    typedef NTSTATUS(NTAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection) {
        PrintStatus("[!] Failed to get NT API functions", 12);
        return false;
    }

    PrintProgress("Allocating memory in target process");
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = ntHeader->OptionalHeader.SizeOfImage;

    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0 || !hSection) {
        PrintStatus("[!] NtCreateSection failed", 12);
        return false;
    }

    BYTE* targetBase = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(hSection, hProc, (PVOID*)&targetBase, 0, 0, NULL, &viewSize, 1, 0, PAGE_EXECUTE_READWRITE);
    if (status != 0 || !targetBase) {
        PrintStatus("[!] NtMapViewOfSection failed", 12);
        CloseHandle(hSection);
        return false;
    }

    MANUAL_MAPPING_DATA data = {};
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = RtlAddFunctionTable;
#endif
    data.pbase = targetBase;
    data.fdwReasonParam = DLL_PROCESS_ATTACH;
    data.SEHSupport = true;

    PrintProgress("Writing PE headers");
    if (!WriteProcessMemory(hProc, targetBase, pSrcData, 0x1000, nullptr)) {
        PrintStatus("[!] Failed to write headers", 12);
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        return false;
    }

    PrintProgress("Writing sections");
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
    for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->SizeOfRawData == 0) continue;

        if (!WriteProcessMemory(hProc, targetBase + section->VirtualAddress,
            pSrcData + section->PointerToRawData,
            section->SizeOfRawData, nullptr)) {
            PrintStatus("[!] Failed to write section", 12);
            VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
            return false;
        }
    }

    PrintProgress("Creating data section");
    HANDLE hDataSection = NULL;
    LARGE_INTEGER dataSize;
    dataSize.QuadPart = sizeof(data);
    status = NtCreateSection(&hDataSection, SECTION_ALL_ACCESS, NULL, &dataSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0 || !hDataSection) {
        PrintStatus("[!] Data section creation failed", 12);
        CloseHandle(hSection);
        return false;
    }

    void* remoteData = NULL;
    SIZE_T dataViewSize = 0;
    status = NtMapViewOfSection(hDataSection, hProc, &remoteData, 0, 0, NULL, &dataViewSize, 1, 0, PAGE_READWRITE);
    if (status != 0 || !remoteData) {
        PrintStatus("[!] Data section mapping failed", 12);
        CloseHandle(hDataSection);
        CloseHandle(hSection);
        return false;
    }
    CloseHandle(hDataSection);

    PrintProgress("Creating shellcode section");
    HANDLE hShellSection = NULL;
    LARGE_INTEGER shellSize;
    shellSize.QuadPart = 0x1000;
    status = NtCreateSection(&hShellSection, SECTION_ALL_ACCESS, NULL, &shellSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0 || !hShellSection) {
        PrintStatus("[!] Shellcode section creation failed", 12);
        typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        if (NtUnmapViewOfSection) NtUnmapViewOfSection(hProc, remoteData);
        CloseHandle(hSection);
        return false;
    }

    void* remoteShell = NULL;
    SIZE_T shellViewSize = 0;
    status = NtMapViewOfSection(hShellSection, hProc, &remoteShell, 0, 0, NULL, &shellViewSize, 1, 0, PAGE_EXECUTE_READWRITE);
    if (status != 0 || !remoteShell) {
        PrintStatus("[!] Shellcode section mapping failed", 12);
        CloseHandle(hShellSection);
        typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        if (NtUnmapViewOfSection) NtUnmapViewOfSection(hProc, remoteData);
        CloseHandle(hSection);
        return false;
    }
    CloseHandle(hShellSection);

    PrintProgress("Writing shellcode");
    if (!WriteProcessMemory(hProc, remoteData, &data, sizeof(data), nullptr) ||
        !WriteProcessMemory(hProc, remoteShell, (LPVOID)Shellcode, 0x1000, nullptr)) {
        PrintStatus("[!] Failed to write shellcode", 12);
        typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        if (NtUnmapViewOfSection) {
            NtUnmapViewOfSection(hProc, remoteData);
            NtUnmapViewOfSection(hProc, remoteShell);
        }
        CloseHandle(hSection);
        return false;
    }

    DWORD oldProtect;
    VirtualProtectEx(hProc, remoteShell, 0x1000, PAGE_EXECUTE_READ, &oldProtect);

    PrintProgress("Creating remote thread");
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remoteShell, remoteData, 0, nullptr);
    if (!hThread) {
        PrintStatus("[!] Thread creation failed", 12);
        return false;
    }

    PrintProgress("Waiting for execution");
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    PrintProgress("Erasing PE headers");
    SIZE_T headerSize = ntHeader->OptionalHeader.SizeOfHeaders;
    BYTE* zeroBuffer = new BYTE[headerSize];
    memset(zeroBuffer, 0, headerSize);
    WriteProcessMemory(hProc, targetBase, zeroBuffer, headerSize, nullptr);
    delete[] zeroBuffer;

    PrintProgress("Adding to PEB module list");
    AddToPebModuleList(hProc, targetBase, L"C:\\Windows\\System32\\dbghelp.dll", ntHeader->OptionalHeader.SizeOfImage);

    PrintProgress("Setting section protections");
    section = IMAGE_FIRST_SECTION(ntHeader);
    for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->SizeOfRawData == 0) continue;

        DWORD protection = PAGE_READONLY;
        DWORD characteristics = section->Characteristics;

        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                protection = PAGE_EXECUTE_READWRITE;
            }
            else if (characteristics & IMAGE_SCN_MEM_READ) {
                protection = PAGE_EXECUTE_READ;
            }
            else {
                protection = PAGE_EXECUTE;
            }
        }
        else if (characteristics & IMAGE_SCN_MEM_WRITE) {
            if (characteristics & IMAGE_SCN_MEM_READ) {
                protection = PAGE_READWRITE;
            }
            else {
                protection = PAGE_WRITECOPY;
            }
        }
        else if (characteristics & IMAGE_SCN_MEM_READ) {
            protection = PAGE_READONLY;
        }

        DWORD oldProtect;
        VirtualProtectEx(hProc, targetBase + section->VirtualAddress,
            section->Misc.VirtualSize, protection, &oldProtect);
    }

    PrintProgress("Cleaning up");
    Sleep(500);

    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    if (NtUnmapViewOfSection) {
        NTSTATUS status1 = NtUnmapViewOfSection(hProc, remoteData);
        NTSTATUS status2 = NtUnmapViewOfSection(hProc, remoteShell);
    }

    CloseHandle(hSection);

    return true;
}

DWORD GetProcessIdByName(const wstring& name) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

bool IsCorrectTargetArchitecture(HANDLE hProc) {
    BOOL bTarget = FALSE;
    if (!IsWow64Process(hProc, &bTarget)) {
        return false;
    }

    BOOL bHost = FALSE;
    IsWow64Process(GetCurrentProcess(), &bHost);

    return (bTarget == bHost);
}

void EnsureAdminPrivileges() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isAdmin) {
        PrintStatus("[!] Administrator privileges required", 12);
        ExitProcess(1);
    }
}

void EnableDebugPrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid);
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        CloseHandle(hToken);
    }
}

BYTE* ReadDllFile(const wstring& path, SIZE_T& fileSize) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return nullptr;
    }

    BYTE* pData = new BYTE[fileSize];
    DWORD bytesRead;
    if (!ReadFile(hFile, pData, fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        delete[] pData;
        CloseHandle(hFile);
        return nullptr;
    }

    CloseHandle(hFile);
    return pData;
}

bool AddToPebModuleList(HANDLE hProc, BYTE* pImageBase, const wstring& dllPath, SIZE_T imageSize) {
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        LIST_ENTRY HashLinks;
        PVOID SectionPointer;
        ULONG CheckSum;
        ULONG TimeDateStamp;
        PVOID LoadedImports;
        PVOID EntryPointActivationContext;
        PVOID PatchInformation;
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;

#ifdef _WIN64
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[21];
        PPEB_LDR_DATA Ldr;
    } PEB, * PPEB;
#else
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PPEB_LDR_DATA Ldr;
    } PEB, * PPEB;
#endif

    PROCESS_BASIC_INFORMATION pbi = {};
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        return false;
    }

    if (NtQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), nullptr) != 0) {
        return false;
    }

    PEB peb = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        return false;
    }

    PEB_LDR_DATA ldr = {};
    if (!ReadProcessMemory(hProc, peb.Ldr, &ldr, sizeof(ldr), &bytesRead)) {
        return false;
    }

    SIZE_T pathLen = (dllPath.length() + 1) * sizeof(wchar_t);
    wchar_t* remotePath = (wchar_t*)VirtualAllocEx(hProc, nullptr, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath || !WriteProcessMemory(hProc, remotePath, dllPath.c_str(), pathLen, &bytesRead)) {
        return false;
    }

    wstring baseName = dllPath.substr(dllPath.find_last_of(L"\\") + 1);
    SIZE_T baseLen = (baseName.length() + 1) * sizeof(wchar_t);
    wchar_t* remoteBase = (wchar_t*)VirtualAllocEx(hProc, nullptr, baseLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBase || !WriteProcessMemory(hProc, remoteBase, baseName.c_str(), baseLen, &bytesRead)) {
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        return false;
    }

    LDR_DATA_TABLE_ENTRY* remoteEntry = (LDR_DATA_TABLE_ENTRY*)VirtualAllocEx(hProc, nullptr,
        sizeof(LDR_DATA_TABLE_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteEntry) {
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        return false;
    }

    LDR_DATA_TABLE_ENTRY entry = {};
    entry.DllBase = pImageBase;
    entry.SizeOfImage = (ULONG)imageSize;
    entry.FullDllName.Buffer = remotePath;
    entry.FullDllName.Length = (USHORT)(dllPath.length() * sizeof(wchar_t));
    entry.FullDllName.MaximumLength = (USHORT)pathLen;
    entry.BaseDllName.Buffer = remoteBase;
    entry.BaseDllName.Length = (USHORT)(baseName.length() * sizeof(wchar_t));
    entry.BaseDllName.MaximumLength = (USHORT)baseLen;
    entry.LoadCount = 1;

    entry.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;
    entry.InLoadOrderLinks.Blink = &peb.Ldr->InLoadOrderModuleList;

    if (!WriteProcessMemory(hProc, remoteEntry, &entry, sizeof(entry), &bytesRead)) {
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteEntry, 0, MEM_RELEASE);
        return false;
    }

    LIST_ENTRY newHead;
    newHead.Flink = (PLIST_ENTRY)&remoteEntry->InLoadOrderLinks;
    newHead.Blink = ldr.InLoadOrderModuleList.Blink;

    if (!WriteProcessMemory(hProc, &peb.Ldr->InLoadOrderModuleList, &newHead, sizeof(LIST_ENTRY), &bytesRead)) {
        return false;
    }

    return true;
}

int main() {
    PrintBanner();
    
    EnsureAdminPrivileges();
    EnableDebugPrivileges();

    PrintStatus("[*] Interactive Mode\n", 10);
    
    string processName = GetInput("Enter process name: ");
    if (processName.empty()) {
        PrintStatus("\n[!] Error: Process name cannot be empty", 12);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    
    cout << endl;
    string dllPath = GetInput("Enter DLL path: ");
    if (dllPath.empty()) {
        PrintStatus("\n[!] Error: DLL path cannot be empty", 12);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    
    cout << endl;
    SetConsoleColor(13);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SetConsoleColor(7);
    cout << endl;
    
    PrintProgress("Finding target process");
    wstring wProcessName(processName.begin(), processName.end());
    DWORD PID = GetProcessIdByName(wProcessName);
    if (PID == 0) {
        PrintStatus("\n[!] Process not found", 12);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    PrintStatus("[+] Found PID: " + to_string(PID), 10);
    
    PrintProgress("Opening process");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc) {
        PrintStatus("\n[!] Failed to open process", 12);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    PrintStatus("[+] Process opened", 10);
    
    if (!IsCorrectTargetArchitecture(hProc)) {
        PrintStatus("\n[!] Architecture mismatch", 12);
        CloseHandle(hProc);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    
    PrintProgress("Reading DLL file");
    wstring wDllPath(dllPath.begin(), dllPath.end());
    SIZE_T dllSize = 0;
    BYTE* dllBytes = ReadDllFile(wDllPath, dllSize);
    if (!dllBytes || dllSize == 0) {
        PrintStatus("\n[!] Failed to read DLL file", 12);
        CloseHandle(hProc);
        PrintStatus("\nPress any key to exit...", 8);
        cin.get();
        return 1;
    }
    PrintStatus("[+] DLL loaded (" + to_string(dllSize) + " bytes)", 10);
    
    cout << endl;
    bool success = ManualMapDll(hProc, dllBytes, dllSize);
    
    CloseHandle(hProc);
    delete[] dllBytes;
    
    cout << endl;
    SetConsoleColor(13);
    SlowPrint("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n", 0);
    SetConsoleColor(7);
    cout << endl;
    
    if (success) {
        PrintStatus("[+] Injection completed successfully!", 10);
    }
    else {
        PrintStatus("[!] Injection failed", 12);
    }
    
    cout << endl;
    PrintStatus("Press any key to exit...", 8);
    cin.get();
    
    return success ? 0 : 1;
}