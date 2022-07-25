#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char code[] = "SHELLCODE_HERE";
    printf("The shellcode length is: %d\n", strlen(code));
    void (*s)() = (void *)code;
    s();
    return 0;
}