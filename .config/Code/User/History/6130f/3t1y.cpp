#include <windows.h>
#include <string.h>

HANDLE hStdin;

int main(){
    CHAR chBuffer[256];
    DWORD cRead;

    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    ReadFile(
        hStdin,
        chBuffer,
        255,
        &cRead,
        NULL
    );

    chBuffer[cRead]='\0';
    chBuffer[strcspn(chBuffer,"\r\n")]='\0';

    CreateFile(
        chBuffer,
        GENERIC_READ,
        read,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    return 0;
}