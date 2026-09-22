#include <windows.h>
#include <string.h>

HANDLE hStdin, hStdout, hFile;

int main(){
    CHAR chBuffer[256];
    DWORD cRead;

    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

    ReadFile(
        hStdin,
        chBuffer,
        255,
        &cRead,
        NULL
    );

    chBuffer[cRead]='\0';
    chBuffer[strcspn(chBuffer,"\r\n")]='\0';

    hFile = CreateFile(
        chBuffer,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    ReadFile(
        hFile,
        chBuffer,
        100,
        &cRead, //reuse ok bc the old version will be overwritten
        NULL
    );

    WriteFile(
        hFile,
        chBuffer,
        100,
        &cRead,
        NULL
    );

    return 0;
}