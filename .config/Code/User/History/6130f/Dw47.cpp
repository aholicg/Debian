#include <windows.h>
#include <string.h>

HANDLE hStdin, hStdout, hFile;

int main(){
    CHAR chBuffer[256];
    DWORD cRead;

    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

    if(!ReadFile(
        hStdin,
        chBuffer,
        255,
        &cRead,
        NULL))
    {
        MessageBox(NULL, TEXT("Error reading file path"), TEXT("Console Error"), MB_OK);
            return 1;
    };

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
    if (hFile == INVALID_HANDLE_VALUE)
    {
        MessageBox(NULL, TEXT("Error opening file"), TEXT("Console Error"), MB_OK);
        return 1;
    }

    if(!ReadFile(
        hFile,
        chBuffer,
        100,
        &cRead, //reuse ok bc the old version will be overwritten
        NULL))
    {
        MessageBox(NULL, TEXT("Error reading file content"), TEXT("Console Error"), MB_OK);
        return 1;
    };

    if(!WriteFile(
        hStdout,
        chBuffer,
        cRead,
        &cRead,
        NULL))
    {
        MessageBox(NULL, TEXT("Error printing out file content"), TEXT("Console Error"), MB_OK);
        return 1;
    };

    CloseHandle(hFile);
    return 0;
}