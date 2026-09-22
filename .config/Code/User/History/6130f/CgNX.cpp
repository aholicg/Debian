#include <windows.h>

HANDLE hStdin;

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
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

    return 0;
}