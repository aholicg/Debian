#include <windows.h>

HANDLE hStdin;

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    CHAR chBuffer[256];
    DWORD cRead;

    hStdin = GetStdHandle(STD_INPUT_HANDLE);

    return 0;
}