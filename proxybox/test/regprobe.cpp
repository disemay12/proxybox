// Проверка изоляции реестра: пишет свой APPDATA в HKCU\Software\PBTest,
// ждёт и читает обратно. Если HKCU изолирован по процессу — прочитает своё.
#include <windows.h>
#include <cstdio>

int main(int argc, char** argv)
{
    const char* dir = argc > 1 ? argv[1] : ".";

    char marker[MAX_PATH] = {0};
    GetEnvironmentVariableA("APPDATA", marker, MAX_PATH);

    HKEY key = nullptr;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\PBTest", 0, nullptr, 0,
                        KEY_ALL_ACCESS, nullptr, &key, nullptr) == ERROR_SUCCESS) {
        RegSetValueExA(key, "val", 0, REG_SZ, (const BYTE*)marker,
                       (DWORD)strlen(marker) + 1);
        RegCloseKey(key);
    }

    Sleep(1500);

    char got[MAX_PATH] = {0};
    DWORD size = sizeof(got);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\PBTest", 0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegQueryValueExA(key, "val", nullptr, nullptr, (LPBYTE)got, &size);
        RegCloseKey(key);
    }

    char path[MAX_PATH * 2];
    snprintf(path, sizeof(path), "%s\\reg-%lu.txt", dir, GetCurrentProcessId());
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "wrote: %s\nread:  %s\n", marker, got);
        fclose(f);
    }
    return 0;
}
