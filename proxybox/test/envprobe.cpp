// Тестовая утилита: пишет свой APPDATA в файл, имя которого содержит PID.
#include <windows.h>
#include <cstdio>

int main(int argc, char** argv)
{
    const char* dir = argc > 1 ? argv[1] : ".";
    char appdata[MAX_PATH] = {0};
    GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);

    char path[MAX_PATH * 2];
    snprintf(path, sizeof(path), "%s\\env-%lu.txt", dir, GetCurrentProcessId());
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n", appdata);
        fclose(f);
    }
    return 0;
}
