#include <windows.h>
#include <cstdio>

int main(int argc, char** argv)
{
    if (argc < 2) return 2;
    HMODULE h = LoadLibraryA(argv[1]);
    printf("module=%p\n", (void*)h);
    if (!h) printf("error=%lu\n", GetLastError());
    return h ? 0 : 1;
}
