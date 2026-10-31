// 32-/64-битный клиент для проверки перехвата: GET / через winsock.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")

int main(int argc, char** argv)
{
    FILE* outFile = nullptr;
    if (argc > 1) outFile = fopen(argv[1], "wb");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 2;

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo("api.ipify.org", "80", &hints, &res) != 0) return 3;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 4;
    DWORD tmo = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        printf("connect failed %d\n", WSAGetLastError());
        return 5;
    }
    printf("connected\n");

    const char* req = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n";
    send(s, req, (int)strlen(req), 0);

    char buf[4096];
    int n;
    while ((n = recv(s, buf, sizeof(buf), 0)) > 0) {
        if (outFile) fwrite(buf, 1, n, outFile);
        else fwrite(buf, 1, n, stdout);
    }
    if (outFile) fclose(outFile);
    closesocket(s);
    freeaddrinfo(res);
    WSACleanup();
    return 0;
}
