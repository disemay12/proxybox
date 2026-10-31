// UDP probe for the pbhook test: DNS query to a public resolver.
//   udpprobe.exe connect  -> connect() + send()/recv()
//   udpprobe.exe sendto   -> sendto()/recvfrom() on an unconnected socket
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv)
{
    const bool useConnect = argc > 1 && strcmp(argv[1], "connect") == 0;
    const char* ip = argc > 2 ? argv[2] : "8.8.8.8";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { printf("socket failed\n"); return 1; }

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(53);
    inet_pton(AF_INET, ip, &to.sin_addr);

    DWORD tmo = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));

    if (useConnect && connect(s, (sockaddr*)&to, sizeof(to)) != 0) {
        printf("connect failed %d\n", WSAGetLastError());
        return 1;
    }

    unsigned char q[] = {0x12,0x34,0x01,0x00,0x00,0x01,0,0,0,0,0,0,
                         7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    int sent = useConnect
        ? send(s, (char*)q, sizeof(q), 0)
        : sendto(s, (char*)q, sizeof(q), 0, (sockaddr*)&to, sizeof(to));
    if (sent <= 0) {
        printf("send failed %d\n", WSAGetLastError());
        return 1;
    }

    char buf[2048];
    int n = useConnect
        ? recv(s, buf, sizeof(buf), 0)
        : recvfrom(s, buf, sizeof(buf), 0, nullptr, nullptr);
    printf("mode=%s sent=%d recv=%d\n", useConnect ? "connect" : "sendto", sent, n);
    if (n > 12) printf("answer_id=%02x%02x answers=%d\n", (unsigned char)buf[0], (unsigned char)buf[1], buf[6] << 8 | buf[7]);
    WSACleanup();
    return n > 0 ? 0 : 1;
}
