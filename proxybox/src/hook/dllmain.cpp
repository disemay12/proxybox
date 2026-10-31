// pbproxy — per-process proxy redirector (injected DLL)
// Hooks winsock connect paths and tunnels every TCP connection through the
// proxy named by the PB_PROXY environment variable of the host process.
//
// PB_PROXY   http://host:port | socks5://host:port | host:port
//            optional credentials: scheme://user:pass@host:port
// PB_LOG     optional path for a diagnostic log
//
// UDP is proxied too when the upstream confirms SOCKS5 UDP ASSOCIATE
// (RFC 1928 §7); if the proxy refuses it (or the scheme is HTTP) datagram
// sockets keep talking to the real destination directly.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include "MinHook.h"
#include "../common/sandbox.h"
#include <shlobj.h>
#include <knownfolders.h>
#include <objbase.h>

#pragma pack(push, 1)
struct PbHdr {
    uint32_t magic;
    uint32_t ip;    // network byte order
    uint16_t port;  // network byte order
    uint8_t  family;
    uint8_t  reserved;
};
#pragma pack(pop)

static const uint32_t PB_MAGIC = 0x424F5850; // "PXOB"

// SOCKS5 UDP request/reply header (RFC 1928 §7): no fragmentation, IPv4 only.
#pragma pack(push, 1)
struct PbUdpHdr {
    uint8_t  rsv[2];
    uint8_t  frag;
    uint8_t  atyp;
    uint32_t ip;    // network byte order
    uint16_t port;  // network byte order
};
#pragma pack(pop)

static const int PB_UDP_HDR = (int)sizeof(PbUdpHdr);

// ---------------------------------------------------------------- globals
static HMODULE g_self = nullptr;
static SOCKET g_listen = INVALID_SOCKET;
static volatile uint16_t g_relayPort = 0;
static volatile LONG g_active = 0;
static thread_local bool t_internal = false;

static int g_scheme = 0; // 0 = http CONNECT, 1 = socks5
static std::string g_proxyHost;
static uint16_t g_proxyPort = 0;
static std::string g_proxyUser;
static std::string g_proxyPass;
static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_logLock;

static CRITICAL_SECTION g_mapLock;
static std::unordered_map<SOCKET, PbHdr> g_pending; // header owed to relay

// ---- SOCKS5 UDP ASSOCIATE state
static volatile LONG g_udpReady = 0;
static SOCKET g_udpSock = INVALID_SOCKET;   // local endpoint the application talks to
static volatile uint16_t g_udpSockPort = 0;
static SOCKET g_udpCtrl = INVALID_SOCKET;   // TCP control channel; RFC 1928 keeps it open
static sockaddr_in g_udpRelay{};            // proxy-side UDP relay
static volatile LONG g_udpPeerCount = 0;    // cheap gate for the hot send path
static std::unordered_map<SOCKET, sockaddr_in> g_udpPeers;    // app socket -> destination
static std::unordered_map<uint64_t, sockaddr_in> g_udpRoutes; // remote endpoint -> app source
static sockaddr_in g_udpLastApp{};          // fallback for replies with an unknown endpoint

// ---------------------------------------------------------------- reals
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *WSAConnect_t)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef BOOL (PASCAL *ConnectEx_t)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef int (WSAAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI *WSASend_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *getpeername_t)(SOCKET, struct sockaddr*, int*);
typedef int (WSAAPI *closesocket_t)(SOCKET);
typedef int (WSAAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static connect_t     real_connect = nullptr;
static WSAConnect_t  real_WSAConnect = nullptr;
static ConnectEx_t   real_ConnectEx = nullptr;
static send_t        real_send = nullptr;
static WSASend_t     real_WSASend = nullptr;
static getpeername_t real_getpeername = nullptr;
static closesocket_t real_closesocket = nullptr;
static sendto_t      real_sendto = nullptr;
static WSASendTo_t   real_WSASendTo = nullptr;
static recvfrom_t    real_recvfrom = nullptr;
static WSARecvFrom_t real_WSARecvFrom = nullptr;

// ---------------------------------------------------------------- log
static void Log(const char* fmt, ...)
{
    if (g_log == INVALID_HANDLE_VALUE) return;
    char line[2048];
    EnterCriticalSection(&g_logLock);
    SYSTEMTIME st;
    GetLocalTime(&st);
    int n = snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d] ",
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    size_t off = (n > 0 && (size_t)n < sizeof(line)) ? (size_t)n : 0;
    va_list ap;
    va_start(ap, fmt);
    size_t avail = sizeof(line) - off;
    int m = vsnprintf(line + off, avail, fmt, ap);
    va_end(ap);
    if (m < 0) m = 0;
    size_t len = off + ((size_t)m < avail ? (size_t)m : avail - 1);
    if (len >= sizeof(line) - 1) len = sizeof(line) - 2;
    line[len++] = '\n';
    // One WriteFile per line: children share PB_LOG, and multiple CRT streams
    // seeking to EOF would overwrite each other's lines.
    DWORD written = 0;
    WriteFile(g_log, line, (DWORD)len, &written, nullptr);
    LeaveCriticalSection(&g_logLock);
}

// ---------------------------------------------------------------- net helpers
static int SendAll(SOCKET s, const char* buf, int len)
{
    int off = 0;
    while (off < len) {
        int n = ::send(s, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += n;
    }
    return off;
}

static bool RecvAll(SOCKET s, char* buf, int len)
{
    int off = 0;
    while (off < len) {
        int n = ::recv(s, buf + off, len - off, 0);
        if (n <= 0) return false;
        off += n;
    }
    return true;
}

static bool ConnectReal(SOCKET s, uint32_t ipNet, uint16_t portNet)
{
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ipNet;
    sa.sin_port = portNet;
    return real_connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0;
}

// ---------------------------------------------------------------- upstream handshake
static bool HandshakeHttp(SOCKET up, const PbHdr& h)
{
    sockaddr_in dst{};
    dst.sin_addr.s_addr = h.ip;
    dst.sin_port = h.port;
    char ip[64] = {0};
    inet_ntop(AF_INET, &dst.sin_addr, ip, sizeof(ip));
    char req[512];
    int n = snprintf(req, sizeof(req),
                     "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\nProxy-Connection: keep-alive\r\n\r\n",
                     ip, ntohs(h.port), ip, ntohs(h.port));
    if (SendAll(up, req, n) != n) return false;

    char resp[2048];
    int used = 0;
    while (used < (int)sizeof(resp) - 1) {
        int r = ::recv(up, resp + used, (int)sizeof(resp) - 1 - used, 0);
        if (r <= 0) return false;
        used += r;
        resp[used] = 0;
        if (strstr(resp, "\r\n\r\n")) break;
    }
    if (used < 12) return false;
    return resp[0] == 'H' && strstr(resp, " 200") != nullptr;
}

// RFC 1928 method selection + optional user/pass auth; shared by CONNECT and
// UDP ASSOCIATE so the credential exchange exists only once.
static bool SocksAuth(SOCKET up)
{
    unsigned char buf[512];
    const bool auth = !g_proxyUser.empty();

    if (auth) {
        buf[0] = 5; buf[1] = 2; buf[2] = 0; buf[3] = 2;
        if (SendAll(up, (char*)buf, 4) != 4) return false;
    } else {
        buf[0] = 5; buf[1] = 1; buf[2] = 0;
        if (SendAll(up, (char*)buf, 3) != 3) return false;
    }

    unsigned char rep[2];
    if (!RecvAll(up, (char*)rep, 2) || rep[0] != 5) return false;

    if (rep[1] == 2) {
        if (!auth) return false;
        size_t ul = g_proxyUser.size() > 255 ? 255 : g_proxyUser.size();
        size_t pl = g_proxyPass.size() > 255 ? 255 : g_proxyPass.size();
        buf[0] = 1; buf[1] = (unsigned char)ul;
        memcpy(buf + 2, g_proxyUser.data(), ul);
        buf[2 + ul] = (unsigned char)pl;
        memcpy(buf + 3 + ul, g_proxyPass.data(), pl);
        int total = 3 + (int)ul + (int)pl;
        if (SendAll(up, (char*)buf, total) != total) return false;
        unsigned char ar[2];
        if (!RecvAll(up, (char*)ar, 2) || ar[1] != 0) return false;
    } else if (rep[1] != 0) {
        return false;
    }
    return true;
}

static bool HandshakeSocks5(SOCKET up, const PbHdr& h)
{
    if (!SocksAuth(up)) return false;

    unsigned char buf[16];
    buf[0] = 5; buf[1] = 1; buf[2] = 0; buf[3] = 1;
    memcpy(buf + 4, &h.ip, 4);
    memcpy(buf + 8, &h.port, 2);
    if (SendAll(up, (char*)buf, 10) != 10) return false;

    unsigned char gr[4];
    if (!RecvAll(up, (char*)gr, 4) || gr[1] != 0) return false;
    int skip = 0;
    if (gr[3] == 1) skip = 4 + 2;
    else if (gr[3] == 4) skip = 16 + 2;
    else if (gr[3] == 3) {
        unsigned char l = 0;
        if (!RecvAll(up, (char*)&l, 1)) return false;
        skip = l + 2;
    } else return false;
    while (skip > 0) {
        unsigned char tmp[64];
        int chunk = skip > (int)sizeof(tmp) ? (int)sizeof(tmp) : skip;
        if (!RecvAll(up, (char*)tmp, chunk)) return false;
        skip -= chunk;
    }
    return true;
}

static void Pump(SOCKET a, SOCKET b)
{
    char buf[32768];
    for (;;) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(a, &rf);
        FD_SET(b, &rf);
        int rc = select(0, &rf, nullptr, nullptr, nullptr);
        if (rc <= 0) break;
        if (FD_ISSET(a, &rf)) {
            int n = ::recv(a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (SendAll(b, buf, n) != n) break;
        }
        if (FD_ISSET(b, &rf)) {
            int n = ::recv(b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (SendAll(a, buf, n) != n) break;
        }
    }
    shutdown(a, SD_BOTH);
    shutdown(b, SD_BOTH);
    closesocket(a);
    closesocket(b);
}

struct RelayJob { SOCKET client; PbHdr hdr; };

static DWORD WINAPI RelayThread(LPVOID param)
{
    RelayJob* job = static_cast<RelayJob*>(param);
    SOCKET client = job->client;
    PbHdr h = job->hdr;
    delete job;

    SOCKET up = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (up == INVALID_SOCKET) { closesocket(client); return 0; }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    char port[16];
    snprintf(port, sizeof(port), "%u", g_proxyPort);
    bool ok = false;
    if (getaddrinfo(g_proxyHost.c_str(), port, &hints, &res) == 0) {
        for (addrinfo* p = res; p; p = p->ai_next) {
            if (real_connect(up, p->ai_addr, (int)p->ai_addrlen) == 0) { ok = true; break; }
        }
        freeaddrinfo(res);
    }
    if (!ok) {
        Log("relay: cannot reach proxy %s:%u", g_proxyHost.c_str(), g_proxyPort);
        closesocket(up);
        closesocket(client);
        return 0;
    }

    unsigned long tmo = 15000;
    setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    setsockopt(up, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmo, sizeof(tmo));

    bool hs = (g_scheme == 1) ? HandshakeSocks5(up, h) : HandshakeHttp(up, h);
    if (!hs) {
        Log("relay: handshake failed");
        closesocket(up);
        closesocket(client);
        return 0;
    }
    tmo = 0;
    setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    setsockopt(up, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmo, sizeof(tmo));

    Pump(client, up);
    return 0;
}

static DWORD WINAPI ListenThread(LPVOID)
{
    for (;;) {
        SOCKET c = accept(g_listen, nullptr, nullptr);
        if (c == INVALID_SOCKET) {
            if (!g_active) return 0;
            Sleep(20);
            continue;
        }
        PbHdr h{};
        if (!RecvAll(c, (char*)&h, sizeof(h)) || h.magic != PB_MAGIC) {
            closesocket(c);
            continue;
        }
        RelayJob* job = new RelayJob{c, h};
        HANDLE th = CreateThread(nullptr, 0, RelayThread, job, 0, nullptr);
        if (th) CloseHandle(th);
        else { delete job; closesocket(c); }
    }
}

// ---------------------------------------------------------------- hooks
static bool IsLoopback(const sockaddr* sa)
{
    if (sa->sa_family == AF_INET) {
        const sockaddr_in* v4 = reinterpret_cast<const sockaddr_in*>(sa);
        return (ntohl(v4->sin_addr.s_addr) >> 24) == 127;
    }
    if (sa->sa_family == AF_INET6) {
        const sockaddr_in6* v6 = reinterpret_cast<const sockaddr_in6*>(sa);
        static const unsigned char lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(&v6->sin6_addr, lo, 16) == 0) return true;
    }
    return false;
}

static bool MakeHeader(const sockaddr* sa, PbHdr& h)
{
    if (!sa || sa->sa_family != AF_INET) return false;
    const sockaddr_in* v4 = reinterpret_cast<const sockaddr_in*>(sa);
    h.magic = PB_MAGIC;
    h.ip = v4->sin_addr.s_addr;
    h.port = v4->sin_port;
    h.family = 2;
    h.reserved = 0;
    return true;
}

static bool WaitWritable(SOCKET s, int ms)
{
    fd_set wf;
    FD_ZERO(&wf);
    FD_SET(s, &wf);
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, nullptr, &wf, nullptr, &tv) > 0;
}

// send that tolerates sockets left in non-blocking mode by the application
static bool SendAllNB(SOCKET s, const char* buf, int len)
{
    int off = 0;
    while (off < len) {
        int n = ::send(s, buf + off, len - off, 0);
        if (n > 0) { off += n; continue; }
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK || e == WSAENOBUFS) {
                if (!WaitWritable(s, 10000)) return false;
                continue;
            }
        }
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- udp relay
static int SockType(SOCKET s)
{
    int type = 0;
    int len = (int)sizeof(type);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &len) != 0) return -1;
    return type;
}

static bool UdpPeer(SOCKET s, sockaddr_in& out)
{
    bool have = false;
    EnterCriticalSection(&g_mapLock);
    auto it = g_udpPeers.find(s);
    if (it != g_udpPeers.end()) { out = it->second; have = true; }
    LeaveCriticalSection(&g_mapLock);
    return have;
}

static void ForgetUdpPeer(SOCKET s)
{
    EnterCriticalSection(&g_mapLock);
    auto it = g_udpPeers.find(s);
    if (it != g_udpPeers.end()) {
        g_udpPeers.erase(it);
        InterlockedDecrement(&g_udpPeerCount);
    }
    LeaveCriticalSection(&g_mapLock);
}

static bool UdpLocalAddr(sockaddr_in& out)
{
    uint16_t port = g_udpSockPort;
    if (!port || g_udpSock == INVALID_SOCKET) return false;
    out = sockaddr_in{};
    out.sin_family = AF_INET;
    out.sin_port = htons(port);
    out.sin_addr.s_addr = inet_addr("127.0.0.1");
    return true;
}

// A proxied datagram socket is connect()ed to our local relay so the kernel
// filter accepts replies; the real destination is kept for the send wrappers.
static bool RedirectUdpPeer(SOCKET s, const struct sockaddr* name, sockaddr_in& relay)
{
    if (!g_udpReady || !name || name->sa_family != AF_INET || IsLoopback(name)) return false;
    if (!UdpLocalAddr(relay)) return false;

    sockaddr_in orig{};
    memcpy(&orig, name, sizeof(orig));
    EnterCriticalSection(&g_mapLock);
    if (g_udpPeers.find(s) == g_udpPeers.end()) InterlockedIncrement(&g_udpPeerCount);
    g_udpPeers[s] = orig;
    LeaveCriticalSection(&g_mapLock);
    return true;
}

static uint64_t UdpRouteKey(const sockaddr_in& a)
{
    return ((uint64_t)a.sin_addr.s_addr << 16) | (uint64_t)a.sin_port;
}

static void RememberUdpRoute(const sockaddr_in& remote, const sockaddr_in& app)
{
    EnterCriticalSection(&g_mapLock);
    if (g_udpRoutes.size() > 512) g_udpRoutes.clear();
    g_udpRoutes[UdpRouteKey(remote)] = app;
    g_udpLastApp = app;
    LeaveCriticalSection(&g_mapLock);
}

static bool UdpAppFor(const sockaddr_in& remote, sockaddr_in& app)
{
    bool have = false;
    EnterCriticalSection(&g_mapLock);
    auto it = g_udpRoutes.find(UdpRouteKey(remote));
    if (it != g_udpRoutes.end()) { app = it->second; have = true; }
    else if (g_udpLastApp.sin_port != 0) { app = g_udpLastApp; have = true; }
    LeaveCriticalSection(&g_mapLock);
    return have;
}

// 0 = ok, 1 = malformed (RSV/ATYP/short), 2 = fragmented (unsupported).
static int ParseUdpEnvelope(const unsigned char* p, int n, sockaddr_in& dst)
{
    if (n < PB_UDP_HDR) return 1;
    PbUdpHdr h{};
    memcpy(&h, p, sizeof(h));
    if (h.frag != 0) return 2;
    if (h.rsv[0] != 0 || h.rsv[1] != 0 || h.atyp != 1) return 1;
    dst = sockaddr_in{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = h.ip;
    dst.sin_port = h.port;
    return 0;
}

// Per-message budget so a broken proxy cannot flood the log.
static int UdpLogBudget(int slot, const char* msg)
{
    static volatile LONG counters[4] = {0, 0, 0, 0};
    if (InterlockedIncrement(&counters[slot]) <= 20) Log("%s", msg);
    return 0;
}

// Wraps one datagram in an RFC 1928 §7 envelope and hands it to the local relay.
// Returns the payload length, the way sendto() accounts for UDP.
static int UdpProxySend(SOCKET s, const char* data, int len, const struct sockaddr* to)
{
    sockaddr_in peer{};
    if (!UdpPeer(s, peer)) { WSASetLastError(WSAENOTSOCK); return SOCKET_ERROR; }
    if (to) {
        if (to->sa_family != AF_INET) { WSASetLastError(WSAEAFNOSUPPORT); return SOCKET_ERROR; }
        memcpy(&peer, to, sizeof(peer));
    }
    sockaddr_in relay{};
    if (!UdpLocalAddr(relay)) { WSASetLastError(WSAENETDOWN); return SOCKET_ERROR; }
    if (len < 0 || len > 65507) { WSASetLastError(WSAEMSGSIZE); return SOCKET_ERROR; }

    unsigned char* pkt = (unsigned char*)malloc((size_t)PB_UDP_HDR + (size_t)len);
    if (!pkt) { WSASetLastError(WSAENOBUFS); return SOCKET_ERROR; }
    PbUdpHdr h{};
    h.atyp = 1;
    h.ip = peer.sin_addr.s_addr;
    h.port = peer.sin_port;
    memcpy(pkt, &h, sizeof(h));
    if (len) memcpy(pkt + PB_UDP_HDR, data, (size_t)len);

    int r = real_sendto(s, (const char*)pkt, PB_UDP_HDR + len, 0,
                        reinterpret_cast<const sockaddr*>(&relay), sizeof(relay));
    free(pkt);
    if (r == SOCKET_ERROR) return SOCKET_ERROR;
    UdpLogBudget(0, "udp: proxying datagrams");
    return len;
}

static int UdpProxySendBufs(SOCKET s, LPWSABUF bufs, DWORD count, const struct sockaddr* to)
{
    if (count == 1) return UdpProxySend(s, bufs[0].buf, (int)bufs[0].len, to);

    int total = 0;
    for (DWORD i = 0; i < count; i++) {
        if (bufs[i].len > 65507 || total > 65507 - (int)bufs[i].len) {
            WSASetLastError(WSAEMSGSIZE);
            return SOCKET_ERROR;
        }
        total += (int)bufs[i].len;
    }
    char* flat = (char*)malloc((size_t)(total ? total : 1));
    if (!flat) { WSASetLastError(WSAENOBUFS); return SOCKET_ERROR; }
    int off = 0;
    for (DWORD i = 0; i < count; i++) {
        memcpy(flat + off, bufs[i].buf, bufs[i].len);
        off += (int)bufs[i].len;
    }
    int r = UdpProxySend(s, flat, total, to);
    free(flat);
    return r;
}

static bool ConnectTimeout(SOCKET s, const sockaddr* sa, int salen, int ms)
{
    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);
    bool ok = ::connect(s, sa, salen) == 0;
    if (!ok) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS) {
            ok = WaitWritable(s, ms);
            if (ok) {
                int soerr = 0;
                int slen = (int)sizeof(soerr);
                ok = getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &slen) == 0 && soerr == 0;
            }
        }
    }
    nonblock = 0;
    ioctlsocket(s, FIONBIO, &nonblock);
    return ok;
}

// RFC 1928 §5/§7: one TCP control channel plus one UDP relay socket per process.
// Runs before the hooks are armed, so the plain winsock calls are safe here.
static bool UdpAssociate()
{
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    char port[16];
    snprintf(port, sizeof(port), "%u", g_proxyPort);
    sockaddr_in proxyAddr{};
    SOCKET ctrl = INVALID_SOCKET;
    int lastErr = 0;
    if (getaddrinfo(g_proxyHost.c_str(), port, &hints, &res) == 0) {
        for (addrinfo* p = res; p; p = p->ai_next) {
            // A failed attempt leaves the socket unusable, so retry on a fresh one.
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) { lastErr = WSAGetLastError(); continue; }
            if (ConnectTimeout(s, p->ai_addr, (int)p->ai_addrlen, 3000)) {
                memcpy(&proxyAddr, p->ai_addr, sizeof(proxyAddr));
                ctrl = s;
                break;
            }
            lastErr = WSAGetLastError();
            closesocket(s);
        }
        freeaddrinfo(res);
    }
    if (ctrl == INVALID_SOCKET) {
        Log("udp: associate failed (connect %s:%u wsa %d)", g_proxyHost.c_str(), g_proxyPort,
            lastErr ? lastErr : WSAGetLastError());
        return false;
    }

    unsigned long tmo = 3000;
    setsockopt(ctrl, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    setsockopt(ctrl, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmo, sizeof(tmo));

    if (!SocksAuth(ctrl)) {
        Log("udp: associate failed (socks negotiation)");
        closesocket(ctrl);
        return false;
    }

    unsigned char req[10] = {5, 3, 0, 1, 0, 0, 0, 0, 0, 0}; // UDP ASSOCIATE, 0.0.0.0:0
    if (SendAll(ctrl, (char*)req, 10) != 10) {
        Log("udp: associate failed (send request)");
        closesocket(ctrl);
        return false;
    }

    unsigned char gr[4] = {0, 0, 0, 0};
    if (!RecvAll(ctrl, (char*)gr, 4) || gr[0] != 5 || gr[1] != 0) {
        Log("udp: associate failed (reply %u/%u)", (unsigned)gr[0], (unsigned)gr[1]);
        closesocket(ctrl);
        return false;
    }

    sockaddr_in relay{};
    relay.sin_family = AF_INET;
    if (gr[3] == 1) {
        unsigned char bnd[6];
        if (!RecvAll(ctrl, (char*)bnd, 6)) {
            Log("udp: associate failed (bnd addr)");
            closesocket(ctrl);
            return false;
        }
        memcpy(&relay.sin_addr, bnd, 4);
        memcpy(&relay.sin_port, bnd + 4, 2);
    } else {
        Log("udp: associate failed (atyp %u)", (unsigned)gr[3]);
        closesocket(ctrl);
        return false;
    }
    // 0.0.0.0 means "same host as the proxy" (mirrors discover.rs::test_udp).
    if (relay.sin_addr.s_addr == 0) relay.sin_addr = proxyAddr.sin_addr;
    if (relay.sin_port == 0) {
        Log("udp: associate failed (bnd port 0)");
        closesocket(ctrl);
        return false;
    }

    SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (u == INVALID_SOCKET) {
        Log("udp: associate failed (udp socket wsa %d)", WSAGetLastError());
        closesocket(ctrl);
        return false;
    }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = inet_addr("127.0.0.1");
    local.sin_port = 0;
    int llen = (int)sizeof(local);
    if (bind(u, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0 ||
        getsockname(u, reinterpret_cast<sockaddr*>(&local), &llen) != 0) {
        Log("udp: associate failed (bind wsa %d)", WSAGetLastError());
        closesocket(u);
        closesocket(ctrl);
        return false;
    }

    tmo = 0;
    setsockopt(ctrl, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    setsockopt(ctrl, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmo, sizeof(tmo));

    g_udpCtrl = ctrl;
    g_udpSock = u;
    g_udpSockPort = ntohs(local.sin_port);
    g_udpRelay = relay;
    g_udpReady = 1;

    char ip[64] = {0};
    inet_ntop(AF_INET, &relay.sin_addr, ip, sizeof(ip));
    Log("udp: associate ok relay=%s:%u", ip, ntohs(relay.sin_port));
    return true;
}

static bool ConnectRelay(SOCKET s, const PbHdr& h)
{
    sockaddr_in relay{};
    relay.sin_family = AF_INET;
    relay.sin_port = htons(g_relayPort);
    relay.sin_addr.s_addr = inet_addr("127.0.0.1");

    t_internal = true;
    int r = real_connect(s, reinterpret_cast<sockaddr*>(&relay), sizeof(relay));
    int err = (r == 0) ? 0 : WSAGetLastError();
    t_internal = false;

    if (r != 0) {
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY) {
            if (!WaitWritable(s, 10000)) { WSASetLastError(WSAETIMEDOUT); return false; }
            int soerr = 0;
            int slen = (int)sizeof(soerr);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &slen) != 0 || soerr != 0) {
                WSASetLastError(soerr ? soerr : WSAECONNREFUSED);
                return false;
            }
        } else {
            WSASetLastError(err);
            return false;
        }
    }

    if (!SendAllNB(s, (const char*)&h, sizeof(h))) {
        WSASetLastError(WSAECONNRESET);
        return false;
    }
    return true;
}

static int WSAAPI hk_connect(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (g_active && !t_internal && name && name->sa_family == AF_INET && !IsLoopback(name) &&
        SockType(s) == SOCK_DGRAM) {
        sockaddr_in udpRelay{};
        if (RedirectUdpPeer(s, name, udpRelay))
            return real_connect(s, reinterpret_cast<const sockaddr*>(&udpRelay), sizeof(udpRelay));
        // No UDP association: the datagram socket stays on the direct path.
        return real_connect(s, name, namelen);
    }

    if (!g_active || t_internal || !name || name->sa_family != AF_INET || IsLoopback(name))
        return real_connect(s, name, namelen);

    PbHdr h{};
    if (!MakeHeader(name, h)) return real_connect(s, name, namelen);

    if (!ConnectRelay(s, h)) {
        int e = WSAGetLastError();
        Log("connect: relay unreachable for %u.%u.%u.%u:%u (wsa %d)",
            (h.ip >> 0) & 0xFF, (h.ip >> 8) & 0xFF, (h.ip >> 16) & 0xFF, (h.ip >> 24) & 0xFF,
            ntohs(h.port), e);
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    static volatile LONG connectLogs = 0;
    if (InterlockedIncrement(&connectLogs) <= 200) {
        Log("connect via proxy %u.%u.%u.%u:%u",
            (h.ip >> 0) & 0xFF, (h.ip >> 8) & 0xFF, (h.ip >> 16) & 0xFF, (h.ip >> 24) & 0xFF,
            ntohs(h.port));
    }
    return 0;
}

static int WSAAPI hk_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen,
                                LPWSABUF, LPWSABUF, LPQOS, LPQOS)
{
    return hk_connect(s, name, namelen);
}

static BOOL PASCAL hk_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen,
                                PVOID lpSendBuffer, DWORD dwSendDataLength,
                                LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped)
{
    if (g_active && !t_internal && name && name->sa_family == AF_INET && !IsLoopback(name) &&
        SockType(s) == SOCK_DGRAM) {
        sockaddr_in udpRelay{};
        if (RedirectUdpPeer(s, name, udpRelay))
            return real_ConnectEx(s, reinterpret_cast<sockaddr*>(&udpRelay), sizeof(udpRelay),
                                  lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        return real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }

    if (!g_active || t_internal || !name || name->sa_family != AF_INET || IsLoopback(name))
        return real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);

    PbHdr h{};
    if (!MakeHeader(name, h))
        return real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);

    // Connect to the relay through the real ConnectEx so completion still flows
    // through the application's own IOCP / event, then owe the header to the
    // first send on this socket.
    sockaddr_in relay{};
    relay.sin_family = AF_INET;
    relay.sin_port = htons(g_relayPort);
    relay.sin_addr.s_addr = inet_addr("127.0.0.1");

    EnterCriticalSection(&g_mapLock);
    g_pending[s] = h;
    LeaveCriticalSection(&g_mapLock);

    return real_ConnectEx(s, reinterpret_cast<sockaddr*>(&relay), sizeof(relay),
                          lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
}

static bool FlushPending(SOCKET s)
{
    PbHdr h{};
    bool have = false;
    EnterCriticalSection(&g_mapLock);
    auto it = g_pending.find(s);
    if (it != g_pending.end()) { h = it->second; g_pending.erase(it); have = true; }
    LeaveCriticalSection(&g_mapLock);
    if (!have) return true;
    return SendAll(s, (const char*)&h, sizeof(h)) == sizeof(h);
}

static int WSAAPI hk_send(SOCKET s, const char* buf, int len, int flags)
{
    if (g_active && !t_internal) {
        sockaddr_in peer{};
        // Games usually send() on a connect()ed UDP socket, so wrap that too.
        if (g_udpPeerCount != 0 && UdpPeer(s, peer))
            return UdpProxySend(s, buf, len, nullptr);
        FlushPending(s);
    }
    return real_send(s, buf, len, flags);
}

static int WSAAPI hk_WSASend(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent,
                             DWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (g_active && !t_internal) {
        sockaddr_in peer{};
        if (g_udpPeerCount != 0 && !ov && UdpPeer(s, peer)) {
            int r = UdpProxySendBufs(s, bufs, count, nullptr);
            if (r == SOCKET_ERROR) return SOCKET_ERROR;
            if (sent) *sent = (DWORD)r;
            return 0;
        }
        FlushPending(s);
    }
    return real_WSASend(s, bufs, count, sent, flags, ov, cb);
}

// Many clients (SA-MP included) never connect() their datagram socket: they only
// call sendto(). On the first such datagram we connect the socket to our relay
// ourselves, so replies come back to a socket the kernel accepts them on.
static bool EnsureUdpProxied(SOCKET s, const struct sockaddr* to)
{
    if (!g_udpReady || !to || to->sa_family != AF_INET || IsLoopback(to)) return false;
    sockaddr_in peer{};
    if (UdpPeer(s, peer)) return true;
    if (SockType(s) != SOCK_DGRAM) return false;

    sockaddr_in relay{};
    if (!RedirectUdpPeer(s, to, relay)) return false;
    if (real_connect(s, reinterpret_cast<const sockaddr*>(&relay), sizeof(relay)) != 0) {
        ForgetUdpPeer(s);
        return false;
    }
    UdpLogBudget(0, "udp: lazy redirect on sendto");
    return true;
}

static int WSAAPI hk_sendto(SOCKET s, const char* buf, int len, int flags,
                            const struct sockaddr* to, int tolen)
{
    if (g_active && !t_internal) {
        sockaddr_in peer{};
        if ((g_udpPeerCount != 0 && UdpPeer(s, peer)) || EnsureUdpProxied(s, to))
            return UdpProxySend(s, buf, len, to);
    }
    return real_sendto(s, buf, len, flags, to, tolen);
}

static int WSAAPI hk_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent,
                               DWORD flags, const struct sockaddr* to, int tolen,
                               LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (g_active && !t_internal && !ov) {
        sockaddr_in peer{};
        if ((g_udpPeerCount != 0 && UdpPeer(s, peer)) || EnsureUdpProxied(s, to)) {
            int r = UdpProxySendBufs(s, bufs, count, to);
            if (r == SOCKET_ERROR) return SOCKET_ERROR;
            if (sent) *sent = (DWORD)r;
            return 0;
        }
    }
    return real_WSASendTo(s, bufs, count, sent, flags, to, tolen, ov, cb);
}

static int WSAAPI hk_recvfrom(SOCKET s, char* buf, int len, int flags,
                              struct sockaddr* from, int* fromlen)
{
    sockaddr_in peer{};
    if (g_active && !t_internal && g_udpPeerCount != 0 && UdpPeer(s, peer)) {
        // Ask the kernel for the payload only: the relay already stripped the
        // SOCKS5 envelope, so the application must not see our loopback source.
        int r = real_recvfrom(s, buf, len, flags, nullptr, nullptr);
        if (r >= 0 && from && fromlen && *fromlen >= (int)sizeof(sockaddr_in)) {
            memcpy(from, &peer, sizeof(peer));
            *fromlen = (int)sizeof(peer);
        }
        return r;
    }
    return real_recvfrom(s, buf, len, flags, from, fromlen);
}

static int WSAAPI hk_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvd,
                                 LPDWORD flags, struct sockaddr* from, LPINT fromlen,
                                 LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    sockaddr_in peer{};
    // Overlapped receivers keep their own address buffer and are passed through.
    if (g_active && !t_internal && g_udpPeerCount != 0 && !ov && UdpPeer(s, peer)) {
        int r = real_WSARecvFrom(s, bufs, count, recvd, flags, nullptr, nullptr, nullptr, nullptr);
        if (r == 0 && from && fromlen && *fromlen >= (int)sizeof(sockaddr_in)) {
            memcpy(from, &peer, sizeof(peer));
            *fromlen = (int)sizeof(peer);
        }
        return r;
    }
    return real_WSARecvFrom(s, bufs, count, recvd, flags, from, fromlen, ov, cb);
}

static int WSAAPI hk_getpeername(SOCKET s, struct sockaddr* name, int* namelen)
{
    sockaddr_in peer{};
    if (g_active && g_udpPeerCount != 0 && name && namelen &&
        *namelen >= (int)sizeof(sockaddr_in) && UdpPeer(s, peer)) {
        memcpy(name, &peer, sizeof(peer));
        *namelen = (int)sizeof(peer);
        return 0;
    }

    int r = real_getpeername(s, name, namelen);
    if (r != 0 || !name || name->sa_family != AF_INET) return r;
    sockaddr_in* v4 = reinterpret_cast<sockaddr_in*>(name);
    if (v4->sin_addr.s_addr != inet_addr("127.0.0.1")) return r;

    PbHdr h{};
    bool have = false;
    EnterCriticalSection(&g_mapLock);
    auto it = g_pending.find(s);
    if (it != g_pending.end()) { h = it->second; have = true; }
    LeaveCriticalSection(&g_mapLock);
    if (!have) return r;

    v4->sin_addr.s_addr = h.ip;
    v4->sin_port = h.port;
    return r;
}

static int WSAAPI hk_closesocket(SOCKET s)
{
    ForgetUdpPeer(s);
    EnterCriticalSection(&g_mapLock);
    g_pending.erase(s);
    LeaveCriticalSection(&g_mapLock);
    return real_closesocket(s);
}

// ---------------------------------------------------------------- udp pump
static DWORD WINAPI UdpRelayThread(LPVOID)
{
    t_internal = true; // our own datagrams must never be re-wrapped by the hooks

    unsigned char* buf = (unsigned char*)malloc(65536);
    if (!buf) return 0;

    for (;;) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(g_udpSock, &rf);
        if (g_udpCtrl != INVALID_SOCKET) FD_SET(g_udpCtrl, &rf);
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        int rc = select(0, &rf, nullptr, nullptr, &tv);
        if (rc == SOCKET_ERROR) { Sleep(50); continue; }
        if (rc == 0) continue;

        if (g_udpCtrl != INVALID_SOCKET && FD_ISSET(g_udpCtrl, &rf)) {
            char tmp[128];
            int c = ::recv(g_udpCtrl, tmp, sizeof(tmp), 0);
            if (c <= 0) {
                // RFC 1928: the association lives as long as the TCP channel.
                Log("udp: control channel lost, udp proxying off");
                g_udpReady = 0;
                break;
            }
        }
        if (!FD_ISSET(g_udpSock, &rf)) continue;

        sockaddr_in from{};
        int flen = (int)sizeof(from);
        int n = ::recvfrom(g_udpSock, (char*)buf, 65536, 0,
                           reinterpret_cast<sockaddr*>(&from), &flen);
        if (n < 0) continue;

        sockaddr_in remote{};
        int kind = ParseUdpEnvelope(buf, n, remote);
        if (kind == 2) { UdpLogBudget(1, "udp: fragmented datagram dropped"); continue; }
        if (kind != 0) { UdpLogBudget(2, "udp: malformed datagram dropped"); continue; }

        const bool fromProxy = from.sin_addr.s_addr == g_udpRelay.sin_addr.s_addr &&
                               from.sin_port == g_udpRelay.sin_port;
        if (fromProxy) {
            sockaddr_in app{};
            if (!UdpAppFor(remote, app)) { UdpLogBudget(3, "udp: reply without route"); continue; }
            ::sendto(g_udpSock, (const char*)buf + PB_UDP_HDR, n - PB_UDP_HDR, 0,
                     reinterpret_cast<const sockaddr*>(&app), sizeof(app));
        } else {
            RememberUdpRoute(remote, from);
            ::sendto(g_udpSock, (const char*)buf, n, 0,
                     reinterpret_cast<const sockaddr*>(&g_udpRelay), sizeof(g_udpRelay));
        }
    }

    free(buf);
    return 0;
}

// ---------------------------------------------------------------- setup
static bool ParseProxy(const std::string& in)
{
    std::string s = in;
    size_t sep = s.find("://");
    if (sep != std::string::npos) {
        std::string scheme = s.substr(0, sep);
        for (auto& c : scheme) c = (char)tolower(c);
        if (scheme == "socks5" || scheme == "socks5h") g_scheme = 1;
        else g_scheme = 0;
        s = s.substr(sep + 3);
    } else {
        g_scheme = 0;
    }
    size_t at = s.rfind('@');
    if (at != std::string::npos) {
        std::string cred = s.substr(0, at);
        s = s.substr(at + 1);
        size_t colon = cred.find(':');
        if (colon != std::string::npos) {
            g_proxyUser = cred.substr(0, colon);
            g_proxyPass = cred.substr(colon + 1);
        } else {
            g_proxyUser = cred;
        }
    }
    size_t colon = s.rfind(':');
    if (colon == std::string::npos) return false;
    g_proxyHost = s.substr(0, colon);
    g_proxyPort = (uint16_t)atoi(s.c_str() + colon + 1);
    return !g_proxyHost.empty() && g_proxyPort != 0;
}

// ---------------------------------------------------------------- sandbox
// A private HKCU is not enough for Shell APIs: SHGetKnownFolderPath resolves
// the profile through the user token, not through HKCU, so Electron/Chromium
// would still share one userData dir and hit the single-instance lock. These
// hooks answer with the per-copy folders instead.
static std::wstring g_sbRoot, g_sbAppData, g_sbLocalAppData, g_sbHome;
static std::wstring g_sbDesktop, g_sbDocuments, g_sbDownloads;
static std::wstring g_sbPictures, g_sbMusic, g_sbVideos;
static HANDLE g_readyEvent = nullptr;

typedef HRESULT (WINAPI *PFN_SHGetFolderPathW)(HWND, int, HANDLE, DWORD, LPWSTR);
typedef HRESULT (WINAPI *PFN_SHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
typedef BOOL    (WINAPI *PFN_SHGetSpecialFolderPathW)(HWND, LPWSTR, int, BOOL);
typedef HRESULT (WINAPI *PFN_SHGetFolderPathAndSubDirW)(HWND, int, HANDLE, DWORD, LPCWSTR, LPWSTR);
typedef HRESULT (WINAPI *PFN_SHGetKnownFolderPath)(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR*);

static PFN_SHGetFolderPathW real_SHGetFolderPathW = nullptr;
static PFN_SHGetFolderPathA real_SHGetFolderPathA = nullptr;
static PFN_SHGetSpecialFolderPathW real_SHGetSpecialFolderPathW = nullptr;
static PFN_SHGetFolderPathAndSubDirW real_SHGetFolderPathAndSubDirW = nullptr;
static PFN_SHGetKnownFolderPath real_SHGetKnownFolderPath = nullptr;

static const GUID kAppData    = {0x3eb685db, 0x65f9, 0x4cf6, {0xa0, 0x3a, 0xe3, 0xef, 0x65, 0x72, 0x9f, 0x3d}};
static const GUID kLocalApp   = {0xf1b32785, 0x6fba, 0x4fcf, {0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91}};
static const GUID kDesktop    = {0xb4bfcc3a, 0xdb2c, 0x424c, {0xb0, 0x29, 0x7f, 0xe9, 0x9a, 0x87, 0xc6, 0x41}};
static const GUID kDocuments  = {0xfdd39ad0, 0x238f, 0x46af, {0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03, 0x69, 0xc7}};
static const GUID kDownloads  = {0x374de290, 0x123f, 0x4565, {0x91, 0x64, 0x39, 0xc4, 0x92, 0x5e, 0x46, 0x7b}};
static const GUID kPictures   = {0x33e28130, 0x4e1e, 0x4676, {0x83, 0x5a, 0x98, 0x39, 0x5c, 0x3b, 0xc3, 0xbb}};
static const GUID kMusic      = {0x4bd8d571, 0x6d19, 0x48d3, {0xbe, 0x97, 0x42, 0x22, 0x20, 0x08, 0x0e, 0x43}};
static const GUID kVideos     = {0x18989b1d, 0x99b5, 0x455b, {0x84, 0x1c, 0xab, 0x7c, 0x74, 0xe4, 0xdd, 0xfc}};
static const GUID kProfile    = {0x5e6c858f, 0x0e22, 0x4760, {0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73}};

static std::wstring EnvW(const wchar_t* name)
{
    wchar_t buf[32768];
    DWORD n = GetEnvironmentVariableW(name, buf, 32768);
    return (n > 0 && n < 32768) ? std::wstring(buf, n) : std::wstring();
}

static std::string Narrow(const std::wstring& w)
{
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static void InitSandboxPaths()
{
    g_sbAppData = EnvW(L"APPDATA");
    if (g_sbAppData.empty()) return;
    g_sbLocalAppData = EnvW(L"LOCALAPPDATA");
    g_sbRoot = pbsandbox::ParentOf(g_sbAppData);
    g_sbHome = EnvW(L"USERPROFILE");
    if (g_sbHome.empty()) g_sbHome = g_sbRoot + L"\\Home";
    g_sbDesktop = g_sbRoot + L"\\Desktop";
    g_sbDocuments = g_sbRoot + L"\\Documents";
    g_sbDownloads = g_sbRoot + L"\\Downloads";
    g_sbPictures = g_sbRoot + L"\\Pictures";
    g_sbMusic = g_sbRoot + L"\\Music";
    g_sbVideos = g_sbRoot + L"\\Videos";
    for (auto& d : {g_sbHome, g_sbDesktop, g_sbDocuments, g_sbDownloads,
                    g_sbPictures, g_sbMusic, g_sbVideos})
        pbsandbox::EnsureDir(d);
}

static bool FolderForCsidl(int csidl, std::wstring& out)
{
    if (g_sbAppData.empty()) return false;
    switch (csidl & ~CSIDL_FLAG_MASK) {
    case CSIDL_APPDATA:        out = g_sbAppData; return true;
    case CSIDL_LOCAL_APPDATA:  out = g_sbLocalAppData; return true;
    case CSIDL_DESKTOP:
    case CSIDL_DESKTOPDIRECTORY: out = g_sbDesktop; return true;
    case CSIDL_PERSONAL:       out = g_sbDocuments; return true;
    case CSIDL_MYPICTURES:     out = g_sbPictures; return true;
    case CSIDL_MYMUSIC:        out = g_sbMusic; return true;
    case CSIDL_MYVIDEO:        out = g_sbVideos; return true;
    default: return false;
    }
}

static bool FolderForGuid(REFKNOWNFOLDERID id, std::wstring& out)
{
    if (g_sbAppData.empty()) return false;
    auto same = [&](const GUID& g) { return memcmp(&id, &g, sizeof(GUID)) == 0; };
    if (same(kAppData))   { out = g_sbAppData; return true; }
    if (same(kLocalApp))  { out = g_sbLocalAppData; return true; }
    if (same(kDesktop))   { out = g_sbDesktop; return true; }
    if (same(kDocuments)) { out = g_sbDocuments; return true; }
    if (same(kDownloads)) { out = g_sbDownloads; return true; }
    if (same(kPictures))  { out = g_sbPictures; return true; }
    if (same(kMusic))     { out = g_sbMusic; return true; }
    if (same(kVideos))    { out = g_sbVideos; return true; }
    if (same(kProfile))   { out = g_sbHome; return true; }
    return false;
}

static HRESULT WINAPI hk_SHGetFolderPathW(HWND hwnd, int csidl, HANDLE token, DWORD flags, LPWSTR path)
{
    std::wstring out;
    if (!token && path && FolderForCsidl(csidl, out)) {
        CreateDirectoryW(out.c_str(), nullptr);
        wcsncpy(path, out.c_str(), MAX_PATH);
        path[MAX_PATH - 1] = 0;
        return S_OK;
    }
    return real_SHGetFolderPathW ? real_SHGetFolderPathW(hwnd, csidl, token, flags, path) : E_FAIL;
}

static HRESULT WINAPI hk_SHGetFolderPathA(HWND hwnd, int csidl, HANDLE token, DWORD flags, LPSTR path)
{
    std::wstring out;
    if (!token && path && FolderForCsidl(csidl, out)) {
        char ansi[MAX_PATH] = {0};
        WideCharToMultiByte(CP_ACP, 0, out.c_str(), -1, ansi, MAX_PATH, nullptr, nullptr);
        lstrcpynA(path, ansi, MAX_PATH);
        return S_OK;
    }
    return real_SHGetFolderPathA ? real_SHGetFolderPathA(hwnd, csidl, token, flags, path) : E_FAIL;
}

static BOOL WINAPI hk_SHGetSpecialFolderPathW(HWND hwnd, LPWSTR path, int csidl, BOOL create)
{
    std::wstring out;
    if (path && FolderForCsidl(csidl, out)) {
        CreateDirectoryW(out.c_str(), nullptr);
        wcsncpy(path, out.c_str(), MAX_PATH);
        path[MAX_PATH - 1] = 0;
        return true;
    }
    return real_SHGetSpecialFolderPathW ? real_SHGetSpecialFolderPathW(hwnd, path, csidl, create) : false;
}

static HRESULT WINAPI hk_SHGetFolderPathAndSubDirW(HWND hwnd, int csidl, HANDLE token,
                                                   DWORD flags, LPCWSTR sub, LPWSTR path)
{
    std::wstring out;
    if (!token && path && FolderForCsidl(csidl, out)) {
        if (sub && *sub) {
            while (*sub == L'\\' || *sub == L'/') ++sub;
            if (*sub) { out += L'\\'; out += sub; }
        }
        CreateDirectoryW(out.c_str(), nullptr);
        wcsncpy(path, out.c_str(), MAX_PATH);
        path[MAX_PATH - 1] = 0;
        return S_OK;
    }
    return real_SHGetFolderPathAndSubDirW
        ? real_SHGetFolderPathAndSubDirW(hwnd, csidl, token, flags, sub, path)
        : E_FAIL;
}

static HRESULT WINAPI hk_SHGetKnownFolderPath(REFKNOWNFOLDERID id, DWORD flags,
                                              HANDLE token, PWSTR* path)
{
    std::wstring out;
    if (!token && path && FolderForGuid(id, out)) {
        CreateDirectoryW(out.c_str(), nullptr);
        SIZE_T bytes = (out.size() + 1) * sizeof(wchar_t);
        PWSTR buf = static_cast<PWSTR>(CoTaskMemAlloc(bytes));
        if (!buf) return E_OUTOFMEMORY;
        memcpy(buf, out.c_str(), bytes);
        *path = buf;
        return S_OK;
    }
    return real_SHGetKnownFolderPath ? real_SHGetKnownFolderPath(id, flags, token, path) : E_FAIL;
}

static void InitShellFolderHooks()
{
    HMODULE sh = GetModuleHandleW(L"shell32.dll");
    if (!sh) sh = LoadLibraryW(L"shell32.dll");
    if (!sh) { Log("sandbox: shell32 not available"); return; }

    void* p = nullptr;
    p = (void*)GetProcAddress(sh, "SHGetFolderPathW");
    if (p) MH_CreateHook(p, (LPVOID)&hk_SHGetFolderPathW, (void**)&real_SHGetFolderPathW);
    p = (void*)GetProcAddress(sh, "SHGetFolderPathA");
    if (p) MH_CreateHook(p, (LPVOID)&hk_SHGetFolderPathA, (void**)&real_SHGetFolderPathA);
    p = (void*)GetProcAddress(sh, "SHGetSpecialFolderPathW");
    if (p) MH_CreateHook(p, (LPVOID)&hk_SHGetSpecialFolderPathW, (void**)&real_SHGetSpecialFolderPathW);
    p = (void*)GetProcAddress(sh, "SHGetFolderPathAndSubDirW");
    if (p) MH_CreateHook(p, (LPVOID)&hk_SHGetFolderPathAndSubDirW, (void**)&real_SHGetFolderPathAndSubDirW);
    p = (void*)GetProcAddress(sh, "SHGetKnownFolderPath");
    if (p) MH_CreateHook(p, (LPVOID)&hk_SHGetKnownFolderPath, (void**)&real_SHGetKnownFolderPath);
    Log("sandbox: shell folder hooks armed");
}

static void SignalSandboxReady()
{
    wchar_t name[64];
    swprintf(name, 64, L"Local\\pbready_%lu", (unsigned long)GetCurrentProcessId());
    g_readyEvent = CreateEventW(nullptr, TRUE, FALSE, name);
    if (g_readyEvent) {
        SetEvent(g_readyEvent);
        Log("sandbox: pbready signaled");
    }
}

static HANDLE g_armEvent = nullptr;

// Proxy hooks only see traffic once g_active is set; tell the injector so it
// does not resume the app into a direct-connect window (slow SOCKS5 handshake).
static void SignalProxyArmed()
{
    if (g_armEvent) return;
    wchar_t name[64];
    swprintf(name, 64, L"Local\\pbarm_%lu", (unsigned long)GetCurrentProcessId());
    g_armEvent = CreateEventW(nullptr, TRUE, FALSE, name);
    if (g_armEvent) {
        SetEvent(g_armEvent);
        Log("sandbox: pbarm signaled");
    }
}

// Переводит HKCU процесса в приватный файл-улей: приложения, которые держат
// настройки и сессию в реестре (Steam и подобные), получают свой изолированный.
static void InitRegistryRedirect()
{
    wchar_t path[MAX_PATH * 4];
    DWORD n = GetEnvironmentVariableW(L"PB_HIVE", path, MAX_PATH * 4);
    if (n == 0 || n >= MAX_PATH * 4) return;

    HKEY hive = nullptr;
    LONG rc = RegLoadAppKeyW(path, &hive, KEY_ALL_ACCESS, 0, 0);
    if (rc != ERROR_SUCCESS) {
        Log("registry: RegLoadAppKey failed %ld (%s)", rc, Narrow(path).c_str());
        return;
    }
    // The injector already seeds this, but a hive created by an older build is
    // still empty; fill the mapping before the app starts reading paths.
    pbsandbox::SeedShellFolders(hive);
    rc = RegOverridePredefKey(HKEY_CURRENT_USER, hive);
    if (rc == ERROR_SUCCESS)
        Log("registry: HKCU -> %s", Narrow(path).c_str());
    else
        Log("registry: RegOverridePredefKey failed %ld", rc);
}

// ---------------------------------------------------------------- child injection
// Environment variables (PB_HIVE, PB_LOG, PB_PROXY) are inherited, the hook DLL
// is not: a child launched by the app (samp.exe -> gta_sa.exe) would bypass the
// proxy and HKCU override. Inject this DLL into every child and wait until its
// sandbox is armed before letting the child run user code.

typedef BOOL (WINAPI *PFN_CreateProcessInternalW)(HANDLE, LPCWSTR, LPWSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
    LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOW,
    LPPROCESS_INFORMATION);

static PFN_CreateProcessInternalW real_CreateProcessInternalW = nullptr;
static PFN_CreateProcessW real_CreateProcessW = nullptr;
static PFN_CreateProcessA real_CreateProcessA = nullptr;
static thread_local bool g_inSpawn = false; // set while spawning our own helper
static volatile LONG g_childHits = 0;
static bool g_managed = false; // PB_PROXY or PB_HIVE present

static std::wstring BaseName(const std::wstring& path)
{
    size_t i = path.find_last_of(L"\\/");
    return i == std::wstring::npos ? path : path.substr(i + 1);
}

// Image name for the hit log: lpApplicationName, else the first command token.
static std::wstring ImageNameW(LPCWSTR app, LPCWSTR cmd)
{
    std::wstring s;
    if (app && *app) {
        s = app;
    } else if (cmd && *cmd) {
        const wchar_t* p = cmd;
        while (*p == L' ' || *p == L'\t') ++p;
        if (*p == L'"') {
            ++p;
            while (*p && *p != L'"') s += *p++;
        } else {
            while (*p && *p != L' ' && *p != L'\t') s += *p++;
        }
    }
    return BaseName(s);
}

static std::wstring ImageNameA(LPCSTR app, LPCSTR cmd)
{
    std::string token;
    const char* src = (app && *app) ? app : nullptr;
    if (!src && cmd && *cmd) {
        const char* p = cmd;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '"') {
            ++p;
            while (*p && *p != '"') token += *p++;
        } else {
            while (*p && *p != ' ' && *p != '\t') token += *p++;
        }
        src = token.c_str();
    }
    if (!src || !*src) return std::wstring();
    wchar_t buf[1024] = {0};
    int n = MultiByteToWideChar(CP_ACP, 0, src, -1, buf, 1024);
    return n > 1 ? BaseName(std::wstring(buf, (size_t)n - 1)) : std::wstring();
}

static bool EnvNamed(const std::wstring& e, const wchar_t* prefix)
{
    return _wcsnicmp(e.c_str(), prefix, wcslen(prefix)) == 0;
}

static bool AnsiEnvNamed(const std::string& e, const char* prefix)
{
    return _strnicmp(e.c_str(), prefix, strlen(prefix)) == 0;
}

static std::string ToAnsi(const std::wstring& w)
{
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// A caller-supplied lpEnvironment replaces the inherited block, which would
// strip PB_PROXY/PB_HIVE and silently unproxy the child. Keep every caller
// entry verbatim and append only the missing PB_* values from this process.
static std::vector<wchar_t> MergeEnvW(const wchar_t* env)
{
    std::vector<std::wstring> entries;
    bool haveProxy = false, haveHive = false, haveLog = false, haveReady = false;
    for (const wchar_t* p = env; *p; p += wcslen(p) + 1) {
        std::wstring e(p);
        entries.push_back(e);
        if (EnvNamed(e, L"PB_PROXY=")) haveProxy = true;
        else if (EnvNamed(e, L"PB_HIVE=")) haveHive = true;
        else if (EnvNamed(e, L"PB_LOG=")) haveLog = true;
        else if (EnvNamed(e, L"PB_READY=")) haveReady = true;
    }
    auto add = [&](const wchar_t* name, bool have) {
        if (have) return;
        std::wstring v = EnvW(name);
        if (v.empty()) return;
        std::wstring entry = name;
        entry += L'=';
        entry += v;
        entries.push_back(std::move(entry));
    };
    add(L"PB_PROXY", haveProxy);
    add(L"PB_HIVE", haveHive);
    add(L"PB_LOG", haveLog);
    add(L"PB_READY", haveReady);

    if (entries.empty()) return std::vector<wchar_t>(2, 0);
    size_t total = 1;
    for (auto& e : entries) total += e.size() + 1;
    std::vector<wchar_t> out(total, 0);
    size_t off = 0;
    for (auto& e : entries) {
        memcpy(&out[off], e.c_str(), e.size() * sizeof(wchar_t));
        off += e.size();
        out[off++] = 0;
    }
    out[off] = 0;
    return out;
}

static std::vector<char> MergeEnvA(const char* env)
{
    std::vector<std::string> entries;
    bool haveProxy = false, haveHive = false, haveLog = false, haveReady = false;
    for (const char* p = env; *p; p += strlen(p) + 1) {
        std::string e(p);
        entries.push_back(e);
        if (AnsiEnvNamed(e, "PB_PROXY=")) haveProxy = true;
        else if (AnsiEnvNamed(e, "PB_HIVE=")) haveHive = true;
        else if (AnsiEnvNamed(e, "PB_LOG=")) haveLog = true;
        else if (AnsiEnvNamed(e, "PB_READY=")) haveReady = true;
    }
    auto add = [&](const char* name, bool have) {
        if (have) return;
        std::wstring wname(name, name + strlen(name));
        std::wstring v = EnvW(wname.c_str());
        if (v.empty()) return;
        std::string a = ToAnsi(v);
        if (a.empty()) return;
        entries.push_back(std::string(name) + "=" + a);
    };
    add("PB_PROXY", haveProxy);
    add("PB_HIVE", haveHive);
    add("PB_LOG", haveLog);
    add("PB_READY", haveReady);

    if (entries.empty()) return std::vector<char>(2, 0);
    size_t total = 1;
    for (auto& e : entries) total += e.size() + 1;
    std::vector<char> out(total, 0);
    size_t off = 0;
    for (auto& e : entries) {
        memcpy(&out[off], e.c_str(), e.size());
        off += e.size();
        out[off++] = 0;
    }
    out[off] = 0;
    return out;
}

static bool InjectSameArch(HANDLE hp, const std::wstring& dll)
{
    SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hp, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return false;

    bool ok = WriteProcessMemory(hp, remote, dll.c_str(), bytes, nullptr) != FALSE;
    if (ok) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryW"));
        if (!loadLib) {
            ok = false;
        } else {
            HANDLE th = CreateRemoteThread(hp, nullptr, 0, loadLib, remote, 0, nullptr);
            if (!th) {
                ok = false;
            } else {
                DWORD wr = WaitForSingleObject(th, 15000);
                DWORD mod = 0;
                GetExitCodeThread(th, &mod);
                ok = (wr == WAIT_OBJECT_0 && mod != 0);
                CloseHandle(th);
            }
        }
    }
    VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
    return ok;
}

#ifdef _WIN64
// A 64-bit process cannot remote LoadLibrary a 32-bit DLL (different address
// space layout); the matching-arch pbinject32 attach helper does it instead.
static bool ChildNeeds32BitHelper(HANDLE hp)
{
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    typedef BOOL (WINAPI *PFN_IsWow64Process2)(HANDLE, USHORT*, USHORT*);
    auto fn2 = reinterpret_cast<PFN_IsWow64Process2>(GetProcAddress(k32, "IsWow64Process2"));
    if (fn2) {
        USHORT pm = 0, nm = 0;
        if (fn2(hp, &pm, &nm)) return pm != IMAGE_FILE_MACHINE_UNKNOWN;
    }
    typedef BOOL (WINAPI *PFN_IsWow64Process)(HANDLE, PBOOL);
    auto fn = reinterpret_cast<PFN_IsWow64Process>(GetProcAddress(k32, "IsWow64Process"));
    BOOL wow = FALSE;
    return fn && fn(hp, &wow) && wow;
}
#endif

static bool SpawnAttachHelper(DWORD pid)
{
    wchar_t self[MAX_PATH * 4] = {0};
    if (!GetModuleFileNameW(g_self, self, MAX_PATH * 4)) return false;
    std::wstring dir = pbsandbox::ParentOf(self);
    std::wstring helper = dir + L"\\pbinject32.exe";
    std::wstring dll = dir + L"\\pbhook32.dll";
    if (GetFileAttributesW(helper.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log("childinject: 32-bit helper missing, child not injected");
        return false;
    }

    std::wstring cmd = L"\"" + helper + L"\" --attach " + std::to_wstring(pid) +
                       L" --dll \"" + dll + L"\"";
    std::wstring mutableCmd = cmd;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};

    g_inSpawn = true;
    BOOL ok;
    if (real_CreateProcessInternalW)
        ok = real_CreateProcessInternalW(nullptr, helper.c_str(), &mutableCmd[0], nullptr, nullptr,
                                         FALSE, DETACHED_PROCESS, nullptr, nullptr, &si, &pi, nullptr);
    else if (real_CreateProcessW)
        ok = real_CreateProcessW(helper.c_str(), &mutableCmd[0], nullptr, nullptr, FALSE,
                                 DETACHED_PROCESS, nullptr, nullptr, &si, &pi);
    else
        ok = CreateProcessW(helper.c_str(), &mutableCmd[0], nullptr, nullptr, FALSE,
                            DETACHED_PROCESS, nullptr, nullptr, &si, &pi);
    DWORD spawnErr = GetLastError();
    g_inSpawn = false;
    if (!ok) {
        Log("childinject: helper spawn failed %lu", (unsigned long)spawnErr);
        return false;
    }

    DWORD wr = WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (wr != WAIT_OBJECT_0) {
        Log("childinject: helper timed out pid=%lu", (unsigned long)pid);
        return false;
    }
    if (code != 0) {
        Log("childinject: helper failed code=%lu pid=%lu", (unsigned long)code, (unsigned long)pid);
        return false;
    }
    Log("childinject: 32-bit helper attached pid=%lu", (unsigned long)pid);
    return true;
}

// SA-MP launches gta_sa.exe suspended and resumes it after its own injection;
// Restricted Electron children cannot create Local\ events; blocking on a
// missing pbready used to stall the spawner for 3 s. This is discovery only.
static bool ChildReadyEventExists(DWORD pid, DWORD timeoutMs)
{
    wchar_t name[64];
    swprintf(name, 64, L"Local\\pbready_%lu", (unsigned long)pid);
    DWORD start = GetTickCount();
    for (;;) {
        HANDLE ev = OpenEventW(SYNCHRONIZE, FALSE, name);
        if (ev) {
            CloseHandle(ev);
            return true;
        }
        if (GetTickCount() - start >= timeoutMs) return false;
        Sleep(10);
    }
}

// Proxy hooks are armed after the sandbox-ready event; wait for that second
// gate so a resumed child cannot send its first TCP packet on the direct path.
static bool WaitChildProxyArmed(DWORD pid, DWORD timeoutMs)
{
    wchar_t name[64];
    swprintf(name, 64, L"Local\\pbarm_%lu", (unsigned long)pid);
    DWORD start = GetTickCount();
    HANDLE ev = nullptr;
    for (;;) {
        ev = OpenEventW(SYNCHRONIZE, FALSE, name);
        if (ev) break;
        if (GetTickCount() - start >= timeoutMs) break;
        Sleep(10);
    }
    if (!ev) return false;
    DWORD elapsed = GetTickCount() - start;
    DWORD wr = WaitForSingleObject(ev, elapsed < timeoutMs ? timeoutMs - elapsed : 0);
    CloseHandle(ev);
    return wr == WAIT_OBJECT_0;
}

static void FinishChildSpawn(const PROCESS_INFORMATION* pi, bool resume,
                             const std::wstring& image)
{
    if (!pi || !pi->hProcess || !pi->hThread) return;
    LONG hit = InterlockedIncrement(&g_childHits);
    Log("childinject: hit n=%ld pid=%lu image=%s", (long)hit,
        (unsigned long)pi->dwProcessId, Narrow(image).c_str());

    bool injected = false;
#ifdef _WIN64
    if (ChildNeeds32BitHelper(pi->hProcess)) {
        injected = SpawnAttachHelper(pi->dwProcessId);
    } else
#endif
    {
        wchar_t self[MAX_PATH * 4] = {0};
        if (GetModuleFileNameW(g_self, self, MAX_PATH * 4)) {
            injected = InjectSameArch(pi->hProcess, self);
            if (!injected)
                Log("childinject: self injection failed pid=%lu", (unsigned long)pi->dwProcessId);
        } else {
            Log("childinject: own module path unavailable");
        }
    }
    if (injected) {
        Log("childinject: injected pid=%lu", (unsigned long)pi->dwProcessId);
        if (resume) {
            // InitThread arms sandbox + proxy on its own thread while the
            // primary thread is still suspended. Do not serialize multi-child
            // Electron launches for seconds: short proxy-arm grace only.
            Sleep(120);
            if (!WaitChildProxyArmed(pi->dwProcessId, 400))
                Log("childinject: proxy arm timeout pid=%lu", (unsigned long)pi->dwProcessId);
        } else {
            // Caller (SA-MP) resumes the child itself. Gate on proxy arm only
            // when the child actually created its ready event; restricted
            // Electron children cannot signal and must not stall the spawner.
            Log("childinject: caller-suspended, waiting sandbox");
            if (ChildReadyEventExists(pi->dwProcessId, 150)) {
                if (!WaitChildProxyArmed(pi->dwProcessId, 5000))
                    Log("childinject: proxy arm timeout pid=%lu", (unsigned long)pi->dwProcessId);
            } else {
                Log("childinject: ready event unseen, async arm pid=%lu",
                    (unsigned long)pi->dwProcessId);
            }
        }
    }
    // A caller that asked for CREATE_SUSPENDED keeps control of the child; we
    // only resume the one we suspended ourselves.
    if (resume) ResumeThread(pi->hThread);
}

// Managed session: app-spawned console children must not allocate conhost, so
// detach them unless the caller explicitly chose a console. GUI children ignore
// DETACHED_PROCESS; DETACHED must never be combined with CREATE_NEW_CONSOLE.
static DWORD ChildFlags(DWORD flags)
{
    DWORD out = flags;
    if (g_managed && !(flags & (CREATE_NEW_CONSOLE | DETACHED_PROCESS)))
        out |= DETACHED_PROCESS;
    if (!(flags & CREATE_SUSPENDED))
        out |= CREATE_SUSPENDED;
    return out;
}

static BOOL WINAPI hk_CreateProcessInternalW(HANDLE hToken, LPCWSTR app, LPWSTR cmd,
    LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
    LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi, PHANDLE newToken)
{
    if (!real_CreateProcessInternalW) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    if (g_inSpawn)
        return real_CreateProcessInternalW(hToken, app, cmd, pa, ta, inherit, flags,
                                           env, cwd, si, pi, newToken);

    std::vector<wchar_t> mergedEnv;
    LPVOID useEnv = env;
    if (env) {
        mergedEnv = MergeEnvW(static_cast<const wchar_t*>(env));
        useEnv = mergedEnv.data();
    }
    const bool addSuspend = (flags & CREATE_SUSPENDED) == 0;
    BOOL ok = real_CreateProcessInternalW(hToken, app, cmd, pa, ta, inherit,
                                          ChildFlags(flags), useEnv, cwd, si, pi, newToken);
    if (!ok) {
        DWORD err = GetLastError();
        Log("childinject: create failed %lu", (unsigned long)err);
        SetLastError(err);
        return FALSE;
    }
    FinishChildSpawn(pi, addSuspend, ImageNameW(app, cmd));
    return TRUE;
}

static BOOL WINAPI hk_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    if (!real_CreateProcessW) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    if (g_inSpawn)
        return real_CreateProcessW(app, cmd, pa, ta, inherit, flags, env, cwd, si, pi);

    std::vector<wchar_t> mergedEnv;
    LPVOID useEnv = env;
    if (env) {
        mergedEnv = MergeEnvW(static_cast<const wchar_t*>(env));
        useEnv = mergedEnv.data();
    }
    const bool addSuspend = (flags & CREATE_SUSPENDED) == 0;
    BOOL ok = real_CreateProcessW(app, cmd, pa, ta, inherit,
                                  ChildFlags(flags), useEnv, cwd, si, pi);
    if (!ok) {
        DWORD err = GetLastError();
        Log("childinject: create failed %lu", (unsigned long)err);
        SetLastError(err);
        return FALSE;
    }
    FinishChildSpawn(pi, addSuspend, ImageNameW(app, cmd));
    return TRUE;
}

static BOOL WINAPI hk_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCSTR cwd,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    if (!real_CreateProcessA) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    if (g_inSpawn)
        return real_CreateProcessA(app, cmd, pa, ta, inherit, flags, env, cwd, si, pi);

    std::vector<wchar_t> mergedW;
    std::vector<char> mergedA;
    LPVOID useEnv = env;
    if (env) {
        if (flags & CREATE_UNICODE_ENVIRONMENT) {
            mergedW = MergeEnvW(static_cast<const wchar_t*>(env));
            useEnv = mergedW.data();
        } else {
            mergedA = MergeEnvA(static_cast<const char*>(env));
            useEnv = mergedA.data();
        }
    }
    const bool addSuspend = (flags & CREATE_SUSPENDED) == 0;
    BOOL ok = real_CreateProcessA(app, cmd, pa, ta, inherit,
                                  ChildFlags(flags), useEnv, cwd, si, pi);
    if (!ok) {
        DWORD err = GetLastError();
        Log("childinject: create failed %lu", (unsigned long)err);
        SetLastError(err);
        return FALSE;
    }
    FinishChildSpawn(pi, addSuspend, ImageNameA(app, cmd));
    return TRUE;
}

static void InitProcessCreationHooks()
{
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");

    // CreateProcessW dispatches inside KERNELBASE on Win8+, so the kernelbase
    // copy is the one that sees normal callers (kernel32 exports are thunks).
    if (kb) {
        void* p = (void*)GetProcAddress(kb, "CreateProcessInternalW");
        if (p && MH_CreateHook(p, (LPVOID)&hk_CreateProcessInternalW,
                               (void**)&real_CreateProcessInternalW) == MH_OK) {
            Log("childinject: hooked kernelbase!CreateProcessInternalW");
            return;
        }
        p = (void*)GetProcAddress(kb, "CreateProcessW");
        if (p && MH_CreateHook(p, (LPVOID)&hk_CreateProcessW,
                               (void**)&real_CreateProcessW) == MH_OK) {
            Log("childinject: hooked kernelbase!CreateProcessW");
            return;
        }
    }
    if (k32) {
        void* p = (void*)GetProcAddress(k32, "CreateProcessW");
        if (p && MH_CreateHook(p, (LPVOID)&hk_CreateProcessW,
                               (void**)&real_CreateProcessW) == MH_OK) {
            Log("childinject: hooked kernel32!CreateProcessW");
            return;
        }
        p = (void*)GetProcAddress(k32, "CreateProcessInternalW");
        if (p && MH_CreateHook(p, (LPVOID)&hk_CreateProcessInternalW,
                               (void**)&real_CreateProcessInternalW) == MH_OK) {
            Log("childinject: hooked kernel32!CreateProcessInternalW");
            return;
        }
    }
    Log("childinject: no process creation hook available");
}

static DWORD WINAPI InitThread(LPVOID){
    InitializeCriticalSection(&g_logLock);
    InitializeCriticalSection(&g_mapLock);
    // Signals pbarm on every exit path, including the direct:// / no-proxy
    // early returns, so a waiter never hangs waiting for the proxy.
    struct ArmGuard { ~ArmGuard() { SignalProxyArmed(); } } armGuard;

    wchar_t logPath[MAX_PATH * 4];
    DWORD n = GetEnvironmentVariableW(L"PB_LOG", logPath, MAX_PATH * 4);
    if (n > 0 && n < MAX_PATH * 4)
        g_log = CreateFileW(logPath, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    char buf[1024];

    // Sandbox first, tunnel second: paths and HKCU belong to the copy even when
    // the user picked `direct://` (no proxy).
    InitRegistryRedirect();
    InitSandboxPaths();
    g_managed = !EnvW(L"PB_PROXY").empty() || !EnvW(L"PB_HIVE").empty();

    bool mhReady = MH_Initialize() == MH_OK;
    if (!mhReady) Log("pbproxy: MH_Initialize failed");
    else {
        InitShellFolderHooks();
        InitProcessCreationHooks();
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
            Log("pbproxy: enable sandbox hooks failed");
    }
    SignalSandboxReady();

    n = GetEnvironmentVariableA("PB_PROXY", buf, sizeof(buf));
    if (n == 0) { Log("pbproxy: PB_PROXY not set"); return 0; }
    if (_stricmp(buf, "direct://") == 0 || _stricmp(buf, "direct") == 0) {
        Log("pbproxy: direct, tunnel off (sandbox active)");
        return 0;
    }
    if (!ParseProxy(buf)) { Log("pbproxy: bad PB_PROXY '%s'", buf); return 0; }
    if (!mhReady) return 0;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;

    // SOCKS5 UDP ASSOCIATE runs before the winsock hooks are armed, so a
    // failure here only costs the 3 s timeout and leaves TCP untouched.
    if (g_scheme == 1) UdpAssociate();

    HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
    HMODULE mswsock = GetModuleHandleW(L"mswsock.dll");
    if (!ws2) ws2 = LoadLibraryW(L"ws2_32.dll");
    if (!mswsock) mswsock = LoadLibraryW(L"mswsock.dll");

    void* p = nullptr;
    p = (void*)GetProcAddress(ws2, "connect");        if (p) MH_CreateHook(p, (LPVOID)&hk_connect, (void**)&real_connect);
    p = (void*)GetProcAddress(ws2, "WSAConnect");     if (p) MH_CreateHook(p, (LPVOID)&hk_WSAConnect, (void**)&real_WSAConnect);
    p = (void*)GetProcAddress(ws2, "send");           if (p) MH_CreateHook(p, (LPVOID)&hk_send, (void**)&real_send);
    p = (void*)GetProcAddress(ws2, "WSASend");        if (p) MH_CreateHook(p, (LPVOID)&hk_WSASend, (void**)&real_WSASend);
    p = (void*)GetProcAddress(ws2, "getpeername");    if (p) MH_CreateHook(p, (LPVOID)&hk_getpeername, (void**)&real_getpeername);
    p = (void*)GetProcAddress(ws2, "closesocket");    if (p) MH_CreateHook(p, (LPVOID)&hk_closesocket, (void**)&real_closesocket);
    p = (void*)GetProcAddress(ws2, "sendto");         if (p) MH_CreateHook(p, (LPVOID)&hk_sendto, (void**)&real_sendto);
    p = (void*)GetProcAddress(ws2, "WSASendTo");      if (p) MH_CreateHook(p, (LPVOID)&hk_WSASendTo, (void**)&real_WSASendTo);
    p = (void*)GetProcAddress(ws2, "recvfrom");       if (p) MH_CreateHook(p, (LPVOID)&hk_recvfrom, (void**)&real_recvfrom);
    p = (void*)GetProcAddress(ws2, "WSARecvFrom");    if (p) MH_CreateHook(p, (LPVOID)&hk_WSARecvFrom, (void**)&real_WSARecvFrom);
    p = mswsock ? (void*)GetProcAddress(mswsock, "ConnectEx") : nullptr;
    if (p) MH_CreateHook(p, (LPVOID)&hk_ConnectEx, (void**)&real_ConnectEx);

    // relay listener
    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen == INVALID_SOCKET) { Log("pbproxy: listen socket failed"); return 0; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = 0;
    if (bind(g_listen, (sockaddr*)&addr, sizeof(addr)) != 0) { Log("pbproxy: bind failed"); return 0; }
    int len = sizeof(addr);
    if (getsockname(g_listen, (sockaddr*)&addr, &len) != 0) { Log("pbproxy: getsockname failed"); return 0; }
    g_relayPort = ntohs(addr.sin_port);
    listen(g_listen, SOMAXCONN);

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) { Log("pbproxy: enable hooks failed"); return 0; }

    HANDLE th = CreateThread(nullptr, 0, ListenThread, nullptr, 0, nullptr);
    if (th) CloseHandle(th);

    g_active = 1;
    if (g_udpReady) {
        HANDLE uth = CreateThread(nullptr, 0, UdpRelayThread, nullptr, 0, nullptr);
        if (uth) CloseHandle(uth);
        else { g_udpReady = 0; Log("udp: relay thread failed"); }
    }
    Log("pbproxy: armed via %s://%s:%u relay=127.0.0.1:%u udp=%s",
        g_scheme ? "socks5" : "http", g_proxyHost.c_str(), g_proxyPort, (unsigned)g_relayPort,
        g_udpReady ? "associate" : "direct");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = mod;
        DisableThreadLibraryCalls(mod);
        HANDLE th = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (th) CloseHandle(th);
    }
    return TRUE;
}
