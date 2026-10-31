"""Minimal SOCKS5 server with UDP ASSOCIATE, for a local hook test only."""
import socket
import struct
import sys
import threading

CONTROL = int(sys.argv[1]) if len(sys.argv) > 1 else 11080
VERBOSE = "-v" in sys.argv
NO_UDP = "-noudp" in sys.argv

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", 0))
UDP_PORT = udp.getsockname()[1]


def log(msg):
    if VERBOSE:
        print(msg, flush=True)


def relay():
    while True:
        try:
            data, addr = udp.recvfrom(65535)
        except OSError:
            return
        if len(data) < 10 or data[0:2] != b"\x00\x00" or data[2] != 0:
            continue
        atyp = data[3]
        if atyp == 1:
            host = socket.inet_ntoa(data[4:8])
            port = struct.unpack("!H", data[8:10])[0]
            hdr, payload = data[:10], data[10:]
        elif atyp == 3:
            n = data[4]
            host = data[5 : 5 + n].decode()
            port = struct.unpack("!H", data[5 + n : 7 + n])[0]
            hdr, payload = data[: 7 + n], data[7 + n :]
        else:
            continue
        log(f"relay {host}:{port} <- {len(payload)} bytes from {addr}")
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.settimeout(5)
        try:
            out.sendto(payload, (host, port))
            resp, _ = out.recvfrom(65535)
        except OSError as exc:
            log(f"relay error: {exc}")
            out.close()
            continue
        out.close()
        udp.sendto(hdr + resp, addr)
        log(f"relay reply {len(resp)} bytes -> {addr}")


threading.Thread(target=relay, daemon=True).start()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", CONTROL))
srv.listen(4)
print(f"listening control={CONTROL} udp={UDP_PORT}", flush=True)


def serve(conn):
    try:
        head = conn.recv(2)
        if len(head) < 2 or head[0] != 5:
            return
        conn.recv(head[1])
        conn.sendall(b"\x05\x00")
        req = conn.recv(4)
        if len(req) < 4:
            return
        atyp = req[3]
        if atyp == 1:
            addr = conn.recv(6)
            host, port = socket.inet_ntoa(addr[:4]), struct.unpack("!H", addr[4:6])[0]
        elif atyp == 3:
            n = conn.recv(1)[0]
            raw = conn.recv(n + 2)
            host, port = raw[:n].decode(), struct.unpack("!H", raw[n : n + 2])[0]
        elif atyp == 4:
            addr = conn.recv(18)
            host, port = socket.inet_ntop(socket.AF_INET6, addr[:16]), struct.unpack("!H", addr[16:18])[0]
        else:
            return

        if req[1] == 1:  # CONNECT: plain TCP tunnel, for the regression check
            log(f"connect {host}:{port}")
            try:
                up = socket.create_connection((host, port), 8)
            except OSError as exc:
                log(f"connect failed: {exc}")
                conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 0))

            def pump(src, dst):
                try:
                    while True:
                        chunk = src.recv(32768)
                        if not chunk:
                            break
                        dst.sendall(chunk)
                except OSError:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            threading.Thread(target=pump, args=(up, conn), daemon=True).start()
            pump(conn, up)
            up.close()
            return

        if req[1] != 3:
            log(f"unexpected command {req[1]}")
            return
        if NO_UDP:
            conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            log("associate refused")
            return
        conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", UDP_PORT))
        log("associate ok")
        while True:
            if not conn.recv(64):
                log("control closed")
                return
    except OSError as exc:
        log(f"control error: {exc}")
    finally:
        conn.close()


while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
