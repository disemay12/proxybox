# RakLite UDP proxy patch

- Source: https://www.blast.hk/threads/258367/
- Author: Софтик Инквизитор (BLASTHACK)
- Target: RakSAMP Lite 18.04.2022
- Downloaded: 2026-10-31

Patch fixes four RakLite bugs that break SOCKS5 UDP:

1. UDP ASSOCIATE destination was the game server instead of `0.0.0.0:0`.
2. Relay address `0.0.0.0` was used literally instead of the proxy IP.
3. Connect retry interval was 150 ms instead of 1000 ms; now adapts to proxy RTT.
4. A query packet was sent directly to the server, bypassing the proxy.

The patch verifies original bytes before writing, so it is a no-op on other
RakLite builds. proxybox copies it to `<RakLite>/scripts/!!proxy_udp_patch.lua`
only when the file is missing; the `!!` prefix makes RakLite load it before
`pb_vision.lua`.

## Additional handshake fix

RakLite 18.04.2022 sends a 4-byte SOCKS5 greeting `05 01 00 00` instead of
`05 01 00`. Strict SOCKS5 servers (gost, 3proxy) reject it with `bad version`.
proxybox starts a local TCP bridge that removes the extra zero byte and
forwards the rest of the handshake to the real proxy. UDP relay still goes
directly to the proxy, as intended.
