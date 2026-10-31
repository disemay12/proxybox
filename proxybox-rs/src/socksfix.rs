//! SOCKS5 handshake fix для RakSAMP Lite.
//!
//! RakLite отправляет приветствие `05 01 00 00` — лишний нулевой байт
//! после списка методов. Gost/3proxy/большинство серверов отвечают
//! `bad version` и рвут соединение. Мост принимает соединение RakLite,
//! выбрасывает лишний байт и прозрачно проксирует TCP до реального
//! SOCKS5-сервера. UDP-релей после handshake идёт напрямую, как и должен.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Поднимает мост на 127.0.0.1:0 и возвращает порт.
pub fn start(upstream: String) -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { continue };
            let upstream = upstream.clone();
            std::thread::spawn(move || {
                let _ = handle(client, &upstream);
            });
        }
    });
    Ok(port)
}

fn handle(mut client: TcpStream, upstream: &str) -> std::io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    client.set_write_timeout(Some(Duration::from_secs(3)))?;

    let mut header = [0u8; 2];
    client.read_exact(&mut header)?;
    if header[0] != 5 || header[1] == 0 || header[1] > 8 {
        return Ok(());
    }
    let mut methods = vec![0u8; header[1] as usize];
    client.read_exact(&mut methods)?;

    // Лишний байт RakLite. Если его вдруг нет — read_exact вернёт ошибку
    // по таймауту, и мы просто пойдём дальше.
    let mut extra = [0u8; 1];
    let _ = client.read_exact(&mut extra);

    let Some(addr) = upstream.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        return Ok(());
    };
    let mut server = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    server.set_read_timeout(None)?;
    server.set_write_timeout(None)?;
    server.write_all(&header)?;
    server.write_all(&methods)?;
    server.flush()?;

    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;

    let mut client_reader = client.try_clone()?;
    let mut server_writer = server.try_clone()?;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut server_writer);
    });
    let _ = std::io::copy(&mut server, &mut client);
    Ok(())
}

/// `socks5://[user:pass@]host:port` → (`host:port`, `user:pass`).
pub fn split_proxy(proxy: &str) -> Option<(String, String)> {
    let rest = proxy
        .strip_prefix("socks5://")
        .or_else(|| proxy.strip_prefix("socks5h://"))?;
    if let Some((auth, host)) = rest.rsplit_once('@') {
        Some((host.to_string(), auth.to_string()))
    } else {
        Some((rest.to_string(), String::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn splits_plain_proxy() {
        let (host, auth) = split_proxy("socks5://1.2.3.4:1080").unwrap();
        assert_eq!(host, "1.2.3.4:1080");
        assert!(auth.is_empty());
    }

    #[test]
    fn splits_auth_proxy() {
        let (host, auth) = split_proxy("socks5://user:pass@1.2.3.4:1080").unwrap();
        assert_eq!(host, "1.2.3.4:1080");
        assert_eq!(auth, "user:pass");
    }

    #[test]
    fn rejects_http() {
        assert!(split_proxy("http://1.2.3.4:8080").is_none());
    }

    #[test]
    fn strips_extra_greeting_byte() {
        let upstream = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let fake = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            socket.write_all(&[5, 0]).unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        let port = start(upstream_addr.to_string()).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.write_all(&[5, 1, 0, 0]).unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, 0]);
        fake.join().unwrap();
    }
}
