//! Приём «зрения» RakLite: Lua-плагин шлёт UDP-датаграммы
//! `token\n{json}` на 127.0.0.1, здесь хранится последнее состояние
//! на процесс. Сетка превью читает его через `snapshots`.
//!
//! Токен выдаётся при запуске копии и привязывается к PID после spawn:
//! чужой процесс не может подмешать состояние в чужой тайл.

#![allow(dead_code)]

use serde::Deserialize;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Состояние считается живым, пока плагин шлёт кадры чаще, чем раз в TTL.
const TTL: Duration = Duration::from_secs(5);
const MAX_DATAGRAM: usize = 60 * 1024;
const MAX_TOKEN: usize = 64;

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Default, Deserialize)]
pub struct State {
    #[serde(rename = "t", default)]
    pub tick: u64,
    #[serde(default)]
    pub nick: String,
    #[serde(rename = "srv", default)]
    pub server: String,
    #[serde(default)]
    pub ping: i32,
    #[serde(default)]
    pub money: i64,
    #[serde(default)]
    pub hp: f32,
    #[serde(default)]
    pub arm: f32,
    #[serde(default)]
    pub pos: [f32; 3],
    #[serde(default)]
    pub rot: f32,
    #[serde(rename = "int", default)]
    pub interior: i32,
    #[serde(default)]
    pub veh: i32,
    #[serde(default)]
    pub conn: bool,
    #[serde(rename = "p", default)]
    pub players: Vec<Player>,
    #[serde(rename = "v", default)]
    pub vehicles: Vec<Vehicle>,
    #[serde(rename = "k", default)]
    pub pickups: Vec<Pickup>,
    #[serde(rename = "l", default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub chat: Vec<String>,
    #[serde(rename = "dlg", default)]
    pub dialog: Option<Dialog>,
}

/// Компактный формат: `[id, x, y, z, nick, color]`.
#[derive(Clone, Debug, Deserialize)]
pub struct Player(pub u16, pub f32, pub f32, pub f32, pub String, pub u32);

/// `[id, x, y, z, model, name]`.
#[derive(Clone, Debug, Deserialize)]
pub struct Vehicle(pub u16, pub f32, pub f32, pub f32, pub i32, pub String);

/// `[id, x, y, z, model]`.
#[derive(Clone, Debug, Deserialize)]
pub struct Pickup(pub u16, pub f32, pub f32, pub f32, pub i32);

/// `[x, y, z, text]`.
#[derive(Clone, Debug, Deserialize)]
pub struct Label(pub f32, pub f32, pub f32, pub String);

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Dialog {
    #[serde(default)]
    pub id: i32,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub b1: String,
    #[serde(default)]
    pub b2: String,
}

impl Player {
    pub fn pos(&self) -> [f32; 3] {
        [self.1, self.2, self.3]
    }
}

impl Vehicle {
    pub fn pos(&self) -> [f32; 3] {
        [self.1, self.2, self.3]
    }
}

impl Pickup {
    pub fn pos(&self) -> [f32; 3] {
        [self.1, self.2, self.3]
    }
}

impl Label {
    pub fn pos(&self) -> [f32; 3] {
        [self.0, self.1, self.2]
    }
}

#[derive(Default)]
struct Inner {
    tokens: HashMap<String, Entry>,
    seq: u64,
}

struct Entry {
    pid: u32,
    state: Option<Arc<State>>,
    at: Option<Instant>,
}

#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<Inner>>,
    port: u16,
}

impl Registry {
    /// Поднимает UDP-приёмник на свободном порту 127.0.0.1.
    pub fn start() -> std::io::Result<Self> {
        let socket = UdpSocket::bind(("127.0.0.1", 0))?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let port = socket.local_addr()?.port();
        let inner = Arc::new(Mutex::new(Inner::default()));
        let receiver = Arc::clone(&inner);
        std::thread::spawn(move || receive(socket, receiver));
        Ok(Self { inner, port })
    }

    /// Заглушка, если порт не поднялся: приложение продолжает работать без vision.
    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            port: 0,
        }
    }

    pub fn enabled(&self) -> bool {
        self.port != 0
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Новый токен для копии; PID привязывается после успешного spawn.
    pub fn issue(&self) -> String {
        if !self.enabled() {
            return String::new();
        }
        let token = new_token();
        lock(&self.inner).tokens.insert(
            token.clone(),
            Entry {
                pid: 0,
                state: None,
                at: None,
            },
        );
        token
    }

    pub fn bind(&self, token: &str, pid: u32) {
        if token.is_empty() || pid == 0 {
            return;
        }
        if let Some(entry) = lock(&self.inner).tokens.get_mut(token) {
            entry.pid = pid;
        }
    }

    pub fn revoke(&self, token: &str) {
        if !token.is_empty() {
            lock(&self.inner).tokens.remove(token);
        }
    }

    /// Свежие состояния: (pid, state, seq). seq меняется на каждый кадр.
    pub fn snapshots(&self) -> Vec<(u32, Arc<State>, u64)> {
        let mut inner = lock(&self.inner);
        let now = Instant::now();
        inner.tokens.retain(|_, entry| match entry.at {
            Some(at) => now.saturating_duration_since(at) < TTL,
            None => true,
        });
        let seq = inner.seq;
        inner
            .tokens
            .values()
            .filter_map(|entry| {
                if entry.pid == 0 {
                    return None;
                }
                entry
                    .state
                    .as_ref()
                    .map(|state| (entry.pid, Arc::clone(state), seq))
            })
            .collect()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn new_token() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    format!("{:x}{:x}{:x}", std::process::id(), now, n)
}

fn receive(socket: UdpSocket, inner: Arc<Mutex<Inner>>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                if n > 0 {
                    accept(&inner, &buf[..n]);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(_) => break,
        }
    }
}

fn accept(inner: &Mutex<Inner>, datagram: &[u8]) {
    let Some(split) = datagram.iter().position(|&b| b == b'\n') else {
        return;
    };
    let token = match std::str::from_utf8(&datagram[..split]) {
        Ok(token) if !token.is_empty() && token.len() <= MAX_TOKEN => token,
        _ => return,
    };
    let body = &datagram[split + 1..];
    if body.is_empty() {
        return;
    }

    // Строки SA-MP часто в CP1251; структура JSON — ASCII, поэтому lossy
    // достаточно, чтобы не терять кадр целиком из-за одного ника.
    let text = String::from_utf8_lossy(body);
    let Ok(state) = serde_json::from_str::<State>(&text) else {
        return;
    };

    let mut inner = lock(inner);
    let Some(entry) = inner.tokens.get_mut(token) else {
        return;
    };
    entry.state = Some(Arc::new(state));
    entry.at = Some(Instant::now());
    inner.seq = inner.seq.wrapping_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with_token(token: &str, pid: u32) -> Arc<Mutex<Inner>> {
        let inner = Arc::new(Mutex::new(Inner::default()));
        inner.lock().unwrap().tokens.insert(
            token.to_string(),
            Entry {
                pid,
                state: None,
                at: None,
            },
        );
        inner
    }

    #[test]
    fn parses_compact_state() {
        let inner = registry_with_token("tok", 42);
        let body = br#"tok
{"t":1,"nick":"Bot","srv":"srv","ping":12,"money":100,"hp":99.5,"arm":0,
"pos":[1,2,3],"rot":90,"int":0,"veh":0,"conn":true,
"p":[[7,10.5,-2.25,3.5,"Neo",255]],"v":[[5,1,2,3,411,"Infernus"]],
"k":[[9,4,5,6,1240]],"l":[[7,8,9,"Label"]],"chat":["hi"],"dlg":null}"#;
        accept(&inner, body);

        let guard = inner.lock().unwrap();
        let state = guard.tokens["tok"].state.as_ref().expect("state");
        assert_eq!(state.nick, "Bot");
        assert_eq!(state.players[0].4, "Neo");
        assert_eq!(state.players[0].pos(), [10.5, -2.25, 3.5]);
        assert_eq!(state.vehicles[0].5, "Infernus");
        assert_eq!(state.labels[0].3, "Label");
        assert_eq!(state.chat, vec!["hi"]);
    }

    #[test]
    fn rejects_unknown_token() {
        let inner = registry_with_token("known", 42);
        accept(&inner, b"other\n{\"nick\":\"Evil\"}");
        let guard = inner.lock().unwrap();
        assert!(guard.tokens["known"].state.is_none());
    }

    #[test]
    fn rejects_malformed_json() {
        let inner = registry_with_token("tok", 42);
        accept(&inner, b"tok\n{not json");
        assert!(inner.lock().unwrap().tokens["tok"].state.is_none());
    }

    #[test]
    fn cp1251_does_not_drop_frame() {
        let inner = registry_with_token("tok", 42);
        let mut datagram = b"tok\n{\"nick\":\"".to_vec();
        datagram.push(0xCF); // 'П' в CP1251, невалидный UTF-8
        datagram.extend_from_slice(b"\",\"pos\":[0,0,0]}");
        accept(&inner, &datagram);
        assert!(inner.lock().unwrap().tokens["tok"].state.is_some());
    }

    #[test]
    fn snapshots_skip_unbound_tokens() {
        let registry = Registry::disabled();
        let token = registry.issue();
        assert!(token.is_empty());
        assert!(registry.snapshots().is_empty());
    }

    #[test]
    fn receives_udp_datagram() {
        let registry = Registry::start().expect("udp listener");
        let token = registry.issue();
        registry.bind(&token, 77);

        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("client socket");
        let payload = format!("{token}\n{{\"nick\":\"Net\",\"pos\":[1,2,3]}}");
        socket
            .send_to(payload.as_bytes(), ("127.0.0.1", registry.port()))
            .expect("send");

        for _ in 0..100 {
            if let Some((_, state, _)) = registry
                .snapshots()
                .into_iter()
                .find(|(pid, _, _)| *pid == 77)
            {
                assert_eq!(state.nick, "Net");
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("state not received");
    }
}
