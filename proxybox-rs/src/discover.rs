//! Автопоиск бесплатных прокси: качает публичные списки, проверяет каждое
//! прокси реальным запросом через туннель и отдаёт рабочие в GUI по мере находки.
//! Сама проверка живёт в `probe` — без внешних процессов.

use eframe::egui;
use std::collections::VecDeque;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Found {
    pub raw: String,
    pub ms: u128,
    pub ip: String,
    /// SOCKS5 UDP ASSOCIATE + реальный UDP-ответ. Для HTTP всегда false.
    pub udp: bool,
}

pub enum Msg {
    Progress { done: u32, total: u32 },
    Found(Found),
    Done,
}

/// Отсоединённый процесс без консоли: CREATE_NO_WINDOW на Win10 оставляет
/// скрытый conhost.exe. Не комбинировать с CREATE_NEW_CONSOLE.
const DETACHED_PROCESS: u32 = 0x0000_0008;

const SOURCES: &[(&str, &str)] = &[
    (
        "socks5",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    ),
    (
        "socks5",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    ),
    (
        "socks5",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    ),
    (
        "socks5",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all",
    ),
    (
        "http",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    ),
    (
        "http",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    ),
];

fn valid_addr(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else { return false };
    if host.is_empty() || host.len() > 64 || host.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    let ok_host = host
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c.is_ascii_alphabetic() || c == '-');
    let ok_port = port.parse::<u16>().map(|p| p > 0).unwrap_or(false);
    ok_host && ok_port
}

/// Возвращает IP при успехе. Проверяем дважды: одиночный ответ у бесплатных
/// прокси часто оказывается случайным. Для SOCKS5 `probe::check` дополнительно
/// подтверждает UDP ASSOCIATE — без него RakLite/SA-MP через прокси не пойдёт.
fn test_proxy(raw: &str) -> Option<(String, u128, bool)> {
    let mut total = 0u128;
    let mut ip = String::new();
    let mut udp = false;
    for attempt in 0..2 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(250));
        }
        let res = crate::probe::check(raw);
        if !res.ok {
            return None;
        }
        total += res.ms;
        ip = res.ip.unwrap_or_default();
        udp = res.udp;
    }
    Some((ip, total / 2, udp))
}

fn shuffled(mut v: Vec<String>) -> Vec<String> {
    // xorshift — без внешних зависимостей, порядок не важен для теста
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        | 1;
    for i in (1..v.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let j = (seed % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
    v
}

pub fn start(tx: Sender<Msg>, ctx: egui::Context, seeds: Vec<String>, max_tests: usize) {
    std::thread::spawn(move || {
        let mut all: Vec<String> = Vec::new();
        for (scheme, url) in SOURCES {
            let Ok(out) = Command::new("curl.exe")
                .creation_flags(DETACHED_PROCESS)
                .args(["-s", "-L", "--max-time", "20", url])
                .output()
            else {
                continue;
            };
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let addr = line.split('\t').next().unwrap_or("").trim();
                if valid_addr(addr) {
                    all.push(format!("{scheme}://{addr}"));
                }
            }
        }

        all.sort();
        all.dedup();
        let mut queue = shuffled(all);
        queue.truncate(max_tests.max(1));
        // сначала проверяем то, что уже есть в списке
        let mut seeded: Vec<String> = seeds;
        seeded.extend(queue);
        let queue = seeded;
        let total = queue.len() as u32;
        if total == 0 {
            let _ = tx.send(Msg::Done);
            ctx.request_repaint();
            return;
        }

        let q = Arc::new(Mutex::new(VecDeque::from(queue)));
        let done = Arc::new(AtomicU32::new(0));
        let alive = Arc::new(AtomicU32::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let mut workers = Vec::new();
        for _ in 0..20 {
            let q = Arc::clone(&q);
            let done = Arc::clone(&done);
            let alive = Arc::clone(&alive);
            let stop = Arc::clone(&stop);
            let tx = tx.clone();
            let ctx = ctx.clone();

            workers.push(std::thread::spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let next = { q.lock().ok().and_then(|mut g| g.pop_front()) };
                let Some(raw) = next else { break };

                if let Some((ip, ms, udp)) = test_proxy(&raw) {
                    alive.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(Msg::Found(Found { raw, ms, ip, udp }));
                }

                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = tx.send(Msg::Progress { done: d, total });
                ctx.request_repaint();
            }));
        }
        for w in workers {
            let _ = w.join();
        }
        let _ = tx.send(Msg::Done);
        ctx.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_host_port() {
        assert!(valid_addr("1.2.3.4:1080"));
        assert!(valid_addr("proxy.example.com:8080"));
    }

    #[test]
    fn rejects_broken_addrs() {
        assert!(!valid_addr("1.2.3.4"));
        assert!(!valid_addr(":1080"));
        assert!(!valid_addr("1.2.3.4:0"));
        assert!(!valid_addr("1.2.3.4:99999"));
        assert!(!valid_addr("1.2.3.4 :1080"));
    }
}
