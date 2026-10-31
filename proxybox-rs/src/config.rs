//! Конфиг v2: прокси — сущности со стабильным id, приложения ссылаются на id,
//! а не на индекс в списке. Файл пишется атомарно, старый формат (v1 и ini)
//! читается и конвертируется один раз.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const SCHEMA: u32 = 2;
/// сколько подряд неудачных проверок делают прокси «мёртвым»
pub const DEAD_FAILS: u32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Proxy {
    pub id: u64,
    pub raw: String,
    /// добавлен руками: авто-обновление списков не вправе его выбросить
    #[serde(default)]
    pub manual: bool,
    /// подтверждён SOCKS5 UDP ASSOCIATE
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub ping_ms: Option<u32>,
    #[serde(default)]
    pub fails: u32,
    /// unix-время последней успешной проверки
    #[serde(default)]
    pub last_ok: u64,
}

impl Proxy {
    pub fn new(id: u64, raw: impl Into<String>, manual: bool) -> Self {
        Self {
            id,
            raw: raw.into(),
            manual,
            udp: false,
            ping_ms: None,
            fails: 0,
            last_ok: 0,
        }
    }

    pub fn dead(&self) -> bool {
        self.fails >= DEAD_FAILS
    }

    /// Псевдопрокси «напрямую»: проверять нечего, UDP/TCP идут как есть.
    pub fn is_direct(&self) -> bool {
        let raw = self.raw.trim();
        raw.eq_ignore_ascii_case("direct") || raw.eq_ignore_ascii_case("direct://")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppEntry {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub args: String,
    /// id прокси из Config::proxies, None = не назначен
    #[serde(default)]
    pub proxy_id: Option<u64>,
    /// сколько копий уже запускалось (номер следующей = copies + 1)
    #[serde(default)]
    pub copies: u32,
}

fn schema_v2() -> u32 {
    SCHEMA
}

fn first_id() -> u64 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "schema_v2")]
    pub schema: u32,
    #[serde(default = "first_id")]
    pub next_id: u64,
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    /// показывать в списке только UDP-прокси
    #[serde(default)]
    pub udp_only: bool,
    #[serde(default)]
    pub apps: Vec<AppEntry>,
    /// 0 = авто, иначе число колонок в сетке превью
    #[serde(default)]
    pub grid_cols: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            next_id: 1,
            proxies: Vec::new(),
            udp_only: false,
            apps: Vec::new(),
            grid_cols: 0,
        }
    }
}

impl Config {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("proxybox.json")
    }

    pub fn load(dir: &Path) -> Self {
        let path = Self::path(dir);
        let text = std::fs::read_to_string(&path)
            .ok()
            .map(|t| t.trim_start_matches('\u{feff}').to_string());
        if let Some(text) = text {
            match serde_json::from_str::<Value>(&text) {
                Ok(value) => {
                    let schema = value.get("schema").and_then(Value::as_u64).unwrap_or(0);
                    if schema >= SCHEMA as u64 {
                        if let Ok(cfg) = serde_json::from_value::<Config>(value.clone()) {
                            return cfg.normalized();
                        }
                    }
                    return Self::migrate(&value);
                }
                // битый json — не повод терять прокси, пробуем ini
                Err(_) => return Self::load_legacy(dir),
            }
        }
        Self::load_legacy(dir)
    }

    /// v1: `proxies: ["socks5://…"]`, `udp_proxies`, `apps[].proxy` = индекс.
    fn migrate(value: &Value) -> Self {
        let mut cfg = Config::default();
        let udp: Vec<String> = value
            .get("udp_proxies")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let raw_list: Vec<String> = value
            .get("proxies")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|item| match item {
                        Value::String(s) => Some(s.clone()),
                        Value::Object(o) => o.get("raw").and_then(Value::as_str).map(str::to_string),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        for raw in raw_list {
            if cfg.proxies.iter().any(|p| p.raw.eq_ignore_ascii_case(&raw)) {
                continue;
            }
            let mut p = Proxy::new(cfg.take_id(), raw, false);
            p.udp = udp.iter().any(|u| u.eq_ignore_ascii_case(&p.raw));
            cfg.proxies.push(p);
        }
        if let Some(apps) = value.get("apps").and_then(Value::as_array) {
            for app in apps {
                let name = app.get("name").and_then(Value::as_str).unwrap_or("app");
                let path = app.get("path").and_then(Value::as_str).unwrap_or_default();
                let idx = app.get("proxy").and_then(Value::as_i64).unwrap_or(-1);
                let proxy_id = if idx >= 0 {
                    cfg.proxies.get(idx as usize).map(|p| p.id)
                } else {
                    app.get("proxy_id").and_then(Value::as_u64)
                };
                cfg.apps.push(AppEntry {
                    name: name.to_string(),
                    path: path.to_string(),
                    args: app
                        .get("args")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    proxy_id,
                    copies: app.get("copies").and_then(Value::as_u64).unwrap_or(0) as u32,
                });
            }
        }
        cfg.udp_only = value
            .get("udp_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        cfg.grid_cols = value
            .get("grid_cols")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        cfg.normalized()
    }

    /// старый формат proxybox.ini из C++-версии
    fn load_legacy(dir: &Path) -> Self {
        let path = dir.join("proxybox.ini");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Config::default();
        };
        let mut cfg = Config::default();
        let mut section = 0;
        for line in text.lines() {
            let s = line.trim();
            if s.is_empty() {
                continue;
            }
            if s == "[proxy]" {
                section = 1;
                continue;
            }
            if s == "[app]" {
                section = 2;
                continue;
            }
            if section == 1 {
                let id = cfg.take_id();
                cfg.proxies.push(Proxy::new(id, s, false));
            } else if section == 2 {
                let parts: Vec<&str> = s.split('|').collect();
                if parts.len() < 4 {
                    continue;
                }
                let idx: i64 = parts[3].parse().unwrap_or(-1);
                let proxy_id = if idx >= 0 {
                    cfg.proxies.get(idx as usize).map(|p| p.id)
                } else {
                    None
                };
                cfg.apps.push(AppEntry {
                    name: parts[0].to_string(),
                    path: parts[1].to_string(),
                    args: parts[2].to_string(),
                    proxy_id,
                    copies: 0,
                });
            }
        }
        cfg.normalized()
    }

    /// Атомарная запись: временный файл + rename поверх. Сбой на любом шаге
    /// оставляет предыдущий proxybox.json целым.
    pub fn save(&self, dir: &Path) {
        let path = Self::path(dir);
        let Ok(json) = serde_json::to_string_pretty(self) else {
            return;
        };
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, json.as_bytes()).is_err() {
            return;
        }
        if std::fs::rename(&tmp, &path).is_err() {
            // rename не удался (файл занят) — пишем напрямую, чтобы не потерять сессию
            let _ = std::fs::write(&path, json.as_bytes());
            let _ = std::fs::remove_file(&tmp);
        }
    }

    // ------------------------------------------------------------ identity
    pub fn take_id(&mut self) -> u64 {
        let id = self.next_id.max(1);
        self.next_id = id + 1;
        id
    }

    pub fn index_of_id(&self, id: u64) -> Option<usize> {
        self.proxies.iter().position(|p| p.id == id)
    }

    pub fn by_id(&self, id: u64) -> Option<&Proxy> {
        self.proxies.iter().find(|p| p.id == id)
    }

    pub fn proxy_of_app(&self, app_idx: usize) -> Option<&Proxy> {
        let app = self.apps.get(app_idx)?;
        self.by_id(app.proxy_id?)
    }

    pub fn app_proxy_index(&self, app_idx: usize) -> Option<usize> {
        let app = self.apps.get(app_idx)?;
        self.index_of_id(app.proxy_id?)
    }

    /// Возвращает id прокси с таким адресом, добавляя новый при отсутствии.
    pub fn ensure_proxy(&mut self, raw: &str, manual: bool) -> u64 {
        if let Some(p) = self
            .proxies
            .iter_mut()
            .find(|p| p.raw.eq_ignore_ascii_case(raw))
        {
            p.manual |= manual;
            return p.id;
        }
        let id = self.take_id();
        self.proxies.push(Proxy::new(id, raw, manual));
        id
    }

    /// Приводит список в порядок: socks5 вперёд, дубликаты схлопнуты,
    /// ссылки приложений на исчезнувшие прокси обнулены.
    pub fn normalize(&mut self) {
        let mut unique: Vec<Proxy> = Vec::new();
        for p in std::mem::take(&mut self.proxies) {
            match unique
                .iter_mut()
                .find(|u| u.raw.eq_ignore_ascii_case(&p.raw))
            {
                Some(u) => {
                    u.manual |= p.manual;
                    u.udp |= p.udp;
                    u.fails = u.fails.min(p.fails);
                    if p.last_ok > u.last_ok {
                        u.last_ok = p.last_ok;
                        u.ping_ms = p.ping_ms;
                    }
                }
                None => unique.push(p),
            }
        }
        unique.sort_by_key(|p| !p.raw.to_lowercase().starts_with("socks5"));
        self.proxies = unique;

        let mut seen = std::collections::HashSet::new();
        let mut next = self.next_id;
        for p in &mut self.proxies {
            if p.id == 0 || !seen.insert(p.id) {
                p.id = next.max(1);
                next = p.id + 1;
                seen.insert(p.id);
            }
            next = next.max(p.id + 1);
        }
        self.next_id = next;
        let ids: Vec<u64> = self.proxies.iter().map(|p| p.id).collect();
        for app in &mut self.apps {
            if let Some(id) = app.proxy_id {
                if !ids.contains(&id) {
                    app.proxy_id = None;
                }
            }
        }
        self.schema = SCHEMA;
    }

    fn normalized(mut self) -> Self {
        self.normalize();
        self
    }

    // ------------------------------------------------------------ health
    /// Результат проверки одного прокси.
    pub fn note_check(
        &mut self,
        id: u64,
        ok: bool,
        udp: bool,
        ping_ms: Option<u128>,
        now: u64,
    ) {
        let Some(p) = self.proxies.iter_mut().find(|p| p.id == id) else {
            return;
        };
        if ok {
            p.fails = 0;
            p.last_ok = now;
            p.udp = udp;
            p.ping_ms = ping_ms.map(|ms| ms.min(u32::MAX as u128) as u32);
        } else {
            p.fails = p.fails.saturating_add(1);
            p.ping_ms = None;
        }
    }

    /// Итог автопоиска: остаются ручные прокси и все, кто ответил сейчас.
    /// Привязки приложений сохраняются, потому что ссылаются на id.
    pub fn reconcile_discovery(&mut self, alive: &[(String, u128, bool)], now: u64) {
        let hits: Vec<(u64, u128, bool)> = alive
            .iter()
            .filter_map(|(raw, ms, udp)| {
                self.proxies
                    .iter()
                    .find(|p| p.raw.eq_ignore_ascii_case(raw))
                    .map(|p| (p.id, *ms, *udp))
            })
            .collect();
        for (id, ms, udp) in &hits {
            self.note_check(*id, true, *udp, Some(*ms), now);
        }
        let alive_ids: Vec<u64> = hits.iter().map(|(id, _, _)| *id).collect();
        self.proxies
            .retain(|p| p.manual || alive_ids.contains(&p.id));
        let ids: Vec<u64> = self.proxies.iter().map(|p| p.id).collect();
        for app in &mut self.apps {
            if let Some(id) = app.proxy_id {
                if !ids.contains(&id) {
                    app.proxy_id = None;
                }
            }
        }
        self.normalize();
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("proxybox-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_v1() -> Value {
        serde_json::from_str(
            r#"{
                "proxies": ["http://1.1.1.1:80", "socks5://2.2.2.2:1080"],
                "udp_proxies": ["socks5://2.2.2.2:1080"],
                "apps": [
                    {"name": "browser", "path": "C:/b.exe", "args": "", "proxy": 1, "copies": 2},
                    {"name": "game", "path": "C:/g.exe", "args": "-x", "proxy": -1, "copies": 0}
                ],
                "grid_cols": 3
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn migrates_v1_and_keeps_udp_and_links() {
        let cfg = Config::migrate(&sample_v1());
        assert_eq!(cfg.schema, SCHEMA);
        assert_eq!(cfg.proxies.len(), 2);
        let socks = cfg
            .proxies
            .iter()
            .find(|p| p.raw.starts_with("socks5"))
            .unwrap();
        assert!(socks.udp);
        assert_eq!(cfg.apps[0].proxy_id, Some(socks.id));
        assert_eq!(cfg.apps[1].proxy_id, None);
        assert_eq!(cfg.apps[0].copies, 2);
        assert_eq!(cfg.grid_cols, 3);
    }

    #[test]
    fn save_is_atomic_and_roundtrips() {
        let dir = temp_dir("save");
        let mut cfg = Config::default();
        let id = cfg.ensure_proxy("socks5://127.0.0.1:1080", true);
        cfg.note_check(id, true, true, Some(42), 12345);
        cfg.apps.push(AppEntry {
            name: "app".into(),
            path: "C:/a.exe".into(),
            args: String::new(),
            proxy_id: Some(id),
            copies: 1,
        });
        cfg.save(&dir);

        let loaded = Config::load(&dir);
        assert_eq!(loaded.proxies.len(), 1);
        assert!(loaded.proxies[0].manual && loaded.proxies[0].udp);
        assert_eq!(loaded.proxies[0].ping_ms, Some(42));
        assert_eq!(loaded.apps[0].proxy_id, Some(id));
        assert!(!dir.join("proxybox.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_proxy_dedupes_case_insensitive() {
        let mut cfg = Config::default();
        let a = cfg.ensure_proxy("SOCKS5://Host:1080", false);
        let b = cfg.ensure_proxy("socks5://host:1080", true);
        assert_eq!(a, b);
        assert_eq!(cfg.proxies.len(), 1);
        assert!(cfg.proxies[0].manual);
    }

    #[test]
    fn discovery_keeps_manual_and_live_but_drops_stale() {
        let mut cfg = Config::default();
        let manual = cfg.ensure_proxy("socks5://manual:1", true);
        let live = cfg.ensure_proxy("socks5://live:2", false);
        let stale = cfg.ensure_proxy("socks5://stale:3", false);
        cfg.apps.push(AppEntry {
            name: "a".into(),
            path: "a.exe".into(),
            args: String::new(),
            proxy_id: Some(stale),
            copies: 0,
        });
        cfg.reconcile_discovery(&[("socks5://live:2".into(), 90, true)], 777);
        let ids: Vec<u64> = cfg.proxies.iter().map(|p| p.id).collect();
        assert!(ids.contains(&manual));
        assert!(ids.contains(&live));
        assert!(!ids.contains(&stale));
        assert_eq!(cfg.apps[0].proxy_id, None);
        assert_eq!(cfg.by_id(live).unwrap().ping_ms, Some(90));
    }

    #[test]
    fn failed_checks_mark_proxy_dead() {
        let mut cfg = Config::default();
        let id = cfg.ensure_proxy("http://x:1", true);
        for _ in 0..DEAD_FAILS {
            cfg.note_check(id, false, false, None, 1);
        }
        assert!(cfg.by_id(id).unwrap().dead());
        cfg.note_check(id, true, false, Some(10), 2);
        assert!(!cfg.by_id(id).unwrap().dead());
    }

    #[test]
    fn ini_legacy_is_imported() {
        let dir = temp_dir("ini");
        std::fs::write(
            dir.join("proxybox.ini"),
            "[proxy]\n1.2.3.4:8080\nsocks5://5.6.7.8:1080\n\n[app]\nRakLite|C:/rak/RakSAMP Lite.exe|--nick x|1|lua\n",
        )
        .unwrap();
        let cfg = Config::load(&dir);
        assert_eq!(cfg.proxies.len(), 2);
        assert_eq!(cfg.apps.len(), 1);
        // socks5 встаёт первым, но привязка идёт по id и не ломается
        assert!(cfg.proxies[0].raw.starts_with("socks5"));
        assert_eq!(cfg.apps[0].proxy_id, Some(cfg.proxies[0].id));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
