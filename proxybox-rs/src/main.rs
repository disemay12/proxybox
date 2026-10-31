#![windows_subsystem = "windows"]

mod bridge;
mod config;
mod discover;
mod grid;
mod probe;
mod socksfix;
mod vision;
mod win;
mod theme;

use config::{AppEntry, Config, Proxy};
use eframe::egui::{
    self, Align2, Color32, FontFamily, FontId, Pos2, Rect, Rounding, Sense, Stroke,
    TextStyle, Vec2,
};
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- palette
const CANVAS: Color32 = Color32::from_rgb(0x0B, 0x0B, 0x0C);
const SURFACE: Color32 = Color32::from_rgb(0x13, 0x13, 0x15);
const SURFACE_HOVER: Color32 = Color32::from_rgb(0x19, 0x1A, 0x1C);
const SURFACE_ACTIVE: Color32 = Color32::from_rgb(0x1E, 0x20, 0x24);
const HAIRLINE: Color32 = Color32::from_rgb(0x23, 0x23, 0x27);
const HAIRLINE_STRONG: Color32 = Color32::from_rgb(0x31, 0x31, 0x39);
const TEXT: Color32 = Color32::from_rgb(0xEC, 0xEC, 0xEF);
const TEXT_MUTED: Color32 = Color32::from_rgb(0x8A, 0x8A, 0x93);
const TEXT_FAINT: Color32 = Color32::from_rgb(0x5C, 0x5C, 0x66);
const ACCENT: Color32 = Color32::from_rgb(0x5B, 0x9D, 0xFF);
const SUCCESS: Color32 = Color32::from_rgb(0x4C, 0xC3, 0x8A);
const DANGER: Color32 = Color32::from_rgb(0xFF, 0x6B, 0x6B);

const ROW_H: f32 = 66.0;
/// Отсоединённый процесс вообще не получает консоль: CREATE_NO_WINDOW на
/// Win10 оставляет скрытый conhost.exe. Не комбинировать с CREATE_NEW_CONSOLE.
const DETACHED_PROCESS: u32 = 0x0000_0008;
const VISION_LUA: &str = include_str!("../assets/pb_vision.lua");
const PROXY_PATCH: &str = include_str!("../assets/!!proxy_udp_patch.lua");

// ---------------------------------------------------------------- state
enum Status {
    Info(String),
    Ok(String),
    Err(String),
}

impl Status {
    fn text(&self) -> &str {
        match self {
            Status::Info(s) | Status::Ok(s) | Status::Err(s) => s,
        }
    }
    fn color(&self) -> Color32 {
        match self {
            Status::Info(_) => TEXT_MUTED,
            Status::Ok(_) => SUCCESS,
            Status::Err(_) => DANGER,
        }
    }
}

struct AddProxyState {
    scheme: usize,
    host: String,
    port: String,
    user: String,
    pass: String,
    error: Option<String>,
}

impl Default for AddProxyState {
    fn default() -> Self {
        Self {
            scheme: 0,
            host: String::new(),
            port: "1080".into(),
            user: String::new(),
            pass: String::new(),
            error: None,
        }
    }
}

struct RunningState {
    items: Vec<win::RunningApp>,
    filter: String,
    selected: Option<usize>,
}

enum Modal {
    None,
    AddProxy(AddProxyState),
    Running(RunningState),
    Args(usize, String),
}

struct PendingLaunch {
    child: std::process::Child,
    started: std::time::Instant,
    app: String,
    proxy: String,
}

struct ProxyBox {
    dir: PathBuf,
    cfg: Config,
    selected: Option<usize>,
    status: Status,
    modal: Modal,
    testing: Option<String>,
    dark_title: bool,
    pending: Option<PendingLaunch>,
    disc_rx: Option<Receiver<discover::Msg>>,
    disc: Option<(u32, u32)>,
    found: usize,
    alive: Vec<(String, u128, bool)>,
    /// результаты проверок из фоновых потоков: (id прокси, итог)
    health_tx: std::sync::mpsc::Sender<(u64, probe::Check)>,
    health_rx: Receiver<(u64, probe::Check)>,
    health_busy: usize,
    health_next: std::time::Instant,
    health_report: bool,
    testing_all: bool,
    ctx: egui::Context,
    grid: grid::Grid,
    vision: vision::Registry,
    hotkey_ok: Arc<AtomicBool>,
    grid_active: bool,
    grid_count: usize,
    grid_note: String,
    grid_items: Vec<grid::PreviewItem>,
    preview_tex: HashMap<isize, egui::TextureHandle>,
    preview_seq: HashMap<isize, u64>,
    /// Корни процессов, запущенных по каждому приложению (только на сессию).
    launched: HashMap<usize, Vec<u32>>,
    /// Процессы удалённых приложений: строки уже нет, но остановить их можно.
    orphans: Vec<u32>,
    app_hwnd: isize,
}

impl ProxyBox {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let dir = win::exe_dir();
        let cfg = Config::load(&dir);
        install_fonts(&cc.egui_ctx);
        install_style(&cc.egui_ctx);
        let hotkey_flag = Arc::new(AtomicBool::new(false));
        let hotkey_ok = Arc::new(AtomicBool::new(false));
        let vision = vision::Registry::start().unwrap_or_else(|_| vision::Registry::disabled());
        let (health_tx, health_rx) = channel();
        let mut app = Self {
            dir,            cfg,
            selected: None,
            status: Status::Info(String::new()),
            modal: Modal::None,
            testing: None,
            dark_title: false,
            pending: None,
            disc_rx: None,
            disc: None,
            found: 0,
            alive: Vec::new(),
            health_tx,
            health_rx,
            health_busy: 0,
            health_next: std::time::Instant::now(),
            health_report: false,
            testing_all: false,
            ctx: cc.egui_ctx.clone(),
            grid: grid::Grid::new(0, hotkey_flag, hotkey_ok.clone(), vision.clone()),
            vision,
            hotkey_ok,
            grid_active: false,
            grid_count: 0,
            grid_note: String::new(),
            grid_items: Vec::new(),
            preview_tex: HashMap::new(),
            preview_seq: HashMap::new(),
            launched: HashMap::new(),
            orphans: Vec::new(),
            app_hwnd: 0,
        };
        if app.cfg.proxies.is_empty() {
            // первый запуск: подхватываем списки, которые лежат рядом
            app.import_proxy_files();
        }
        app.normalize_proxies();
        app.sync_grid();
        bridge::set_log_path(app.dir.join("logs").join("bridge.log"));
        app.selected = if app.cfg.apps.is_empty() { None } else { Some(0) };
        app.refresh_status();
        app
    }

    // ------------------------------------------------------------ data
    fn import_proxy_files(&mut self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return };
        let mut found: Vec<(bool, String)> = Vec::new();
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_lowercase();
            if !(name.starts_with("live-") && name.ends_with(".tsv")) {
                continue;
            }
            let socks = name.contains("socks5");
            if let Ok(raw_text) = std::fs::read_to_string(e.path()) {
                let text = raw_text.trim_start_matches('\u{feff}');
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let addr = line.split('\t').next().unwrap_or("").trim();
                    let Some((host, port)) = addr.rsplit_once(':') else { continue };
                    if host.is_empty() || host.chars().any(|c| c.is_whitespace()) {
                        continue;
                    }
                    if port.parse::<u16>().is_err() {
                        continue;
                    }
                    found.push((socks, addr.to_string()));
                }
            }
        }
        found.sort_by(|a, b| b.0.cmp(&a.0));
        for (socks, addr) in found {
            let raw = format!("{}://{}", if socks { "socks5" } else { "http" }, addr);
            self.cfg.ensure_proxy(&raw, false);
        }
    }

    /// socks5 вперёд (публичные http-прокси с порта 80 почти не умеют CONNECT),
    /// дубликаты схлопываются, привязки приложений идут по id и не сбиваются.
    fn normalize_proxies(&mut self) {
        self.cfg.normalize();
        self.save();
    }

    fn save(&self) {
        self.sync_grid();
        self.cfg.save(&self.dir);
    }

    /// Колонки превью обновляются перед каждой записью конфига.
    fn sync_grid(&self) {
        self.grid.set_cols(self.cfg.grid_cols);
    }

    fn refresh_status(&mut self) {
        let n = self.cfg.proxies.len();
        let a = self.cfg.apps.len();
        let dead = self.cfg.proxies.iter().filter(|p| p.dead()).count();
        self.status = if dead > 0 {
            Status::Info(format!(
                "прокси: {n} (мёртвых: {dead})   ·   приложений: {a}"
            ))
        } else {
            Status::Info(format!("прокси: {n}   ·   приложений: {a}"))
        };
    }

    /// Метка прокси в UI: UDP подтверждён — годится для RakLite; пинг и
    /// «мёртв» приходят из фоновых проверок.
    fn proxy_label(&self, p: &Proxy) -> String {
        let mut label = p.raw.clone();
        if p.dead() {
            label.push_str("  · мёртв");
        } else if let Some(ms) = p.ping_ms {
            label.push_str(&format!("  · {ms} ms"));
        }
        if p.udp {
            label.push_str("  · UDP");
        }
        label
    }

    fn current_proxy_index(&self) -> Option<usize> {
        self.selected.and_then(|i| self.cfg.app_proxy_index(i))
    }

    fn assign_proxy(&mut self, idx: usize) {
        let Some(id) = self.cfg.proxies.get(idx).map(|p| p.id) else {
            return;
        };
        if let Some(sel) = self.selected {
            if sel < self.cfg.apps.len() {
                self.cfg.apps[sel].proxy_id = Some(id);
                self.save();
                let name = self.cfg.apps[sel].name.clone();
                let raw = self.cfg.proxies[idx].raw.clone();
                self.status = Status::Info(format!("{name} → {raw}"));
            }
        }
    }

    fn add_app(&mut self, path: String, name: String) {
        // одна и та же программа может быть добавлена несколько раз —
        // это и есть разные аккаунты: у каждой записи свой прокси и свои копии
        let proxy_id = self
            .current_proxy_index()
            .and_then(|i| self.cfg.proxies.get(i))
            .map(|p| p.id)
            .or_else(|| self.cfg.proxies.first().map(|p| p.id));
        self.cfg.apps.push(AppEntry {
            name: name.clone(),
            path,
            args: String::new(),
            proxy_id,
            copies: 0,
        });
        self.selected = Some(self.cfg.apps.len() - 1);
        self.save();
        self.status = Status::Info(format!("добавлено: {name}"));
    }

    fn profile_root(&self, idx: usize) -> std::path::PathBuf {
        let app = &self.cfg.apps[idx];
        let slug: String = app
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        self.dir
            .join("profiles")
            .join(format!("{slug}-{idx}"))
    }

    fn add_proxy(&mut self, raw: String) {
        if self
            .cfg
            .proxies
            .iter()
            .any(|p| p.raw.eq_ignore_ascii_case(&raw))
        {
            self.status = Status::Err("такой прокси уже есть".into());
            return;
        }
        let id = self.cfg.ensure_proxy(&raw, true);
        self.cfg.proxies.sort_by_key(|p| !p.raw.to_lowercase().starts_with("socks5"));
        self.save();
        self.kick_health(vec![id]);
        self.status = Status::Ok(format!("прокси добавлен: {raw}"));
    }

    fn remove_selected(&mut self) {
        if let Some(sel) = self.selected {
            let name = self.cfg.apps[sel].name.clone();
            // запущенные процессы удалённой строки не убиваем: переносим их
            // в сессионные сироты, чтобы «Стоп всё» мог их остановить
            let live = self.live_pids(sel);
            self.launched.remove(&sel);
            for pid in live {
                if !self.orphans.contains(&pid) {
                    self.orphans.push(pid);
                }
            }
            self.cfg.apps.remove(sel);
            // индексы ниже удалённой сдвигаются на единицу
            let shifted: HashMap<usize, Vec<u32>> = self
                .launched
                .drain()
                .filter_map(|(idx, pids)| {
                    if idx > sel {
                        Some((idx - 1, pids))
                    } else {
                        Some((idx, pids))
                    }
                })
                .collect();
            self.launched = shifted;
            self.selected = if self.cfg.apps.is_empty() {
                None
            } else {
                Some(sel.min(self.cfg.apps.len() - 1))
            };
            self.save();
            self.status = Status::Info(format!("удалено: {name}"));
        }
    }

    // ------------------------------------------------------------ actions
    fn launch(&mut self, idx: usize) {
        self.launch_slot(idx, None);
    }

    /// RakLite сам умеет SOCKS5 (UDP ASSOCIATE), поэтому pbhook ему не нужен:
    /// инжект проксирует TCP и может сломать нативный прокси-хендшейк.
    fn launch_raklite(&mut self, idx: usize, slot: Option<u32>, app: &AppEntry, proxy: &Proxy) {
        let raw = proxy.raw.clone();
        let direct = raw.eq_ignore_ascii_case("direct://") || raw.eq_ignore_ascii_case("direct");
        if !direct && !raw.to_ascii_lowercase().starts_with("socks5") {
            self.status = Status::Err(
                "RakLite: нужен SOCKS5-прокси; HTTP не несёт UDP и SA-MP не проксирует".into(),
            );
            return;
        }

        let slot = slot.unwrap_or(app.copies + 1);
        let sandbox = self.profile_root(idx).join(slot.to_string());
        let roaming = sandbox.join("Roaming");
        let local = sandbox.join("Local");
        let temp = sandbox.join("Temp");
        let _ = std::fs::create_dir_all(&roaming);
        let _ = std::fs::create_dir_all(&local);
        let _ = std::fs::create_dir_all(&temp);

        let vision_token = self.vision.issue();
        // скрипты кладём рядом с exe, чтобы не просить пользователя копировать вручную
        let mut scripts_ok = true;
        if let Some(dir) = std::path::Path::new(&app.path).parent() {
            let scripts = dir.join("scripts");
            if std::fs::create_dir_all(&scripts).is_err() {
                scripts_ok = false;
            } else {
                for (name, body) in [
                    ("pb_vision.lua", VISION_LUA),
                    ("!!proxy_udp_patch.lua", PROXY_PATCH),
                ] {
                    let target = scripts.join(name);
                    if !target.exists() && std::fs::write(&target, body).is_err() {
                        scripts_ok = false;
                    }
                }
            }
        }
        let mut proxy_for_lua = if direct {
            String::new()
        } else {
            raw.clone()
        };
        let mut bridge_note = "";
        if !direct {
            if let Some((upstream, auth)) = socksfix::split_proxy(&raw) {
                match socksfix::start(upstream) {
                    Ok(port) => {
                        proxy_for_lua = if auth.is_empty() {
                            format!("socks5://127.0.0.1:{port}")
                        } else {
                            format!("socks5://{auth}@127.0.0.1:{port}")
                        };
                        bridge_note = " · handshake fix";
                    }
                    Err(_) => bridge_note = " · bridge failed",
                }
            }
        }

        let mut cmd = std::process::Command::new(&app.path);
        cmd.creation_flags(DETACHED_PROCESS);
        for arg in split_args(&app.args) {
            cmd.arg(arg);
        }
        cmd.env("PB_PROXY", &proxy_for_lua)
            .env("APPDATA", &roaming)
            .env("LOCALAPPDATA", &local)
            .env("TEMP", &temp)
            .env("TMP", &temp);
        if self.vision.enabled() {
            cmd.env("PB_VISION_PORT", self.vision.port().to_string())
                .env("PB_VISION_TOKEN", &vision_token);
        }
        if let Some(dir) = std::path::Path::new(&app.path).parent() {
            cmd.current_dir(dir);
        }

        match cmd.spawn() {
            Ok(child) => {
                self.vision.bind(&vision_token, child.id());
                self.grid.add_root(child.id());
                self.track_launch(idx, child.id());
                self.bump_copies(idx, slot);
                self.pending = Some(PendingLaunch {
                    child,
                    started: std::time::Instant::now(),
                    app: format!("{} (копия {slot})", app.name),
                    proxy: raw.clone(),
                });
                let udp = proxy.udp;
                let scripts_note = if scripts_ok {
                    ""
                } else {
                    " · не удалось положить скрипты в scripts"
                };
                self.status = if direct {
                    Status::Ok(format!(
                        "RakLite: копия {slot} · direct (без прокси){}",
                        scripts_note
                    ))
                } else {
                    Status::Ok(format!(
                        "RakLite: копия {slot} · native SOCKS5 {raw}{}{}{}",
                        if udp { " · UDP" } else { " · UDP не подтверждён" },
                        bridge_note,
                        scripts_note
                    ))
                };
            }
            Err(e) => {
                self.vision.revoke(&vision_token);
                self.status = Status::Err(format!("не удалось запустить RakLite: {e}"));
            }
        }
    }

    fn launch_slot(&mut self, idx: usize, slot: Option<u32>) {
        let Some(app) = self.cfg.apps.get(idx).cloned() else { return };

        // без назначенного прокси берём первый доступный, чтобы «Запустить» всегда работал
        let mut proxy_id = app
            .proxy_id
            .filter(|id| self.cfg.by_id(*id).is_some());
        if proxy_id.is_none() {
            let Some(first) = self.cfg.proxies.first().map(|p| p.id) else {
                self.status = Status::Err("нет прокси — добавьте свой или обновите списки".into());
                return;
            };
            if let Some(a) = self.cfg.apps.get_mut(idx) {
                a.proxy_id = Some(first);
            }
            proxy_id = Some(first);
            self.save();
        }
        let Some(meta) = proxy_id.and_then(|id| self.cfg.by_id(id)).cloned() else {
            return;
        };
        if meta.dead() {
            // запуск не блокируем: прокси мог ожить, но пользователь должен знать
            self.status = Status::Info(format!(
                "{} — 3 проверки подряд не прошли, соединение может не установиться",
                meta.raw
            ));
        }
        let proxy = meta.raw.clone();

        if is_raklite(&app.path) {
            self.launch_raklite(idx, slot, &app, &meta);
            return;
        }

        // 32-битным целям нужен свой инжектор и своя DLL
        let machine = pe_machine(&app.path);
        let is32 = machine == Some(0x014c);
        let (injector_name, dll_name) = if is32 {
            ("pbinject32.exe", "pbhook32.dll")
        } else {
            ("pbinject.exe", "pbhook64.dll")
        };
        let injector = self.dir.join(injector_name);
        let dll = self.dir.join(dll_name);
        if !injector.exists() || !dll.exists() {
            self.status = Status::Err(format!(
                "нет {injector_name} / {dll_name} рядом с proxybox.exe{}",
                if is32 { " (32-битная сборка)" } else { "" }
            ));
            return;
        }

        // Chromium-подобные браузеры качают трафик в дочернем сетевом процессе,
        // куда DLL не попадает. Для них — родной флаг, без инъекции.
        if is_chromium(&app.path) {
            let Some(port) = bridge::bridge_for(&proxy) else {
                self.status = Status::Err("не удалось поднять локальный мост для браузера".into());
                return;
            };
            // своя папка профиля на каждую копию: отдельные cookie, логины, сессия
            let slot = slot.unwrap_or(app.copies + 1);
            let profile = self.profile_root(idx).join(slot.to_string());
            let _ = std::fs::create_dir_all(&profile);

            let mut cmd = std::process::Command::new(&app.path);
            cmd.creation_flags(DETACHED_PROCESS);
            if !app.args.contains("--user-data-dir") {
                cmd.arg(format!("--user-data-dir={}", profile.display()));
                cmd.arg("--no-first-run");
                cmd.arg("--no-default-browser-check");
            }
            if !app.args.contains("--proxy-server") {
                cmd.arg(format!("--proxy-server=http://127.0.0.1:{port}"));
                cmd.arg("--proxy-bypass-list=<-loopback>");
            }
            for a in split_args(&app.args) {
                cmd.arg(a);
            }
            cmd.current_dir(&self.dir);
            match cmd.spawn() {
                Ok(child) => {
                    self.grid.add_root(child.id());
                    self.track_launch(idx, child.id());
                    self.bump_copies(idx, slot);
                    self.status = Status::Ok(format!(
                        "копия {slot} · {} · через 127.0.0.1:{port} → {proxy}",
                        app.name
                    ));
                }
                Err(e) => self.status = Status::Err(format!("не удалось запустить: {e}")),
            }
            return;
        }

        // Firefox: профиль на копию + жёстко прописанный HTTP-прокси на мост.
        // Иначе его socket-процесс ходит мимо внедрённой DLL.
        if is_firefox(&app.path) {
            let Some(port) = bridge::bridge_for(&proxy) else {
                self.status = Status::Err("не удалось поднять локальный мост для Firefox".into());
                return;
            };
            let slot = slot.unwrap_or(app.copies + 1);
            let profile = self
                .profile_root(idx)
                .join(slot.to_string())
                .join("profile");
            let _ = std::fs::create_dir_all(&profile);
            let prefs = format!(
                "user_pref(\"network.proxy.type\", 1);\n\
                 user_pref(\"network.proxy.http\", \"127.0.0.1\");\n\
                 user_pref(\"network.proxy.http_port\", {port});\n\
                 user_pref(\"network.proxy.share_proxy_settings\", true);\n\
                 user_pref(\"network.proxy.no_proxies_on\", \"\");\n\
                 user_pref(\"network.proxy.allow_hijacking_localhost\", true);\n\
                 user_pref(\"browser.shell.checkDefaultBrowser\", false);\n\
                 user_pref(\"browser.startup.page\", 0);\n"
            );
            let _ = std::fs::write(profile.join("user.js"), prefs);

            let mut cmd = std::process::Command::new(&app.path);
            cmd.creation_flags(DETACHED_PROCESS);
            cmd.arg("-profile").arg(&profile).arg("-no-remote");
            for a in split_args(&app.args) {
                cmd.arg(a);
            }
            cmd.current_dir(&self.dir);
            match cmd.spawn() {
                Ok(child) => {
                    self.grid.add_root(child.id());
                    self.track_launch(idx, child.id());
                    self.bump_copies(idx, slot);
                    self.status = Status::Ok(format!(
                        "копия {slot} · {} · Firefox через 127.0.0.1:{port} → {proxy}",
                        app.name
                    ));
                }
                Err(e) => self.status = Status::Err(format!("не удалось запустить: {e}")),
            }
            return;
        }

        let logs = self.dir.join("logs");
        let _ = std::fs::create_dir_all(&logs);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let log = logs.join(format!("{stamp}-{}.log", std::process::id()));

        // своя песочница на каждую копию: приложение думает, что у него
        // отдельный профиль пользователя — значит и отдельный аккаунт
        let slot = slot.unwrap_or(app.copies + 1);
        let sandbox = self.profile_root(idx).join(slot.to_string());
        let roaming = sandbox.join("Roaming");
        let local = sandbox.join("Local");
        let temp = sandbox.join("Temp");
        let _ = std::fs::create_dir_all(&roaming);
        let _ = std::fs::create_dir_all(&local);
        let _ = std::fs::create_dir_all(&temp);

        let vision_token = self.vision.issue();
        let mut cmd = std::process::Command::new(&injector);
        cmd.creation_flags(DETACHED_PROCESS);
        cmd.arg("--dll").arg(&dll).arg("--").arg(&app.path);
        for a in split_args(&app.args) {
            cmd.arg(a);
        }
        cmd.env("PB_PROXY", &proxy)
            .env("PB_LOG", &log)
            .env("PB_HIVE", sandbox.join("registry.hive"))
            .env("APPDATA", &roaming)
            .env("LOCALAPPDATA", &local)
            .env("TEMP", &temp)
            .env("TMP", &temp);
        sandbox_home(&mut cmd, &sandbox);
        if self.vision.enabled() {
            cmd.env("PB_VISION_PORT", self.vision.port().to_string())
                .env("PB_VISION_TOKEN", &vision_token);
        }
        cmd.current_dir(&self.dir);

        match cmd.spawn() {
            Ok(child) => {
                // инжектор падает сразу, если DLL не легла; проверяем без блокировки UI
                self.vision.bind(&vision_token, child.id());
                self.grid.add_root(child.id());
                self.track_launch(idx, child.id());
                self.bump_copies(idx, slot);
                self.pending = Some(PendingLaunch {
                    child,
                    started: std::time::Instant::now(),
                    app: format!("{} (копия {slot})", app.name),
                    proxy: proxy.clone(),
                });
                self.status = Status::Info(format!("запускаю: {} копия {slot}", app.name));
            }
            Err(e) => {
                self.vision.revoke(&vision_token);
                self.status = Status::Err(format!("не удалось запустить: {e}"));
            }
        }
    }

    fn bump_copies(&mut self, idx: usize, slot: u32) {
        if let Some(app) = self.cfg.apps.get_mut(idx) {
            if slot > app.copies {
                app.copies = slot;
            }
        }
        self.save();
    }

    fn track_launch(&mut self, idx: usize, pid: u32) {
        if pid == 0 {
            return;
        }
        let pids = self.launched.entry(idx).or_default();
        if !pids.contains(&pid) {
            pids.push(pid);
        }
    }

    /// Живые корни приложения; завершившиеся pid вычищаются при чтении.
    fn live_pids(&mut self, idx: usize) -> Vec<u32> {
        let Some(pids) = self.launched.get_mut(&idx) else {
            return Vec::new();
        };
        pids.retain(|pid| win::pid_alive(*pid));
        let live = pids.clone();
        if live.is_empty() {
            self.launched.remove(&idx);
        }
        live
    }

    fn live_total(&mut self) -> usize {
        self.orphans.retain(|pid| win::pid_alive(*pid));
        let keys: Vec<usize> = self.launched.keys().copied().collect();
        keys.into_iter()
            .map(|idx| self.live_pids(idx).len())
            .sum::<usize>()
            + self.orphans.len()
    }

    /// Останавливает дерево каждого корня приложения и очищает трек.
    fn kill_app(&mut self, idx: usize) -> usize {
        let Some(pids) = self.launched.remove(&idx) else {
            return 0;
        };
        self.drop_pending_for(&pids);
        let mut killed = 0;
        for pid in &pids {
            killed += win::kill_tree(*pid);
        }
        self.report_kill(killed, survivors_after(&pids));
        killed
    }

    fn kill_all(&mut self) -> usize {
        let mut roots: Vec<u32> = self.launched.drain().flat_map(|(_, pids)| pids).collect();
        self.orphans.retain(|pid| win::pid_alive(*pid));
        roots.append(&mut self.orphans);
        roots.sort_unstable();
        roots.dedup();
        self.drop_pending_for(&roots);
        let mut killed = 0;
        for pid in &roots {
            killed += win::kill_tree(*pid);
        }
        self.report_kill(killed, survivors_after(&roots));
        killed
    }

    /// Если убит ещё не подтверждённый запуск, poll_launch не должен
    /// перезаписать статус убийства результатом инъекции.
    fn drop_pending_for(&mut self, roots: &[u32]) {
        let pending = self.pending.as_ref().map(|p| p.child.id());
        if pending_in_roots(pending, roots) {
            self.pending = None;
        }
    }

    /// Защищённый/повышенный процесс не считается убитым.
    fn report_kill(&mut self, killed: usize, survivors: usize) {
        self.status = kill_status(killed, survivors);
    }

    fn poll_launch(&mut self) {
        let Some(p) = &mut self.pending else { return };
        let done = matches!(p.child.try_wait(), Ok(Some(_)));
        let timeout = p.started.elapsed().as_millis() > 1500;
        if !done && !timeout {
            return;
        }
        let code = p.child.try_wait().ok().flatten().and_then(|s| s.code());
        let app = p.app.clone();
        let proxy = p.proxy.clone();
        self.pending = None;
        if done && code != Some(0) {
            self.status = Status::Err(format!(
                "не удалось внедрить хук в {} — 32-бит? защита процесса?",
                app
            ));
        } else {
            self.status = Status::Ok(format!("запущено: {} · {}", app, proxy));
        }
    }

    fn test_proxy(&mut self, _ctx: &egui::Context) {
        let Some(idx) = self.current_proxy_index() else {
            self.status = Status::Err("сначала выберите прокси".into());
            return;
        };
        let proxy = self.cfg.proxies[idx].clone();
        self.testing = Some(proxy.raw.clone());
        self.health_report = true;
        self.status = Status::Info(format!("проверяю {} …", proxy.raw));
        self.kick_health(vec![proxy.id]);
        if self.health_busy == 0 {
            self.testing = None;
            self.health_report = false;
            self.status = Status::Info("проверять нечего: direct:// идёт напрямую".into());
        }
    }

    fn test_all(&mut self) {
        let ids: Vec<u64> = self.cfg.proxies.iter().map(|p| p.id).collect();
        if ids.is_empty() {
            self.status = Status::Err("список прокси пуст — нажмите «Найти»".into());
            return;
        }
        self.testing_all = true;
        self.health_report = true;
        self.status = Status::Info(format!("проверяю все прокси: {} …", ids.len()));
        self.kick_health(ids);
        if self.health_busy == 0 {
            self.testing_all = false;
            self.health_report = false;
            self.status = Status::Info("нечего проверять: только direct://".into());
        }
    }

    /// Фоновая проверка: каждый прокси — свой поток, UI не блокируется
    /// и не зависит от curl.exe.
    fn kick_health(&mut self, ids: Vec<u64>) {
        let mut jobs = Vec::new();
        for id in ids {
            if let Some(p) = self.cfg.by_id(id) {
                if p.is_direct() {
                    continue;
                }
                jobs.push((id, p.raw.clone()));
            }
        }
        for (id, raw) in jobs {
            self.health_busy += 1;
            let tx = self.health_tx.clone();
            let ctx = self.ctx.clone();
            std::thread::spawn(move || {
                let check = probe::check(&raw);
                let _ = tx.send((id, check));
                ctx.request_repaint();
            });
        }
    }

    fn poll_health(&mut self) {
        let mut last: Option<(u64, probe::Check)> = None;
        while let Ok((id, check)) = self.health_rx.try_recv() {
            self.health_busy = self.health_busy.saturating_sub(1);
            let udp = check.udp;
            let ping = check.ok.then_some(check.ms);
            self.cfg
                .note_check(id, check.ok, udp, ping, config::now_secs());
            last = Some((id, check));
        }
        let Some((id, check)) = last else { return };
        if self.health_report {
            let raw = self.cfg.by_id(id).map(|p| p.raw.clone()).unwrap_or_default();
            self.status = if check.ok {
                Status::Ok(format!(
                    "{raw}: IP {} · {} ms{}",
                    check.ip.unwrap_or_default(),
                    check.ms,
                    if check.udp { " · UDP" } else { "" }
                ))
            } else {
                Status::Err(format!(
                    "{raw}: {}",
                    check.error.unwrap_or_else(|| "не отвечает".into())
                ))
            };
        }
        if self.health_busy == 0 {
            self.testing = None;
            self.testing_all = false;
            self.health_report = false;
            self.save();
        }
    }

    /// Мониторинг только тех прокси, что реально назначены приложениям.
    fn tick_health(&mut self) {
        if self.health_busy > 0 || std::time::Instant::now() < self.health_next {
            return;
        }
        self.health_next = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut ids: Vec<u64> = self.cfg.apps.iter().filter_map(|a| a.proxy_id).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.truncate(24);
        if ids.is_empty() {
            return;
        }
        self.kick_health(ids);
    }

    fn start_discovery(&mut self, ctx: &egui::Context) {
        if self.disc_rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        self.disc_rx = Some(rx);
        self.disc = Some((0, 0));
        self.found = 0;
        self.alive.clear();
        self.status = Status::Info("ищу бесплатные прокси в интернете…".into());
        let seeds: Vec<String> = self.cfg.proxies.iter().map(|p| p.raw.clone()).collect();
        discover::start(tx, ctx.clone(), seeds, 600);
    }

    fn poll_discovery(&mut self) {
        let Some(rx) = &self.disc_rx else { return };
        let mut finished = false;
        loop {
            match rx.try_recv() {
                Ok(discover::Msg::Progress { done, total }) => {
                    self.disc = Some((done, total));
                    self.status = Status::Info(format!(
                        "проверяю прокси: {done}/{total}, рабочих {}",
                        self.found
                    ));
                }
                Ok(discover::Msg::Found(f)) => {
                    self.alive.push((f.raw.clone(), f.ms, f.udp));
                    let id = self.cfg.ensure_proxy(&f.raw, false);
                    self.cfg
                        .note_check(id, true, f.udp, Some(f.ms), config::now_secs());
                    self.found = self.found.max(self.alive.len());
                    self.status = Status::Ok(format!(
                        "найден {} · {} · {} ms{}",
                        f.raw,
                        f.ip,
                        f.ms,
                        if f.udp { " · UDP" } else { "" }
                    ));
                }
                Ok(discover::Msg::Done) => {
                    finished = true;
                    break;
                }
                Err(_) => break,
            }
        }
        if finished {
            self.disc_rx = None;
            self.disc = None;

            // оставляем ручные прокси и всё, что ответило сейчас; привязки
            // приложений идут по id и переживают обновление списка
            let mut alive = std::mem::take(&mut self.alive);
            alive.sort_by_key(|(_, ms, _)| *ms);
            alive.dedup_by(|a, b| a.0.eq_ignore_ascii_case(&b.0));
            self.cfg.reconcile_discovery(&alive, config::now_secs());
            self.found = self.cfg.proxies.len();
            self.save();
            self.status = if self.found > 0 {
                Status::Ok(format!("рабочих прокси: {}", self.found))
            } else {
                Status::Err("рабочих прокси не нашлось, попробуйте ещё раз".into())
            };
        }
    }

    // ------------------------------------------------------------ grid
    fn start_grid(&mut self) {
        self.sync_grid();
        let _ = self.grid.activate();
        self.status = Status::Ok(if self.hotkey_ok.load(Ordering::Relaxed) {
            "превью включены · Ctrl+Alt+G — переключить".to_string()
        } else {
            "превью включены · горячая клавиша занята".to_string()
        });
    }

    fn stop_grid(&mut self) {
        self.grid.deactivate();
        self.status = Status::Info("превью выключены".into());
    }

    /// Кадры приходят из воркера; текстуру обновляем только когда сменился seq.
    fn sync_previews(&mut self, ctx: &egui::Context) {
        let alive: Vec<isize> = self.grid_items.iter().map(|i| i.key).collect();
        self.preview_tex.retain(|h, _| alive.contains(h));
        self.preview_seq.retain(|h, _| alive.contains(h));

        // vision-тайл рисуется вектором; старую текстуру окна не держим
        for item in &self.grid_items {
            if item.vision.is_some() {
                self.preview_tex.remove(&item.key);
                self.preview_seq.remove(&item.key);
            }
        }

        for item in &self.grid_items {
            let Some(frame) = &item.frame else { continue };
            if self.preview_seq.get(&item.key) == Some(&item.seq) {
                continue;
            }
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [item.width, item.height],
                frame.as_slice(),
            );
            let texture = ctx.load_texture(
                format!("preview-{}", item.key),
                image,
                egui::TextureOptions::LINEAR,
            );
            self.preview_tex.insert(item.key, texture);
            self.preview_seq.insert(item.key, item.seq);
        }
    }

    // ------------------------------------------------------------ ui
    fn title_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("titlebar")
            .exact_height(42.0)
            .frame(egui::Frame::none().fill(CANVAS))
            .show(ctx, |ui| {
                let rect = ui.max_rect();
                let bar = ui.interact(rect, ui.id().with("drag"), Sense::click_and_drag());
                if bar.drag_started() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
                if bar.double_clicked() {
                    let max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!max));
                }

                ui.horizontal_centered(|ui| {
                    ui.add_space(18.0);
                    ui.label(
                        egui::RichText::new("proxybox")
                            .font(FontId::proportional(13.5))
                            .strong()
                            .color(TEXT),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "{} прокси · {} приложений",
                            self.cfg.proxies.len(),
                            self.cfg.apps.len()
                        ))
                        .font(FontId::proportional(11.0))
                        .color(TEXT_FAINT),
                    );

                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            ui.add_space(8.0);
                            if caption_button(ui, CaptionKind::Close) {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                            let max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
                            if caption_button(ui, CaptionKind::Max) {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!max));
                            }
                            if caption_button(ui, CaptionKind::Min) {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                            }
                        },
                    );
                });
            });
    }

    fn grid_banner(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (dot, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
            ui.painter().circle_filled(dot.center(), 3.5, ACCENT);
            ui.label(
                egui::RichText::new("Превью окон")
                    .font(FontId::proportional(12.0))
                    .strong()
                    .color(TEXT),
            );
            let note = if self.grid_note.is_empty() {
                grid::windows_label(self.grid_count)
            } else {
                self.grid_note.clone()
            };
            ui.label(
                egui::RichText::new(note)
                    .font(FontId::proportional(11.5))
                    .color(TEXT_MUTED),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Выключить превью").clicked() {
                    self.stop_grid();
                }
                let hint = if self.hotkey_ok.load(Ordering::Relaxed) {
                    "Ctrl+Alt+G — переключить"
                } else {
                    "Ctrl+Alt+G занят другой программой"
                };
                ui.label(
                    egui::RichText::new(hint)
                        .font(FontId::proportional(11.0))
                        .color(TEXT_FAINT),
                );
            });
        });
    }

    fn preview_grid(&mut self, ui: &mut egui::Ui) {
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.label(
                egui::RichText::new("ПРЕВЬЮ ОКОН, ЗАПУЩЕННЫХ ЧЕРЕЗ ПРОКСИ")
                    .font(FontId::proportional(10.5))
                    .color(TEXT_FAINT),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(20.0);
                let mut cols = self.cfg.grid_cols;
                let cols_label = if cols == 0 {
                    "Авто".to_string()
                } else {
                    cols.to_string()
                };
                egui::ComboBox::from_id_source("preview_cols")
                    .width(62.0)
                    .selected_text(
                        egui::RichText::new(cols_label).font(FontId::proportional(11.5)),
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut cols, 0, "Авто");
                        for n in 2..=5 {
                            ui.selectable_value(&mut cols, n, n.to_string());
                        }
                    });
                if cols != self.cfg.grid_cols {
                    self.cfg.grid_cols = cols;
                    self.grid.set_cols(cols);
                    self.cfg.save(&self.dir);
                }
                ui.label(
                    egui::RichText::new("КОЛОНКИ")
                        .font(FontId::proportional(10.0))
                        .color(TEXT_FAINT),
                );
            });
        });
        ui.add_space(10.0);

        let items = self.grid_items.clone();
        if items.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Пока нет окон")
                        .font(FontId::proportional(15.0))
                        .color(TEXT_MUTED),
                );
                ui.add_space(5.0);
                ui.label(
                    egui::RichText::new("Запустите приложение через прокси — превью появится здесь")
                        .font(FontId::proportional(11.5))
                        .color(TEXT_FAINT),
                );
            });
            return;
        }

        let width = (ui.available_width() - 40.0).max(220.0);
        let mut cols = if self.cfg.grid_cols > 0 {
            self.cfg.grid_cols.min(items.len())
        } else {
            grid::best_cols(items.len(), width as i32, ui.available_height().max(200.0) as i32)
        };
        let gap = 12.0;
        // предпочтение пользователя сохраняем, но рисуем только колонки,
        // которые реально влезают при минимальной ячейке 160 px
        let fit_cols = (((width + gap) / (160.0 + gap)).floor() as usize).max(1);
        cols = cols.min(fit_cols).max(1);
        let cell_w = ((width - gap * (cols - 1) as f32) / cols as f32).max(160.0);
        let rows = (items.len() + cols - 1) / cols;
        let fit_h = (ui.available_height() - 8.0 - gap * rows.saturating_sub(1) as f32)
            / rows as f32;
        let cell_h = (cell_w * 0.62).min(fit_h).max(140.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (row, chunk) in items.chunks(cols).enumerate() {
                    if row > 0 {
                        ui.add_space(gap);
                    }
                    ui.horizontal(|ui| {
                        ui.add_space(20.0);
                        for (i, item) in chunk.iter().enumerate() {
                            if i > 0 {
                                ui.add_space(gap);
                            }
                            self.preview_tile(ui, item, cell_w, cell_h);
                        }
                    });
                }
            });
    }

    fn preview_tile(&mut self, ui: &mut egui::Ui, item: &grid::PreviewItem, w: f32, h: f32) {
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
        let hover = resp.hovered();
        ui.painter().rect_filled(
            rect,
            Rounding::same(10.0),
            if hover { SURFACE_HOVER } else { SURFACE },
        );
        ui.painter().rect_stroke(
            rect,
            Rounding::same(10.0),
            Stroke::new(1.0_f32, if hover { HAIRLINE_STRONG } else { HAIRLINE }),
        );

        let header = Rect::from_min_size(rect.min, Vec2::new(w, 26.0));
        let footer = Rect::from_min_max(
            Pos2::new(rect.left(), rect.bottom() - 28.0),
            rect.max,
        );
        let image = Rect::from_min_max(
            Pos2::new(rect.left() + 6.0, header.bottom() + 2.0),
            Pos2::new(rect.right() - 6.0, footer.top() - 2.0),
        );

        let title = match item.vision.as_deref() {
            Some(state) if !state.nick.is_empty() => {
                if state.server.is_empty() {
                    state.nick.clone()
                } else {
                    format!("{} · {}", state.nick, state.server)
                }
            }
            _ if item.title.is_empty() => format!("pid {}", item.pid),
            _ => item.title.clone(),
        };
        ui.painter()
            .with_clip_rect(header.shrink2(Vec2::new(8.0, 0.0)))
            .text(
                header.left_center() + Vec2::new(10.0, 0.0),
                Align2::LEFT_CENTER,
                &title,
                FontId::proportional(11.5),
                if hover { TEXT } else { TEXT_MUTED },
            );

        ui.painter().rect_filled(image, Rounding::same(6.0), CANVAS);
        if let Some(state) = item.vision.as_deref() {
            self.draw_vision(ui, image, state);
        } else {
            let texture = if item.frame.is_some() {
                self.preview_tex.get(&item.key)
            } else {
                None
            };
            if let Some(tex) = texture {
                let ts = tex.size_vec2();
                if ts.x > 0.0 && ts.y > 0.0 {
                    let scale = (image.width() / ts.x).min(image.height() / ts.y);
                    let dst = Rect::from_center_size(image.center(), ts * scale);
                    ui.painter().image(
                        tex.id(),
                        dst,
                        Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                        Color32::WHITE,
                    );
                }
            } else {
                let msg = if item.minimized {
                    "свёрнуто"
                } else {
                    "кадр недоступен"
                };
                ui.painter().text(
                    image.center(),
                    Align2::CENTER_CENTER,
                    msg,
                    FontId::proportional(12.0),
                    TEXT_FAINT,
                );
            }
        }

        let footer_text = match item.vision.as_deref() {
            Some(state) => format!("pid {} · {} ms · ${}", item.pid, state.ping, state.money),
            None => format!("pid {}", item.pid),
        };
        // у тайлов с окном справа стоят кнопки — текст не должен в них заезжать
        let text_right = if item.hwnd != 0 {
            (footer.right() - 123.0).max(footer.left() + 2.0)
        } else {
            footer.right()
        };
        ui.painter()
            .with_clip_rect(Rect::from_min_max(
                footer.min,
                Pos2::new(text_right, footer.bottom()),
            ))
            .text(
                footer.left_center() + Vec2::new(10.0, 0.0),
                Align2::LEFT_CENTER,
                footer_text,
                FontId::monospace(10.0),
                TEXT_FAINT,
            );

        if item.hwnd != 0 {
            let close_rect = Rect::from_center_size(
                Pos2::new(footer.right() - 18.0, footer.center().y),
                Vec2::new(26.0, 20.0),
            );
            let kill_rect = Rect::from_center_size(
                Pos2::new(footer.right() - 48.0, footer.center().y),
                Vec2::new(24.0, 20.0),
            );
            let focus_rect = Rect::from_center_size(
                Pos2::new(footer.right() - 92.0, footer.center().y),
                Vec2::new(58.0, 20.0),
            );
            // кликабельная зона выше визуальной: 24 px внутри 28 px футера
            let close_hit = Rect::from_center_size(close_rect.center(), Vec2::new(26.0, 24.0));
            let kill_hit = Rect::from_center_size(kill_rect.center(), Vec2::new(24.0, 24.0));
            let focus_hit = Rect::from_center_size(focus_rect.center(), Vec2::new(58.0, 24.0));
            let close = ui.interact(
                close_hit,
                ui.id().with(("pv-close", item.key)),
                Sense::click(),
            );
            let kill = ui
                .interact(kill_hit, ui.id().with(("pv-kill", item.key)), Sense::click())
                .on_hover_text("Убить процесс с дочерними");
            let focus = ui.interact(
                focus_hit,
                ui.id().with(("pv-focus", item.key)),
                Sense::click(),
            );
            if close.hovered() || kill.hovered() || focus.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            if close.hovered() {
                ui.painter()
                    .rect_filled(close_rect, Rounding::same(5.0), SURFACE_ACTIVE);
            }
            if kill.hovered() {
                ui.painter()
                    .rect_filled(kill_rect, Rounding::same(5.0), SURFACE_ACTIVE);
            }
            if focus.hovered() {
                ui.painter()
                    .rect_filled(focus_rect, Rounding::same(5.0), SURFACE_ACTIVE);
            }
            ui.painter().text(
                close_rect.center(),
                Align2::CENTER_CENTER,
                "×",
                FontId::proportional(13.0),
                if close.hovered() { DANGER } else { TEXT_FAINT },
            );
            ui.painter().rect_filled(
                Rect::from_center_size(kill_rect.center(), Vec2::splat(6.0)),
                Rounding::same(1.0),
                if kill.hovered() { DANGER } else { TEXT_FAINT },
            );
            ui.painter().text(
                focus_rect.center(),
                Align2::CENTER_CENTER,
                if item.minimized { "развернуть" } else { "фокус" },
                FontId::proportional(10.5),
                if focus.hovered() { TEXT } else { TEXT_FAINT },
            );

            if close.clicked() {
                win::close_window(item.hwnd);
            } else if kill.clicked() {
                self.drop_pending_for(&[item.pid]);
                let killed = win::kill_tree(item.pid);
                self.status = kill_status(killed, survivors_after(&[item.pid]));
            } else if focus.clicked() || resp.clicked() {
                win::focus_window(item.hwnd);
            }
        } else {
            let live = Rect::from_center_size(
                Pos2::new(footer.right() - 30.0, footer.center().y),
                Vec2::new(44.0, 18.0),
            );
            ui.painter()
                .rect_filled(live, Rounding::same(9.0), SURFACE_ACTIVE);
            ui.painter().text(
                live.center(),
                Align2::CENTER_CENTER,
                "live",
                FontId::proportional(9.5),
                SUCCESS,
            );
        }
    }

    /// 2D-радар по состоянию RakLite: бот в центре, вокруг — игроки,
    /// машины, пикапы и 3D-лейблы. Никакой геометрии GTA здесь нет.
    fn draw_vision(&self, ui: &egui::Ui, rect: Rect, state: &vision::State) {
        let painter = ui.painter().with_clip_rect(rect);
        let range = 180.0f32;
        let scale = (rect.width().min(rect.height()) / (range * 2.0)).max(0.01);
        let center = rect.center();
        let [bx, by, _] = state.pos;
        let map = |x: f32, y: f32| {
            Pos2::new(
                center.x + (x - bx) * scale,
                center.y - (y - by) * scale,
            )
        };

        for radius in [50.0f32, 100.0, 150.0] {
            painter.circle_stroke(center, radius * scale, Stroke::new(1.0_f32, HAIRLINE));
        }
        painter.line_segment(
            [Pos2::new(rect.left(), center.y), Pos2::new(rect.right(), center.y)],
            Stroke::new(1.0_f32, HAIRLINE),
        );
        painter.line_segment(
            [Pos2::new(center.x, rect.top()), Pos2::new(center.x, rect.bottom())],
            Stroke::new(1.0_f32, HAIRLINE),
        );

        for pickup in &state.pickups {
            let p = map(pickup.1, pickup.2);
            if !rect.contains(p) {
                continue;
            }
            let r = 3.0;
            painter.add(egui::Shape::convex_polygon(
                vec![
                    Pos2::new(p.x, p.y - r),
                    Pos2::new(p.x + r, p.y),
                    Pos2::new(p.x, p.y + r),
                    Pos2::new(p.x - r, p.y),
                ],
                Color32::from_rgb(0xB8, 0x9A, 0x4C),
                Stroke::NONE,
            ));
        }

        for vehicle in &state.vehicles {
            let p = map(vehicle.1, vehicle.2);
            if !rect.contains(p) {
                continue;
            }
            let size = Vec2::new((2.0 * scale).max(2.0), (4.5 * scale).max(3.0));
            painter.rect_filled(
                Rect::from_center_size(p, size),
                1.5,
                Color32::from_rgb(0x5C, 0x5C, 0x66),
            );
        }

        for label in &state.labels {
            let p = map(label.0, label.1);
            if !rect.contains(p) {
                continue;
            }
            painter.text(
                p,
                Align2::CENTER_BOTTOM,
                &label.3,
                FontId::proportional(8.5),
                TEXT_FAINT,
            );
        }

        for player in &state.players {
            let p = map(player.1, player.2);
            if !rect.shrink(4.0).contains(p) {
                continue;
            }
            painter.circle_filled(p, 3.2, samp_color(player.5));
            painter.text(
                p + Vec2::new(6.0, -5.0),
                Align2::LEFT_BOTTOM,
                &player.4,
                FontId::proportional(9.5),
                TEXT_MUTED,
            );
        }

        // GTA: 0° — север, 90° — запад; на экране y растёт вниз.
        let angle = state.rot.to_radians();
        let dir = Vec2::new(-angle.sin(), -angle.cos());
        let side = Vec2::new(-dir.y, dir.x);
        painter.add(egui::Shape::convex_polygon(
            vec![
                center + dir * 8.0,
                center - dir * 5.0 + side * 4.5,
                center - dir * 5.0 - side * 4.5,
            ],
            ACCENT,
            Stroke::NONE,
        ));

        let hud = Rect::from_min_size(
            rect.min + Vec2::new(6.0, 6.0),
            Vec2::new((rect.width() - 12.0).max(1.0), 30.0),
        );
        painter.rect_filled(hud, 4.0, Color32::from_black_alpha(150));
        painter.text(
            hud.left_top() + Vec2::new(6.0, 3.0),
            Align2::LEFT_TOP,
            format!("{}  {} ms  ${}", state.server, state.ping, state.money),
            FontId::proportional(9.5),
            TEXT,
        );
        let vehicle = if state.veh > 0 {
            format!("  veh {}", state.veh)
        } else {
            String::new()
        };
        painter.text(
            hud.left_top() + Vec2::new(6.0, 16.0),
            Align2::LEFT_TOP,
            format!(
                "HP {:.0}  AR {:.0}  int {}{}",
                state.hp, state.arm, state.interior, vehicle
            ),
            FontId::proportional(9.5),
            TEXT_MUTED,
        );

        let start = state.chat.len().saturating_sub(4);
        if start < state.chat.len() {
            let lines = &state.chat[start..];
            let chat_rect = Rect::from_min_max(
                Pos2::new(rect.left() + 6.0, rect.bottom() - 14.0 * lines.len() as f32 - 8.0),
                Pos2::new(rect.right() - 6.0, rect.bottom() - 6.0),
            );
            painter.rect_filled(chat_rect, 4.0, Color32::from_black_alpha(170));
            for (i, line) in lines.iter().enumerate() {
                painter.text(
                    chat_rect.left_top() + Vec2::new(5.0, 2.0 + 14.0 * i as f32),
                    Align2::LEFT_TOP,
                    line,
                    FontId::proportional(9.0),
                    TEXT_MUTED,
                );
            }
        }

        if let Some(dialog) = &state.dialog {
            let box_rect = Rect::from_center_size(
                rect.center(),
                Vec2::new(
                    (rect.width() * 0.82).max(140.0),
                    (rect.height() * 0.58).max(70.0),
                ),
            );
            painter.rect_filled(box_rect, 5.0, Color32::from_rgb(0x13, 0x13, 0x15));
            painter.rect_stroke(box_rect, 5.0, Stroke::new(1.0_f32, HAIRLINE_STRONG));
            painter.text(
                box_rect.left_top() + Vec2::new(8.0, 6.0),
                Align2::LEFT_TOP,
                &dialog.title,
                FontId::proportional(10.5),
                TEXT,
            );
            let text = dialog
                .text
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ");
            painter.text(
                box_rect.left_top() + Vec2::new(8.0, 24.0),
                Align2::LEFT_TOP,
                text,
                FontId::proportional(9.0),
                TEXT_MUTED,
            );
            painter.text(
                box_rect.left_bottom() + Vec2::new(8.0, -6.0),
                Align2::LEFT_BOTTOM,
                format!("[{}]  [{}]", dialog.b1, dialog.b2),
                FontId::proportional(9.0),
                TEXT_FAINT,
            );
        }
    }

    fn proxy_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.label(
                egui::RichText::new(if self.selected.is_some() {
                    "ПРОКСИ ДЛЯ ВЫДЕЛЕННОГО ПРИЛОЖЕНИЯ"
                } else {
                    "ПРОКСИ — ВЫБЕРИТЕ ПРИЛОЖЕНИЕ В СПИСКЕ"
                })
                .font(FontId::proportional(10.5))
                .color(TEXT_FAINT),
            );
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            let full = ui.available_width() - 20.0;
            let combo_w = full - 250.0;
            let proxies = self.cfg.proxies.clone();
            let current = self.current_proxy_index();
            let mut chosen = current;
            let label = current
                .and_then(|i| proxies.get(i))
                .map(|p| self.proxy_label(p))
                .unwrap_or_else(|| "— не выбран —".to_string());
            let visible: Vec<(usize, Proxy)> = proxies
                .iter()
                .cloned()
                .enumerate()
                .filter(|(i, p)| !self.cfg.udp_only || current == Some(*i) || p.udp)
                .collect();

            ui.add_enabled_ui(self.selected.is_some(), |ui| {
                let combo = egui::ComboBox::from_id_source("proxy_combo")
                    .width(combo_w.max(180.0))
                    .selected_text(egui::RichText::new(label).font(FontId::monospace(12.0)));
                combo.show_ui(ui, |ui| {
                    ui.set_min_width(combo_w.max(240.0));
                    if proxies.is_empty() {
                        ui.label(
                            egui::RichText::new("нет прокси — добавьте свой или обновите списки")
                                .color(TEXT_MUTED),
                        );
                    } else if visible.is_empty() {
                        ui.label(
                            egui::RichText::new("нет UDP-прокси — нажмите «Найти»")
                                .color(TEXT_MUTED),
                        );
                    }
                    for (i, p) in visible.iter() {
                        let text = if p.dead() {
                            egui::RichText::new(format!("{}  · мёртв", p.raw))
                                .font(FontId::monospace(11.5))
                                .color(DANGER)
                        } else if p.udp {
                            egui::RichText::new(self.proxy_label(p))
                                .font(FontId::monospace(11.5))
                                .color(SUCCESS)
                        } else {
                            egui::RichText::new(self.proxy_label(p)).font(FontId::monospace(11.5))
                        };
                        if ui.selectable_label(chosen == Some(*i), text).clicked() {
                            chosen = Some(*i);
                        }
                    }
                });
            });
            if chosen != current {
                if let Some(i) = chosen {
                    self.assign_proxy(i);
                }
            }

            let mut udp_only = self.cfg.udp_only;
            if ui
                .checkbox(&mut udp_only, "UDP")
                .on_hover_text("только SOCKS5 с подтверждённым UDP")
                .changed()
            {
                self.cfg.udp_only = udp_only;
                self.save();
            }

            ui.add_space(4.0);
            let add = ui.add(egui::Button::new("+").min_size(Vec2::new(30.0, 28.0)));
            if add.on_hover_text("Добавить свой прокси").clicked() {
                self.modal = Modal::AddProxy(AddProxyState::default());
            }

            ui.add_space(4.0);
            let searching = self.disc.is_some();
            let label = match self.disc {
                Some((done, total)) if total > 0 => format!("{done}/{total}"),
                Some(_) => "Поиск…".to_string(),
                None => "Найти".to_string(),
            };
            let find = ui
                .add_enabled(!searching, egui::Button::new(label).min_size(Vec2::new(78.0, 28.0)))
                .on_hover_text("Найти бесплатные прокси в интернете");
            if find.clicked() {
                let ctx = ui.ctx().clone();
                self.start_discovery(&ctx);
            }

            let testing = self.testing.is_some() || self.testing_all;
            let test_label = if testing { "Проверяю…" } else { "Проверить" };
            let btn = ui.add_enabled(!testing, egui::Button::new(test_label));
            if btn.clicked() {
                let ctx = ui.ctx().clone();
                self.test_proxy(&ctx);
            }
            let all = ui
                .add_enabled(!testing, egui::Button::new("Все"))
                .on_hover_text("Проверить все прокси фоновыми потоками");
            if all.clicked() {
                self.test_all();
            }
        });
        ui.add_space(12.0);
    }

    fn app_list(&mut self, ui: &mut egui::Ui) {
        if self.cfg.apps.is_empty() {
            ui.add_space(56.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Пока пусто")
                        .font(FontId::proportional(15.0))
                        .color(TEXT_MUTED),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("Добавьте exe или выберите уже запущенное приложение")
                        .font(FontId::proportional(12.0))
                        .color(TEXT_FAINT),
                );
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    let w = 300.0;
                    ui.add_space((ui.available_width() - w).max(0.0) / 2.0);
                    if ui.add(primary_button("Добавить приложение")).clicked() {
                        self.pick_file();
                    }
                    ui.add_space(4.0);
                    if ui.button("Из запущенных").clicked() {
                        self.open_running();
                    }
                });
            });
            return;
        }

        let mut launch: Option<usize> = None;
        let mut remove: Option<usize> = None;
        let mut kill: Option<usize> = None;
        let mut open_args: Option<usize> = None;
        let mut new_selection: Option<usize> = None;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(4.0);
                for idx in 0..self.cfg.apps.len() {
                    let action = self.row(ui, idx);
                    match action {
                        RowAction::None => {}
                        RowAction::Select => new_selection = Some(idx),
                        RowAction::Launch => {
                            new_selection = Some(idx);
                            launch = Some(idx);
                        }
                        RowAction::Remove => remove = Some(idx),
                        RowAction::Kill => kill = Some(idx),
                        RowAction::Args => {
                            new_selection = Some(idx);
                            open_args = Some(idx);
                        }
                    }
                    ui.add_space(2.0);
                }
                ui.add_space(8.0);
            });

        if let Some(i) = new_selection {
            self.selected = Some(i);
        }
        if let Some(i) = launch {
            self.launch(i);
        }
        if let Some(i) = remove {
            self.selected = Some(i);
            self.remove_selected();
        }
        if let Some(i) = kill {
            self.kill_app(i);
        }
        if let Some(i) = open_args {
            let args = self.cfg.apps[i].args.clone();
            self.modal = Modal::Args(i, args);
        }
    }

    fn row(&mut self, ui: &mut egui::Ui, idx: usize) -> RowAction {
        let mut action = RowAction::None;
        let running = self.live_pids(idx);
        let width = ui.available_width();
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, ROW_H), Sense::click());

        let selected = self.selected == Some(idx);
        let hover_t = ui
            .ctx()
            .animate_bool_with_time(ui.id().with(("h", idx)), resp.hovered(), 0.12);
        let sel_t = ui
            .ctx()
            .animate_bool_with_time(ui.id().with(("s", idx)), selected, 0.12);

        let bg = mix(mix(CANVAS, SURFACE_HOVER, hover_t), SURFACE_ACTIVE, sel_t * 0.85);
        let body = rect.shrink2(Vec2::new(12.0, 2.0));
        ui.painter().rect_filled(body, Rounding::same(10.0), bg);

        if sel_t > 0.01 {
            let bar = Rect::from_min_size(
                Pos2::new(body.left() + 1.0, body.top() + 12.0),
                Vec2::new(2.0, body.height() - 24.0),
            );
            ui.painter()
                .rect_filled(bar, Rounding::same(1.0), ACCENT.gamma_multiply(sel_t));
        }

        let app = &self.cfg.apps[idx];
        let text_x = body.left() + 18.0;
        let title_font = FontId::proportional(14.5);
        let path_font = FontId::monospace(11.0);

        // чип прокси: сначала измеряем, чтобы текст не заезжал под него
        let (proxy_text, proxy_color) = match self.cfg.proxy_of_app(idx) {
            Some(p) if p.dead() => (p.raw.clone(), DANGER.gamma_multiply(0.85)),
            Some(p) => (p.raw.clone(), TEXT_MUTED),
            None => ("без прокси".to_string(), DANGER.gamma_multiply(0.85)),
        };
        let chip_font = FontId::monospace(11.0);
        // длинный прокси не должен растягивать чип на весь ряд
        let chip_text = elide(
            ui.painter(),
            &proxy_text,
            chip_font.clone(),
            (body.width() - 252.0).max(64.0),
        );
        let galley = ui
            .painter()
            .layout_no_wrap(chip_text, chip_font.clone(), proxy_color);
        let chip_size = Vec2::new(galley.size().x + 18.0, 24.0);
        let chip = Rect::from_center_size(
            Pos2::new(body.right() - 128.0 - chip_size.x / 2.0, body.center().y - 2.0),
            chip_size,
        );

        // 128 px справа под чип и кнопки, 8 px зазор, 18 px левый отступ
        let max_text = (body.width() - chip_size.x - 154.0).max(80.0);
        let title = elide(ui.painter(), &app.name, title_font.clone(), max_text);
        ui.painter().text(
            Pos2::new(text_x, body.top() + 18.0),
            Align2::LEFT_TOP,
            title,
            title_font,
            if selected { TEXT } else { TEXT.gamma_multiply(0.92) },
        );
        let path_label = if app.copies > 0 {
            format!("{}   ·   копий: {}", app.path, app.copies)
        } else {
            app.path.clone()
        };
        let path = elide(ui.painter(), &path_label, path_font.clone(), max_text);
        ui.painter().text(
            Pos2::new(text_x, body.top() + 40.0),
            Align2::LEFT_TOP,
            path,
            path_font,
            TEXT_FAINT,
        );

        ui.painter().rect_filled(chip, Rounding::same(6.0), SURFACE);
        ui.painter()
            .rect_stroke(chip, Rounding::same(6.0), Stroke::new(1.0_f32, HAIRLINE));
        ui.painter().text(
            chip.center(),
            Align2::CENTER_CENTER,
            galley.text(),
            chip_font,
            proxy_color,
        );

        // кнопка запуска
        let play_rect = Rect::from_center_size(
            Pos2::new(body.right() - 34.0, body.center().y),
            Vec2::new(34.0, 34.0),
        );
        let play = ui.interact(
            play_rect,
            ui.id().with(("play", idx)),
            Sense::click(),
        );
        let play_t = ui
            .ctx()
            .animate_bool_with_time(ui.id().with(("ph", idx)), play.hovered(), 0.12);
        let play_bg = mix(SURFACE, ACCENT, play_t * 0.9);
        ui.painter().circle_filled(play_rect.center(), 16.0, play_bg);
        if play_t < 0.5 {
            ui.painter().circle_stroke(
                play_rect.center(),
                16.0,
                Stroke::new(1.0_f32, HAIRLINE_STRONG),
            );
        }
        let tri_center = play_rect.center() + Vec2::new(1.0, 0.0)
            - if play.is_pointer_button_down_on() {
                Vec2::new(0.0, 1.0)
            } else {
                Vec2::ZERO
            };
        let tri = vec![
            Pos2::new(tri_center.x - 4.0, tri_center.y - 6.0),
            Pos2::new(tri_center.x - 4.0, tri_center.y + 6.0),
            Pos2::new(tri_center.x + 7.0, tri_center.y),
        ];
        let tri_color = mix(TEXT_MUTED, Color32::from_rgb(0x0B, 0x0B, 0x0C), play_t);
        ui.painter()
            .add(egui::Shape::convex_polygon(tri, tri_color, Stroke::NONE));

        // удалить
        let del_rect = Rect::from_center_size(
            Pos2::new(body.right() - 72.0, body.center().y),
            Vec2::new(26.0, 26.0),
        );
        if selected || resp.hovered() {
            let del = ui.interact(del_rect, ui.id().with(("del", idx)), Sense::click());
            let del_t = ui
                .ctx()
                .animate_bool_with_time(ui.id().with(("dh", idx)), del.hovered(), 0.12);
            if del_t > 0.01 {
                ui.painter()
                    .circle_filled(del_rect.center(), 13.0, SURFACE_HOVER);
            }
            let c = mix(TEXT_FAINT, DANGER, del_t);
            let ctr = del_rect.center();
            ui.painter().line_segment(
                [ctr + Vec2::new(-4.0, -4.0), ctr + Vec2::new(4.0, 4.0)],
                Stroke::new(1.4_f32, c),
            );
            ui.painter().line_segment(
                [ctr + Vec2::new(4.0, -4.0), ctr + Vec2::new(-4.0, 4.0)],
                Stroke::new(1.4_f32, c),
            );
            if del.clicked() {
                action = RowAction::Remove;
            }
        }

        // остановить всё дерево приложения; управление есть только при живых pid
        if !running.is_empty() {
            let kill_rect = Rect::from_center_size(
                Pos2::new(body.right() - 108.0, body.center().y),
                Vec2::new(28.0, 28.0),
            );
            let kill = ui
                .interact(kill_rect, ui.id().with(("kill", idx)), Sense::click())
                .on_hover_text("Убить все процессы приложения");
            let kill_t = ui.ctx().animate_bool_with_time(
                ui.id().with(("kh", idx)),
                kill.hovered(),
                0.12,
            );
            if kill_t > 0.01 {
                ui.painter()
                    .circle_filled(kill_rect.center(), 14.0, SURFACE_HOVER);
            }
            ui.painter().circle_stroke(
                kill_rect.center(),
                13.5,
                Stroke::new(1.0_f32, mix(HAIRLINE_STRONG, DANGER, kill_t)),
            );
            ui.painter().rect_filled(
                Rect::from_center_size(kill_rect.center(), Vec2::splat(7.0)),
                Rounding::same(1.0),
                mix(TEXT_FAINT, DANGER, kill_t),
            );
            if kill.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            if kill.clicked() {
                action = RowAction::Kill;
            }
        }

        if resp.clicked() {
            action = RowAction::Select;
        }
        if resp.double_clicked() {
            action = RowAction::Launch;
        }
        if resp.secondary_clicked() {
            action = RowAction::Args;
        }
        if play.clicked() {
            action = RowAction::Launch;
        }
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
        }
        action
    }

    fn footer(&mut self, ui: &mut egui::Ui) {
        let running = self.live_total();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            if !self.cfg.apps.is_empty() {
                if ui.button("+  Приложение").clicked() {
                    self.pick_file();
                }
                if ui.button("Из запущенных").clicked() {
                    self.open_running();
                }
                footer_divider(ui);
                let label = if self.grid_active { "Сетка: вкл" } else { "Сетка" };
                let grid_btn = ui
                    .add(egui::Button::new(label))
                    .on_hover_text("Превью окон, запущенных через прокси");
                if grid_btn.clicked() {
                    if self.grid_active {
                        self.stop_grid();
                    } else {
                        self.start_grid();
                    }
                }
            }
            if running > 0 {
                footer_divider(ui);
                if stop_all_button(ui) {
                    self.kill_all();
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(20.0);
                let dot = match &self.status {
                    Status::Ok(_) => SUCCESS,
                    Status::Err(_) => DANGER,
                    Status::Info(_) => TEXT_FAINT,
                };
                ui.label(
                    egui::RichText::new(self.status.text())
                        .font(FontId::proportional(11.5))
                        .color(self.status.color()),
                );
                ui.add_space(2.0);
                let (dot_rect, _) = ui.allocate_exact_size(Vec2::new(10.0, 10.0), Sense::hover());
                ui.painter().circle_filled(dot_rect.center(), 3.0, dot);
            });
        });
        ui.add_space(10.0);
    }

    fn pick_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Программы", &["exe"])
            .pick_file()
        {
            let name = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "app".into());
            self.add_app(path.to_string_lossy().to_string(), name);
        }
    }

    fn open_running(&mut self) {
        let items = win::running_apps();
        self.modal = Modal::Running(RunningState {
            items,
            filter: String::new(),
            selected: None,
        });
    }

    // ------------------------------------------------------------ modals
    fn modals(&mut self, ctx: &egui::Context) {
        enum Pending {
            Close,
            AddProxy(String),
            AddApp(String, String),
            SaveArgs(usize, String),
            ResetCopies(usize),
            LaunchSlot(usize, u32),
        }
        let mut pending: Option<Pending> = None;

        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.modal = Modal::None;
            return;
        }

        if !matches!(self.modal, Modal::None) {
            egui::Area::new(egui::Id::new("modal_scrim"))
                .order(egui::Order::Middle)
                .fixed_pos(egui::Pos2::ZERO)
                .show(ctx, |ui| {
                    let screen = ctx.screen_rect();
                    ui.painter()
                        .rect_filled(screen, 0.0, Color32::from_black_alpha(140));
                    ui.allocate_exact_size(screen.size(), Sense::click());
                });
        }

        match &mut self.modal {
            Modal::None => return,
            Modal::AddProxy(state) => {
                let mut open = true;
                let mut submit = false;
                let mut cancel = false;
                egui::Window::new("Добавить прокси").order(egui::Order::Foreground)
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                    .default_width(420.0)
                    .show(ctx, |ui| {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            egui::ComboBox::from_id_source("scheme")
                                .width(110.0)
                                .selected_text(if state.scheme == 0 { "SOCKS5" } else { "HTTP" })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut state.scheme, 0, "SOCKS5");
                                    ui.selectable_value(&mut state.scheme, 1, "HTTP");
                                });
                            ui.label(egui::RichText::new("тип прокси").size(11.0).color(TEXT_FAINT));
                        });
                        ui.add_space(10.0);
                        labelled(ui, "Хост", &mut state.host, "1.2.3.4");
                        ui.add_space(8.0);
                        labelled(ui, "Порт", &mut state.port, "1080");
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(
                                    egui::RichText::new("Логин (необязательно)")
                                        .size(11.0)
                                        .color(TEXT_FAINT),
                                );
                                ui.add(
                                    egui::TextEdit::singleline(&mut state.user)
                                        .desired_width(190.0)
                                        .hint_text("user"),
                                );
                            });
                            ui.add_space(8.0);
                            ui.vertical(|ui| {
                                ui.label(
                                    egui::RichText::new("Пароль").size(11.0).color(TEXT_FAINT),
                                );
                                ui.add(
                                    egui::TextEdit::singleline(&mut state.pass)
                                        .password(true)
                                        .desired_width(190.0)
                                        .hint_text("pass"),
                                );
                            });
                        });
                        if let Some(err) = &state.error {
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new(format!("! {err}"))
                                    .size(11.5)
                                    .color(DANGER),
                            );
                        }
                        ui.add_space(14.0);
                        ui.horizontal(|ui| {
                            if ui.button("Отмена").clicked() {
                                cancel = true;
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.add(primary_button("Добавить")).clicked() {
                                        submit = true;
                                    }
                                },
                            );
                        });
                    });

                if submit {
                    let host = state.host.trim().to_string();
                    let port: u32 = state.port.trim().parse().unwrap_or(0);
                    if host.is_empty() {
                        state.error = Some("укажите хост".into());
                    } else if port == 0 || port > 65535 {
                        state.error = Some("порт должен быть 1–65535".into());
                    } else {
                        let scheme = if state.scheme == 0 { "socks5" } else { "http" };
                        let auth = if state.user.trim().is_empty() {
                            String::new()
                        } else {
                            format!("{}:{}@", state.user.trim(), state.pass.trim())
                        };
                        pending = Some(Pending::AddProxy(format!(
                            "{scheme}://{auth}{host}:{port}"
                        )));
                    }
                } else if cancel || !open {
                    pending = Some(Pending::Close);
                }
            }

            Modal::Running(state) => {
                let mut open = true;
                let mut add: Option<usize> = None;
                let mut close = false;
                egui::Window::new("Запущенные приложения").order(egui::Order::Foreground)
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(true)
                    .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                    .default_size(Vec2::new(560.0, 420.0))
                    .show(ctx, |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut state.filter)
                                .hint_text("фильтр по имени")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(6.0);
                        egui::ScrollArea::vertical()
                            .max_height(300.0)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if state.items.is_empty() {
                                    ui.label(
                                        egui::RichText::new("Ничего не найдено").color(TEXT_MUTED),
                                    );
                                }
                                let filter = state.filter.to_lowercase();
                                for (i, item) in state.items.iter().enumerate() {
                                    if !filter.is_empty()
                                        && !item.name.to_lowercase().contains(&filter)
                                    {
                                        continue;
                                    }
                                    let selected = state.selected == Some(i);
                                    let resp = ui.add(
                                        egui::Button::new(
                                            egui::RichText::new(format!(
                                                "{}   {}",
                                                item.name, item.title
                                            ))
                                            .font(FontId::proportional(12.5)),
                                        )
                                        .fill(if selected { SURFACE_ACTIVE } else { SURFACE })
                                        .min_size(Vec2::new(ui.available_width(), 30.0)),
                                    );
                                    if resp.clicked() {
                                        state.selected = Some(i);
                                    }
                                    if resp.double_clicked() {
                                        add = Some(i);
                                    }
                                }
                            });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Отмена").clicked() {
                                close = true;
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.add(primary_button("Добавить")).clicked() {
                                        if let Some(s) = state.selected {
                                            add = Some(s);
                                        }
                                    }
                                },
                            );
                        });
                    });

                if let Some(i) = add {
                    if let Some(item) = state.items.get(i) {
                        pending = Some(Pending::AddApp(item.path.clone(), item.name.clone()));
                    }
                } else if close || !open {
                    pending = Some(Pending::Close);
                }
            }

            Modal::Args(idx, text) => {
                let idx = *idx;
                let mut open = true;
                let mut save = false;
                let mut cancel = false;
                let mut reset = false;
                let mut launch_slot: Option<u32> = None;
                let (name, copies) = self
                    .cfg
                    .apps
                    .get(idx)
                    .map(|a| (a.name.clone(), a.copies))
                    .unwrap_or_default();
                egui::Window::new(format!("Аргументы · {name}")).order(egui::Order::Foreground)
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                    .default_width(460.0)
                    .show(ctx, |ui| {
                        ui.label(
                            egui::RichText::new(
                                "Командная строка, например --profile-directory=Work",
                            )
                            .size(11.0)
                            .color(TEXT_FAINT),
                        );
                        ui.add_space(6.0);
                        ui.add(
                            egui::TextEdit::multiline(text)
                                .desired_rows(3)
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new(format!(
                                "Копий запускалось: {copies}. У каждой своя папка профиля и свой прокси-туннель."
                            ))
                            .size(11.0)
                            .color(TEXT_FAINT),
                        );
                        if copies > 0 {
                            ui.add_space(6.0);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    egui::RichText::new("Запустить копию:")
                                        .size(11.0)
                                        .color(TEXT_FAINT),
                                );
                                for slot in 1..=copies.min(12) {
                                    if ui.small_button(format!("{slot}")).clicked() {
                                        launch_slot = Some(slot);
                                    }
                                }
                            });
                        }
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Отмена").clicked() {
                                cancel = true;
                            }
                            if ui.button("Сбросить копии").clicked() {
                                reset = true;
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.add(primary_button("Сохранить")).clicked() {
                                        save = true;
                                    }
                                },
                            );
                        });
                    });
                if let Some(slot) = launch_slot {
                    pending = Some(Pending::LaunchSlot(idx, slot));
                } else if reset {
                    pending = Some(Pending::ResetCopies(idx));
                } else if save {
                    pending = Some(Pending::SaveArgs(idx, text.clone()));
                } else if cancel || !open {
                    pending = Some(Pending::Close);
                }
            }
        }

        match pending {
            Some(Pending::AddProxy(raw)) => {
                self.modal = Modal::None;
                self.add_proxy(raw);
            }
            Some(Pending::AddApp(path, name)) => {
                self.modal = Modal::None;
                self.add_app(path, name);
            }
            Some(Pending::SaveArgs(idx, text)) => {
                self.modal = Modal::None;
                if let Some(app) = self.cfg.apps.get_mut(idx) {
                    app.args = text;
                }
                self.save();
                self.status = Status::Info("аргументы сохранены".into());
            }
            Some(Pending::ResetCopies(idx)) => {
                self.modal = Modal::None;
                let dir = self.profile_root(idx);
                let _ = std::fs::remove_dir_all(&dir);
                if let Some(app) = self.cfg.apps.get_mut(idx) {
                    app.copies = 0;
                }
                self.save();
                self.status = Status::Ok("профили копий удалены, счётчик сброшен".into());
            }
            Some(Pending::LaunchSlot(idx, slot)) => {
                self.modal = Modal::None;
                self.launch_slot(idx, Some(slot));
            }
            Some(Pending::Close) => self.modal = Modal::None,
            None => {}
        }
    }
}

#[derive(PartialEq)]
enum RowAction {
    None,
    Select,
    Launch,
    Kill,
    Remove,
    Args,
}

impl eframe::App for ProxyBox {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.app_hwnd == 0 {
            let hwnd = win::main_window();
            if hwnd != 0 {
                self.app_hwnd = hwnd;
                self.grid.set_app_hwnd(hwnd);
            }
        }
        if !self.dark_title && self.app_hwnd != 0 {
            self.dark_title = true;
            theme::apply_dark_titlebar(self.app_hwnd);
        }
        self.poll_health();
        self.tick_health();
        self.poll_launch();
        self.poll_discovery();

        let grid::Snapshot {
            active,
            items,
            note,
        } = self.grid.snapshot();
        if self.grid_active && !active {
            self.status = Status::Info("превью выключены".into());
        }
        self.grid_active = active;
        self.grid_count = items.len();
        self.grid_items = items;
        if active {
            self.grid_note = note;
        }
        self.sync_previews(ctx);
        // воркер снимает кадры раз в 600 мс — чаще перерисовываться незачем
        ctx.request_repaint_after(std::time::Duration::from_millis(if self.grid_active {
            400
        } else {
            900
        }));

        if self.pending.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        resize_zones(ctx);

        ctx.input(|i| {
            if i.key_pressed(egui::Key::Enter) {
                if let Some(sel) = self.selected {
                    self.launch(sel);
                }
            }
            if i.key_pressed(egui::Key::Delete) {
                self.remove_selected();
            }
        });

        self.title_bar(ctx);

        if self.grid_active {
            egui::TopBottomPanel::top("grid_banner")
                .frame(
                    egui::Frame::none()
                        .fill(SURFACE)
                        .inner_margin(egui::Margin::symmetric(20.0, 9.0)),
                )
                .show(ctx, |ui| self.grid_banner(ui));
        }

        egui::TopBottomPanel::bottom("footer")
            .frame(egui::Frame::none().fill(CANVAS).inner_margin(egui::Margin::ZERO))
            .show(ctx, |ui| self.footer(ui));

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(CANVAS))
            .show(ctx, |ui| {
                if self.grid_active {
                    self.preview_grid(ui);
                } else {
                    self.proxy_bar(ui);
                    self.app_list(ui);
                }
            });

        self.modals(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.grid.shutdown();
    }
}

// ---------------------------------------------------------------- helpers
#[derive(Clone, Copy, PartialEq)]
enum CaptionKind {
    Min,
    Max,
    Close,
}

fn caption_button(ui: &mut egui::Ui, kind: CaptionKind) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(34.0, 26.0), Sense::click());
    let t = ui
        .ctx()
        .animate_bool_with_time(ui.id().with(("cap", kind as u8)), resp.hovered(), 0.12);
    let bg = mix(CANVAS, if kind == CaptionKind::Close { DANGER } else { SURFACE_HOVER }, t);
    ui.painter().rect_filled(rect, Rounding::same(6.0), bg);
    let c = mix(TEXT_MUTED, if kind == CaptionKind::Close { Color32::WHITE } else { TEXT }, t);
    let ctr = rect.center();
    let stroke = Stroke::new(1.2_f32, c);
    match kind {
        CaptionKind::Min => {
            ui.painter()
                .line_segment([ctr + Vec2::new(-5.0, 0.0), ctr + Vec2::new(5.0, 0.0)], stroke);
        }
        CaptionKind::Max => {
            let r = Rect::from_center_size(ctr, Vec2::new(9.0, 9.0));
            ui.painter().rect_stroke(r, Rounding::same(1.5), stroke);
        }
        CaptionKind::Close => {
            ui.painter().line_segment(
                [ctr + Vec2::new(-4.5, -4.5), ctr + Vec2::new(4.5, 4.5)],
                stroke,
            );
            ui.painter().line_segment(
                [ctr + Vec2::new(4.5, -4.5), ctr + Vec2::new(-4.5, 4.5)],
                stroke,
            );
        }
    }
    resp.clicked()
}

fn footer_divider(ui: &mut egui::Ui) {
    ui.add_space(2.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(1.0, 18.0), Sense::hover());
    ui.painter().rect_filled(rect, Rounding::ZERO, HAIRLINE_STRONG);
    ui.add_space(2.0);
}

/// Ghost-кнопка «Стоп всё»: фон и danger-цвет только на hover.
fn stop_all_button(ui: &mut egui::Ui) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(78.0, 28.0), Sense::click());
    let t = ui
        .ctx()
        .animate_bool_with_time(ui.id().with("stop-all"), resp.hovered(), 0.12);
    if t > 0.01 {
        ui.painter()
            .rect_filled(rect, Rounding::same(6.0), mix(CANVAS, SURFACE_HOVER, t));
        ui.painter().rect_stroke(
            rect,
            Rounding::same(6.0),
            Stroke::new(1.0_f32, mix(HAIRLINE, DANGER, t)),
        );
    }
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        "Стоп всё",
        FontId::proportional(12.5),
        mix(TEXT_MUTED, DANGER, t),
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp.on_hover_text("Убить все процессы, запущенные через proxybox")
        .clicked()
}

fn kill_status(killed: usize, survivors: usize) -> Status {
    if survivors == 0 {
        Status::Ok(format!("остановлено процессов: {killed}"))
    } else {
        Status::Err(format!(
            "остановлено процессов: {killed} · живы: {survivors} — нет прав / защищённый процесс"
        ))
    }
}

fn pending_in_roots(pending: Option<u32>, roots: &[u32]) -> bool {
    pending.map_or(false, |pid| roots.contains(&pid))
}

/// TerminateProcess асинхронен для внешнего наблюдателя: дерево из многих
/// процессов может исчезать из снимка сотни миллисекунд. Опрашиваем до 800 мс,
/// чтобы не объявлять выживших, которые уже завершаются.
fn survivors_after(roots: &[u32]) -> usize {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
    loop {
        let survivors = win::trees_alive(roots);
        if survivors == 0 {
            return 0;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return survivors;
        }
        std::thread::sleep(left.min(std::time::Duration::from_millis(50)));
    }
}

fn resize_zones(ctx: &egui::Context) {
    use egui::ResizeDirection as D;
    if ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
        return;
    }
    let Some(p) = ctx.input(|i| i.pointer.hover_pos()) else { return };
    let rect = ctx.screen_rect();
    let m = 6.0;
    let l = p.x - rect.left() < m;
    let r = rect.right() - p.x < m;
    let t = p.y - rect.top() < m;
    let b = rect.bottom() - p.y < m;
    let dir = match (l, r, t, b) {
        (true, _, true, _) => Some(D::NorthWest),
        (_, true, true, _) => Some(D::NorthEast),
        (true, _, _, true) => Some(D::SouthWest),
        (_, true, _, true) => Some(D::SouthEast),
        (true, _, _, _) => Some(D::West),
        (_, true, _, _) => Some(D::East),
        (_, _, true, _) => Some(D::North),
        (_, _, _, true) => Some(D::South),
        _ => None,
    };
    if let Some(dir) = dir {
        ctx.set_cursor_icon(match dir {
            D::NorthWest | D::SouthEast => egui::CursorIcon::ResizeNwSe,
            D::NorthEast | D::SouthWest => egui::CursorIcon::ResizeNeSw,
            D::North | D::South => egui::CursorIcon::ResizeVertical,
            _ => egui::CursorIcon::ResizeHorizontal,
        });
        if ctx.input(|i| i.pointer.primary_pressed()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(dir));
        }
    }
}

fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(text.to_string())
            .color(Color32::from_rgb(0x08, 0x0A, 0x0F))
            .strong(),
    )
    .fill(ACCENT)
}

fn labelled(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.vertical(|ui| {
        ui.label(egui::RichText::new(label).size(11.0).color(TEXT_FAINT));
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(f32::INFINITY),
        );
    });
}

fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let lerp = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgb(lerp(a.r(), b.r()), lerp(a.g(), b.g()), lerp(a.b(), b.b()))
}

fn elide(painter: &egui::Painter, text: &str, font: FontId, max_w: f32) -> String {
    if painter
        .layout_no_wrap(text.to_string(), font.clone(), Color32::WHITE)
        .size()
        .x
        <= max_w
    {
        return text.to_string();
    }
    let mut chars: Vec<char> = text.chars().collect();
    while !chars.is_empty() {
        chars.pop();
        let candidate: String = chars.iter().collect::<String>() + "…";
        if painter
            .layout_no_wrap(candidate.clone(), font.clone(), Color32::WHITE)
            .size()
            .x
            <= max_w
        {
            return candidate;
        }
    }
    "…".into()
}

/// Home-relative state (`~/.zcode`, `~/.gitconfig`, Node `os.homedir()`) lives
/// outside APPDATA, so every copy gets its own profile root too.
fn sandbox_home(cmd: &mut std::process::Command, sandbox: &std::path::Path) {
    let home = sandbox.join("Home");
    let _ = std::fs::create_dir_all(&home);
    cmd.env("HOME", &home).env("USERPROFILE", &home);
}

fn is_chromium(path: &str) -> bool {
    let name = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        name.as_str(),
        "chrome.exe"
            | "msedge.exe"
            | "brave.exe"
            | "chromium.exe"
            | "vivaldi.exe"
            | "opera.exe"
            | "yandex.exe"
            | "browser.exe"
    )
}

fn is_firefox(path: &str) -> bool {
    std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().eq_ignore_ascii_case("firefox.exe"))
        .unwrap_or(false)
}

fn is_raklite(path: &str) -> bool {
    let name = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    name.contains("raksamp") || name.contains("raklite") || name.contains("rakbot")
}

/// IMAGE_FILE_HEADER.Machine из PE-заголовка: 0x014c — x86, 0x8664 — x64.
fn pe_machine(path: &str) -> Option<u16> {
    let data = std::fs::read(path).ok()?;
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return None;
    }
    let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if data.len() < lfanew + 6 || &data[lfanew..lfanew + 4] != b"PE\0\0" {
        return None;
    }
    Some(u16::from_le_bytes(
        data[lfanew + 4..lfanew + 6].try_into().ok()?,
    ))
}

/// SA-MP color: 0xRRGGBBAA; нулевой цвет заменяем акцентом.
fn samp_color(value: u32) -> Color32 {
    if value == 0 {
        return ACCENT;
    }
    let r = ((value >> 24) & 0xff) as u8;
    let g = ((value >> 16) & 0xff) as u8;
    let b = ((value >> 8) & 0xff) as u8;
    Color32::from_rgb(r.max(48), g.max(48), b.max(48))
}

fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let mut ok = false;
    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf") {
        fonts
            .font_data
            .insert("segoe".into(), egui::FontData::from_owned(bytes).into());
        if let Some(list) = fonts.families.get_mut(&FontFamily::Proportional) {
            list.insert(0, "segoe".into());
        }
        ok = true;
    }
    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\consola.ttf") {
        fonts
            .font_data
            .insert("consola".into(), egui::FontData::from_owned(bytes).into());
        if let Some(list) = fonts.families.get_mut(&FontFamily::Monospace) {
            list.insert(0, "consola".into());
        }
    }
    if ok {
        ctx.set_fonts(fonts);
    }
}

fn install_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = CANVAS;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = Color32::from_rgb(0x0E, 0x0E, 0x10);
    visuals.faint_bg_color = SURFACE;
    visuals.override_text_color = Some(TEXT);
    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.35);
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);

    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, HAIRLINE);
    visuals.widgets.noninteractive.rounding = Rounding::same(6.0);

    visuals.widgets.inactive.bg_fill = SURFACE;
    visuals.widgets.inactive.weak_bg_fill = SURFACE;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, HAIRLINE);
    visuals.widgets.inactive.rounding = Rounding::same(6.0);

    visuals.widgets.hovered.bg_fill = SURFACE_HOVER;
    visuals.widgets.hovered.weak_bg_fill = SURFACE_HOVER;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, HAIRLINE_STRONG);
    visuals.widgets.hovered.rounding = Rounding::same(6.0);

    visuals.widgets.active.bg_fill = SURFACE_ACTIVE;
    visuals.widgets.active.weak_bg_fill = SURFACE_ACTIVE;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, HAIRLINE_STRONG);
    visuals.widgets.active.rounding = Rounding::same(6.0);

    visuals.window_stroke = Stroke::new(1.0_f32, HAIRLINE_STRONG);
    visuals.window_rounding = Rounding::same(10.0);
    visuals.menu_rounding = Rounding::same(8.0);

    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(16.0);
    style.animation_time = 0.12;

    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(19.0)),
        (TextStyle::Body, FontId::proportional(13.5)),
        (TextStyle::Button, FontId::proportional(13.0)),
        (TextStyle::Small, FontId::proportional(11.0)),
        (TextStyle::Monospace, FontId::monospace(11.5)),
    ]
    .into();

    ctx.set_style(style);
}

fn main() -> eframe::Result<()> {
    // одно окно на систему: два процесса делят proxybox.json и нумерацию профилей
    if !win::claim_single_instance("proxybox") {
        return Ok(());
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([820.0, 520.0])
            .with_decorations(false)
            .with_title("proxybox"),
        ..Default::default()
    };
    eframe::run_native(
        "proxybox",
        options,
        Box::new(|cc| Ok(Box::new(ProxyBox::new(cc)))),
    )
}

#[cfg(test)]
mod tests {
    use super::pending_in_roots;

    #[test]
    fn pending_is_dropped_only_when_its_root_is_killed() {
        assert!(pending_in_roots(Some(42), &[7, 42]));
        assert!(!pending_in_roots(Some(42), &[7, 8]));
        assert!(!pending_in_roots(None, &[42]));
    }
}
