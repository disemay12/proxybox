//! Превью окон: кадры только тех процессов, которые запущены через proxybox.
//! Окна не двигаются и не перекладываются — fullscreen-игры один раз
//! переводятся в оконный режим, чтобы их вообще можно было показать.

use crate::vision;
use crate::win;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::RECT;
use windows::Win32::UI::WindowsAndMessaging::WINDOWPLACEMENT;

const TICK: Duration = Duration::from_millis(600);
const THUMB_W: u32 = 480;
const THUMB_H: u32 = 270;

#[derive(Clone)]
pub struct PreviewItem {
    /// Ключ тайла: hwnd для окна, отрицательный pid для vision без окна.
    pub key: isize,
    pub hwnd: isize,
    pub pid: u32,
    pub title: String,
    pub minimized: bool,
    pub frame: Option<Arc<Vec<u8>>>,
    pub width: usize,
    pub height: usize,
    pub seq: u64,
    pub vision: Option<Arc<vision::State>>,
}

pub struct Snapshot {
    pub active: bool,
    pub items: Vec<PreviewItem>,
    pub note: String,
}

struct Shared {
    active: bool,
    roots: Vec<u32>,
    cols: usize,
    app_hwnd: isize,
    vision: vision::Registry,
    items: Vec<PreviewItem>,
    note: String,
    stop: bool,
    ack: Option<Sender<()>>,
}

pub struct Grid {
    shared: Arc<Mutex<Shared>>,
}

impl Grid {
    pub fn new(
        app_hwnd: isize,
        hotkey_flag: Arc<AtomicBool>,
        hotkey_ok: Arc<AtomicBool>,
        vision: vision::Registry,
    ) -> Self {
        win::spawn_hotkey(hotkey_flag.clone(), hotkey_ok);
        let shared = Arc::new(Mutex::new(Shared {
            active: false,
            roots: Vec::new(),
            cols: 0,
            app_hwnd,
            vision,
            items: Vec::new(),
            note: String::new(),
            stop: false,
            ack: None,
        }));
        let worker_shared = Arc::clone(&shared);
        std::thread::spawn(move || worker(worker_shared, hotkey_flag));
        Self { shared }
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_app_hwnd(&self, hwnd: isize) {
        if hwnd != 0 {
            self.lock().app_hwnd = hwnd;
        }
    }

    /// PID процесса, запущенного через прокси. Его потомки (сама игра,
    /// дочерние процессы браузера) попадают в превью автоматически.
    pub fn add_root(&self, pid: u32) {
        if pid == 0 {
            return;
        }
        let mut shared = self.lock();
        if !shared.roots.contains(&pid) {
            shared.roots.push(pid);
        }
    }

    pub fn set_cols(&self, cols: usize) {
        self.lock().cols = cols.min(8);
    }

    pub fn activate(&self) -> bool {
        let mut shared = self.lock();
        shared.active = true;
        shared.note = "превью включены".into();
        true
    }

    pub fn deactivate(&self) {
        let mut shared = self.lock();
        shared.active = false;
        shared.note = "превью выключены".into();
        shared.items.clear();
    }

    pub fn snapshot(&self) -> Snapshot {
        let shared = self.lock();
        Snapshot {
            active: shared.active,
            items: shared.items.clone(),
            note: shared.note.clone(),
        }
    }

    /// Останавливает воркер и возвращает fullscreen-окна в исходный вид.
    pub fn shutdown(&mut self) {
        let rx = {
            let mut shared = self.lock();
            if shared.stop {
                return;
            }
            shared.stop = true;
            shared.active = false;
            let (tx, rx) = channel();
            shared.ack = Some(tx);
            rx
        };
        let _ = rx.recv_timeout(Duration::from_millis(2000));
    }
}

enum Stage {
    Placed,
    AltSent,
    Done,
}

struct Converted {
    hwnd: isize,
    style: u32,
    ex_style: u32,
    placement: WINDOWPLACEMENT,
    stage: Stage,
    at: Instant,
}

fn worker(shared: Arc<Mutex<Shared>>, hotkey: Arc<AtomicBool>) {
    let mut tracked: Vec<u32> = Vec::new();
    let mut converted: Vec<Converted> = Vec::new();
    let mut seq = 0u64;

    loop {
        std::thread::sleep(TICK);

        let (stop, mut active, app_hwnd, ack, turned_on) = {
            let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
            let mut turned_on = false;

            if hotkey.swap(false, Ordering::Relaxed) {
                if g.active {
                    g.active = false;
                    g.note = "превью выключены".into();
                    g.items.clear();
                } else {
                    g.active = true;
                    g.note = "превью включены".into();
                    turned_on = true;
                }
            }

            if g.stop {
                (true, false, g.app_hwnd, g.ack.take(), false)
            } else {
                (false, g.active, g.app_hwnd, None, turned_on)
            }
        };

        if stop {
            restore_all(&mut converted);
            if let Some(tx) = ack {
                let _ = tx.send(());
            }
            return;
        }

        if turned_on {
            win::restore_and_focus(app_hwnd);
        }

        // дерево процессов: корни — то, что запустил proxybox,
        // tracked переживает смерть промежуточного лаунчера/инжектора
        let procs = win::process_tree();
        let alive: HashSet<u32> = procs.iter().map(|(pid, _)| *pid).collect();
        let roots = {
            let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
            g.roots.retain(|p| alive.contains(p));
            g.roots.clone()
        };
        tracked.retain(|p| alive.contains(p));
        for pid in descendants(&roots, &procs) {
            if !tracked.contains(&pid) {
                tracked.push(pid);
            }
        }

        if !active {
            continue;
        }

        converted.retain(|c| win::is_window(c.hwnd));
        let tracked_set: HashSet<u32> = tracked.iter().copied().collect();
        let windows = win::preview_windows(&tracked_set);
        let vision_registry = {
            let g = shared.lock().unwrap_or_else(|e| e.into_inner());
            g.vision.clone()
        };
        let mut vision_by_pid: HashMap<u32, (Arc<vision::State>, u64)> = vision_registry
            .snapshots()
            .into_iter()
            .map(|(pid, state, seq)| (pid, (state, seq)))
            .collect();
        let area = win::work_area(app_hwnd);
        let now = Instant::now();
        for (slot, w) in windows.iter().enumerate() {
            // у vision-окна тайл рисуется по состоянию, fullscreen не трогаем
            if w.minimized || vision_by_pid.contains_key(&w.pid) || !win::is_fullscreen(w.hwnd) {
                continue;
            }
            convert(&mut converted, w.hwnd, slot, area, now);
        }

        let mut items = Vec::with_capacity(windows.len() + vision_by_pid.len());
        for w in &windows {
            let state = vision_by_pid.remove(&w.pid);
            let (frame, width, height) = if w.minimized || state.is_some() {
                (None, 0, 0)
            } else {
                match win::capture_rgba(w.hwnd, THUMB_W, THUMB_H) {
                    Some((pixels, tw, th)) => {
                        seq += 1;
                        (Some(Arc::new(pixels)), tw, th)
                    }
                    None => (None, 0, 0),
                }
            };
            let item_seq = match &state {
                Some((_, vision_seq)) => *vision_seq,
                None => seq,
            };
            items.push(PreviewItem {
                key: w.hwnd,
                hwnd: w.hwnd,
                pid: w.pid,
                title: w.title.clone(),
                minimized: w.minimized,
                frame,
                width,
                height,
                seq: item_seq,
                vision: state.map(|(state, _)| state),
            });
        }

        // бот без окна (консольная сборка / свёрнут в трей) всё равно виден
        for (pid, (state, vision_seq)) in vision_by_pid {
            items.push(PreviewItem {
                key: -(pid as isize) - 1,
                hwnd: 0,
                pid,
                title: if state.nick.is_empty() {
                    format!("pid {pid}")
                } else {
                    format!("{} · {}", state.nick, state.server)
                },
                minimized: false,
                frame: None,
                width: 0,
                height: 0,
                seq: vision_seq,
                vision: Some(state),
            });
        }
        items.sort_by_key(|item| (item.pid, item.key));

        let count = items.len();
        let note = if count == 0 {
            "нет окон — запустите приложение через прокси".to_string()
        } else {
            windows_label(count)
        };

        let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
        g.items = items;
        g.note = note;
        active = g.active;

        if !active {
            g.items.clear();
        }
    }
}

fn descendants(roots: &[u32], procs: &[(u32, u32)]) -> Vec<u32> {
    let mut out: Vec<u32> = roots.to_vec();
    loop {
        let mut added = false;
        for (pid, parent) in procs {
            if out.contains(parent) && !out.contains(pid) {
                out.push(*pid);
                added = true;
            }
        }
        if !added {
            return out;
        }
    }
}

fn convert(converted: &mut Vec<Converted>, hwnd: isize, slot: usize, area: RECT, now: Instant) {
    if let Some(c) = converted.iter_mut().find(|c| c.hwnd == hwnd) {
        match c.stage {
            Stage::Placed if now.saturating_duration_since(c.at) >= Duration::from_millis(400) => {
                win::send_alt_enter(hwnd);
                c.stage = Stage::AltSent;
                c.at = now;
            }
            Stage::AltSent if now.saturating_duration_since(c.at) >= Duration::from_millis(1500) => {
                win::apply_grid(hwnd, windowed_target(area, slot));
                c.stage = Stage::Done;
            }
            _ => {}
        }
        return;
    }

    let (style, ex_style) = win::window_styles(hwnd);
    let placement = win::window_placement(hwnd);
    win::apply_grid(hwnd, windowed_target(area, slot));
    converted.push(Converted {
        hwnd,
        style,
        ex_style,
        placement,
        stage: Stage::Placed,
        at: now,
    });
}

fn windowed_target(area: RECT, slot: usize) -> RECT {
    let aw = (area.right - area.left).max(1);
    let ah = (area.bottom - area.top).max(1);
    let w = (aw * 2 / 3).clamp(640, 1600).min(aw);
    let h = (w * 9 / 16).clamp(360, (ah - 40).max(360)).min(ah);
    let offset = (slot % 5) as i32 * 28;
    let x = (area.left + (aw - w) / 2 + offset).clamp(area.left, (area.right - w).max(area.left));
    let y = (area.top + (ah - h) / 2 + offset).clamp(area.top, (area.bottom - h).max(area.top));
    RECT {
        left: x,
        top: y,
        right: x + w,
        bottom: y + h,
    }
}

fn restore_all(converted: &mut Vec<Converted>) {
    for c in converted.drain(..) {
        // если игрок сам вернул fullscreen — не спорим с ним
        if win::is_window(c.hwnd) && !win::is_fullscreen(c.hwnd) {
            win::restore_window(c.hwnd, c.style, c.ex_style, c.placement);
        }
    }
}

/// «1 окно», «2 окна», «5 окон».
pub fn windows_label(n: usize) -> String {
    let word = match n % 100 {
        11..=14 => "окон",
        _ => match n % 10 {
            1 => "окно",
            2..=4 => "окна",
            _ => "окон",
        },
    };
    format!("{n} {word}")
}

/// Колонки, при которых ячейка ближе всего к 16:9. 0 — авто.
pub fn best_cols(n: usize, w: i32, h: i32) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut best = 1;
    let mut best_score = 0.0f32;
    for cols in 1..=n {
        let rows = (n + cols - 1) / cols;
        let cell_w = w as f32 / cols as f32;
        let cell_h = h as f32 / rows as f32;
        let score = (cell_w / 16.0).min(cell_h / 9.0);
        if score > best_score + 0.01 {
            best_score = score;
            best = cols;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_children_and_grandchildren() {
        let procs = vec![(10, 1), (20, 10), (30, 20), (40, 1)];
        let found = descendants(&[10], &procs);
        assert!(found.contains(&10));
        assert!(found.contains(&20));
        assert!(found.contains(&30));
        assert!(!found.contains(&40));
    }

    #[test]
    fn survives_dead_intermediate_launcher() {
        // инжектор (20) умер, игра (30) осталась его потомком по PID
        let procs = vec![(30, 20)];
        let tracked = vec![30u32];
        let found = descendants(&[], &procs);
        assert!(found.is_empty());
        assert!(tracked.contains(&30));
    }

    #[test]
    fn windows_label_plural() {
        assert_eq!(windows_label(1), "1 окно");
        assert_eq!(windows_label(2), "2 окна");
        assert_eq!(windows_label(5), "5 окон");
        assert_eq!(windows_label(11), "11 окон");
        assert_eq!(windows_label(21), "21 окно");
    }

    #[test]
    fn best_cols_prefers_wide_cells() {
        assert_eq!(best_cols(1, 1920, 1040), 1);
        assert_eq!(best_cols(2, 1920, 1040), 2);
        assert_eq!(best_cols(4, 1920, 1040), 2);
        for n in 1..=12 {
            let cols = best_cols(n, 1920, 1040);
            assert!(cols >= 1 && cols <= n);
        }
    }

    #[test]
    fn windowed_target_stays_inside_work_area() {
        let area = RECT {
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1040,
        };
        for slot in 0..10 {
            let r = windowed_target(area, slot);
            assert!(r.left >= area.left && r.top >= area.top);
            assert!(r.right <= area.right && r.bottom <= area.bottom);
            assert!(r.right > r.left && r.bottom > r.top);
        }
    }
}
