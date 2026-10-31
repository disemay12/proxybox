use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, ERROR_ALREADY_EXISTS, FALSE, HANDLE, HWND, LPARAM, RECT, TRUE,
    WPARAM,
};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, GetMonitorInfoW,
    MonitorFromWindow, ReleaseDC, SelectObject, SetStretchBltMode, StretchBlt, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HALFTONE, HBITMAP, HDC, HGDIOBJ, MONITORINFO,
    MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTOPRIMARY, SRCCOPY,
};
use windows::Win32::Storage::Xps::{PrintWindow, PRINT_WINDOW_FLAGS};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    CreateMutexW, OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    RegisterHotKey, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_KEYUP, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, VIRTUAL_KEY, VK_MENU, VK_RETURN,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, FindWindowW, GetForegroundWindow, GetMessageW, GetSystemMetrics, GetWindow,
    GetWindowLongPtrW, GetWindowPlacement, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, IsZoomed, PostMessageW,
    PW_RENDERFULLCONTENT, SetForegroundWindow, SetWindowLongPtrW, SetWindowPlacement, SetWindowPos,
    ShowWindow, GWL_EXSTYLE, GWL_STYLE, GW_OWNER, HWND_TOP, MSG, SM_CXSCREEN, SM_CYSCREEN,
    SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW,
    SW_RESTORE, SW_SHOWNORMAL, WM_CLOSE, WM_HOTKEY, WM_SYSKEYDOWN, WM_SYSKEYUP,
    WINDOWPLACEMENT, WS_CAPTION, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_EX_APPWINDOW,
    WS_EX_TOOLWINDOW, WS_MAXIMIZEBOX, WS_MINIMIZEBOX, WS_POPUP, WS_SYSMENU, WS_THICKFRAME,
    WS_VISIBLE,
};

const HOTKEY_ID: i32 = 0xB10C;

fn as_hwnd(h: isize) -> HWND {
    HWND(h as *mut core::ffi::c_void)
}

#[derive(Clone, Debug)]
pub struct RunningApp {
    pub name: String,
    pub path: String,
    pub title: String,
}

#[derive(Clone, Debug)]
pub struct PreviewWindow {
    pub hwnd: isize,
    pub pid: u32,
    pub title: String,
    pub minimized: bool,
}

struct Collect {
    items: Vec<RunningApp>,
    own_pid: u32,
}

struct CollectPreview<'a> {
    pids: &'a HashSet<u32>,
    own_pid: u32,
    items: Vec<PreviewWindow>,
}

fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        if ok.is_err() || len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let data = &mut *(lparam.0 as *mut Collect);

    if !IsWindowVisible(hwnd).as_bool() {
        return TRUE;
    }
    if let Ok(owner) = GetWindow(hwnd, GW_OWNER) {
        if !owner.is_invalid() {
            return TRUE;
        }
    }
    if GetWindowTextLengthW(hwnd) <= 0 {
        return TRUE;
    }

    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 || pid == data.own_pid {
        return TRUE;
    }

    let Some(exe) = process_path(pid) else {
        return TRUE;
    };
    if data.items.iter().any(|a| a.path.eq_ignore_ascii_case(&exe)) {
        return TRUE;
    }
    let lower = exe.to_lowercase();
    if lower.contains("\\windows\\system32\\textinputhost.exe")
        || lower.contains("\\windows\\system32\\applicationframehost.exe")
    {
        return TRUE;
    }

    let mut title_buf = [0u16; 512];
    let title_len = GetWindowTextW(hwnd, &mut title_buf);
    let title = String::from_utf16_lossy(&title_buf[..title_len.max(0) as usize]);

    let name = std::path::Path::new(&exe)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| exe.clone());

    data.items.push(RunningApp {
        name,
        path: exe,
        title,
    });
    TRUE
}

/// Служебные процессы proxybox: их консольные окна в превью не нужны.
fn is_tool_process(pid: u32) -> bool {
    let Some(exe) = process_path(pid) else {
        return true;
    };
    let name = std::path::Path::new(&exe)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(name.as_str(), "pbinject.exe" | "pbinject32.exe" | "conhost.exe")
}

unsafe extern "system" fn enum_preview(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let data = &mut *(lparam.0 as *mut CollectPreview);

    // свёрнутое окно остаётся visible, но на всякий случай берём и iconic
    let minimized = IsIconic(hwnd).as_bool();
    if !IsWindowVisible(hwnd).as_bool() && !minimized {
        return TRUE;
    }
    if let Ok(owner) = GetWindow(hwnd, GW_OWNER) {
        if !owner.is_invalid() {
            return TRUE;
        }
    }
    if GetWindowTextLengthW(hwnd) <= 0 {
        return TRUE;
    }

    let ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32;
    if ex_style & WS_EX_TOOLWINDOW.0 != 0 {
        return TRUE;
    }

    let mut cloaked = 0u32;
    let _ = DwmGetWindowAttribute(
        hwnd,
        DWMWA_CLOAKED,
        &mut cloaked as *mut u32 as *mut core::ffi::c_void,
        std::mem::size_of::<u32>() as u32,
    );
    if cloaked != 0 {
        return TRUE;
    }

    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 || pid == data.own_pid || !data.pids.contains(&pid) {
        return TRUE;
    }
    if is_tool_process(pid) {
        return TRUE;
    }

    let mut title_buf = [0u16; 512];
    let title_len = GetWindowTextW(hwnd, &mut title_buf);
    let title = String::from_utf16_lossy(&title_buf[..title_len.max(0) as usize]);

    data.items.push(PreviewWindow {
        hwnd: hwnd.0 as isize,
        pid,
        title,
        minimized,
    });
    TRUE
}

unsafe extern "system" fn find_main_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let out = &mut *(lparam.0 as *mut isize);
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == std::process::id() && IsWindowVisible(hwnd).as_bool() && GetWindowTextLengthW(hwnd) > 0 {
        *out = hwnd.0 as isize;
        return FALSE;
    }
    TRUE
}

/// HWND главного окна этого процесса (для тёмного заголовка и фокуса).
pub fn main_window() -> isize {
    let mut found: isize = 0;
    unsafe {
        let _ = EnumWindows(Some(find_main_window), LPARAM(&mut found as *mut isize as isize));
    }
    found
}

/// Становится единственным экземпляром. Если proxybox уже запущен — поднимает
/// его окно и возвращает false: второе окно затирало бы профили и конфиг.
pub fn claim_single_instance(title: &str) -> bool {
    let name: Vec<u16> = "Local\\proxybox-single\u{0}".encode_utf16().collect();
    let mutex = unsafe { CreateMutexW(None, FALSE, PCWSTR(name.as_ptr())) };
    // GetLastError читаем сразу: CreateMutexW не сбрасывает его при успехе
    let err = unsafe { GetLastError() };
    let already = err.0 == ERROR_ALREADY_EXISTS.0;
    if already {
        drop(mutex);
        focus_window_by_title(title);
        return false;
    }
    // HANDLE в windows-rs не закрывается сам по себе, но держим значение
    // явно до конца процесса: мьютекс должен переживать первый экземпляр.
    if let Ok(handle) = mutex {
        std::mem::forget(Box::new(handle));
    }
    true
}

fn focus_window_by_title(title: &str) {
    let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(wide.as_ptr())) else {
            return;
        };
        if IsIconic(hwnd).as_bool() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        }
        let _ = SetForegroundWindow(hwnd);
    }
}

pub fn running_apps() -> Vec<RunningApp> {
    let mut data = Collect {
        items: Vec::new(),
        own_pid: std::process::id(),
    };
    unsafe {
        let _ = EnumWindows(Some(enum_proc), LPARAM(&mut data as *mut Collect as isize));
    }
    data.items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    data.items
}

/// Все top-level окна процессов из `pids`.
pub fn preview_windows(pids: &HashSet<u32>) -> Vec<PreviewWindow> {
    let mut data = CollectPreview {
        pids,
        own_pid: std::process::id(),
        items: Vec::new(),
    };
    unsafe {
        let _ = EnumWindows(
            Some(enum_preview),
            LPARAM(&mut data as *mut CollectPreview as isize),
        );
    }
    data.items.sort_by_key(|w| (w.pid, w.hwnd));
    data.items
}

/// Снимок дерева процессов: (pid, parent pid).
pub fn process_tree() -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                out.push((entry.th32ProcessID, entry.th32ParentProcessID));
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// Жив ли процесс. Свой pid всегда «не живой»: приложение не должно
/// показывать кнопку остановки для самого proxybox.
pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 || pid == std::process::id() {
        return false;
    }
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => false,
        }
    }
}

/// Порядок завершения дерева: сам корень и все потомки, сначала листья.
/// `own` исключается, чтобы не убить proxybox; кривые циклы в снимке
/// процессов не зацикливают обход.
fn kill_order(root: u32, procs: &[(u32, u32)], own: u32) -> Vec<u32> {
    if root == 0 || root == own {
        return Vec::new();
    }
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, parent) in procs {
        if *pid != 0 && *pid != own {
            children.entry(*parent).or_default().push(*pid);
        }
    }

    let mut seen = HashSet::new();
    seen.insert(root);
    let mut queue = VecDeque::from([(root, 0usize)]);
    let mut order: Vec<(u32, usize)> = Vec::new();
    while let Some((pid, depth)) = queue.pop_front() {
        order.push((pid, depth));
        if let Some(kids) = children.get(&pid) {
            for &kid in kids {
                if seen.insert(kid) {
                    queue.push_back((kid, depth + 1));
                }
            }
        }
    }

    order.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    order.into_iter().map(|(pid, _)| pid).collect()
}

fn terminate(pid: u32) -> bool {
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) else {
            return false;
        };
        let ok = TerminateProcess(handle, 1).is_ok();
        let _ = CloseHandle(handle);
        ok
    }
}

/// Завершает процесс и всех его потомков, начиная с листьев.
/// Возвращает число реально завершённых процессов; proxybox не трогает.
pub fn kill_tree(pid: u32) -> usize {
    let own = std::process::id();
    let order = kill_order(pid, &process_tree(), own);
    let mut killed = 0;
    for target in order {
        if terminate(target) {
            killed += 1;
        }
    }
    killed
}

/// Сколько процессов из деревьев `roots` (корни + потомки) ещё живо.
/// Нужен для честного результата: защищённый процесс не считается убитым.
pub fn trees_alive(roots: &[u32]) -> usize {
    let own = std::process::id();
    let procs = process_tree();
    let alive: HashSet<u32> = procs.iter().map(|(pid, _)| *pid).collect();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, parent) in &procs {
        children.entry(*parent).or_default().push(*pid);
    }
    let mut seen = HashSet::new();
    let mut stack: Vec<u32> = roots
        .iter()
        .copied()
        .filter(|pid| *pid != 0 && *pid != own)
        .collect();
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        if let Some(kids) = children.get(&pid) {
            stack.extend(kids.iter().copied().filter(|kid| *kid != own));
        }
    }
    seen.iter().filter(|pid| alive.contains(pid)).count()
}

pub fn is_window(hwnd: isize) -> bool {
    hwnd != 0 && unsafe { IsWindow(as_hwnd(hwnd)).as_bool() }
}

pub fn window_rect(hwnd: isize) -> Option<RECT> {
    let mut rect = RECT::default();
    unsafe { GetWindowRect(as_hwnd(hwnd), &mut rect).ok().map(|_| rect) }
}

pub fn window_styles(hwnd: isize) -> (u32, u32) {
    unsafe {
        (
            GetWindowLongPtrW(as_hwnd(hwnd), GWL_STYLE) as u32,
            GetWindowLongPtrW(as_hwnd(hwnd), GWL_EXSTYLE) as u32,
        )
    }
}

/// Полное размещение окна: обычный прямоугольник + состояние
/// (normal/minimized/maximized). Этого достаточно, чтобы вернуть окно
/// ровно туда, где оно было до перевода в оконный режим.
pub fn window_placement(hwnd: isize) -> WINDOWPLACEMENT {
    let mut wp = WINDOWPLACEMENT {
        length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
        ..Default::default()
    };
    unsafe {
        if GetWindowPlacement(as_hwnd(hwnd), &mut wp).is_err() {
            wp.rcNormalPosition = window_rect(hwnd).unwrap_or_default();
            wp.showCmd = SW_SHOWNORMAL.0 as u32;
        }
    }
    wp
}

fn monitor_rect(hwnd: isize) -> Option<RECT> {
    unsafe {
        let mon = MonitorFromWindow(as_hwnd(hwnd), MONITOR_DEFAULTTONEAREST);
        if mon.0.is_null() {
            return None;
        }
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if !GetMonitorInfoW(mon, &mut info).as_bool() {
            return None;
        }
        Some(info.rcMonitor)
    }
}

/// Окно занимает весь монитор — значит игра (или другое приложение) ушла в fullscreen.
pub fn is_fullscreen(hwnd: isize) -> bool {
    // развёрнутое в рабочую область окно — это не fullscreen, его не трогаем
    if unsafe { IsZoomed(as_hwnd(hwnd)).as_bool() } {
        return false;
    }
    let Some(rect) = window_rect(hwnd) else {
        return false;
    };
    let Some(mon) = monitor_rect(hwnd) else {
        return false;
    };
    let tol = 2;
    rect.left <= mon.left + tol
        && rect.top <= mon.top + tol
        && rect.right >= mon.right - tol
        && rect.bottom >= mon.bottom - tol
}

/// Рабочая область монитора, на котором находится proxybox.
pub fn work_area(app_hwnd: isize) -> RECT {
    unsafe {
        let target = if app_hwnd != 0 {
            as_hwnd(app_hwnd)
        } else {
            as_hwnd(0)
        };
        let mon = MonitorFromWindow(target, MONITOR_DEFAULTTOPRIMARY);
        if !mon.0.is_null() {
            let mut info = MONITORINFO {
                cbSize: std::mem::size_of::<MONITORINFO>() as u32,
                ..Default::default()
            };
            if GetMonitorInfoW(mon, &mut info).as_bool() {
                return info.rcWork;
            }
        }
        RECT {
            left: 0,
            top: 0,
            right: GetSystemMetrics(SM_CXSCREEN),
            bottom: GetSystemMetrics(SM_CYSCREEN),
        }
    }
}

/// Снимает рамку/заголовок и ставит окно точно в ячейку сетки.
pub fn apply_grid(hwnd: isize, target: RECT) -> bool {
    let h = as_hwnd(hwnd);
    unsafe {
        if IsIconic(h).as_bool() || IsZoomed(h).as_bool() {
            let _ = ShowWindow(h, SW_RESTORE);
        }

        let style = GetWindowLongPtrW(h, GWL_STYLE) as u32;
        let strip = WS_CAPTION.0
            | WS_THICKFRAME.0
            | WS_MINIMIZEBOX.0
            | WS_MAXIMIZEBOX.0
            | WS_SYSMENU.0;
        let mut flags = SWP_NOACTIVATE | SWP_SHOWWINDOW;

        if style & (WS_CAPTION.0 | WS_THICKFRAME.0) != 0 || style & WS_POPUP.0 == 0 {
            let new_style = (style & !strip)
                | WS_POPUP.0
                | WS_VISIBLE.0
                | WS_CLIPCHILDREN.0
                | WS_CLIPSIBLINGS.0;
            let _ = SetWindowLongPtrW(h, GWL_STYLE, new_style as isize);
            let ex_style = GetWindowLongPtrW(h, GWL_EXSTYLE) as u32;
            let _ = SetWindowLongPtrW(h, GWL_EXSTYLE, (ex_style | WS_EX_APPWINDOW.0) as isize);
            flags |= SWP_FRAMECHANGED;
        }

        SetWindowPos(
            h,
            HWND_TOP,
            target.left,
            target.top,
            (target.right - target.left).max(1),
            (target.bottom - target.top).max(1),
            flags,
        )
        .is_ok()
    }
}

pub fn restore_window(hwnd: isize, style: u32, ex_style: u32, placement: WINDOWPLACEMENT) {
    let h = as_hwnd(hwnd);
    unsafe {
        let _ = SetWindowLongPtrW(h, GWL_STYLE, style as isize);
        let _ = SetWindowLongPtrW(h, GWL_EXSTYLE, ex_style as isize);
        // SetWindowPlacement возвращает и нормальный прямоугольник, и состояние:
        // свёрнутое окно снова свернётся, но откроется там, где было
        let mut wp = placement;
        wp.length = std::mem::size_of::<WINDOWPLACEMENT>() as u32;
        let _ = SetWindowPlacement(h, &wp);
        let _ = SetWindowPos(
            h,
            HWND_TOP,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
        );
    }
}

pub fn restore_and_focus(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    unsafe {
        let h = as_hwnd(hwnd);
        let _ = ShowWindow(h, SW_RESTORE);
        let _ = SetForegroundWindow(h);
    }
}

fn key(vk: VIRTUAL_KEY, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0,
                dwFlags: if up {
                    KEYEVENTF_KEYUP
                } else {
                    KEYBD_EVENT_FLAGS(0)
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Alt+Enter — единственный способ вытащить игру из эксклюзивного fullscreen.
pub fn send_alt_enter(hwnd: isize) {
    let h = as_hwnd(hwnd);
    unsafe {
        let _ = SetForegroundWindow(h);
        // SendInput бьёт по активному окну: если фокус не забрали, шлём
        // сообщение точечно, иначе Alt+Enter уйдёт в чужое приложение
        if GetForegroundWindow() == h {
            let inputs = [
                key(VK_MENU, false),
                key(VK_RETURN, false),
                key(VK_RETURN, true),
                key(VK_MENU, true),
            ];
            if SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) > 0 {
                return;
            }
        }
        let down = LPARAM(0x201C0001);
        let up = LPARAM(0xE01C0001u32 as i32 as isize);
        let _ = PostMessageW(
            h,
            WM_SYSKEYDOWN,
            windows::Win32::Foundation::WPARAM(VK_RETURN.0 as usize),
            down,
        );
        let _ = PostMessageW(
            h,
            WM_SYSKEYUP,
            windows::Win32::Foundation::WPARAM(VK_RETURN.0 as usize),
            up,
        );
    }
}

/// Глобальный Ctrl+Alt+G: переключает превью, даже когда proxybox свёрнут.
pub fn spawn_hotkey(flag: Arc<AtomicBool>, ok: Arc<AtomicBool>) {
    std::thread::spawn(move || unsafe {
        let hwnd = as_hwnd(0);
        if RegisterHotKey(
            hwnd,
            HOTKEY_ID,
            MOD_CONTROL | MOD_ALT | MOD_NOREPEAT,
            0x47, // G
        )
        .is_ok()
        {
            ok.store(true, Ordering::Relaxed);
            let mut msg = MSG::default();
            loop {
                let r = GetMessageW(&mut msg, hwnd, 0, 0);
                if r.0 == 0 || r.0 == -1 {
                    break;
                }
                if msg.message == WM_HOTKEY && msg.wParam.0 == HOTKEY_ID as usize {
                    flag.store(true, Ordering::Relaxed);
                }
            }
        }
    });
}

pub fn exe_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Поднимает окно на передний план, свёрнутое — разворачивает.
pub fn focus_window(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    unsafe {
        let h = as_hwnd(hwnd);
        if IsIconic(h).as_bool() {
            let _ = ShowWindow(h, SW_RESTORE);
        }
        let _ = SetForegroundWindow(h);
    }
}

pub fn close_window(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    unsafe {
        let _ = PostMessageW(as_hwnd(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
    }
}

struct Dib {
    dc: HDC,
    bmp: HBITMAP,
    old: HGDIOBJ,
    bits: *mut u8,
    w: u32,
    h: u32,
}

impl Dib {
    fn new(screen: HDC, w: u32, h: u32) -> Option<Self> {
        unsafe {
            let dc = CreateCompatibleDC(screen);
            if dc.0.is_null() {
                return None;
            }
            let bmi = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: w as i32,
                    // отрицательная высота = top-down, иначе кадр перевёрнут
                    biHeight: -(h as i32),
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
            let Ok(bmp) =
                CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &mut bits, HANDLE(std::ptr::null_mut()), 0)
            else {
                let _ = DeleteDC(dc);
                return None;
            };
            let old = SelectObject(dc, bmp);
            Some(Self {
                dc,
                bmp,
                old,
                bits: bits as *mut u8,
                w,
                h,
            })
        }
    }

    fn pixels(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.bits, (self.w * self.h * 4) as usize) }
    }
}

impl Drop for Dib {
    fn drop(&mut self) {
        unsafe {
            let _ = SelectObject(self.dc, self.old);
            let _ = DeleteObject(self.bmp);
            let _ = DeleteDC(self.dc);
        }
    }
}

/// Кадр окна в RGBA, уменьшенный до max_w×max_h. PrintWindow с
/// PW_RENDERFULLCONTENT забирает и содержимое DWM-композиции (D3D в окне).
pub fn capture_rgba(hwnd: isize, max_w: u32, max_h: u32) -> Option<(Vec<u8>, usize, usize)> {
    if hwnd == 0 {
        return None;
    }
    let rect = window_rect(hwnd)?;
    let w = (rect.right - rect.left).max(1) as u32;
    let h = (rect.bottom - rect.top).max(1) as u32;
    if w > 8192 || h > 8192 {
        return None;
    }
    let scale = (max_w as f32 / w as f32)
        .min(max_h as f32 / h as f32)
        .min(1.0);
    let tw = ((w as f32 * scale) as u32).max(1);
    let th = ((h as f32 * scale) as u32).max(1);

    unsafe {
        let screen = GetDC(as_hwnd(0));
        if screen.0.is_null() {
            return None;
        }
        let result = (|| {
            let src = Dib::new(screen, w, h)?;
            let dst = Dib::new(screen, tw, th)?;
            if !PrintWindow(
                as_hwnd(hwnd),
                src.dc,
                PRINT_WINDOW_FLAGS(PW_RENDERFULLCONTENT),
            )
            .as_bool()
            {
                return None;
            }
            let _ = SetStretchBltMode(dst.dc, HALFTONE);
            if !StretchBlt(
                dst.dc,
                0,
                0,
                tw as i32,
                th as i32,
                src.dc,
                0,
                0,
                w as i32,
                h as i32,
                SRCCOPY,
            )
            .as_bool()
            {
                return None;
            }
            let mut rgba = Vec::with_capacity((tw * th * 4) as usize);
            for px in dst.pixels().chunks_exact(4) {
                rgba.extend_from_slice(&[px[2], px[1], px[0], 255]);
            }
            Some((rgba, tw as usize, th as usize))
        })();
        let _ = ReleaseDC(as_hwnd(0), screen);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{kill_order, kill_tree, process_path, process_tree, trees_alive};
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Без консоли и без скрытого conhost.exe (CREATE_NO_WINDOW его создаёт).
    /// Не комбинировать с CREATE_NEW_CONSOLE.
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    struct TreeKillGuard {
        root: u32,
        bat: PathBuf,
    }

    impl Drop for TreeKillGuard {
        fn drop(&mut self) {
            kill_tree(self.root);
            let _ = std::fs::remove_file(&self.bat);
        }
    }

    #[test]
    fn kill_tree_terminates_live_process_tree() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let bat = std::env::temp_dir().join(format!(
            "proxybox-kill-tree-{}-{stamp}.bat",
            std::process::id()
        ));
        // root ждёт 30 секунд, параллельно оставляя живого ребёнка
        let script = "@echo off\r\n\
                      start \"\" /b cmd.exe /c \"ping -n 30 127.0.0.1 >nul\"\r\n\
                      ping -n 30 127.0.0.1 >nul\r\n";
        std::fs::write(&bat, script).expect("write kill-tree fixture");
        let mut guard = TreeKillGuard {
            root: 0,
            bat: bat.clone(),
        };

        let child = std::process::Command::new("cmd.exe")
            .arg("/c")
            .arg(&bat)
            .creation_flags(DETACHED_PROCESS)
            .spawn()
            .expect("spawn kill-tree root");
        let root = child.id();
        guard.root = root;

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut has_descendant = false;
        while Instant::now() < deadline {
            has_descendant = process_tree().iter().any(|&(pid, parent)| {
                parent == root
                    && pid != root
                    && process_path(pid)
                        .map(|path| path.to_ascii_lowercase().ends_with("\\cmd.exe"))
                        .unwrap_or(false)
            });
            if has_descendant {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !has_descendant {
            // машина не успела поднять ребёнка — не считаем это провалом
            return;
        }

        kill_tree(root);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut survivors = trees_alive(&[root]);
        while survivors > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            survivors = trees_alive(&[root]);
        }
        assert_eq!(
            survivors, 0,
            "kill_tree оставил живыми {survivors} процесс(ов) тестового дерева"
        );
    }

    #[test]
    fn kill_order_is_leaf_first() {
        let procs = vec![(10, 1), (20, 10), (30, 20), (40, 1)];
        assert_eq!(kill_order(10, &procs, 999), vec![30, 20, 10]);
    }

    #[test]
    fn kill_order_leaves_unrelated_processes_alone() {
        let procs = vec![(10, 1), (20, 10), (40, 1), (50, 40)];
        let order = kill_order(10, &procs, 999);
        assert_eq!(order, vec![20, 10]);
        assert!(!order.contains(&40) && !order.contains(&50));
    }

    #[test]
    fn kill_order_skips_self_and_invalid_roots() {
        let procs = vec![(10, 1), (20, 10)];
        assert!(kill_order(20, &procs, 20).is_empty());
        assert!(kill_order(0, &procs, 999).is_empty());
    }

    #[test]
    fn kill_order_survives_cycles() {
        let procs = vec![(10, 20), (20, 10), (30, 10)];
        let order = kill_order(10, &procs, 999);
        assert_eq!(order.len(), 3);
        assert_eq!(order.last(), Some(&10));
    }
}
