use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWINDOWATTRIBUTE, DWMWA_USE_IMMERSIVE_DARK_MODE,
};

/// Dark system title bar so it does not clash with the app canvas.
pub fn apply_dark_titlebar(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    unsafe {
        let hwnd = HWND(hwnd as *mut core::ffi::c_void);
        let on: i32 = 1;
        let ptr = &on as *const i32 as *const core::ffi::c_void;
        let size = std::mem::size_of::<i32>() as u32;
        let _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ptr, size);
        // Windows 10 1809-1909 knows the attribute under number 19
        let _ = DwmSetWindowAttribute(hwnd, DWMWINDOWATTRIBUTE(19), ptr, size);
    }
}
