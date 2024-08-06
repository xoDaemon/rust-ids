use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{BOOL, HANDLE, HWND},
        UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE},
    },
};

#[no_mangle]
extern "C" fn windows_alert(ip: &str) {
    unsafe {
        MessageBoxA(
            HWND(0),
            PCSTR(format!("Found traffic from {}\x00", ip).as_ptr()),
            PCSTR("Network Monitoring Alert\x00".as_ptr()),
            MESSAGEBOX_STYLE(0),
        );
    }
}

#[no_mangle]
#[allow(unused_variables)]
#[allow(non_snake_case)]
extern "system" fn WindowsAlertSystem(
    dll_module: HANDLE,
    call_reason: u32,
    lpv_reserved: &u32,
) -> BOOL {
    match call_reason {
        _ => {
            return BOOL(1);
        }
    }
}