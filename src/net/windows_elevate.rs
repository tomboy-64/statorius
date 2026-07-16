//! Windows-only: trigger a UAC elevation prompt for a copy of ourselves via
//! `ShellExecuteW`'s "runas" verb - the same mechanism behind any "Run as
//! administrator" action in Explorer.

#![cfg(target_os = "windows")]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Launch `exe args` elevated. Returns as soon as the OS accepts the
/// request - it does NOT wait for the launched process to do anything, and
/// deliberately gives back no process handle (`ShellExecuteW` doesn't
/// provide one). Liveness of the resulting process is tracked entirely over
/// the IPC connection afterward, not here.
pub fn shell_execute_runas(exe: &Path, args: &str) -> Result<(), String> {
    let operation = to_wide("runas");
    let file = to_wide(&exe.display().to_string());
    let params = to_wide(args);

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };

    // Per the Win32 docs: success is any value > 32; values <= 32 are error
    // codes (with the same meanings as `FindExecutable`'s).
    let code = result as isize;
    if code > 32 {
        Ok(())
    } else if code == 1223 {
        // ERROR_CANCELLED
        Err("Elevation was declined (the UAC prompt was cancelled).".to_owned())
    } else {
        Err(format!("ShellExecuteW failed (code {code})."))
    }
}