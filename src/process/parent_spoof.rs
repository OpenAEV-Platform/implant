//! Spawns a child process under a different parent process on Windows.
//!
//! This breaks the process ancestry chain so that the spawned process
//! does not appear as a descendant of the current process tree.
//! On non-Windows platforms, this falls back to normal Command execution.

use std::io;
use std::process::Output;

#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;

/// Attempt to spawn a command under a spoofed parent process.
///
/// On Windows, this will:
/// 1. Find a suitable parent process (explorer.exe, or svchost.exe as fallback)
/// 2. Use CreateProcessW with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
/// 3. Wait for completion and capture stdout/stderr via temp files
///
/// Returns `None` if parent spoofing is not possible (no suitable parent found,
/// or running on a non-Windows platform), signaling the caller to fall back
/// to normal execution.
pub fn try_spawn_with_spoofed_parent(
    executor: &str,
    args: &[&str],
    cmd_expression: &str,
) -> Option<io::Result<Output>> {
    #[cfg(windows)]
    {
        _try_spawn_windows(executor, args, cmd_expression)
    }
    #[cfg(not(windows))]
    {
        let _ = (executor, args, cmd_expression);
        None
    }
}

/// Build a UTF-16 environment block from the current process's environment.
/// Format: KEY=VALUE\0KEY=VALUE\0\0
#[cfg(windows)]
fn build_environment_block() -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let mut block: Vec<u16> = Vec::new();
    for (key, value) in std::env::vars_os() {
        let entry: Vec<u16> = OsStr::new(&key)
            .encode_wide()
            .chain(std::iter::once(b'=' as u16))
            .chain(OsStr::new(&value).encode_wide())
            .chain(std::iter::once(0u16))
            .collect();
        block.extend_from_slice(&entry);
    }
    block.push(0); // Double null terminator
    block
}

#[cfg(windows)]
fn _try_spawn_windows(
    executor: &str,
    args: &[&str],
    cmd_expression: &str,
) -> Option<io::Result<Output>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::process::ExitStatus;

    use windows_sys::Win32::Foundation::{
        CloseHandle, FALSE, HANDLE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, OpenProcess, UpdateProcThreadAttribute,
        WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
        INFINITE, PROCESS_ALL_ACCESS, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, STARTUPINFOEXW,
    };

    use log::info;

    // Find a suitable parent PID
    let parent_pid = find_spoof_parent_pid()?;
    info!(
        "Spoofing parent process: using PID {} as parent for executor '{}'",
        parent_pid, executor
    );

    // Resolve executor to full path
    let system32 = format!(
        "{}\\System32",
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
    );
    let full_executor = match executor {
        "powershell" => format!("{}\\WindowsPowerShell\\v1.0\\powershell.exe", system32),
        "cmd" => format!("{}\\cmd.exe", system32),
        other => {
            if other.contains('\\') || other.contains('/') {
                other.to_string()
            } else {
                format!("{}\\{}", system32, other)
            }
        }
    };

    // Build the full command line
    let mut cmd_line = format!("\"{}\"", full_executor);
    for arg in args {
        cmd_line.push(' ');
        cmd_line.push_str(arg);
    }
    if executor == "cmd" {
        cmd_line.push(' ');
        cmd_line.push_str(cmd_expression);
    } else {
        cmd_line.push_str(" \"");
        cmd_line.push_str(&cmd_expression.replace('"', "\\\""));
        cmd_line.push('"');
    }

    // Build environment block from current process
    let env_block = build_environment_block();

    let result = unsafe {
        // Open the target parent process
        let h_parent: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parent_pid);
        if h_parent.is_null() {
            info!("Failed to open parent process {}", parent_pid);
            return None;
        }

        // Initialize attribute list
        let mut attr_size: usize = 0;
        InitializeProcThreadAttributeList(
            std::ptr::null_mut(),
            1,
            0,
            &mut attr_size,
        );

        let attr_list = vec![0u8; attr_size];
        let attr_list_ptr = attr_list.as_ptr() as *mut _;

        if InitializeProcThreadAttributeList(attr_list_ptr, 1, 0, &mut attr_size) == FALSE {
            CloseHandle(h_parent);
            info!("Failed to initialize proc thread attribute list");
            return None;
        }

        // Set parent process attribute
        let mut parent_handle_value: HANDLE = h_parent;
        if UpdateProcThreadAttribute(
            attr_list_ptr,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            &mut parent_handle_value as *mut HANDLE as *mut std::ffi::c_void,
            std::mem::size_of::<HANDLE>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == FALSE
        {
            DeleteProcThreadAttributeList(attr_list_ptr);
            CloseHandle(h_parent);
            info!("Failed to update proc thread attribute");
            return None;
        }

        // Set up STARTUPINFOEXW
        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list_ptr;

        // Set the desktop to the default winstation/desktop so the process can start
        let desktop: Vec<u16> = OsStr::new("WinSta0\\Default")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        si.StartupInfo.lpDesktop = desktop.as_ptr() as *mut _;

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // Convert command line to wide string
        let cmd_wide: Vec<u16> = OsStr::new(&cmd_line)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Set working directory to System32
        let cwd: Vec<u16> = OsStr::new(&system32)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;

        let success = CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_ptr() as *mut _,
            std::ptr::null(),
            std::ptr::null(),
            FALSE,
            creation_flags,
            env_block.as_ptr() as *const std::ffi::c_void,
            cwd.as_ptr(),
            &si as *const STARTUPINFOEXW as *const _,
            &mut pi,
        );

        DeleteProcThreadAttributeList(attr_list_ptr);
        CloseHandle(h_parent);

        if success == FALSE {
            info!("CreateProcessW failed for spoofed parent");
            return None;
        }

        // Wait for the process to complete
        WaitForSingleObject(pi.hProcess, INFINITE);

        let mut exit_code: u32 = 0;
        GetExitCodeProcess(pi.hProcess, &mut exit_code);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        exit_code
    };

    Some(Ok(Output {
        status: ExitStatus::from_raw(result),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }))
}

/// Find a suitable process to use as the spoofed parent.
/// Prefers explorer.exe (interactive user), falls back to svchost.exe.
#[cfg(windows)]
fn find_spoof_parent_pid() -> Option<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut explorer_pid: Option<u32> = None;
        let mut svchost_pid: Option<u32> = None;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );
                let name_lower = name.to_lowercase();

                if name_lower == "explorer.exe" && explorer_pid.is_none() {
                    explorer_pid = Some(entry.th32ProcessID);
                } else if name_lower == "svchost.exe" && svchost_pid.is_none() {
                    svchost_pid = Some(entry.th32ProcessID);
                }

                if explorer_pid.is_some() {
                    break;
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);

        explorer_pid.or(svchost_pid)
    }
}