use std::io::ErrorKind;
use std::process::{Command, ExitStatus, Output, Stdio};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

use crate::common::error_model::Error;
use crate::handle::handle_command::compute_command;
use crate::process::exec_utils::is_executor_present;

#[cfg(windows)]
use log::{error, info, warn};

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::os::windows::process::{CommandExt, ExitStatusExt};
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::ReadFile;
#[cfg(windows)]
use windows::Win32::System::Pipes::PeekNamedPipe;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

#[derive(Debug, Deserialize)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub status: String,
    pub exit_code: i32,
}

pub fn invoke_command(
    executor: &str,
    cmd_expression: &str,
    args: &[&str],
) -> std::io::Result<Output> {
    let mut command = Command::new(executor);

    let result = match executor {
        // For CMD we use "raw_args" to fix issue #3161;
        #[cfg(windows)]
        "cmd" => command.args(args).raw_arg(cmd_expression),
        // for other executors, we still use "args" as they are working properly.
        _ => command.args(args).arg(cmd_expression),
    }
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output();

    match result {
        Ok(output) => Ok(output),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            #[cfg(unix)]
            let exit_status = ExitStatus::from_raw(256);

            #[cfg(windows)]
            let exit_status = ExitStatus::from_raw(1);

            Ok(Output {
                status: exit_status,
                stdout: Vec::new(),
                stderr: format!("{e}").into_bytes(),
            })
        }
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
pub fn invoke_command_nonblocking(cmd_expression: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut child = Command::new("powershell")
        .args(args)
        .arg(cmd_expression)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id();
    info!("Spawned PID: {}", pid);

    // Get the handles
    let stdout_handle = HANDLE(child.stdout.as_ref().unwrap().as_raw_handle() as _);
    let stderr_handle = HANDLE(child.stderr.as_ref().unwrap().as_raw_handle() as _);

    let mut stdout_data = Vec::new();
    let mut stderr_data = Vec::new();

    let start = Instant::now();
    let max_total_time = Duration::from_secs(300); // Timeout total for the command
    let inactivity_timeout = Duration::from_secs(120); // Timeout if nothing is pushed onto the stdout or stderr anymore
    let mut last_data_time = Instant::now();

    info!("Entering read loop");

    loop {
        let mut got_data = false;

        // Read stdout without blocking it
        let stdout_bytes = read_pipe_nonblocking(stdout_handle);
        if !stdout_bytes.is_empty() {
            info!("Got {} bytes from stdout", stdout_bytes.len());
            stdout_data.extend(stdout_bytes);
            last_data_time = Instant::now();
            got_data = true;
        }

        // Read stderr without blocking it
        let stderr_bytes = read_pipe_nonblocking(stderr_handle);
        if !stderr_bytes.is_empty() {
            info!("Got {} bytes from stderr", stderr_bytes.len());
            stderr_data.extend(stderr_bytes);
            last_data_time = Instant::now();
            got_data = true;
        }

        // Check if the process ended
        match child.try_wait() {
            Ok(Some(status)) => {
                info!("Process exited with exit code: {:?}", status.code());

                // Read one last time
                std::thread::sleep(Duration::from_millis(100));
                stdout_data.extend(read_pipe_nonblocking(stdout_handle));
                stderr_data.extend(read_pipe_nonblocking(stderr_handle));

                // Send back the results
                return Ok(Output {
                    status,
                    stdout: stdout_data,
                    stderr: stderr_data,
                });
            }
            Ok(None) => {
                // Process still ongoing
            }
            Err(e) => {
                error!("try_wait error: {}", e);
                break;
            }
        }

        // Timeout total
        if start.elapsed() > max_total_time {
            warn!("Total timeout reached, killing process");
            let _ = child.kill();
            break;
        }

        // Timeout without any data in the handles
        if last_data_time.elapsed() > inactivity_timeout {
            warn!(
                "Inactivity timeout ({:?}), killing process",
                inactivity_timeout
            );
            let _ = child.kill();
            break;
        }

        // We wait a bit before retrying
        if !got_data {
            std::thread::sleep(Duration::from_millis(1000));
        }
    }

    info!(
        "Loop ended, stdout={} bytes, stderr={} bytes",
        stdout_data.len(),
        stderr_data.len()
    );

    // Wait for the end of the process
    let status = child.wait().unwrap_or_else(|_| ExitStatus::from_raw(1));

    Ok(Output {
        status,
        stdout: stdout_data,
        stderr: stderr_data,
    })
}

#[cfg(windows)]
fn read_pipe_nonblocking(handle: windows::Win32::Foundation::HANDLE) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        let mut available: u32 = 0;

        // Check how many bytes are available
        let peek_result = unsafe {
            PeekNamedPipe(
                handle,
                None,
                0,
                None,
                Some(&mut available as *mut u32),
                None,
            )
        };

        if peek_result.is_err() || available == 0 {
            break;
        }

        // Read what's available
        let to_read = (available as usize).min(chunk.len()) as u32;
        let mut bytes_read: u32 = 0;

        let read_result = unsafe {
            ReadFile(
                handle,
                Some(&mut chunk[..to_read as usize]),
                Some(&mut bytes_read),
                None,
            )
        };

        if read_result.is_err() || bytes_read == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[..bytes_read as usize]);

        // If we read everything, we stop
        if bytes_read < to_read {
            break;
        }
    }

    buffer
}

pub fn decode_command(encoded_command: &str) -> String {
    let decoded_bytes = STANDARD
        .decode(encoded_command)
        .expect("Failed to decode Base64 command");
    let decoded = String::from_utf8(decoded_bytes).expect("Decoded command is not valid UTF-8");
    compute_command(&decoded)
}

pub fn format_powershell_command(command: String) -> String {
    format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;$ErrorActionPreference = 'Stop'; {command} ; exit $LASTEXITCODE"
    )
}

pub fn format_windows_command(command: String) -> String {
    format!("setlocal & {command} & exit /b errorlevel")
}

pub fn manage_result(invoke_output: Output, pre_check: bool) -> Result<ExecutionResult, Error> {
    let invoke_result = invoke_output.clone();
    let exit_code = invoke_result.status.code().unwrap_or(-99);

    let stdout = decode_output(&invoke_result.stdout);
    let stderr = decode_output(&invoke_result.stderr);

    let exit_status = match exit_code {
        0 if stderr.is_empty() => "SUCCESS",
        0 if !stderr.is_empty() => "WARNING",
        1 if pre_check => "SUCCESS",
        -99 => "ERROR",
        127 => "COMMAND_NOT_FOUND",
        126 => "COMMAND_CANNOT_BE_EXECUTED",
        _ => "MAYBE_PREVENTED",
    };

    Ok(ExecutionResult {
        stdout,
        stderr,
        exit_code,
        status: String::from(exit_status),
    })
}

pub fn decode_output(raw_bytes: &[u8]) -> String {
    // Try decoding as UTF-8
    if let Ok(decoded) = String::from_utf8(raw_bytes.to_vec()) {
        return decoded; // Return if successful
    }
    // Fallback to UTF-8 lossy decoding
    String::from_utf8_lossy(raw_bytes).to_string()
}

#[cfg(target_os = "windows")]
pub fn get_executor(executor: &str) -> &str {
    match executor {
        "cmd" | "bash" | "sh" => executor,
        _ => "powershell",
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_executor(executor: &str) -> &str {
    match executor {
        "bash" => executor,
        "psh" => "powershell",
        _ => "sh",
    }
}

#[cfg(target_os = "windows")]
pub fn get_psh_arg() -> Vec<&'static str> {
    Vec::from([
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-NonInteractive",
        "-NoProfile",
        "-Command",
    ])
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_psh_arg() -> Vec<&'static str> {
    Vec::from([
        "-ExecutionPolicy",
        "Bypass",
        "-NonInteractive",
        "-NoProfile",
        "-Command",
    ])
}

pub fn command_execution(
    command: &str,
    executor: &str,
    pre_check: bool,
) -> Result<ExecutionResult, Error> {
    let final_executor = get_executor(executor);
    let mut formatted_cmd = decode_command(command);
    let mut args: Vec<&str> = vec!["-c"];

    if !is_executor_present(final_executor) {
        return Err(Error::Internal(format!(
            "Executor {final_executor} is not available."
        )));
    }

    let invoke_output = if final_executor == "powershell" {
        formatted_cmd = format_powershell_command(formatted_cmd);

        #[cfg(windows)]
        {
            args = get_psh_arg();
            info!(">>> Using direct spawn with args: {:?}", args);
            invoke_command_nonblocking(&formatted_cmd, &args)
        }
        #[cfg(not(windows))]
        {
            args = get_psh_arg();
            invoke_command(final_executor, &formatted_cmd, &args)
        }
    } else if final_executor == "cmd" {
        args = vec!["/V", "/C"];
        let formatted = format_windows_command(formatted_cmd);
        invoke_command(final_executor, &formatted, &args)
    } else {
        invoke_command(final_executor, &formatted_cmd, &args)
    };
    manage_result(invoke_output?, pre_check)
}
