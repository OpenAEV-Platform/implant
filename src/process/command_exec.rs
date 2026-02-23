use std::io::ErrorKind;
use std::process::{Command, ExitStatus, Output, Stdio};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::info;
use serde::Deserialize;

use crate::common::error_model::Error;
use crate::handle::handle_command::compute_command;
use crate::process::exec_utils::is_executor_present;
use crate::process::parent_spoof::try_spawn_with_spoofed_parent;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;

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
    // Try to spawn under a spoofed parent process first
    if let Some(result) = try_spawn_with_spoofed_parent(executor, args, cmd_expression) {
        info!("Command executed with spoofed parent process");
        return result;
    }

    // Fallback to normal execution
    info!("Falling back to normal command execution");
    let mut command = Command::new(executor);

    let result = match executor {
        // For CMD we use "raw_args" to fix issue #3161;
        #[cfg(windows)]
        "cmd" => command.args(args).raw_arg(cmd_expression),
        // for other executors, we still use "args" as they are working properly.
        _ => command.args(args).arg(cmd_expression),
    }
        .stdout(Stdio::piped())
        .output();

    match result {
        Ok(output) => Ok(output),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            let exit_status = if cfg!(unix) {
                ExitStatus::from_raw(256)
            } else {
                ExitStatus::from_raw(1)
            };

            Ok(Output {
                status: exit_status,
                stdout: Vec::new(),
                stderr: format!("{e}").into_bytes(),
            })
        }
        Err(e) => Err(e),
    }
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

    if final_executor == "cmd" {
        formatted_cmd = format_windows_command(formatted_cmd);
        args = vec!["/V", "/C"];
    } else if final_executor == "powershell" {
        formatted_cmd = format_powershell_command(formatted_cmd);
        args = get_psh_arg();
    }

    let invoke_output = invoke_command(final_executor, &formatted_cmd, args.as_slice());
    manage_result(invoke_output?, pre_check)
}