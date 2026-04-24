use std::process::Output;

use serde::Deserialize;

use crate::common::constants::*;
use crate::common::error_model::Error;

#[derive(Debug, Deserialize)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub status: String,
    pub exit_code: i32,
}

pub fn manage_result(
    invoke_output: Output,
    pre_check: bool,
    executor: &str,
) -> Result<ExecutionResult, Error> {
    let exit_code = invoke_output.status.code().unwrap_or(-99);
    let stdout = decode_output(&invoke_output.stdout);
    let stderr = decode_output(&invoke_output.stderr);

    let exit_status = match exit_code {
        0 if stderr.is_empty() => STATUS_SUCCESS,
        0 if !stderr.is_empty() => STATUS_WARNING,
        _ if stderr.contains("CommandNotFoundException") => STATUS_COMMAND_NOT_FOUND,
        1 if pre_check => STATUS_SUCCESS,
        _ => map_exit_code(exit_code, executor, &stderr),
    };

    Ok(ExecutionResult {
        stdout,
        stderr,
        exit_code,
        status: String::from(exit_status),
    })
}

pub fn handle_io_error(e: std::io::Error) -> Result<ExecutionResult, Error> {
    let status = match e.kind() {
        std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
        _ => STATUS_ERROR,
    };
    Ok(ExecutionResult {
        stdout: String::new(),
        stderr: format!("{e}"),
        exit_code: -1,
        status: String::from(status),
    })
}

// -- PRIVATE --

pub(crate) fn decode_output(raw_bytes: &[u8]) -> String {
    // Try decoding as UTF-8
    if let Ok(decoded) = String::from_utf8(raw_bytes.to_vec()) {
        return decoded; // Return if successful
    }
    // Fallback to UTF-8 lossy decoding
    String::from_utf8_lossy(raw_bytes).to_string()
}

#[cfg(windows)]
fn map_exit_code(exit_code: i32, executor: &str, stderr: &str) -> &'static str {
    use crate::common::constants::{EXECUTOR_CMD, EXECUTOR_POWERSHELL, EXECUTOR_PWSH};

    match executor {
        EXECUTOR_CMD => match exit_code {
            5 => STATUS_ACCESS_DENIED,
            9009 => STATUS_COMMAND_NOT_FOUND,
            1460 => STATUS_TIMEOUT,
            _ => STATUS_ERROR,
        },
        EXECUTOR_POWERSHELL | EXECUTOR_PWSH => match exit_code {
            1 if stderr.contains("CommandNotFoundException") => STATUS_COMMAND_NOT_FOUND,
            5 => STATUS_ACCESS_DENIED,
            126 => STATUS_COMMAND_CANNOT_BE_EXECUTED,
            127 => STATUS_COMMAND_NOT_FOUND,
            -1073741510 => STATUS_INTERRUPTED,
            _ => STATUS_ERROR,
        },
        // bash/sh on Windows
        _ => match exit_code {
            2 => STATUS_INVALID_USAGE,
            5 => STATUS_ACCESS_DENIED,
            124 => STATUS_TIMEOUT,
            126 => STATUS_COMMAND_CANNOT_BE_EXECUTED,
            127 => STATUS_COMMAND_NOT_FOUND,
            130 => STATUS_INTERRUPTED,
            _ => STATUS_ERROR,
        },
    }
}

#[cfg(unix)]
fn map_exit_code(exit_code: i32, _executor: &str, _stderr: &str) -> &'static str {
    match exit_code {
        2 => STATUS_INVALID_USAGE,
        77 => STATUS_ACCESS_DENIED,
        124 => STATUS_TIMEOUT,
        126 => STATUS_COMMAND_CANNOT_BE_EXECUTED,
        127 => STATUS_COMMAND_NOT_FOUND,
        130 => STATUS_INTERRUPTED,
        _ => STATUS_ERROR,
    }
}
