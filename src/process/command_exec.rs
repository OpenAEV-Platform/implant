use std::process::{Command, Stdio};

use base64::{engine::general_purpose::STANDARD, Engine as _};

#[cfg(unix)]
use crate::common::constants::EXECUTOR_PSH;
use crate::common::constants::{EXECUTOR_BASH, EXECUTOR_CMD, EXECUTOR_POWERSHELL, EXECUTOR_SH};
use crate::common::error_model::Error;
use crate::common::execution_result::{handle_io_error, manage_result, ExecutionResult};
use crate::handle::handle_command::compute_command;
use crate::process::exec_utils::is_executor_present;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub fn invoke_command(
    executor: &str,
    cmd_expression: &str,
    args: &[&str],
    pre_check: bool,
) -> Result<ExecutionResult, Error> {
    let mut command = Command::new(executor);

    let result = match executor {
        // For CMD we use "raw_args" to fix issue #3161;
        #[cfg(windows)]
        EXECUTOR_CMD => command.args(args).raw_arg(cmd_expression),
        // for other executors, we still use "args" as they are working properly.
        _ => command.args(args).arg(cmd_expression),
    }
    .stdout(Stdio::piped())
    .output();

    match result {
        Ok(output) => manage_result(output, pre_check, executor),
        Err(e) => handle_io_error(e),
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

#[cfg(windows)]
pub fn get_executor(executor: &str) -> &str {
    match executor {
        EXECUTOR_CMD | EXECUTOR_BASH | EXECUTOR_SH => executor,
        _ => EXECUTOR_POWERSHELL,
    }
}

#[cfg(unix)]
pub fn get_executor(executor: &str) -> &str {
    match executor {
        EXECUTOR_BASH => executor,
        EXECUTOR_PSH => EXECUTOR_POWERSHELL,
        _ => EXECUTOR_SH,
    }
}

#[cfg(windows)]
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

#[cfg(unix)]
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

    if final_executor == EXECUTOR_CMD {
        formatted_cmd = format_windows_command(formatted_cmd);
        args = vec!["/V", "/C"];
    } else if final_executor == EXECUTOR_POWERSHELL {
        formatted_cmd = format_powershell_command(formatted_cmd);
        args = get_psh_arg();
    }

    invoke_command(final_executor, &formatted_cmd, args.as_slice(), pre_check)
}
