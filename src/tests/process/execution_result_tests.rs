#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;

use std::process::{ExitStatus, Output};

use crate::common::constants::*;
use crate::common::execution_result::manage_result;

// -- HELPERS --

fn make_output(exit_code: i32, stdout: &str, stderr: &str) -> Output {
    #[cfg(windows)]
    let status = ExitStatus::from_raw(exit_code as u32);
    #[cfg(unix)]
    let status = ExitStatus::from_raw(exit_code << 8);
    Output {
        status,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

// -- CROSS-CUTTING RULES (ALL OS) --

#[test]
fn test_success() {
    let output = make_output(0, "ok", "");
    let result = manage_result(output, false, EXECUTOR_CMD).unwrap();
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(result.exit_code, 0);
}

#[test]
fn test_warning_when_stderr_non_empty() {
    let output = make_output(0, "ok", "some warning");
    let result = manage_result(output, false, EXECUTOR_CMD).unwrap();
    assert_eq!(result.status, STATUS_WARNING);
}

#[test]
fn test_pre_check_success_on_code_1() {
    let output = make_output(1, "", "stderr");
    let result = manage_result(output, true, EXECUTOR_CMD).unwrap();
    assert_eq!(result.status, STATUS_SUCCESS);
}

// -- CMD (WINDOWS) --

#[test]
#[cfg(windows)]
fn test_cmd_exit_codes() {
    let output = make_output(1, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_CMD).unwrap();
    assert_eq!(result.status, STATUS_ERROR);

    let output = make_output(5, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_CMD).unwrap();
    assert_eq!(result.status, STATUS_ACCESS_DENIED);

    let output = make_output(9009, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_CMD).unwrap();
    assert_eq!(result.status, STATUS_COMMAND_NOT_FOUND);

    let output = make_output(1460, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_CMD).unwrap();
    assert_eq!(result.status, STATUS_TIMEOUT);

    let output = make_output(42, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_CMD).unwrap();
    assert_eq!(result.status, STATUS_ERROR);
}

// -- POWERSHELL (WINDOWS) --

#[test]
#[cfg(windows)]
fn test_powershell_exit_codes() {
    let output = make_output(1, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.status, STATUS_ERROR);

    let output = make_output(5, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.status, STATUS_ACCESS_DENIED);

    let output = make_output(126, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.status, STATUS_COMMAND_CANNOT_BE_EXECUTED);

    let output = make_output(127, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.status, STATUS_COMMAND_NOT_FOUND);

    let output = make_output(-1073741510, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.status, STATUS_INTERRUPTED);

    let output = make_output(99, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.status, STATUS_ERROR);
}

// -- BASH/SH ON WINDOWS --

#[test]
#[cfg(windows)]
fn test_bash_windows_exit_codes() {
    let output = make_output(1, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_BASH).unwrap();
    assert_eq!(result.status, STATUS_ERROR);

    let output = make_output(2, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_BASH).unwrap();
    assert_eq!(result.status, STATUS_INVALID_USAGE);

    let output = make_output(5, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_BASH).unwrap();
    assert_eq!(result.status, STATUS_ACCESS_DENIED);

    let output = make_output(124, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_BASH).unwrap();
    assert_eq!(result.status, STATUS_TIMEOUT);

    let output = make_output(126, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_BASH).unwrap();
    assert_eq!(result.status, STATUS_COMMAND_CANNOT_BE_EXECUTED);

    let output = make_output(127, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_BASH).unwrap();
    assert_eq!(result.status, STATUS_COMMAND_NOT_FOUND);

    let output = make_output(130, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_BASH).unwrap();
    assert_eq!(result.status, STATUS_INTERRUPTED);

    let output = make_output(42, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_BASH).unwrap();
    assert_eq!(result.status, STATUS_ERROR);
}

// -- UNIX (BASH/SH) --

#[test]
#[cfg(unix)]
fn test_unix_exit_codes() {
    let output = make_output(1, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_SH).unwrap();
    assert_eq!(result.status, STATUS_ERROR);

    let output = make_output(2, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_SH).unwrap();
    assert_eq!(result.status, STATUS_INVALID_USAGE);

    let output = make_output(77, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_SH).unwrap();
    assert_eq!(result.status, STATUS_ACCESS_DENIED);

    let output = make_output(124, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_SH).unwrap();
    assert_eq!(result.status, STATUS_TIMEOUT);

    let output = make_output(126, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_SH).unwrap();
    assert_eq!(result.status, STATUS_COMMAND_CANNOT_BE_EXECUTED);

    let output = make_output(127, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_SH).unwrap();
    assert_eq!(result.status, STATUS_COMMAND_NOT_FOUND);

    let output = make_output(130, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_SH).unwrap();
    assert_eq!(result.status, STATUS_INTERRUPTED);

    let output = make_output(42, "", "stderr");
    let result = manage_result(output, false, EXECUTOR_SH).unwrap();
    assert_eq!(result.status, STATUS_ERROR);
}
