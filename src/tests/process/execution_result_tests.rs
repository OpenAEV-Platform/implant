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

// Base64 obfuscation runs the payload as `powershell -Enc`. Windows PowerShell
// then writes the error stream as CLIXML when stderr is redirected. The same
// payload in plain text reports the error text below (issue 72).
#[test]
fn test_base64_obfuscation_clixml_stderr() {
    let clixml = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S=\"progress\" RefId=\"1\"><TNRef RefId=\"0\" /><MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><S S=\"Error\">Invoke-WebRequest : Unable to connect to the remote server_x000D__x000A_</S><S S=\"Error\">At line:2 char:1_x000D__x000A_</S><S S=\"Error\">+ Invoke-WebRequest -Uri http://127.0.0.1 -Method POST -Body $content_x000D__x000A_</S><S S=\"Error\">+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~_x000D__x000A_</S><S S=\"Error\">    + CategoryInfo          : NotSpecified: (:) [Invoke-WebRequest], WebException_x000D__x000A_</S><S S=\"Error\">    + FullyQualifiedErrorId : System.Net.WebException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand_x000D__x000A_</S><S S=\"Error\"> _x000D__x000A_</S></Objs>";
    let expected = "Invoke-WebRequest : Unable to connect to the remote server\r\nAt line:2 char:1\r\n+ Invoke-WebRequest -Uri http://127.0.0.1 -Method POST -Body $content\r\n+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\r\n    + CategoryInfo          : NotSpecified: (:) [Invoke-WebRequest], WebException\r\n    + FullyQualifiedErrorId : System.Net.WebException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand\r\n \r\n";
    let output = make_output(1, "", clixml);
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.exit_code, 1);
    assert_eq!(result.stdout, "");
    assert_eq!(result.stderr, expected);
    assert_eq!(result.status, STATUS_ERROR);

    // Progress records alone are not a warning, and ordinary stderr is kept.
    let progress_only = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>";
    let output = make_output(0, "ok", progress_only);
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.stdout, "ok");
    assert_eq!(result.stderr, "");
    assert_eq!(result.status, STATUS_SUCCESS);

    let output = make_output(0, "ok", "some warning");
    let result = manage_result(output, false, EXECUTOR_POWERSHELL).unwrap();
    assert_eq!(result.stderr, "some warning");
    assert_eq!(result.status, STATUS_WARNING);
}
