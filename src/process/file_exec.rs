use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{env, fs};

#[cfg(unix)]
use crate::common::constants::EXECUTOR_BASH;
#[cfg(windows)]
use crate::common::constants::EXECUTOR_POWERSHELL;
use crate::common::error_model::Error;
use crate::common::execution_result::{handle_io_error, manage_result, ExecutionResult};
use crate::process::exec_utils::is_executor_present;

fn compute_working_file(filename: &str) -> PathBuf {
    let current_exe_path = env::current_exe()
        .map_err(|e| Error::Internal(format!("Cannot get current executable path: {e}")))
        .expect("Cannot get current executable path");
    let parent_path = current_exe_path
        .parent()
        .ok_or_else(|| Error::Internal("Cannot determine executable parent directory".to_string()))
        .expect("Cannot determine executable parent directory");
    // Resolve the payloads path and create it on the fly
    let folder_name = parent_path.file_name().unwrap().to_str().unwrap();
    let parent_parent_path = parent_path
        .parent()
        .unwrap()
        .parent()
        .ok_or_else(|| Error::Internal("Cannot determine parent directory of parent".to_string()))
        .expect("Cannot determine parent directory of parent");
    let executable_path = parent_parent_path.join("payloads").join(folder_name);
    executable_path.join(filename)
}

#[cfg(windows)]
pub fn file_execution(filename: &str) -> Result<ExecutionResult, Error> {
    let executor = "powershell.exe";
    if !is_executor_present(executor) {
        return Err(Error::Internal(format!(
            "Executor '{executor}' is not available."
        )));
    }
    let script_file_name = compute_working_file(filename);
    let win_path = format!(
        "$ErrorActionPreference = 'Stop'; & '{}'; exit $LASTEXITCODE",
        script_file_name.to_str().unwrap()
    );
    let command_args = &[
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-NonInteractive",
        "-NoProfile",
        "-Command",
    ];
    let invoke_output = Command::new(executor)
        .args(command_args)
        .arg(win_path)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?
        .wait_with_output();

    match invoke_output {
        Ok(output) => manage_result(output, false, EXECUTOR_POWERSHELL),
        Err(e) => handle_io_error(e),
    }
}

#[cfg(unix)]
pub fn file_execution(filename: &str) -> Result<ExecutionResult, Error> {
    let executor = EXECUTOR_BASH;
    if !is_executor_present(executor) {
        return Err(Error::Internal(format!(
            "Executor '{executor}' is not available."
        )));
    }
    let script_file_name = compute_working_file(filename);
    // Prepare and execute the command
    let command_args = &[script_file_name.to_str().unwrap()];
    let invoke_output = Command::new(executor)
        .args(command_args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?
        .wait_with_output();

    match invoke_output {
        Ok(output) => manage_result(output, false, EXECUTOR_BASH),
        Err(e) => handle_io_error(e),
    }
}

pub fn delete_file(filename: &str) -> Result<(), Error> {
    let file_path = get_output_path(filename)?;
    fs::remove_file(&file_path).map_err(|e| {
        Error::Internal(format!("Cannot delete file '{}': {e}", file_path.display()))
    })?;
    Ok(())
}

pub fn get_output_path(filename: &str) -> Result<PathBuf, Error> {
    let current_exe_path = env::current_exe()
        .map_err(|e| Error::Internal(format!("Cannot get current executable path: {e}")))?;
    let parent_path = current_exe_path.parent().ok_or_else(|| {
        Error::Internal("Cannot determine executable parent directory".to_string())
    })?;

    // Resolve the payloads path and create it on the fly
    let folder_name = parent_path.file_name().unwrap().to_str().unwrap();
    let parent_parent_path = parent_path.parent().unwrap().parent().ok_or_else(|| {
        Error::Internal("Cannot determine parent directory of parent".to_string())
    })?;
    let payloads_path = parent_parent_path.join("payloads").join(folder_name);
    Ok(payloads_path.join(filename))
}
