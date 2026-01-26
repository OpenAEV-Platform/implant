use log::info;

use crate::api::manage_inject::UpdateInput;
use crate::api::Client;
use crate::common::error_model::Error;
use crate::handle::{ExecutionOutput, ExecutionParam};
use crate::process::command_exec::ExecutionResult;

const PREVIEW_LOGS_SIZE: usize = 100000;

pub fn handle_execution_result(
    params: &ExecutionParam,
    api: &Client,
    command_result: Result<ExecutionResult, Error>,
    elapsed: u128,
) -> i32 {
    match command_result {
        Ok(res) => {
            let stdout = res.stdout;
            let stderr = res.stderr;
            let exit_code = res.exit_code;
            let message = ExecutionOutput {
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                exit_code,
            };
            let execution_message = serde_json::to_string(&message).unwrap();
            let size_of_message = execution_message.len();
            // If the execution traces are too big
            if size_of_message > params.max_size {
                // We add a truncated version in the logs
                let mut truncated_stdout = stdout.clone();
                let mut truncated_stderr = stderr.clone();
                truncated_stdout.truncate(PREVIEW_LOGS_SIZE);
                truncated_stderr.truncate(PREVIEW_LOGS_SIZE);
                info!(
                    "{} execution stdout: {:?}",
                    params.semantic,
                    truncated_stdout.clone()
                );
                info!(
                    "{} execution stderr: {:?}",
                    params.semantic,
                    truncated_stderr.clone()
                );

                // And we set the inject into an ERROR status with some traces
                let error_message = ExecutionOutput {
                    stdout: truncated_stdout,
                    stderr: truncated_stderr,
                    exit_code,
                };
                let mut info_message = format!("The generated logs are above the maximum size of {} characters. This is unprocessable by OpenAEV. Here are the beginning of the logs :\n", params.max_size);
                info_message.push_str(serde_json::to_string(&error_message).unwrap().as_str());
                let _ = api.update_status(
                    params.inject_id.clone(),
                    params.agent_id.clone(),
                    UpdateInput {
                        execution_message: info_message,
                        execution_status: String::from("ERROR"),
                        execution_duration: elapsed,
                        execution_action: String::from(params.semantic.as_str()),
                    },
                );
            } else {
                info!("{} execution stdout: {:?}", params.semantic, stdout.clone());
                info!("{} execution stderr: {:?}", params.semantic, stderr.clone());
                let _ = api.update_status(
                    params.inject_id.clone(),
                    params.agent_id.clone(),
                    UpdateInput {
                        execution_message,
                        execution_status: res.status,
                        execution_duration: elapsed,
                        execution_action: params.semantic.clone(),
                    },
                );
            }
            // Return execution code
            res.exit_code
        }
        Err(err) => {
            info!("implant execution error: {err:?}");
            let stderr = format!("{err:?}");
            let stdout = String::new();
            let message = ExecutionOutput {
                stderr,
                stdout,
                exit_code: -1,
            };
            let execution_message = serde_json::to_string(&message).unwrap();
            let _ = api.update_status(
                params.inject_id.clone(),
                params.agent_id.clone(),
                UpdateInput {
                    execution_message,
                    execution_status: String::from("ERROR"),
                    execution_duration: elapsed,
                    execution_action: params.semantic.clone(),
                },
            );
            // Return error code
            -1
        }
    }
}
