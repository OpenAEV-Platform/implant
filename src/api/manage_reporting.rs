use crate::api::manage_inject::UpdateInput;
use crate::api::Client;
use crate::common::constants::{STATUS_ERROR, STATUS_SUCCESS};
use crate::handle::ExecutionOutput;

pub fn report_success(
    api: &Client,
    semantic: &str,
    inject_id: String,
    agent_id: String,
    stdout: String,
    stderr: Option<String>,
    duration: u128,
) {
    let message = ExecutionOutput {
        stderr: stderr.unwrap_or_default(),
        stdout,
        exit_code: -1,
    };
    let execution_message = serde_json::to_string(&message).unwrap();
    let _ = api.update_status(
        inject_id.clone(),
        agent_id.clone(),
        UpdateInput {
            execution_message,
            execution_status: String::from(STATUS_SUCCESS),
            execution_duration: duration,
            execution_action: String::from(semantic),
        },
    );
}

pub fn report_error(
    api: &Client,
    semantic: &str,
    inject_id: String,
    agent_id: String,
    stdout: Option<String>,
    stderr: String,
    duration: u128,
) {
    let message = ExecutionOutput {
        stdout: stdout.unwrap_or_default(),
        stderr,
        exit_code: -1,
    };
    let execution_message = serde_json::to_string(&message).unwrap();
    let _ = api.update_status(
        inject_id.clone(),
        agent_id.clone(),
        UpdateInput {
            execution_message,
            execution_status: String::from(STATUS_ERROR),
            execution_duration: duration,
            execution_action: String::from(semantic),
        },
    );
}
