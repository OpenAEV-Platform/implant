use crate::api::manage_inject::UpdateInput;
use crate::api::Client;
use crate::common::constants::{STATUS_ERROR, STATUS_SUCCESS};
use crate::handle::{ExecutionOutput, ExecutionParam};

pub fn report_success(
    api: &Client,
    params: &ExecutionParam,
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
        params.inject_id.clone(),
        params.agent_id.clone(),
        params.tenant_id.clone(),
        UpdateInput {
            execution_message,
            execution_status: String::from(STATUS_SUCCESS),
            execution_duration: duration,
            execution_action: params.semantic.clone(),
        },
    );
}

pub fn report_error(
    api: &Client,
    params: &ExecutionParam,
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
        params.inject_id.clone(),
        params.agent_id.clone(),
        params.tenant_id.clone(),
        UpdateInput {
            execution_message,
            execution_status: String::from(STATUS_ERROR),
            execution_duration: duration,
            execution_action: params.semantic.clone(),
        },
    );
}
