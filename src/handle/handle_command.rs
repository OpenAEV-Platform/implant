use std::env;
use std::path::PathBuf;
use std::time::Instant;

use log::info;

use crate::api::manage_inject::InjectorContractPayload;
use crate::api::Client;
use crate::handle::handle_execution::handle_execution_result;
use crate::process::command_exec::command_execution;

fn compute_working_dir() -> PathBuf {
    let current_exe_path = env::current_exe().unwrap();
    let parent_path = current_exe_path.parent().unwrap();
    let folder_name = parent_path.file_name().unwrap().to_str().unwrap();
    let payloads_path = parent_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("payloads");
    payloads_path.join(folder_name)
}

pub fn compute_command(command: &str) -> String {
    let executable_command = command;
    let working_dir = compute_working_dir();
    executable_command.replace("#{location}", working_dir.to_str().unwrap())
}

pub fn handle_execution_command(
    semantic: &str,
    api: &Client,
    inject_id: String,
    agent_id: String,
    command: &str,
    executor: &str,
    pre_check: bool,
) -> i32 {
    let now = Instant::now();
    info!("{semantic} execution: {command:?}");
    let command_result = command_execution(command, executor, pre_check);
    let elapsed = now.elapsed().as_millis();
    handle_execution_result(semantic, api, inject_id, agent_id, command_result, elapsed)
}

pub fn handle_command(
    inject_id: String,
    agent_id: String,
    api: &Client,
    contract_payload: &InjectorContractPayload,
) {
    let command = contract_payload.command_content.clone().unwrap();
    let executor = contract_payload.command_executor.clone().unwrap();
    let _ = handle_execution_command(
        "command_execution",
        api,
        inject_id.clone(),
        agent_id.clone(),
        &command,
        &executor,
        false,
    );
}
