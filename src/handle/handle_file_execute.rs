use std::time::Instant;

use crate::api::manage_inject::InjectorContractPayload;
use crate::api::Client;
use crate::handle::handle_file::{handle_execution_file, handle_file};
use crate::handle::ExecutionParam;

pub fn handle_file_execute(
    inject_id: String,
    agent_id: String,
    tenant_id: String,
    started_at: Instant,
    api: &Client,
    contract_payload: &InjectorContractPayload,
    max_size: usize,
) {
    let InjectorContractPayload {
        executable_file, ..
    } = contract_payload;
    let handle_file = handle_file(
        inject_id.clone(),
        agent_id.clone(),
        tenant_id.clone(),
        started_at,
        api,
        executable_file,
        false,
    );
    match handle_file {
        Ok(filename) => {
            handle_execution_file(
                &ExecutionParam {
                    semantic: String::from("file_execution"),
                    inject_id,
                    agent_id,
                    tenant_id,
                    max_size,
                    started_at,
                },
                api,
                &filename,
            );
        }
        Err(_) => {
            // Nothing to do here as handle by handle_file
        }
    }
}
