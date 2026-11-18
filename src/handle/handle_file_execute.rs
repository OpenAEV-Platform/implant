use std::time::Instant;

use crate::api::manage_inject::InjectorContractPayload;
use crate::api::Client;
use crate::handle::handle_file::{handle_execution_file, handle_file};

pub fn handle_file_execute(
    inject_id: String,
    agent_id: String,
    tenant_id: String,
    api: &Client,
    contract_payload: &InjectorContractPayload,
    max_size: usize,
    started_at: Instant,
) {
    let InjectorContractPayload {
        executable_file, ..
    } = contract_payload;
    let handle_file = handle_file(
        inject_id.clone(),
        agent_id.clone(),
        tenant_id.clone(),
        api,
        executable_file,
        false,
        started_at,
    );
    match handle_file {
        Ok(filename) => {
            handle_execution_file(
                api,
                inject_id.clone(),
                agent_id.clone(),
                tenant_id.clone(),
                &filename,
                max_size,
                started_at,
            );
        }
        Err(_) => {
            // Nothing to do here as handle by handle_file
        }
    }
}
