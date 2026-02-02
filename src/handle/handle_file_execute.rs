use crate::api::manage_inject::InjectorContractPayload;
use crate::api::Client;
use crate::handle::handle_file::{handle_execution_file, handle_file};

pub fn handle_file_execute(
    inject_id: String,
    agent_id: String,
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
        api,
        executable_file,
        false,
    );
    match handle_file {
        Ok(filename) => {
            handle_execution_file(
                "file_execution",
                api,
                inject_id.clone(),
                agent_id.clone(),
                &filename,
                max_size,
            );
        }
        Err(_) => {
            // Nothing to do here as handle by handle_file
        }
    }
}
