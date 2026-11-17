use crate::api::manage_inject::InjectorContractPayload;
use crate::api::Client;
use crate::handle::handle_file::handle_file;
use crate::process::file_exec::delete_file;

pub fn handle_file_drop(
    inject_id: String,
    agent_id: String,
    tenant_id: String,
    api: &Client,
    contract_payload: &InjectorContractPayload,
) {
    let InjectorContractPayload { file_drop_file, .. } = contract_payload;
    if let Ok(filename) = handle_file(inject_id, agent_id, tenant_id, api, file_drop_file, false) {
        let _ = delete_file(&filename);
    }
}
