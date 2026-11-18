use std::time::Instant;

use log::info;

use crate::api::manage_reporting::{report_error, report_success};
use crate::api::Client;
use crate::common::error_model::Error;
use crate::handle::handle_execution::handle_execution_result;
use crate::handle::ExecutionParam;
use crate::process::file_exec::file_execution;

pub fn handle_execution_file(params: &ExecutionParam, api: &Client, filename: &String) -> i32 {
    info!("{} execution: {filename:?}", params.semantic);
    let command_result = file_execution(filename.as_str());
    handle_execution_result(params, api, command_result)
}

pub fn handle_file(
    inject_id: String,
    agent_id: String,
    tenant_id: String,
    started_at: Instant,
    api: &Client,
    file_target: &Option<String>,
    in_memory: bool,
) -> Result<String, Error> {
    match file_target {
        None => {
            let stderr = String::from("Payload download fail, document not specified");
            report_error(
                api,
                &ExecutionParam {
                    semantic: "file_drop".parse().unwrap(),
                    inject_id: inject_id.clone(),
                    agent_id: agent_id.clone(),
                    tenant_id: tenant_id.clone(),
                    max_size: 0,
                    started_at,
                },
                None,
                stderr.clone(),
            );
            Err(Error::Internal(stderr))
        }
        Some(document_id) => {
            let download = api.download_file(document_id, tenant_id.clone(), in_memory);
            match download {
                Ok(filename) => {
                    let stdout = String::from("File downloaded with success");
                    report_success(
                        api,
                        &ExecutionParam {
                            semantic: "file_drop".parse().unwrap(),
                            inject_id: inject_id.clone(),
                            agent_id: agent_id.clone(),
                            tenant_id: tenant_id.clone(),
                            max_size: 0,
                            started_at,
                        },
                        stdout,
                        None,
                    );
                    Ok(filename)
                }
                Err(err) => {
                    let stderr = format!("{err:?}");
                    report_error(
                        api,
                        &ExecutionParam {
                            semantic: "file_drop".parse().unwrap(),
                            inject_id: inject_id.clone(),
                            agent_id: agent_id.clone(),
                            tenant_id: tenant_id.clone(),
                            max_size: 0,
                            started_at,
                        },
                        None,
                        stderr,
                    );
                    Err(err)
                }
            }
        }
    }
}
