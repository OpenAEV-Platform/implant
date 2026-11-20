use std::time::Instant;

use log::info;

use crate::api::manage_reporting::{report_error, report_success};
use crate::api::Client;
use crate::common::error_model::Error;
use crate::handle::handle_execution::handle_execution_result;
use crate::handle::ExecutionParam;
use crate::process::file_exec::file_execution;

pub fn handle_execution_file(
    api: &Client,
    inject_id: String,
    agent_id: String,
    tenant_id: String,
    filename: &String,
    max_size: usize,
    started_at: Instant,
) -> i32 {
    info!("file_execution execution: {filename:?}");
    let command_result = file_execution(filename.as_str());
    let elapsed = started_at.elapsed().as_millis();
    handle_execution_result(
        &ExecutionParam {
            semantic: String::from("file_execution"),
            inject_id,
            agent_id,
            tenant_id,
            max_size,
        },
        api,
        command_result,
        elapsed,
    )
}

pub fn handle_file(
    inject_id: String,
    agent_id: String,
    tenant_id: String,
    api: &Client,
    file_target: &Option<String>,
    in_memory: bool,
    started_at: Instant,
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
                },
                None,
                stderr.clone(),
                started_at.elapsed().as_millis(),
            );
            Err(Error::Internal(stderr))
        }
        Some(document_id) => {
            let download = api.download_file(document_id, tenant_id.clone(), in_memory);
            let elapsed = started_at.elapsed().as_millis();
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
                        },
                        stdout,
                        None,
                        elapsed,
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
                        },
                        None,
                        stderr,
                        elapsed,
                    );
                    Err(err)
                }
            }
        }
    }
}
