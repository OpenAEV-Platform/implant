use std::time::Instant;

use log::info;

use crate::api::manage_reporting::{report_error, report_success};
use crate::api::Client;
use crate::common::error_model::Error;
use crate::handle::handle_execution::handle_execution_result;
use crate::handle::ExecutionParam;
use crate::process::file_exec::file_execution;

pub fn handle_execution_file(
    semantic: &str,
    api: &Client,
    inject_id: String,
    agent_id: String,
    filename: &String,
    max_size: usize,
) -> i32 {
    let now = Instant::now();
    info!("{semantic} execution: {filename:?}");
    let command_result = file_execution(filename.as_str());
    let elapsed = now.elapsed().as_millis();
    handle_execution_result(
        &ExecutionParam {
            semantic: semantic.to_owned(),
            inject_id,
            agent_id,
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
    api: &Client,
    file_target: &Option<String>,
    in_memory: bool,
) -> Result<String, Error> {
    match file_target {
        None => {
            let stderr = String::from("Payload download fail, document not specified");
            report_error(
                api,
                "file_drop",
                inject_id.clone(),
                agent_id.clone(),
                None,
                stderr.clone(),
                0,
            );
            Err(Error::Internal(stderr))
        }
        Some(document_id) => {
            let now = Instant::now();
            let download = api.download_file(document_id, in_memory);
            let elapsed = now.elapsed().as_millis();
            match download {
                Ok(filename) => {
                    let stdout = String::from("File downloaded with success");
                    report_success(
                        api,
                        "file_drop",
                        inject_id.clone(),
                        agent_id.clone(),
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
                        "file_drop",
                        inject_id.clone(),
                        agent_id.clone(),
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
