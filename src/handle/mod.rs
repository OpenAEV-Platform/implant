use serde::{Deserialize, Serialize};

pub mod handle_command;
pub mod handle_dns_resolution;
mod handle_execution;
pub mod handle_file;
pub mod handle_file_drop;
pub mod handle_file_execute;

#[derive(Debug, Deserialize, Serialize)]
pub struct ExecutionOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub struct ExecutionParam {
    pub semantic: String,
    pub inject_id: String,
    pub agent_id: String,
    pub max_size: usize,
}
