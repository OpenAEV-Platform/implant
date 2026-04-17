use std::path::Path;

use rolling_file::{BasicRollingFileAppender, RollingConditionBasic};
use tracing_appender::non_blocking::WorkerGuard;

const PREFIX_LOG_NAME: &str = "openaev-implant.log";

pub fn init_logger(exe_dir: &Path) -> WorkerGuard {
    let log_file = exe_dir.join(PREFIX_LOG_NAME);
    let condition = RollingConditionBasic::new().daily();
    let file_appender = BasicRollingFileAppender::new(log_file, condition, 3).unwrap();
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .json()
        .with_writer(file_writer)
        .init();
    guard
}
