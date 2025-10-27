use crate::common::error_model::Error;
use percent_encoding::percent_decode_str;
use std::process::Command;

pub fn is_executor_present(executor: &str) -> bool {
    Command::new(executor)
        .spawn()
        .map(|mut child| child.kill().is_ok())
        .unwrap_or(false)
}

pub fn decode_filename(name: &str) -> Result<String, Error> {
    percent_decode_str(name)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .map_err(|err| Error::Internal(format!("Invalid filename: {}", err)))
}
