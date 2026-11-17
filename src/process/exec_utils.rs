use crate::common::error_model::Error;
use percent_encoding::percent_decode_str;
use std::ffi::OsStr;
use std::path::{Component, Path};
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

pub fn sanitize_filename(name: &str) -> Result<String, Error> {
    let reject = |reason: &str| Error::Internal(format!("Invalid filename {name:?}: {reason}"));

    if name.is_empty() {
        return Err(reject("empty"));
    }

    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(reject("contains a path separator"));
    }

    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == OsStr::new(name) => {
            Ok(name.to_owned())
        }
        _ => Err(reject("not a plain filename")),
    }
}
