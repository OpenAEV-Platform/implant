use std::process::Output;

use serde::Deserialize;

use crate::common::constants::*;
use crate::common::error_model::Error;

#[derive(Debug, Deserialize)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub status: String,
    pub exit_code: i32,
}

pub fn manage_result(
    invoke_output: Output,
    pre_check: bool,
    executor: &str,
) -> Result<ExecutionResult, Error> {
    let exit_code = invoke_output.status.code().unwrap_or(-99);
    let stdout = decode_output(&invoke_output.stdout);
    // `powershell -Enc` (base64 obfuscation) writes progress and error records
    // to a redirected stderr as CLIXML. Report the error text instead.
    let stderr = strip_powershell_clixml(&decode_output(&invoke_output.stderr));

    let exit_status = match exit_code {
        0 if stderr.is_empty() => STATUS_SUCCESS,
        0 if !stderr.is_empty() => STATUS_WARNING,
        _ if stderr.contains("CommandNotFoundException") => STATUS_COMMAND_NOT_FOUND,
        1 if pre_check => STATUS_SUCCESS,
        _ => map_exit_code(exit_code, executor, &stderr),
    };

    Ok(ExecutionResult {
        stdout,
        stderr,
        exit_code,
        status: String::from(exit_status),
    })
}

pub fn handle_io_error(e: std::io::Error) -> Result<ExecutionResult, Error> {
    let status = match e.kind() {
        std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
        _ => STATUS_ERROR,
    };
    Ok(ExecutionResult {
        stdout: String::new(),
        stderr: format!("{e}"),
        exit_code: -1,
        status: String::from(status),
    })
}

// -- PRIVATE --

pub(crate) fn decode_output(raw_bytes: &[u8]) -> String {
    // Try decoding as UTF-8
    if let Ok(decoded) = String::from_utf8(raw_bytes.to_vec()) {
        return decoded; // Return if successful
    }
    // Fallback to UTF-8 lossy decoding
    String::from_utf8_lossy(raw_bytes).to_string()
}

fn strip_powershell_clixml(text: &str) -> String {
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    let Some(after_marker) = trimmed.strip_prefix("#< CLIXML") else {
        return text.to_string();
    };
    let xml = after_marker.trim_start();
    if !xml.starts_with("<Objs") {
        return text.to_string();
    }

    let mut out = String::new();
    let mut cursor = 0;
    while let Some(rel) = xml[cursor..].find("<S ") {
        let start = cursor + rel;
        let Some(tag_end) = xml[start..].find('>') else {
            break;
        };
        let open = &xml[start..start + tag_end];
        let content_at = start + tag_end + 1;
        let Some(end_rel) = xml[content_at..].find("</S>") else {
            break;
        };
        if is_clixml_stderr_stream(open) {
            let content = &xml[content_at..content_at + end_rel];
            out.push_str(&decode_clixml_text(content));
        }
        cursor = content_at + end_rel + "</S>".len();
    }
    out
}

fn is_clixml_stderr_stream(open_tag: &str) -> bool {
    open_tag.contains("S=\"Error\"")
        || open_tag.contains("S=\"Warning\"")
        || open_tag.contains("S='Error'")
        || open_tag.contains("S='Warning'")
}

fn decode_clixml_text(raw: &str) -> String {
    decode_powershell_hex_escapes(&decode_xml_entities(raw))
}

fn decode_xml_entities(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let Some(end) = rest.find(';') else {
            break;
        };
        if let Some(ch) = xml_entity(&rest[1..end]) {
            out.push(ch);
            rest = &rest[end + 1..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

fn xml_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => xml_numeric_entity(entity),
    }
}

fn xml_numeric_entity(entity: &str) -> Option<char> {
    let code = if let Some(hex) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        let digits = entity.strip_prefix('#')?;
        digits.parse().ok()?
    };
    char::from_u32(code)
}

fn decode_powershell_hex_escapes(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if let Some(ch) = powershell_hex_escape(bytes, i) {
            out.push(ch);
            i += 7;
            continue;
        }
        let ch = raw[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn powershell_hex_escape(bytes: &[u8], i: usize) -> Option<char> {
    if i + 6 >= bytes.len() || bytes[i] != b'_' || bytes[i + 1] != b'x' || bytes[i + 6] != b'_' {
        return None;
    }
    let mut code = 0u32;
    for byte in &bytes[i + 2..i + 6] {
        code = code * 16 + hex_value(*byte)?;
    }
    char::from_u32(code)
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(byte - b'A' + 10)),
        _ => None,
    }
}

#[cfg(windows)]
fn map_exit_code(exit_code: i32, executor: &str, stderr: &str) -> &'static str {
    use crate::common::constants::{EXECUTOR_CMD, EXECUTOR_POWERSHELL, EXECUTOR_PWSH};

    match executor {
        EXECUTOR_CMD => match exit_code {
            5 => STATUS_ACCESS_DENIED,
            9009 => STATUS_COMMAND_NOT_FOUND,
            1460 => STATUS_TIMEOUT,
            _ => STATUS_ERROR,
        },
        EXECUTOR_POWERSHELL | EXECUTOR_PWSH => match exit_code {
            1 if stderr.contains("CommandNotFoundException") => STATUS_COMMAND_NOT_FOUND,
            1 if stderr.contains("Access is denied") => STATUS_ACCESS_DENIED,
            5 => STATUS_ACCESS_DENIED,
            126 => STATUS_COMMAND_CANNOT_BE_EXECUTED,
            127 => STATUS_COMMAND_NOT_FOUND,
            -1073741510 => STATUS_INTERRUPTED,
            _ => STATUS_ERROR,
        },
        // bash/sh on Windows
        _ => match exit_code {
            2 => STATUS_INVALID_USAGE,
            5 => STATUS_ACCESS_DENIED,
            124 => STATUS_TIMEOUT,
            126 => STATUS_COMMAND_CANNOT_BE_EXECUTED,
            127 => STATUS_COMMAND_NOT_FOUND,
            130 => STATUS_INTERRUPTED,
            _ => STATUS_ERROR,
        },
    }
}

#[cfg(unix)]
fn map_exit_code(exit_code: i32, _executor: &str, _stderr: &str) -> &'static str {
    match exit_code {
        2 => STATUS_INVALID_USAGE,
        77 => STATUS_ACCESS_DENIED,
        124 => STATUS_TIMEOUT,
        126 => STATUS_COMMAND_CANNOT_BE_EXECUTED,
        127 => STATUS_COMMAND_NOT_FOUND,
        130 => STATUS_INTERRUPTED,
        _ => STATUS_ERROR,
    }
}
