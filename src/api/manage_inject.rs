use super::Client;
use crate::common::error_model::Error;
use crate::process::exec_utils::decode_filename;
use crate::process::file_exec::get_output_path;
use log::{error, info};
use mailparse::{parse_content_disposition, parse_header};
use reqwest::blocking::Response;
use reqwest::header::CONTENT_DISPOSITION;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::thread::sleep;
use std::time::Duration;
use std::{fs, io};

pub fn write_response<W>(writer: W, response: reqwest::blocking::Response) -> std::io::Result<u64>
where
    W: Write,
{
    let mut writer = BufWriter::new(writer);
    let content = response
        .error_for_status()
        .map_err(io::Error::other)?
        .bytes()
        .map_err(io::Error::other)?
        .as_ref()
        .to_owned();
    io::copy(&mut content.as_slice(), &mut writer)
}

#[derive(Debug, Deserialize)]
pub struct PayloadArg {
    pub r#type: String,
    pub key: String,
    pub description: Option<String>,
    pub default_value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PayloadPrerequisite {
    pub executor: String,
    pub get_command: String,
    pub check_command: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InjectorContractPayload {
    pub payload_id: Option<String>,
    pub payload_type: String,
    pub payload_arguments: Option<Vec<PayloadArg>>,
    // FileDrop
    pub file_drop_file: Option<String>,
    // Executable
    pub executable_file: Option<String>,
    // DnsResolution
    pub dns_resolution_hostname: Option<String>,
    // Clear zip password for an encrypted malware sample; when present the downloaded file is a
    // password-protected zip that must be decrypted in memory before it is dropped/executed.
    pub payload_sample_zip_password: Option<String>,
    // Prerequisites
    pub payload_prerequisites: Option<Vec<PayloadPrerequisite>>,
    // Command
    pub command_executor: Option<String>,
    pub command_content: Option<String>,
    // Cleanup
    pub payload_cleanup_executor: Option<String>,
    pub payload_cleanup_command: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateInjectResponse {
    #[allow(dead_code)]
    pub inject_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateInput {
    pub execution_message: String,
    pub execution_status: String,
    pub execution_action: String,
    pub execution_duration: u128,
}

impl Client {
    pub fn get_executable_payload(
        &self,
        inject_id: &str,
        agent_id: &str,
        tenant_id: &str,
    ) -> Result<InjectorContractPayload, Error> {
        match self
            .get(&format!(
                "/api/tenants/{tenant_id}/injects/{inject_id}/{agent_id}/executable-payload"
            ))
            .send()
        {
            Ok(response) => {
                if response.status().is_success() {
                    response
                        .json::<InjectorContractPayload>()
                        .map_err(|e| Error::Internal(e.to_string()))
                } else {
                    let msg = response
                        .text()
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Err(Error::Api(msg))
                }
            }
            Err(err) => Err(Error::Internal(err.to_string())),
        }
    }

    pub fn update_status(
        &self,
        inject_id: String,
        agent_id: String,
        tenant_id: String,
        input: UpdateInput,
    ) -> Result<UpdateInjectResponse, Error> {
        self.update_status_retry(inject_id, agent_id, tenant_id, input, 20)
    }

    fn update_status_retry(
        &self,
        inject_id: String,
        agent_id: String,
        tenant_id: String,
        input: UpdateInput,
        retry: u64,
    ) -> Result<UpdateInjectResponse, Error> {
        let post_data = json!(input);
        match self
            .post(&format!(
                "/api/tenants/{tenant_id}/injects/execution/{agent_id}/callback/{inject_id}"
            ))
            .json(&post_data)
            .send()
        {
            Ok(response) => {
                self.update_status_response(response, inject_id, agent_id, tenant_id, input, retry)
            }
            Err(err) => Err(Error::Internal(err.to_string())),
        }
    }

    fn update_status_response(
        &self,
        response: Response,
        inject_id: String,
        agent_id: String,
        tenant_id: String,
        input: UpdateInput,
        retry: u64,
    ) -> Result<UpdateInjectResponse, Error> {
        if response.status().is_success() {
            info!(
                "response {} to update status for inject id: {:?} and agent id: {:?}",
                response.status(),
                inject_id,
                agent_id
            );
            response
                .json::<UpdateInjectResponse>()
                .map_err(|e| Error::Internal(e.to_string()))
        } else if response.status().is_client_error() && retry > 0 {
            sleep(Duration::from_secs(10));
            info!("retry {retry:?} to update status for inject id: {inject_id:?} and agent id: {agent_id:?}");
            self.update_status_retry(inject_id, agent_id, tenant_id, input, retry - 1)
        } else {
            let msg = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("error message {msg:?} to update status for inject id: {inject_id:?} and agent id: {agent_id:?}");
            Err(Error::Api(msg))
        }
    }

    pub fn download_file(
        &self,
        document_id: &String,
        tenant_id: String,
        in_memory: bool,
    ) -> Result<String, Error> {
        self.download_file_maybe_encrypted(document_id, tenant_id, in_memory, &None)
    }

    /// Download a file by id. When `sample_zip_password` is set, the downloaded object is a
    /// password-protected zip (a malware sample): it is buffered and decrypted in memory, and the
    /// single contained entry is written out as the working file, just before detonation.
    pub fn download_file_maybe_encrypted(
        &self,
        document_id: &String,
        tenant_id: String,
        in_memory: bool,
        sample_zip_password: &Option<String>,
    ) -> Result<String, Error> {
        match self
            .get(&format!("/api/tenants/{tenant_id}/files/{document_id}/file"))
            .send()
        {
            Ok(response) => {
                if response.status().is_success() {
                    if let Some(password) = sample_zip_password {
                        return decrypt_sample_to_disk(response, password);
                    }
                    let name = extract_filename(&response)?;
                    let decoded_name = decode_filename(&name)?;
                    let output_path = get_output_path(&decoded_name)?;
                    if in_memory {
                        let buf = BufWriter::new(Vec::new());
                        let _ = write_response(buf, response);
                        Ok(decoded_name)
                    } else {
                        let output_file = File::create(output_path.clone())?;
                        let file_write = write_response(output_file, response);
                        match file_write {
                            Ok(_) => Ok(decoded_name),
                            Err(err) => {
                                let _ = fs::remove_file(output_path.clone());
                                Err(Error::Io(err))
                            }
                        }
                    }
                } else {
                    let msg = response
                        .text()
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Err(Error::Api(msg))
                }
            }
            Err(err) => Err(Error::Internal(err.to_string())),
        }
    }
}

/// Read the encrypted-zip response fully, decrypt its single entry with the given password, and
/// write the plaintext sample to the working payloads directory. Returns the extracted file name.
fn decrypt_sample_to_disk(
    response: Response,
    password: &str,
) -> Result<String, Error> {
    let bytes = response
        .bytes()
        .map_err(|e| Error::Internal(e.to_string()))?
        .to_vec();
    let reader = std::io::Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|e| Error::Internal(e.to_string()))?;
    let mut entry = archive
        .by_index_decrypt(0, password.as_bytes())
        .map_err(|e| Error::Internal(e.to_string()))?;
    let entry_name = entry
        .enclosed_name()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "sample".to_string());
    let output_path = get_output_path(&entry_name)?;
    let mut output_file = File::create(output_path.clone())?;
    match io::copy(&mut entry, &mut output_file) {
        Ok(_) => Ok(entry_name),
        Err(err) => {
            let _ = fs::remove_file(output_path);
            Err(Error::Io(err))
        }
    }
}

fn extract_filename(response: &Response) -> Result<String, Error> {
    let content_disposition = response
        .headers()
        .get(CONTENT_DISPOSITION)
        .and_then(|val| val.to_str().ok())
        .unwrap_or("");

    let content_to_parse = format!("Content-Disposition: {content_disposition}");
    let (parsed, _) = parse_header(content_to_parse.as_bytes())
        .map_err(|_| Error::Internal("Failed to parse Content-Disposition".to_string()))?;
    let dis = parse_content_disposition(&parsed.get_value());

    dis.params
        .get("filename")
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Internal("Filename not found".to_string()))
}
