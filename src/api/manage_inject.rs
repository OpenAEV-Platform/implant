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

    /// Downloads a document (dropped file / executable payload) as the service-account (implant)
    /// token.
    ///
    /// TEMPORARY (#294): this uses the dedicated `.../agent-file` route, scoped server-side via
    /// `AGENT_DOCUMENT_ACCESS` / `AGENT_DOCUMENT_READ`, so the service-account token never needs
    /// the `SEARCH` capability (platform-wide document listing). This is DISTINCT from the human
    /// route `.../documents/{document_id}/file`, which stays reserved for human users via
    /// `ACCESS_DOCUMENTS` / `READ`. Revert to `/file` once #294's durable per-document scoping
    /// lands on the server.
    ///
    /// ⚠️ RELEASE SYNC: the `agent-file` segment must match the server. The implant binary is
    /// published to JFrog (`openaev-implant`) and pinned into an OpenAEV release at build time by
    /// `core-engine/scripts/download-binaries.sh` (bundled under
    /// `openaev-api/src/main/resources/implants/` and served by `InjectorApi.downloadImplant`).
    /// This change MUST ship in the SAME OpenAEV release as the server route change: a pre-change
    /// implant against a post-change server (or the reverse) would 404 every in-flight inject file
    /// download. When cutting the release, ensure the implant version pinned by
    /// `download-binaries.sh` is a build that contains this commit.
    pub fn download_file(
        &self,
        document_id: &String,
        tenant_id: String,
        in_memory: bool,
    ) -> Result<String, Error> {
        match self
            .get(&format!(
                // TEMPORARY (#294): service-account route, distinct from the human `/file` route.
                "/api/tenants/{tenant_id}/documents/{document_id}/agent-file"
            ))
            .send()
        {
            Ok(response) => {
                if response.status().is_success() {
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
