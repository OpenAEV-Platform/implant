use crate::api::manage_inject::InjectorContractPayload;
use crate::api::Client;
use crate::handle::handle_file::handle_file;
use crate::handle::handle_file_drop::handle_file_drop;
use crate::process::file_exec::get_output_path;
use crate::tests::api::client::TOKEN_TEST;
use mockito::{Mock, ServerGuard};
use serde_json::json;
use std::fs;

const TENANT_ID: &str = "tenant";
const AGENT_ID: &str = "agent";
const INJECT_ID: &str = "inject";
const DOCUMENT_ID: &str = "document";

fn mock_platform(server: &mut ServerGuard, filename: &str) -> Vec<Mock> {
    vec![
        server
            .mock(
                "GET",
                format!("/api/tenants/{TENANT_ID}/documents/{DOCUMENT_ID}/agent-file").as_str(),
            )
            .with_status(200)
            .with_header(
                "content-disposition",
                &format!("attachment; filename=\"{filename}\""),
            )
            .with_body("payload")
            .create(),
        server
            .mock(
                "POST",
                format!(
                    "/api/tenants/{TENANT_ID}/injects/execution/{AGENT_ID}/callback/{INJECT_ID}"
                )
                .as_str(),
            )
            .with_status(200)
            .with_body(json!({ "inject_id": INJECT_ID }).to_string())
            .create(),
    ]
}

fn payload_path(filename: &str) -> std::path::PathBuf {
    let path = get_output_path(filename).unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

#[test]
fn test_handle_file_keeps_downloaded_file_for_execution() {
    // -- PREPARE --
    let filename = "handle-file-keeps.sh";
    let path = payload_path(filename);
    let mut server = mockito::Server::new();
    let _mocks = mock_platform(&mut server, filename);
    let client = Client::new(server.url(), TOKEN_TEST.to_string(), false, false);

    // -- EXECUTE --
    let result = handle_file(
        INJECT_ID.to_string(),
        AGENT_ID.to_string(),
        TENANT_ID.to_string(),
        &client,
        &Some(DOCUMENT_ID.to_string()),
        false,
    );

    // -- ASSERT --
    assert_eq!(result.unwrap(), filename);
    assert!(path.exists(), "the executable must still be there to run");

    // -- CLEAN --
    fs::remove_file(path).unwrap();
}

#[test]
fn test_handle_file_drop_deletes_downloaded_file() {
    // -- PREPARE --
    let filename = "handle-file-drop-deletes.txt";
    let path = payload_path(filename);
    let mut server = mockito::Server::new();
    let _mocks = mock_platform(&mut server, filename);
    let client = Client::new(server.url(), TOKEN_TEST.to_string(), false, false);
    let payload: InjectorContractPayload = serde_json::from_value(json!({
        "payload_type": "FileDrop",
        "file_drop_file": DOCUMENT_ID,
    }))
    .unwrap();

    // -- EXECUTE --
    handle_file_drop(
        INJECT_ID.to_string(),
        AGENT_ID.to_string(),
        TENANT_ID.to_string(),
        &client,
        &payload,
    );

    // -- ASSERT --
    assert!(!path.exists(), "a dropped file is deleted after download");
}
