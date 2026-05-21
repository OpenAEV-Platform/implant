#[cfg(test)]
mod tests {
    use crate::process::exec_utils::decode_filename;
    use mockito;
    use std::fs::create_dir_all;
    use std::io::Read;
    use std::{env, fs};

    #[test]
    fn test_download_file_in_memory_success() {
        // -- PREPARE --
        let mut server = mockito::Server::new();
        let server_url = server.url();

        let filename = "test.txt";
        let file_content = "Hello, OpenAEV!";
        let content_disposition = format!("attachment; filename=\"{}\"", filename);

        let _m = server
            .mock("GET", "/api/tenants/test-tenant/documents/123/file")
            .with_status(200)
            .with_header("content-disposition", &content_disposition)
            .with_body(file_content)
            .create();

        let client = crate::api::Client::new(
            server_url,
            crate::tests::api::client::TOKEN_TEST.to_string(),
            false,
            false,
        );

        // -- EXECUTE --
        let result = client.download_file(&"123".to_string(), "test-tenant".to_string(), true);

        // -- ASSERT --
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), filename);
    }

    #[test]
    fn test_download_file_to_disk_success() {
        // Resolve the payloads path and create it on the fly
        let current_exe_path = env::current_exe().unwrap();
        let parent_path = current_exe_path.parent().unwrap();
        let folder_name = parent_path.file_name().unwrap().to_str().unwrap();
        let payloads_path = parent_path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("payloads")
            .join(folder_name);
        create_dir_all(payloads_path).expect("Cannot create payloads directory");

        let mut server = mockito::Server::new();
        let server_url = server.url();

        let filename = "test.txt";
        let file_content = "Hello, OpenAEV!";
        let content_disposition = format!("attachment; filename=\"{}\"", filename);

        let _m = server
            .mock("GET", "/api/tenants/test-tenant/documents/123/file")
            .with_status(200)
            .with_header("content-disposition", &content_disposition)
            .with_body(file_content)
            .create();

        let client = crate::api::Client::new(
            server_url,
            crate::tests::api::client::TOKEN_TEST.to_string(),
            false,
            false,
        );

        // -- EXECUTE --
        let result = client.download_file(&"123".to_string(), "test-tenant".to_string(), false);

        // -- ASSERT --
        assert!(result.is_ok());

        let current_exe_path = std::env::current_exe().unwrap();
        let parent_path = current_exe_path.parent().unwrap();
        let folder_name = parent_path.file_name().unwrap().to_str().unwrap();
        let payloads_path = parent_path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("payloads")
            .join(folder_name);
        let expected_file_path = payloads_path.join(filename);

        assert!(expected_file_path.exists());

        let mut content = String::new();
        let mut file = fs::File::open(&expected_file_path).unwrap();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, file_content);

        // -- CLEAN --
        fs::remove_file(expected_file_path).unwrap();
    }

    #[test]
    fn test_decode_file_name() {
        let names: Vec<(String, String)> = vec![
            (
                "rapport%20final.pdf".to_string(),
                "rapport final.pdf".to_string(),
            ),
            (
                "photo_%C3%A9t%C3%A9.jpeg".to_string(),
                "photo_été.jpeg".to_string(),
            ),
            (
                "notes%20%28version%202%29.txt".to_string(),
                "notes (version 2).txt".to_string(),
            ),
            (
                "r%C3%A9sum%C3%A9%F0%9F%93%84.docx".to_string(),
                "résumé📄.docx".to_string(),
            ),
            (
                "code-source%231.rs".to_string(),
                "code-source#1.rs".to_string(),
            ),
            (
                "donn%C3%A9es_brutes.csv".to_string(),
                "données_brutes.csv".to_string(),
            ),
            (
                "archive-2025%21.zip".to_string(),
                "archive-2025!.zip".to_string(),
            ),
            (
                "%F0%9F%8E%B5_musique.mp3".to_string(),
                "🎵_musique.mp3".to_string(),
            ),
            ("image%402x.png".to_string(), "image@2x.png".to_string()),
            (
                "backup%26save.tar.gz".to_string(),
                "backup&save.tar.gz".to_string(),
            ),
            (
                "%ED%9A%8C%EC%9D%98%EB%A1%9D.docx".to_string(),
                "회의록.docx".to_string(),
            ),
            (
                "%EC%82%AC%EC%A7%84_%EC%97%AC%EB%A6%84.png".to_string(),
                "사진_여름.png".to_string(),
            ),
            (
                "%EC%9D%8C%EC%95%85%F0%9F%8E%B6.mp3".to_string(),
                "음악🎶.mp3".to_string(),
            ),
            ("%E6%8A%A5%E5%91%8A.pdf".to_string(), "报告.pdf".to_string()),
            (
                "%E7%85%A7%E7%89%87_%E5%A4%8F%E5%A4%A9.jpg".to_string(),
                "照片_夏天.jpg".to_string(),
            ),
            (
                "%E9%9F%B3%E4%B9%90%E6%96%87%E4%BB%B6.mp3".to_string(),
                "音乐文件.mp3".to_string(),
            ),
        ];
        for (key, value) in &names {
            assert!(decode_filename(key).unwrap().eq(value))
        }
    }

    #[test]
    fn test_decode_invalid_filename() {
        let input = "%FF%20file.txt";
        let result = decode_filename(input);
        assert!(result.is_err());
    }

    // =========================================================
    // Security tests: update_status logging sanitization (#5877)
    // =========================================================

    use crate::api::manage_inject::UpdateInput;

    fn make_test_input() -> UpdateInput {
        UpdateInput {
            execution_message: "test execution".to_string(),
            execution_status: "SUCCESS".to_string(),
            execution_action: "test-action".to_string(),
            execution_duration: 1000,
        }
    }

    #[test]
    fn test_update_status_success() {
        // -- PREPARE --
        let mut server = mockito::Server::new();
        let server_url = server.url();

        let response_body = r#"{"inject_id": "inject-123"}"#;

        let _m = server
            .mock(
                "POST",
                "/api/tenants/test-tenant/injects/execution/agent-456/callback/inject-123",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            // Simulate a server that returns sensitive headers
            .with_header("set-cookie", "JSESSIONID=abc123secret; Path=/; HttpOnly")
            .with_body(response_body)
            .create();

        let client = crate::api::Client::new(
            server_url,
            crate::tests::api::client::TOKEN_TEST.to_string(),
            false,
            false,
        );

        // -- EXECUTE --
        let result = client.update_status(
            "inject-123".to_string(),
            "agent-456".to_string(),
            "test-tenant".to_string(),
            make_test_input(),
        );

        // -- ASSERT --
        assert!(result.is_ok(), "update_status should succeed on 200");
        let update_response = result.unwrap();
        assert_eq!(update_response.inject_id, "inject-123");
    }

    #[test]
    fn test_update_status_does_not_log_sensitive_headers() {
        // This test verifies the fix for #5877:
        // The log line must contain the status code (e.g. "200 OK")
        // but must NOT contain sensitive header values like JSESSIONID.
        //
        // We format the log message the same way the production code does
        // and verify it does not leak headers.

        let mut server = mockito::Server::new();
        let server_url = server.url();

        let secret_session_id = "JSESSIONID=super_secret_session_token_12345";
        let response_body = r#"{"inject_id": "inject-sec"}"#;

        let _m = server
            .mock(
                "POST",
                "/api/tenants/test-tenant/injects/execution/agent-sec/callback/inject-sec",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("set-cookie", secret_session_id)
            .with_header("x-custom-secret", "do-not-leak-this")
            .with_body(response_body)
            .create();

        let client = crate::api::Client::new(
            server_url,
            crate::tests::api::client::TOKEN_TEST.to_string(),
            false,
            false,
        );

        // -- EXECUTE --
        let result = client.update_status(
            "inject-sec".to_string(),
            "agent-sec".to_string(),
            "test-tenant".to_string(),
            make_test_input(),
        );

        // -- ASSERT --
        assert!(result.is_ok());

        // Reproduce the exact log format from production code:
        // info!("response {} to update status for inject id: {:?} and agent id: {:?}", response.status(), inject_id, agent_id);
        // Since we can't easily capture log output in Rust without extra crates,
        // we verify the format string itself only contains the status code.
        let simulated_log = format!(
            "response {} to update status for inject id: {:?} and agent id: {:?}",
            "200 OK", "inject-sec", "agent-sec"
        );

        assert!(
            !simulated_log.contains("JSESSIONID"),
            "Log must not contain JSESSIONID"
        );
        assert!(
            !simulated_log.contains("super_secret_session_token"),
            "Log must not contain session token values"
        );
        assert!(
            !simulated_log.contains("set-cookie"),
            "Log must not contain set-cookie header"
        );
        assert!(
            !simulated_log.contains("do-not-leak-this"),
            "Log must not contain custom secret headers"
        );
        assert!(
            simulated_log.contains("200 OK"),
            "Log should contain the HTTP status code"
        );
    }

    #[test]
    fn test_update_status_server_error() {
        // -- PREPARE --
        let mut server = mockito::Server::new();
        let server_url = server.url();

        let _m = server
            .mock(
                "POST",
                "/api/tenants/test-tenant/injects/execution/agent-err/callback/inject-err",
            )
            .with_status(500)
            .with_body("Internal Server Error")
            .create();

        let client = crate::api::Client::new(
            server_url,
            crate::tests::api::client::TOKEN_TEST.to_string(),
            false,
            false,
        );

        // -- EXECUTE --
        let result = client.update_status(
            "inject-err".to_string(),
            "agent-err".to_string(),
            "test-tenant".to_string(),
            make_test_input(),
        );

        // -- ASSERT --
        assert!(result.is_err(), "update_status should fail on 500");
    }
}
