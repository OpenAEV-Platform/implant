#[cfg(test)]
mod tests {
    use crate::process::exec_utils::decode_filename;
    use mockito;
    use std::fs::create_dir_all;
    use std::io::{Read, Write};
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
            .mock("GET", "/api/tenants/test-tenant/files/123/file")
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
            .mock("GET", "/api/tenants/test-tenant/files/123/file")
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
    fn test_download_encrypted_sample_to_disk_success() {
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
        create_dir_all(&payloads_path).expect("Cannot create payloads directory");

        // Build a password-protected (AES-256) zip holding a single sample entry, in memory,
        // mirroring what the OpenAEV Files feature serves for an encrypted malware sample.
        let sample_name = "decrypted-sample.txt";
        let sample_content = "Hello, encrypted OpenAEV!";
        let password = "s3cr3t-p4ss";
        let mut zip_buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_buffer);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .with_aes_encryption(zip::AesMode::Aes256, password);
            zip.start_file(sample_name, options).unwrap();
            zip.write_all(sample_content.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        let zip_bytes = zip_buffer.into_inner();

        let mut server = mockito::Server::new();
        let server_url = server.url();

        let _m = server
            .mock("GET", "/api/tenants/test-tenant/files/123/file")
            .with_status(200)
            .with_body(zip_bytes)
            .create();

        let client = crate::api::Client::new(
            server_url,
            crate::tests::api::client::TOKEN_TEST.to_string(),
            false,
            false,
        );

        // -- EXECUTE --
        let result = client.download_file_maybe_encrypted(
            &"123".to_string(),
            "test-tenant".to_string(),
            false,
            &Some(password.to_string()),
        );

        // -- ASSERT --
        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap(), sample_name);

        let expected_file_path = payloads_path.join(sample_name);
        assert!(expected_file_path.exists());

        let mut content = String::new();
        let mut file = fs::File::open(&expected_file_path).unwrap();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, sample_content);

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
}
