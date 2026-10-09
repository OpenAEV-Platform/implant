pub const TOKEN_TEST: &str = "token";

#[cfg(test)]
mod tests {
    use crate::api::{Client, AUTHORIZATION_HEADER};
    use crate::tests::api::client::TOKEN_TEST;
    use mockito;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
    use std::env;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    // Serves HTTPS on a loopback port with a fresh self-signed certificate and returns its URL.
    fn serve_self_signed_https() -> String {
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certified.cert.der().clone()], key.into())
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut tls =
                    StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), stream);
                // a client rejecting the certificate aborts the handshake, so this read fails
                let mut request = [0u8; 4096];
                if tls.read(&mut request).is_ok() {
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
            }
        });
        url
    }

    #[test]
    fn test_client_headers() {
        // -- PREPARE
        let mut server = mockito::Server::new();
        let server_url = server.url();
        server
            .mock("POST", "/api/test")
            .match_header(
                "user-agent",
                format!("openaev-implant/{}", crate::api::VERSION).as_str(),
            )
            .match_header(
                AUTHORIZATION_HEADER,
                format!("Bearer {}", TOKEN_TEST).as_str(),
            )
            .with_status(200)
            .create();
        let client = Client::new(server_url, TOKEN_TEST.to_string(), false, false);

        // -- EXECUTE & ASSERT --
        let res = client.post("/api/test").send();
        assert!(res.is_ok(), "User-Agent should match expected format");
    }

    #[test]
    fn test_with_proxy_disables_http_proxy() {
        // -- PREPARE --
        env::set_var("HTTP_PROXY", "http://127.0.0.1:9999");

        let mut server = mockito::Server::new();
        let server_url = server.url();
        server.mock("POST", "/api/test").with_status(200).create();
        let client_without_proxy =
            Client::new(server_url.clone(), TOKEN_TEST.to_string(), false, false);
        let client_with_proxy =
            Client::new(server_url.clone(), TOKEN_TEST.to_string(), false, true);

        // -- EXECUTE --
        let res_without_proxy = client_without_proxy.post("/api/test").send();
        let res_with_proxy = client_with_proxy.post("/api/test").send();

        // -- ASSERT --
        assert!(res_without_proxy.is_ok(), "Client should bypass the proxy");
        assert!(
            res_with_proxy.is_err(),
            "Client should not bypass the proxy"
        );

        // -- CLEAN --
        env::remove_var("HTTP_PROXY");
    }

    #[test]
    fn test_unsecured_certificate_acceptance() {
        // -- PREPARE --
        let url = serve_self_signed_https();
        let client_without_unsecured_certificate =
            Client::new(url.clone(), TOKEN_TEST.to_string(), false, false);
        let client_with_unsecured_certificate =
            Client::new(url, TOKEN_TEST.to_string(), true, false);

        // -- EXECUTE --
        let res_without_unsecured_certificate = client_without_unsecured_certificate.get("").send();
        let res_with_unsecured_certificate = client_with_unsecured_certificate.get("").send();

        // -- ASSERT --
        assert!(
            res_without_unsecured_certificate.is_err(),
            "Client should not bypass the bad ssl"
        );
        assert!(
            res_with_unsecured_certificate.is_ok(),
            "Client should bypass the bad ssl when unsecured: {:?}",
            res_with_unsecured_certificate.err()
        );
    }

    #[test]
    fn test_bundled_roots_trust_a_public_chain() {
        // -- PREPARE --
        // chain served by sha256.badssl.com, issued by Let's Encrypt and cross-signed by ISRG Root X1
        let mut chain =
            CertificateDer::pem_slice_iter(include_bytes!("fixtures/sha256.badssl.com.pem"))
                .map(|cert| cert.unwrap());
        let end_entity = chain.next().unwrap();
        let intermediates: Vec<_> = chain.collect();
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        // 2026-10-09, inside the chain's validity window so its expiry never fails the test
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_791_504_000));

        // -- EXECUTE --
        let res = verifier.verify_server_cert(
            &end_entity,
            &intermediates,
            &ServerName::try_from("sha256.badssl.com").unwrap(),
            &[],
            now,
        );

        // -- ASSERT --
        assert!(
            res.is_ok(),
            "Bundled roots should trust a publicly valid certificate: {res:?}"
        );
    }

    #[test]
    #[ignore = "requires the os-trust-store CI job"]
    fn test_os_trust_store_is_consulted() {
        // -- PREPARE --
        let url = env::var("OAEV_OS_TRUST_URL")
            .expect("OAEV_OS_TRUST_URL must be set by the os-trust-store CI job");
        let client = Client::new(url, TOKEN_TEST.to_string(), false, false);

        // -- EXECUTE & ASSERT --
        assert!(
            client.get("").send().is_ok(),
            "Client should trust a CA present only in the OS trust store"
        );
    }
}
