use std::time::Duration;

pub mod manage_inject;
pub mod manage_reporting;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AUTHORIZATION_HEADER: &str = "Authorization";

#[derive(Debug)]
pub struct Client {
    http_client: reqwest::blocking::Client,
    server_url: String,
    token: String,
}

impl Client {
    pub fn new(
        server_url: String,
        token: String,
        unsecured_certificate: bool,
        with_proxy: bool,
    ) -> Client {
        let mut http_client = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .user_agent(format!("openaev-implant/{VERSION}"));
        if !with_proxy {
            http_client = http_client.no_proxy();
        }
        if unsecured_certificate {
            http_client = http_client.danger_accept_invalid_certs(true);
        }
        // Remove trailing slash
        let mut url = server_url;
        if url.ends_with('/') {
            url.pop();
        }
        // Initiate client
        Client {
            http_client: http_client.build().unwrap(),
            server_url: url,
            token,
        }
    }

    pub fn post(&self, route: &str) -> reqwest::blocking::RequestBuilder {
        let api_route = format!("{}{}", self.server_url, route);

        self.http_client
            .post(&api_route)
            .header(AUTHORIZATION_HEADER, &format!("Bearer {}", self.token))
    }

    pub fn get(&self, route: &str) -> reqwest::blocking::RequestBuilder {
        let api_route = format!("{}{}", self.server_url, route);

        self.http_client
            .get(&api_route)
            .header(AUTHORIZATION_HEADER, &format!("Bearer {}", self.token))
    }
}
