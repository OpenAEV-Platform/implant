use std::sync::Arc;
use std::time::Duration;
use rustls::{ClientConfig, RootCertStore};
use ureq::{Agent, Request};

pub mod manage_inject;
pub mod manage_reporting;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub struct Client {
    http_client: Agent,
    server_url: String,
    token: String,
}

impl Client {
    pub fn new(server_url: String, token: String, unsecured_certificate: bool, with_proxy: bool) -> Client {
        let mut http_client = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .user_agent(format!("openbas-implant/{}", VERSION).as_str())
            .try_proxy_from_env(with_proxy);

        if unsecured_certificate {
            let config = ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            http_client = http_client.tls_config(Arc::new(config));
        }

        // Remove trailing slash
        let mut url = server_url;
        if url.ends_with('/') {
            url.pop();
        }
        // Initiate client
        Client {
            http_client: http_client.build(),
            server_url: url,
            token,
        }
    }

    pub fn post(&self, route: &str) -> Request {
        let api_route = format!("{}{}", self.server_url, route);
        let request = self.http_client.post(&api_route)
            .set("Authorization", &format!("Bearer {}", self.token));
        return request;
    }

    pub fn get(&self, route: &str) -> Request {
        let api_route = format!("{}{}", self.server_url, route);
        let request = self.http_client.get(&api_route)
            .set("Authorization", &format!("Bearer {}", self.token));
        return request;
    }
}