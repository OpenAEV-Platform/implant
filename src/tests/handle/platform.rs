use mockito::{Matcher, Mock, ServerGuard};
use serde_json::json;
use std::time::{Duration, Instant};

pub const TENANT_ID: &str = "tenant";
pub const AGENT_ID: &str = "agent";
pub const INJECT_ID: &str = "inject";
pub const TOKEN: &str = "token";

pub fn mock_callback(server: &mut ServerGuard, body: Matcher) -> Mock {
    server
        .mock(
            "POST",
            format!("/api/tenants/{TENANT_ID}/injects/execution/{AGENT_ID}/callback/{INJECT_ID}")
                .as_str(),
        )
        .match_body(body)
        .with_status(200)
        .with_body(json!({ "inject_id": INJECT_ID }).to_string())
        .create()
}

pub fn started_five_seconds_ago() -> Instant {
    Instant::now().checked_sub(Duration::from_secs(5)).unwrap()
}

pub fn duration_since_five_seconds_ago() -> Matcher {
    Matcher::Regex(r#""execution_duration":5\d{3}[,}]"#.to_string())
}
