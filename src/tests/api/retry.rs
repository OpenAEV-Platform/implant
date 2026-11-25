use crate::api::manage_inject::UpdateInput;
use crate::api::retry::RetryPolicy;
use crate::api::Client;
use crate::common::constants::STATUS_INFO;
use crate::tests::api::client::TOKEN_TEST;
use crate::tests::api::tls_server::{serve_scripted_https, Received, Step};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const UPDATE_ANSWER: &str = r#"{"inject_id": "inject"}"#;
const PAYLOAD_ANSWER: &str =
    r#"{"payload_type": "Command", "command_executor": "sh", "command_content": "echo ok"}"#;

// Fast backoff so the tests stay short; same retry rules as the default policy.
fn fast_policy(total_budget: Duration) -> RetryPolicy {
    RetryPolicy {
        request_timeout: Duration::from_secs(5),
        total_budget,
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(100),
        client_error_retries: 2,
        client_error_delay: Duration::from_millis(20),
    }
}

fn client(url: String, policy: RetryPolicy) -> Client {
    // the scripted server uses a self-signed certificate
    Client::with_retry_policy(url, TOKEN_TEST.to_string(), true, false, policy)
}

fn complete(message: &str) -> UpdateInput {
    UpdateInput {
        execution_message: message.to_string(),
        execution_status: String::from(STATUS_INFO),
        execution_action: String::from("complete"),
        execution_duration: 1,
    }
}

fn received(log: &Arc<Mutex<Vec<Received>>>) -> Vec<Received> {
    log.lock().unwrap().clone()
}

#[test]
fn test_update_status_survives_dropped_connections_and_5xx() {
    // -- PREPARE --
    let (url, log) = serve_scripted_https(vec![
        Step::Drop,
        Step::Drop,
        Step::status(503, "busy"),
        Step::status(200, UPDATE_ANSWER),
    ]);
    let api = client(url, fast_policy(Duration::from_secs(30)));

    // -- EXECUTE --
    let result = api.update_status(
        "inject".to_string(),
        "agent".to_string(),
        "tenant".to_string(),
        complete("Payload completed"),
    );

    // -- ASSERT --
    assert!(
        result.is_ok(),
        "the complete trace must be delivered: {result:?}"
    );
    let requests = received(&log);
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().all(|r| r.request_line
        == "POST /api/tenants/tenant/injects/execution/agent/callback/inject HTTP/1.1"));
    let accepted: Vec<&Received> = requests
        .iter()
        .filter(|r| r.answered == Some(200))
        .collect();
    assert_eq!(
        accepted.len(),
        1,
        "the complete trace is received exactly once"
    );
    assert!(accepted[0].body.contains("Payload completed"));
}

#[test]
fn test_update_status_retries_429() {
    let (url, log) = serve_scripted_https(vec![
        Step::status(429, "slow down"),
        Step::status(200, UPDATE_ANSWER),
    ]);
    let api = client(url, fast_policy(Duration::from_secs(30)));

    let result = api.update_status(
        "inject".to_string(),
        "agent".to_string(),
        "tenant".to_string(),
        complete("done"),
    );

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(received(&log).len(), 2);
}

#[test]
fn test_update_status_keeps_retrying_client_errors() {
    let (url, log) = serve_scripted_https(vec![
        Step::status(404, "not yet"),
        Step::status(200, UPDATE_ANSWER),
    ]);
    let api = client(url, fast_policy(Duration::from_secs(30)));

    let result = api.update_status(
        "inject".to_string(),
        "agent".to_string(),
        "tenant".to_string(),
        complete("done"),
    );

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(received(&log).len(), 2);
}

#[test]
fn test_update_status_gives_up_when_budget_is_spent() {
    let (url, _log) = serve_scripted_https(vec![Step::status(503, "down"); 50]);
    let api = client(url, fast_policy(Duration::from_millis(300)));

    let started = Instant::now();
    let result = api.update_status(
        "inject".to_string(),
        "agent".to_string(),
        "tenant".to_string(),
        complete("done"),
    );

    let err = result
        .expect_err("a server down for the whole budget fails")
        .to_string();
    assert!(err.starts_with("HTTP 503"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn test_update_status_waits_for_a_slow_platform() {
    // -- PREPARE: an answer after 8 s, past the former 5 s request timeout --
    let (url, log) = serve_scripted_https(vec![Step::delayed(
        Duration::from_secs(8),
        200,
        UPDATE_ANSWER,
    )]);
    let api = Client::new(url, TOKEN_TEST.to_string(), true, false);

    // -- EXECUTE --
    let result = api.update_status(
        "inject".to_string(),
        "agent".to_string(),
        "tenant".to_string(),
        complete("done"),
    );

    // -- ASSERT --
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        received(&log).len(),
        1,
        "no second request while the first is pending"
    );
}

#[test]
fn test_payload_fetch_survives_a_dropped_connection() {
    let (url, log) = serve_scripted_https(vec![Step::Drop, Step::status(200, PAYLOAD_ANSWER)]);
    let api = client(url, fast_policy(Duration::from_secs(30)));

    let payload =
        crate::fetch_payload(&api, "inject", "agent", "tenant", Instant::now()).expect("payload");

    assert_eq!(payload.payload_type, "Command");
    let requests = received(&log);
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|r| r.request_line
        == "GET /api/tenants/tenant/injects/inject/agent/executable-payload HTTP/1.1"));
}

#[test]
fn test_payload_fetch_failure_reports_transport_error() {
    // -- PREPARE: no retry budget, so the dropped fetch is final, then the trace is accepted --
    let (url, log) = serve_scripted_https(vec![Step::Drop, Step::status(200, UPDATE_ANSWER)]);
    let api = client(url, fast_policy(Duration::ZERO));

    // -- EXECUTE --
    let payload = crate::fetch_payload(&api, "inject", "agent", "tenant", Instant::now());

    // -- ASSERT --
    assert!(payload.is_none());
    let requests = received(&log);
    assert_eq!(requests.len(), 2);
    let trace = &requests[1];
    assert!(trace.request_line.starts_with("POST "));
    assert!(
        trace.body.contains("\"execution_status\":\"ERROR\""),
        "{}",
        trace.body
    );
    assert!(
        trace.body.contains("Fail getting payload: transport error"),
        "{}",
        trace.body
    );
}

#[test]
fn test_payload_fetch_failure_reports_http_error() {
    let (url, log) = serve_scripted_https(vec![
        Step::status(404, "inject not found"),
        Step::status(200, UPDATE_ANSWER),
    ]);
    let api = client(url, fast_policy(Duration::from_secs(30)));

    let payload = crate::fetch_payload(&api, "inject", "agent", "tenant", Instant::now());

    assert!(payload.is_none());
    let requests = received(&log);
    assert_eq!(requests.len(), 2, "a 4xx payload answer is not retried");
    assert!(
        requests[1]
            .body
            .contains("Fail getting payload: HTTP 404: inject not found"),
        "{}",
        requests[1].body
    );
}

#[test]
fn test_backoff_is_bounded_and_jittered() {
    let policy = RetryPolicy::default();
    for attempt in 0..40 {
        let delay = policy.backoff(attempt);
        let full = policy
            .initial_backoff
            .saturating_mul(2u32.saturating_pow(attempt.min(16)))
            .min(policy.max_backoff);
        assert!(
            delay >= full / 2 && delay <= full,
            "attempt {attempt}: {delay:?}"
        );
    }
}
