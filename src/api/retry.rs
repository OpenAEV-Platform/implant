use crate::common::error_model::Error;
use log::{error, info, warn};
use reqwest::blocking::{RequestBuilder, Response};
use std::error::Error as StdError;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_RETRY_BUDGET_SECS: u64 = 300;

/// How the implant retries a request to the platform.
///
/// Transport errors (DNS, connect, TLS, proxy, timeout), 5xx and 429 answers are retried with a
/// bounded exponential backoff and jitter until `total_budget` is spent. Other 4xx answers are
/// retried `client_error_retries` times every `client_error_delay` when the caller allows it.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub request_timeout: Duration,
    pub total_budget: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub client_error_retries: u64,
    pub client_error_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS, DEFAULT_RETRY_BUDGET_SECS)
    }
}

impl RetryPolicy {
    pub fn from_secs(request_timeout_secs: u64, retry_budget_secs: u64) -> Self {
        RetryPolicy {
            request_timeout: Duration::from_secs(request_timeout_secs.max(1)),
            total_budget: Duration::from_secs(retry_budget_secs),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            client_error_retries: 20,
            client_error_delay: Duration::from_secs(10),
        }
    }

    /// Backoff before attempt `attempt + 1` (attempt starts at 0): exponential, capped, with
    /// jitter in [backoff / 2, backoff].
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.min(16));
        let backoff = self
            .initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff);
        let half = backoff / 2;
        half + jitter(backoff - half)
    }
}

fn jitter(range: Duration) -> Duration {
    let range_nanos = range.as_nanos() as u64;
    if range_nanos == 0 {
        return Duration::ZERO;
    }
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    // splitmix64 step, enough to spread concurrent implants
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    Duration::from_nanos(z % range_nanos)
}

/// The full error chain of a transport error: reqwest's own message omits the cause.
pub fn describe_transport_error(err: &reqwest::Error) -> String {
    let mut message = err.to_string();
    let mut current = err.source();
    while let Some(cause) = current {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        current = cause.source();
    }
    message
}

enum Failure {
    Transient(String),
    ClientError(String),
}

/// Sends the request `build` makes until it answers 2xx or the policy gives up.
///
/// `what` names the request in the implant log. The final error names a transport failure as
/// `transport error: ...` and an HTTP failure as `HTTP <status>: <body>`.
pub fn send_with_retry<F>(
    policy: &RetryPolicy,
    what: &str,
    retry_client_errors: bool,
    build: F,
) -> Result<Response, Error>
where
    F: Fn() -> RequestBuilder,
{
    let started = Instant::now();
    let mut transient_attempts: u32 = 0;
    let mut client_error_retries_left = policy.client_error_retries;
    loop {
        let failure = match build().send() {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return Ok(response);
                }
                let body = response
                    .text()
                    .unwrap_or_else(|_| "Unknown error".to_string());
                let message = format!("HTTP {}: {body}", status.as_u16());
                if status.is_server_error() || status.as_u16() == 429 {
                    Failure::Transient(message)
                } else {
                    Failure::ClientError(message)
                }
            }
            Err(err) => Failure::Transient(format!(
                "transport error: {}",
                describe_transport_error(&err)
            )),
        };
        match failure {
            Failure::Transient(message) => {
                let delay = policy.backoff(transient_attempts);
                if started.elapsed() + delay > policy.total_budget {
                    error!(
                        "{what} failed after {} attempt(s) in {:?}, giving up: {message}",
                        transient_attempts + 1,
                        started.elapsed()
                    );
                    return Err(final_error(message));
                }
                transient_attempts += 1;
                warn!("{what} failed (attempt {transient_attempts}), retrying in {delay:?}: {message}");
                sleep(delay);
            }
            Failure::ClientError(message) => {
                if !retry_client_errors || client_error_retries_left == 0 {
                    error!("{what} failed, giving up: {message}");
                    return Err(Error::Api(message));
                }
                client_error_retries_left -= 1;
                info!(
                    "{what} failed, retry {} left in {:?}: {message}",
                    client_error_retries_left, policy.client_error_delay
                );
                sleep(policy.client_error_delay);
            }
        }
    }
}

fn final_error(message: String) -> Error {
    if message.starts_with("HTTP ") {
        Error::Api(message)
    } else {
        Error::Internal(message)
    }
}
