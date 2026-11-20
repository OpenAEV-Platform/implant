use crate::api::manage_inject::InjectorContractPayload;
use crate::api::Client;
use crate::handle::handle_dns_resolution::handle_dns_resolution;
use crate::tests::handle::platform::{
    duration_since_five_seconds_ago, mock_callback, started_five_seconds_ago, AGENT_ID, INJECT_ID,
    TENANT_ID, TOKEN,
};
use serde_json::json;

#[test]
fn test_handle_dns_resolution_sends_time_since_start() {
    // -- PREPARE --
    let mut server = mockito::Server::new();
    let trace_with_time_since_start = mock_callback(&mut server, duration_since_five_seconds_ago());
    let client = Client::new(server.url(), TOKEN.to_string(), false, false);
    let payload: InjectorContractPayload = serde_json::from_value(json!({
        "payload_type": "DnsResolution",
        "dns_resolution_hostname": "localhost",
    }))
    .unwrap();

    // -- EXECUTE --
    handle_dns_resolution(
        INJECT_ID.to_string(),
        AGENT_ID.to_string(),
        TENANT_ID.to_string(),
        &client,
        &payload,
        started_five_seconds_ago(),
    );

    // -- ASSERT --
    trace_with_time_since_start.assert();
}
