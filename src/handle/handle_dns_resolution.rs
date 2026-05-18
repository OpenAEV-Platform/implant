use std::net::{SocketAddr, ToSocketAddrs};

use log::info;

use crate::api::manage_inject::{InjectorContractPayload, UpdateInput};
use crate::api::Client;
use crate::common::constants::{STATUS_ERROR, STATUS_SUCCESS};
use crate::handle::ExecutionOutput;

pub fn handle_dns_resolution(
    inject_id: String,
    agent_id: String,
    tenant_id: String,
    api: &Client,
    contract_payload: &InjectorContractPayload,
) {
    let hostname_raw = &contract_payload.dns_resolution_hostname;
    let data = hostname_raw.clone().unwrap();
    let hostnames = data.split("\n");
    for hostname in hostnames {
        // to_socket_addrs required a port to check. By default, using http 80.
        info!("dns resolution execution: {:?}", format!("{}:80", hostname));
        let addrs_command = format!("{hostname}:80").to_socket_addrs();
        let input = match addrs_command {
            Ok(addrs) => {
                let stdout = format!(
                    "{hostname}: {}",
                    addrs
                        .map(|socket_addr: SocketAddr| {
                            match socket_addr {
                                SocketAddr::V4(v4) => v4.ip().to_string(),
                                SocketAddr::V6(v6) => v6.ip().to_string(),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                let stderr = String::new();
                let message = ExecutionOutput {
                    stdout,
                    stderr,
                    exit_code: 0,
                };
                UpdateInput {
                    execution_message: serde_json::to_string(&message).unwrap(),
                    execution_status: String::from(STATUS_SUCCESS),
                    execution_duration: 0,
                    execution_action: String::from("dns_resolution"),
                }
            }
            Err(error) => {
                let stdout = String::new();
                let stderr = error.to_string();
                let message = ExecutionOutput {
                    stdout,
                    stderr,
                    exit_code: 1,
                };
                UpdateInput {
                    execution_message: serde_json::to_string(&message).unwrap(),
                    execution_status: String::from(STATUS_ERROR),
                    execution_duration: 0,
                    execution_action: String::from("dns_resolution"),
                }
            }
        };
        let _ = api.update_status(
            inject_id.clone(),
            agent_id.clone(),
            tenant_id.clone(),
            input,
        );
    }
}
