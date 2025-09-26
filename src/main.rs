use clap::{arg, Parser};
use log::{error, info};
use rolling_file::{BasicRollingFileAppender, RollingConditionBasic};
use std::env;
use std::fs::create_dir_all;
use std::ops::Deref;
use std::panic;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use crate::api::manage_inject::{InjectorContractPayload, UpdateInput};
use crate::api::Client;
use crate::common::error_model::Error;
use crate::handle::handle_command::{compute_command, handle_command, handle_execution_command};
use crate::handle::handle_dns_resolution::handle_dns_resolution;
use crate::handle::handle_file_drop::handle_file_drop;
use crate::handle::handle_file_execute::handle_file_execute;

mod api;
mod common;
mod handle;
mod process;

#[cfg(test)]
mod tests;

pub static THREADS_CONTROL: AtomicBool = AtomicBool::new(true);
const ENV_PRODUCTION: &str = "production";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const PREFIX_LOG_NAME: &str = "openbas-implant.log";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // short: d for destination
    #[arg(short = 'd', long)]
    uri: String,
    #[arg(short, long)]
    token: String,
    #[arg(short = 's', long)]
    unsecured_certificate: String,
    #[arg(short, long)]
    with_proxy: String,
    #[arg(short, long)]
    agent_id: String,
    #[arg(short, long)]
    inject_id: String,
}

// Get and log all errors from the implant execution
pub fn set_error_hook() {
    panic::set_hook(Box::new(|panic_info| {
        let (filename, line) = panic_info
            .location()
            .map(|loc| (loc.file(), loc.line()))
            .unwrap_or(("<unknown>", 0));

        let cause = panic_info
            .payload()
            .downcast_ref::<String>()
            .map(String::deref);

        let cause = cause.unwrap_or_else(|| {
            panic_info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .unwrap_or("<cause unknown>")
        });
        error!("An error occurred in file {filename:?} line {line:?}: {cause:?}");
        // Send the error and logs to OpenAEV for the inject and agent concerned
        let args = Args::parse();
        let api = Client::new(
            args.uri,
            args.token,
            args.unsecured_certificate == "true",
            args.with_proxy == "true",
        );
        let _ = api.update_status(
            args.inject_id,
            args.agent_id,
            UpdateInput {
                execution_message: String::from(cause),
                execution_status: String::from("ERROR"),
                execution_duration: 0,
                execution_action: String::from("complete"),
            },
        );
    }));
}

pub fn mode() -> String {
    env::var("env").unwrap_or_else(|_| ENV_PRODUCTION.into())
}

pub fn handle_payload(
    inject_id: String,
    agent_id: String,
    api: &Client,
    contract_payload: &InjectorContractPayload,
    duration: Instant,
) {
    let mut prerequisites_code = 0;
    let mut execution_message = "Payload completed";
    let mut execution_status = "INFO";
    // region download files parameters
    if let Some(slice_arguments) = contract_payload.payload_arguments.as_deref() {
        // println!("Slice reference exists. Length: {}", slice_arguments.len());
        for argument in slice_arguments {
            // println!("Arg ID: {}", argument.key);
            if argument.r#type == "document" {
                // Download the file
                match &argument.default_value {
                    None => {
                        // Nothing to do but strange.
                    }
                    Some(uri) => {
                        let _ = api.download_file(uri, false);
                    }
                }
            }
        }
    }
    // endregion
    // region prerequisite execution
    let prerequisites_data = &contract_payload.payload_prerequisites;
    let empty_prerequisites = vec![];
    let prerequisites = match prerequisites_data {
        None => &empty_prerequisites,
        Some(args) => args,
    };
    for prerequisite in prerequisites.iter() {
        let mut check_status = 1;
        let check_cmd = &prerequisite.check_command;
        if check_cmd.is_some() && !check_cmd.clone().unwrap().is_empty() {
            let check_prerequisites = compute_command(check_cmd.as_ref().unwrap());
            check_status = handle_execution_command(
                "prerequisite_check",
                api,
                inject_id.clone(),
                agent_id.clone(),
                &check_prerequisites,
                &prerequisite.executor,
                true,
            );
        }
        // If exit 0, prerequisite are already satisfied
        if check_status != 0 {
            let install_prerequisites = compute_command(&prerequisite.get_command);
            prerequisites_code += handle_execution_command(
                "prerequisite_execution",
                api,
                inject_id.clone(),
                agent_id.clone(),
                &install_prerequisites,
                &prerequisite.executor,
                false,
            );
        }
    }
    // endregion
    // region implant execution
    // If prerequisites succeed to be executed, execute the command.
    if prerequisites_code == 0 {
        let payload_type = &contract_payload.payload_type;
        match payload_type.as_str() {
            "Command" => handle_command(inject_id.clone(), agent_id.clone(), api, contract_payload),
            "DnsResolution" => {
                handle_dns_resolution(inject_id.clone(), agent_id.clone(), api, contract_payload)
            }
            "Executable" => {
                handle_file_execute(inject_id.clone(), agent_id.clone(), api, contract_payload)
            }
            "FileDrop" => {
                handle_file_drop(inject_id.clone(), agent_id.clone(), api, contract_payload)
            }
            // "NetworkTraffic" => {}, // Not implemented yet
            _ => {
                let _ = api.update_status(
                    inject_id.clone(),
                    agent_id.clone(),
                    UpdateInput {
                        execution_message: String::from("Payload execution type not supported."),
                        execution_status: String::from("ERROR"),
                        execution_duration: duration.elapsed().as_millis(),
                        execution_action: String::from("complete"),
                    },
                );
            }
        }
    } else {
        execution_message = "Payload execution not executed due to dependencies failure.";
        execution_status = "ERROR";
    }
    // endregion
    // region cleanup execution
    // Cleanup command will be executed independently of the previous commands success.
    let cleanup = contract_payload.payload_cleanup_command.clone();
    if let Some(ref cleanup_value) = cleanup {
        if !cleanup_value.is_empty() {
            let executable_cleanup = compute_command(cleanup_value);
            let executor = contract_payload.payload_cleanup_executor.clone().unwrap();
            let _ = handle_execution_command(
                "cleanup_execution",
                api,
                inject_id.clone(),
                agent_id.clone(),
                &executable_cleanup,
                &executor,
                false,
            );
        }
    }
    // endregion
    let _ = api.update_status(
        inject_id.clone(),
        agent_id.clone(),
        UpdateInput {
            execution_message: String::from(execution_message),
            execution_status: String::from(execution_status),
            execution_duration: duration.elapsed().as_millis(),
            execution_action: String::from("complete"),
        },
    );
}

fn main() -> Result<(), Error> {
    set_error_hook();
    // region Init logger
    let duration = Instant::now();
    let current_exe_path = env::current_exe().unwrap();
    let parent_path = current_exe_path.parent().unwrap();
    let log_file = parent_path.join(PREFIX_LOG_NAME);

    // Resolve the payloads path and create it on the fly
    let folder_name = parent_path.file_name().unwrap().to_str().unwrap();
    let payloads_path = parent_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("payloads")
        .join(folder_name);
    create_dir_all(payloads_path).expect("Unable to create payload directory");

    let condition = RollingConditionBasic::new().daily();
    let file_appender = BasicRollingFileAppender::new(log_file, condition, 3).unwrap();
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .json()
        .with_writer(file_writer)
        .init();
    // endregion
    // region Process execution

    let args = Args::parse();
    info!("Starting OpenBAS implant {} {}", VERSION, mode());
    let api = Client::new(
        args.uri,
        args.token,
        args.unsecured_certificate == "true",
        args.with_proxy == "true",
    );
    let payload = api.get_executable_payload(args.inject_id.as_str(), args.agent_id.as_str());
    let contract_payload = payload.unwrap_or_else(|err| panic!("Fail getting payload {err}"));
    handle_payload(
        args.inject_id.clone(),
        args.agent_id.clone(),
        &api,
        &contract_payload,
        duration,
    );
    // endregion
    Ok(())
}
