//! # Keycloak CLI
//!
//! Command-line tools for Keycloak Rust administration.

#![forbid(unsafe_code)]
#![deny(warnings)]
#![allow(clippy::uninlined_format_args)]

use clap::Parser;
use kc_cli::{
    cli::{Cli, Command},
    commands::{
        run_client, run_config, run_crypto, run_export, run_group, run_import, run_realm,
        run_role, run_status, run_user,
    },
    config::CliConfig,
    output::error,
};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load configuration
    let mut config = match CliConfig::load() {
        Ok(c) => c,
        Err(e) => {
            error(&format!("Failed to load configuration: {}", e));
            std::process::exit(1);
        }
    };

    // Execute command
    let result = match cli.command {
        Command::Realm(cmd) => {
            run_realm(cmd, &config, cli.server.as_deref(), cli.output).await
        }
        Command::User(cmd) => {
            run_user(
                cmd,
                &config,
                cli.server.as_deref(),
                cli.realm.as_deref(),
                cli.output,
            )
            .await
        }
        Command::Client(cmd) => {
            run_client(
                cmd,
                &config,
                cli.server.as_deref(),
                cli.realm.as_deref(),
                cli.output,
            )
            .await
        }
        Command::Role(cmd) => {
            run_role(
                cmd,
                &config,
                cli.server.as_deref(),
                cli.realm.as_deref(),
                cli.output,
            )
            .await
        }
        Command::Group(cmd) => {
            run_group(
                cmd,
                &config,
                cli.server.as_deref(),
                cli.realm.as_deref(),
                cli.output,
            )
            .await
        }
        Command::Export(args) => run_export(args, &config, cli.server.as_deref()).await,
        Command::Import(args) => run_import(args, &config, cli.server.as_deref()).await,
        Command::Crypto(cmd) => run_crypto(cmd, &config).await,
        Command::Config(cmd) => run_config(cmd, &mut config),
        Command::Status => run_status(&config, cli.server.as_deref()).await,
    };

    if let Err(e) = result {
        error(&e.to_string());
        std::process::exit(1);
    }
}
