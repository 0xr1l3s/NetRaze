use anyhow::Result;
use clap::{Parser, Subcommand};
use getexec_app::GetexecApp;
use getexec_config::AppConfig;
use getexec_core::ScanRequest;
use std::collections::BTreeMap;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "getexec", about = "CLI Rust de Getexec")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Protocols,
    Modules,
    Plan {
        protocol: String,
        #[arg(required = true)]
        targets: Vec<String>,
        #[arg(long)]
        module: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let cli = Cli::parse();
    let app = GetexecApp::bootstrap(AppConfig::default());

    match cli.command {
        Command::Protocols => {
            for protocol in app.protocol_catalog() {
                println!(
                    "{} ({}) port {}",
                    protocol.display_name, protocol.key, protocol.default_port
                );
            }
        }
        Command::Modules => {
            for module in app.module_catalog() {
                println!("{} [{}]", module.key, module.supported_protocols.join(", "));
            }
        }
        Command::Plan {
            protocol,
            targets,
            module,
        } => {
            let plan = app
                .plan_scan(ScanRequest {
                    protocol,
                    raw_targets: targets,
                    selected_module: module,
                    options: BTreeMap::new(),
                })
                .await?;
            println!(
                "plan: protocol={} targets={} threads={} timeout={}s",
                plan.request.protocol,
                plan.request.raw_targets.len(),
                plan.concurrency,
                plan.timeout_seconds
            );
        }
    }

    Ok(())
}
