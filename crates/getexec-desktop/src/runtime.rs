use serde::{Deserialize, Serialize};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{Duration, sleep};

use getexec_protocols::smb::{SmbClient, SmbCredential, SmbScanResult, list_directory, download_file, upload_file, create_directory, delete_remote_file, delete_remote_directory, remote_dump_sam, remote_dump_lsa, enum_av, smb_fingerprint, execute_command_live};
use getexec_protocols::smb::connection::is_port_open;
use getexec_protocols::targets::parse_target_list;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Success,
    Error,
}

#[derive(Debug, Clone)]
pub enum RuntimeEvent {
    Log { level: LogLevel, message: String },
    SmbResult(Box<SmbScanResult>),
    ScanProgress { done: usize, total: usize },
    ScanStarted { target_label: String },
    ScanFinished,
    LoginResult {
        ip: String,
        cred_label: String,
        success: bool,
        admin: bool,
    },
    ShareEnumResult {
        host_node_id: usize,
        ip: String,
        hostname: String,
        shares: Vec<String>,
    },
    BrowseResult {
        browser_id: usize,
        entries: Vec<(String, bool, u64)>,
        error: Option<String>,
    },
    FileOpResult {
        browser_id: usize,
        success: bool,
        message: String,
    },
    UserEnumResult {
        host_node_id: usize,
        ip: String,
        hostname: String,
        users: Vec<(String, bool, bool, u32)>, // (name, disabled, locked, priv_level)
    },
    DumpResult {
        host_node_id: usize,
        ip: String,
        hostname: String,
        dump_type: String,
        entries: Vec<String>,
        error: Option<String>,
    },
    EnumAvResult {
        host_node_id: usize,
        ip: String,
        hostname: String,
        products: Vec<String>,
        error: Option<String>,
    },
    FingerprintResult {
        ip: String,
        hostname: String,
        domain: String,
        os_info: String,
        signing: bool,
        smbv1: bool,
    },
    ExecResult {
        console_id: u64,
        command: String,
        output: String,
        error: Option<String>,
    },
}

// Keep backward compat alias
pub type RuntimeLogEvent = RuntimeEvent;

#[derive(Debug)]
pub struct RuntimeServices {
    runtime: Runtime,
    log_tx: UnboundedSender<RuntimeEvent>,
}

impl RuntimeServices {
    pub fn new(log_tx: UnboundedSender<RuntimeEvent>) -> Self {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Impossible de creer le runtime tokio");

        Self { runtime, log_tx }
    }

    pub fn spawn_heartbeat(&self) {
        self.runtime.spawn(async move {
            loop {
                sleep(Duration::from_secs(5)).await;
            }
        });
    }

    /// Launch a real SMB scan against one or more targets.
    /// Supports CIDR notation, IP ranges, and single IPs.
    /// Does a port 445 pre-scan to filter live hosts before full enumeration.
    pub fn spawn_smb_scan(
        &self,
        raw_targets: Vec<String>,
        credential: Option<SmbCredential>,
        threads: usize,
        timeout_seconds: u64,
    ) {
        let tx = self.log_tx.clone();

        self.runtime.spawn(async move {
            // Send the original target string for subnet label
            let target_label = raw_targets.join(", ");
            let _ = tx.send(RuntimeEvent::ScanStarted {
                target_label: target_label.clone(),
            });

            // Phase 1: Expand CIDR/ranges into individual IPs
            let all_ips: Vec<String> = raw_targets
                .iter()
                .flat_map(|t| parse_target_list(t))
                .collect();

            let total_ips = all_ips.len();
            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Info,
                message: format!(
                    "Expansion des cibles: {} entrée(s) → {} IP(s)",
                    raw_targets.len(),
                    total_ips
                ),
            });

            if total_ips == 0 {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Error,
                    message: "Aucune cible valide".to_owned(),
                });
                let _ = tx.send(RuntimeEvent::ScanFinished);
                return;
            }

            // Phase 2: Port 445 pre-scan (parallel via spawn_blocking)
            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Info,
                message: format!("Pré-scan port 445 sur {} IP(s)...", total_ips),
            });

            let timeout_ms = (timeout_seconds * 1000).min(3000);
            let chunk_size = threads.max(1);
            let mut live_hosts: Vec<String> = Vec::new();
            let mut scanned: usize = 0;

            for chunk in all_ips.chunks(chunk_size) {
                let mut handles = Vec::new();
                for ip in chunk {
                    let ip_clone = ip.clone();
                    handles.push(tokio::task::spawn_blocking(move || {
                        let open = is_port_open(&ip_clone, 445, timeout_ms);
                        (ip_clone, open)
                    }));
                }

                for handle in handles {
                    if let Ok((ip, open)) = handle.await {
                        scanned += 1;
                        if open {
                            live_hosts.push(ip.clone());
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Success,
                                message: format!("  ✓ {} port 445 ouvert", ip),
                            });
                        }
                        let _ = tx.send(RuntimeEvent::ScanProgress {
                            done: scanned,
                            total: total_ips + live_hosts.len() * 5, // estimate
                        });
                    }
                }
            }

            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Info,
                message: format!(
                    "Pré-scan terminé: {}/{} hôte(s) avec port 445 ouvert",
                    live_hosts.len(),
                    total_ips
                ),
            });

            if live_hosts.is_empty() {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Warning,
                    message: "Aucun hôte avec port 445 ouvert".to_owned(),
                });
                let _ = tx.send(RuntimeEvent::ScanFinished);
                return;
            }

            // Phase 3: Full SMB enumeration on live hosts
            let total_live = live_hosts.len();
            // total_steps = pre-scan done + 5 steps per live host
            let total_steps = total_ips + total_live * 5;
            let mut step = total_ips; // pre-scan already done

            for (idx, target) in live_hosts.iter().enumerate() {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!(
                        "[{}/{}] SMB scan: {}...",
                        idx + 1,
                        total_live,
                        target
                    ),
                });

                let mut client = SmbClient::new(target);
                if let Some(ref cred) = credential {
                    client = client.with_credential(cred.clone());
                }

                // Step 0: Fingerprint (no auth needed)
                {
                    let fp_target = target.clone();
                    let fp_tx = tx.clone();
                    let fp_result = tokio::task::spawn_blocking(move || smb_fingerprint(&fp_target)).await;
                    if let Ok(Ok(fp)) = fp_result {
                        let nxc_line = fp.nxc_line(target);
                        let _ = fp_tx.send(RuntimeEvent::Log {
                            level: LogLevel::Success,
                            message: nxc_line,
                        });
                        let _ = fp_tx.send(RuntimeEvent::FingerprintResult {
                            ip: target.clone(),
                            hostname: fp.hostname,
                            domain: if fp.dns_domain.is_empty() { fp.domain } else { fp.dns_domain },
                            os_info: fp.os_info,
                            signing: fp.signing,
                            smbv1: fp.smbv1,
                        });
                    }
                }

                // Step 1: Connect
                let connect_err = client.connect().await.err();
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                if let Some(err) = connect_err {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{}: ERREUR connexion - {}", target, err),
                    });
                    let result = SmbScanResult {
                        target: target.clone(),
                        hostname: None,
                        os_info: None,
                        signing: None,
                        smb_version: None,
                        shares: Vec::new(),
                        users: Vec::new(),
                        admin: false,
                        error: Some(err),
                    };
                    let _ = tx.send(RuntimeEvent::SmbResult(Box::new(result)));
                    step += 4;
                    let _ = tx.send(RuntimeEvent::ScanProgress {
                        done: step,
                        total: total_steps,
                    });
                    continue;
                }

                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!("{}: connecté, récupération infos...", target),
                });

                // Step 2: Server info
                let server_info = client.server_info().await.ok();
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                if let Some(ref si) = server_info {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Info,
                        message: format!("{}: {} ({})", target, si.name, si.os_version),
                    });
                }

                // Step 3: Shares (with access checks)
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!("{}: énumération des partages...", target),
                });
                let shares = client.enum_shares_with_access().await.unwrap_or_default();
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                for share in &shares {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Info,
                        message: format!(
                            "  {} [{}] ({}) {}",
                            share.name,
                            share.share_type.display_str(),
                            share.access.display_str(),
                            share.remark
                        ),
                    });
                }

                // Step 4: Admin check
                let admin = client.check_admin().await;
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                // Step 5: Users (if admin) + disconnect
                let mut users = Vec::new();
                if admin {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{}: Pwn3d! (accès admin)", target),
                    });
                    users = client.enum_users().await.unwrap_or_default();
                    for user in &users {
                        let utag = if user.disabled {
                            "DISABLED"
                        } else if user.locked {
                            "LOCKED"
                        } else {
                            "ACTIVE"
                        };
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Info,
                            message: format!("  User: {} [{}]", user.name, utag),
                        });
                    }
                }
                client.disconnect().await;
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                let admin_tag = if admin { " (Pwn3d!)" } else { "" };
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Success,
                    message: format!(
                        "{}: {} - {} partage(s){}",
                        target,
                        server_info
                            .as_ref()
                            .map(|s| s.name.as_str())
                            .unwrap_or("?"),
                        shares.len(),
                        admin_tag
                    ),
                });

                let result = SmbScanResult {
                    target: target.clone(),
                    hostname: server_info.as_ref().map(|s| s.name.clone()),
                    os_info: server_info.as_ref().map(|s| s.os_version.clone()),
                    signing: None,
                    smb_version: None,
                    shares,
                    users,
                    admin,
                    error: None,
                };
                let _ = tx.send(RuntimeEvent::SmbResult(Box::new(result)));
            }

            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Success,
                message: "SMB scan terminé".to_owned(),
            });
            let _ = tx.send(RuntimeEvent::ScanFinished);
        });
    }

    pub fn emit_log(&self, level: LogLevel, message: impl Into<String>) {
        let _ = self.log_tx.send(RuntimeEvent::Log {
            level,
            message: message.into(),
        });
    }

    pub fn emit_error(&self, message: impl Into<String>) {
        self.emit_log(LogLevel::Error, message);
    }

    /// Attempt SMB login to a host with given credentials.
    pub fn spawn_login_attempt(
        &self,
        ip: String,
        username: String,
        domain: String,
        secret: String,
        cred_type: crate::state::CredType,
    ) {
        let tx = self.log_tx.clone();
        let cred_label = if domain.is_empty() {
            format!(".\\{username}")
        } else {
            format!("{domain}\\{username}")
        };
        let cred_label_clone = cred_label.clone();

        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{}: tentative login en tant que {cred_label}...", ip),
        });

        self.runtime.spawn(async move {
            let smb_cred = match cred_type {
                crate::state::CredType::Hash => {
                    match SmbCredential::with_hash(&username, &domain, &secret) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("{ip}: hash invalide: {e}"),
                            });
                            let _ = tx.send(RuntimeEvent::LoginResult {
                                ip,
                                cred_label: cred_label_clone,
                                success: false,
                                admin: false,
                            });
                            return;
                        }
                    }
                }
                crate::state::CredType::Password => {
                    SmbCredential::new(&username, &domain, &secret)
                }
            };
            let mut client = SmbClient::new(&ip).with_credential(smb_cred);
            let success = client.connect().await.is_ok();
            let mut admin = false;

            if success {
                admin = client.check_admin().await;
                client.disconnect().await;
            }

            let admin_tag = if admin { " (Pwn3d!)" } else { "" };
            let _ = tx.send(RuntimeEvent::Log {
                level: if success { LogLevel::Success } else { LogLevel::Error },
                message: if success {
                    format!("{}: ✔ login réussi en tant que {cred_label_clone}{admin_tag}", ip)
                } else {
                    format!("{}: ✘ login échoué pour {cred_label_clone}", ip)
                },
            });

            let _ = tx.send(RuntimeEvent::LoginResult {
                ip,
                cred_label: cred_label_clone,
                success,
                admin,
            });
        });
    }

    /// Enumerate shares on a host and send result back.
    pub fn spawn_share_enum(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: énumération des shares..."),
        });

        let ip_clone = ip.clone();
        let hostname_clone = hostname.clone();
        self.runtime.spawn(async move {
            let mut client = SmbClient::new(&ip_clone);
            let result = client.connect().await;
            let shares = if result.is_ok() {
                match client.enum_shares_with_access().await {
                    Ok(shares) => {
                        let formatted: Vec<String> = shares.iter().map(|s| {
                            format!("{} [{}] ({})", s.name, s.share_type.display_str(), s.access.display_str())
                        }).collect();
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Success,
                            message: format!("{ip_clone}: {} share(s) trouvé(s)", formatted.len()),
                        });
                        client.disconnect().await;
                        formatted
                    }
                    Err(e) => {
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Error,
                            message: format!("{ip_clone}: erreur enum shares: {e}"),
                        });
                        client.disconnect().await;
                        Vec::new()
                    }
                }
            } else {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Error,
                    message: format!("{ip_clone}: connexion échouée pour enum shares"),
                });
                Vec::new()
            };

            let _ = tx.send(RuntimeEvent::ShareEnumResult {
                host_node_id,
                ip: ip_clone,
                hostname: hostname_clone,
                shares,
            });
        });
    }

    pub fn spawn_user_enum(&self, host_node_id: usize, ip: String, hostname: String) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: énumération des utilisateurs..."),
        });

        let ip_clone = ip.clone();
        let hostname_clone = hostname.clone();
        self.runtime.spawn(async move {
            let target = format!("\\\\{ip_clone}");
            let result = tokio::task::spawn_blocking(move || {
                getexec_protocols::smb::users::enum_users(&target)
            }).await;

            let users = match result {
                Ok(Ok(user_list)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{ip_clone}: {} utilisateur(s) trouvé(s)", user_list.len()),
                    });
                    user_list.into_iter().map(|u| (u.name, u.disabled, u.locked, u.privilege_level)).collect()
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip_clone}: erreur enum users: {e}"),
                    });
                    Vec::new()
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip_clone}: task panic: {e}"),
                    });
                    Vec::new()
                }
            };

            let _ = tx.send(RuntimeEvent::UserEnumResult {
                host_node_id,
                ip: ip_clone,
                hostname: hostname_clone,
                users,
            });
        });
    }

    pub fn spawn_dump_sam(&self, host_node_id: usize, ip: String, hostname: String) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: SAM dump en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        self.runtime.spawn(async move {
            let ip3 = ip2.clone();
            let result = tokio::task::spawn_blocking(move || remote_dump_sam(&ip3)).await;

            let (entries, error) = match result {
                Ok(Ok(dump)) => {
                    let lines: Vec<String> = dump.hashes.iter().map(|h| h.to_string()).collect();
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{ip2}: SAM dump — {} hash(es)", lines.len()),
                    });
                    let err = if dump.errors.is_empty() {
                        None
                    } else {
                        Some(dump.errors.join("; "))
                    };
                    (lines, err)
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: SAM dump failed: {e}"),
                    });
                    (Vec::new(), Some(e))
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: SAM task panic: {e}"),
                    });
                    (Vec::new(), Some(format!("task panic: {e}")))
                }
            };

            let _ = tx.send(RuntimeEvent::DumpResult {
                host_node_id,
                ip: ip2,
                hostname: hostname2,
                dump_type: "SAM".to_string(),
                entries,
                error,
            });
        });
    }

    pub fn spawn_dump_lsa(&self, host_node_id: usize, ip: String, hostname: String) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: LSA dump en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        self.runtime.spawn(async move {
            let ip3 = ip2.clone();
            let result = tokio::task::spawn_blocking(move || remote_dump_lsa(&ip3)).await;

            let (entries, error) = match result {
                Ok(Ok(dump)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{ip2}: LSA dump — {} secret(s)", dump.secrets.len()),
                    });
                    let err = if dump.errors.is_empty() {
                        None
                    } else {
                        Some(dump.errors.join("; "))
                    };
                    (dump.secrets, err)
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: LSA dump failed: {e}"),
                    });
                    (Vec::new(), Some(e))
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: LSA task panic: {e}"),
                    });
                    (Vec::new(), Some(format!("task panic: {e}")))
                }
            };

            let _ = tx.send(RuntimeEvent::DumpResult {
                host_node_id,
                ip: ip2,
                hostname: hostname2,
                dump_type: "LSA".to_string(),
                entries,
                error,
            });
        });
    }

    pub fn spawn_enum_av(&self, host_node_id: usize, ip: String, hostname: String, username: String, domain: String, secret: String) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: AV/EDR enumeration en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        self.runtime.spawn(async move {
            let ip3 = ip2.clone();
            let cred = SmbCredential::new(&username, &domain, &secret);
            let result = tokio::task::spawn_blocking(move || enum_av(&ip3, Some(&cred))).await;

            let (products, error) = match result {
                Ok(av_result) => {
                    let lines: Vec<String> = av_result.products.iter().map(|p| p.to_line()).collect();
                    if lines.is_empty() {
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Warning,
                            message: format!("{ip2}: No AV/EDR detected"),
                        });
                    } else {
                        for p in &av_result.products {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Success,
                                message: format!("{ip2}: Found {} {}", p.name, p.status_label()),
                            });
                        }
                    }
                    let err = if av_result.errors.is_empty() {
                        None
                    } else {
                        Some(av_result.errors.join("; "))
                    };
                    (lines, err)
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: AV enum task panic: {e}"),
                    });
                    (Vec::new(), Some(format!("task panic: {e}")))
                }
            };

            let _ = tx.send(RuntimeEvent::EnumAvResult {
                host_node_id,
                ip: ip2,
                hostname: hostname2,
                products,
                error,
            });
        });
    }

    pub fn spawn_browse_directory(&self, browser_id: usize, unc_path: String) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(move || list_directory(&unc_path)).await;

            match result {
                Ok(Ok(entries)) => {
                    let mapped: Vec<(String, bool, u64)> = entries
                        .into_iter()
                        .map(|e| (e.name, e.is_dir, e.size))
                        .collect();
                    let _ = tx.send(RuntimeEvent::BrowseResult {
                        browser_id,
                        entries: mapped,
                        error: None,
                    });
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::BrowseResult {
                        browser_id,
                        entries: Vec::new(),
                        error: Some(e),
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::BrowseResult {
                        browser_id,
                        entries: Vec::new(),
                        error: Some(format!("task panicked: {e}")),
                    });
                }
            }
        });
    }

    pub fn spawn_download(&self, browser_id: usize, remote_unc: String, local_path: String) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let r = remote_unc.clone();
            let l = local_path.clone();
            let result = tokio::task::spawn_blocking(move || download_file(&r, &l)).await;
            match result {
                Ok(Ok(())) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: true,
                        message: format!("Downloaded to {local_path}"),
                    });
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: false,
                        message: e,
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: false,
                        message: format!("task panicked: {e}"),
                    });
                }
            }
        });
    }

    pub fn spawn_upload(&self, browser_id: usize, local_path: String, remote_unc: String) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let l = local_path.clone();
            let r = remote_unc.clone();
            let result = tokio::task::spawn_blocking(move || upload_file(&l, &r)).await;
            match result {
                Ok(Ok(())) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: true,
                        message: "Upload complete".to_string(),
                    });
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: false,
                        message: e,
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: false,
                        message: format!("task panicked: {e}"),
                    });
                }
            }
        });
    }

    pub fn spawn_create_folder(&self, browser_id: usize, unc_path: String) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let p = unc_path.clone();
            let result = tokio::task::spawn_blocking(move || create_directory(&p)).await;
            match result {
                Ok(Ok(())) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: true,
                        message: "Folder created".to_string(),
                    });
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: false,
                        message: e,
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: false,
                        message: format!("task panicked: {e}"),
                    });
                }
            }
        });
    }

    pub fn spawn_delete(&self, browser_id: usize, unc_path: String, is_dir: bool) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let p = unc_path.clone();
            let result = tokio::task::spawn_blocking(move || {
                if is_dir {
                    delete_remote_directory(&p)
                } else {
                    delete_remote_file(&p)
                }
            }).await;
            match result {
                Ok(Ok(())) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: true,
                        message: "Deleted".to_string(),
                    });
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: false,
                        message: e,
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::FileOpResult {
                        browser_id,
                        success: false,
                        message: format!("task panicked: {e}"),
                    });
                }
            }
        });
    }

    /// Fingerprint a host via raw SMB2 negotiate + NTLMSSP challenge (no auth needed).
    pub fn spawn_fingerprint(&self, ip: String) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: SMB fingerprint en cours..."),
        });

        self.runtime.spawn(async move {
            let ip2 = ip.clone();
            let result = tokio::task::spawn_blocking(move || smb_fingerprint(&ip2)).await;

            match result {
                Ok(Ok(fp)) => {
                    let nxc_line = fp.nxc_line(&ip);
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: nxc_line,
                    });
                    let _ = tx.send(RuntimeEvent::FingerprintResult {
                        ip,
                        hostname: fp.hostname,
                        domain: if fp.dns_domain.is_empty() { fp.domain } else { fp.dns_domain },
                        os_info: fp.os_info,
                        signing: fp.signing,
                        smbv1: fp.smbv1,
                    });
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Warning,
                        message: format!("{ip}: fingerprint failed: {e}"),
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Warning,
                        message: format!("{ip}: fingerprint task panic: {e}"),
                    });
                }
            }
        });
    }

    /// Execute a command on a remote host via SMB (smbexec-style).
    /// Requires admin credentials. Output is sent back via `ExecResult`.
    pub fn spawn_exec_command(
        &self,
        console_id: u64,
        ip: String,
        username: String,
        domain: String,
        secret: String,
        cred_type: crate::state::CredType,
        command: String,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: exec `{command}`"),
        });

        self.runtime.spawn(async move {
            let cmd_for_task = command.clone();
            let ip_for_task = ip.clone();
            // Clone the log channel into the blocking task so every trace line
            // from execute_command_live streams to the UI immediately. This is
            // essential for diagnosing hangs: if the function blocks on a Win32
            // call we still see the last log before the hang.
            let live_tx = tx.clone();
            let ip_for_log = ip.clone();
            let result = tokio::task::spawn_blocking(move || {
                let cred = match cred_type {
                    crate::state::CredType::Hash => {
                        match SmbCredential::with_hash(&username, &domain, &secret) {
                            Ok(c) => c,
                            Err(e) => {
                                return (
                                    Err(format!("hash invalide: {e}")),
                                    Vec::<String>::new(),
                                );
                            }
                        }
                    }
                    crate::state::CredType::Password => {
                        SmbCredential::new(&username, &domain, &secret)
                    }
                };
                let logger = |line: &str| {
                    let _ = live_tx.send(RuntimeEvent::Log {
                        level: LogLevel::Info,
                        message: format!("{}[trace] {}", ip_for_log, line),
                    });
                };
                execute_command_live(&ip_for_task, Some(&cred), &cmd_for_task, &logger)
            })
            .await;

            match result {
                Ok((Ok(output), _trace)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{ip}: exec ok ({} bytes)", output.len()),
                    });
                    let _ = tx.send(RuntimeEvent::ExecResult {
                        console_id,
                        command,
                        output,
                        error: None,
                    });
                }
                Ok((Err(e), _trace)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip}: exec failed: {e}"),
                    });
                    let _ = tx.send(RuntimeEvent::ExecResult {
                        console_id,
                        command,
                        output: String::new(),
                        error: Some(e),
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::ExecResult {
                        console_id,
                        command,
                        output: String::new(),
                        error: Some(format!("task panicked: {e}")),
                    });
                }
            }
        });
    }
}
