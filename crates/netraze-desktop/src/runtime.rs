use serde::{Deserialize, Serialize};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};

use netraze_protocols::smb::connection::is_port_open;
use netraze_protocols::smb::{
    SmbClient, SmbCredential, SmbScanResult, create_directory, delete_remote_directory,
    delete_remote_file, download_file, enum_av, execute_command_live, list_directory,
    remote_dump_lsa, remote_dump_sam, smb_fingerprint, upload_file,
};
use netraze_protocols::targets::parse_target_list;

use crate::state::CredentialRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Success,
    Error,
}

#[derive(Debug, Clone)]
pub enum RuntimeEvent {
    Log {
        level: LogLevel,
        message: String,
    },
    SmbResult(Box<SmbScanResult>),
    ScanProgress {
        done: usize,
        total: usize,
    },
    ScanStarted {
        target_label: String,
    },
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
        /// Label of the credential that ran the enumeration — stored on the
        /// SharesNode so later Browse clicks can resolve it back.
        cred_label: Option<String>,
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
        result: Result<netraze_protocols::users::UserEnumerationOutcome, String>,
    },
    DirectoryResult {
        endpoint: String,
        cred_label: String,
        result: Result<netraze_core::DirectoryInventory, String>,
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
                    message: format!("[{}/{}] SMB scan: {}...", idx + 1, total_live, target),
                });

                let mut client = SmbClient::new(target);
                if let Some(ref cred) = credential {
                    client = client.with_credential(cred.clone());
                }

                // Step 0: Fingerprint (no auth needed)
                {
                    let fp_target = target.clone();
                    let fp_tx = tx.clone();
                    let fp_result =
                        tokio::task::spawn_blocking(move || smb_fingerprint(&fp_target)).await;
                    if let Ok(Ok(fp)) = fp_result {
                        let nxc_line = fp.nxc_line(target);
                        let _ = fp_tx.send(RuntimeEvent::Log {
                            level: LogLevel::Success,
                            message: nxc_line,
                        });
                        let _ = fp_tx.send(RuntimeEvent::FingerprintResult {
                            ip: target.clone(),
                            hostname: fp.hostname,
                            domain: if fp.dns_domain.is_empty() {
                                fp.domain
                            } else {
                                fp.dns_domain
                            },
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
                        server_info.as_ref().map(|s| s.name.as_str()).unwrap_or("?"),
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

    /// Launch explicit LDAP/NTLM directory discovery. Targets are processed in
    /// bounded batches so a large CIDR cannot create an unbounded task set.
    pub fn spawn_ldap_scan(
        &self,
        raw_targets: Vec<String>,
        credential: CredentialRecord,
        threads: usize,
        timeout_seconds: u64,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let target_label = raw_targets.join(", ");
            let _ = tx.send(RuntimeEvent::ScanStarted { target_label });
            let targets = raw_targets
                .iter()
                .flat_map(|target| parse_target_list(target))
                .collect::<Vec<_>>();
            let total = targets.len();
            if total == 0 {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Error,
                    message: "Aucune cible LDAP valide".to_owned(),
                });
                let _ = tx.send(RuntimeEvent::ScanFinished);
                return;
            }

            let ntlm = match cred_to_ntlm(&credential) {
                Ok(credential) => credential,
                Err(error) => {
                    let label = crate::state::cred_label(&credential);
                    for target in targets {
                        let endpoint = netraze_protocols::targets::with_default_port(&target, 389);
                        let _ = tx.send(RuntimeEvent::DirectoryResult {
                            endpoint,
                            cred_label: label.clone(),
                            result: Err(error.clone()),
                        });
                    }
                    let _ = tx.send(RuntimeEvent::ScanFinished);
                    return;
                }
            };

            let username = credential.username.clone();
            let domain = credential.domain.clone();
            let secret = credential.secret.clone();
            let label = crate::state::cred_label(&credential);
            let timeout = Duration::from_secs(timeout_seconds.max(1));
            let mut completed = 0_usize;
            for batch in targets.chunks(threads.max(1)) {
                let mut tasks = JoinSet::new();
                for target in batch {
                    let endpoint = netraze_protocols::targets::with_default_port(target, 389);
                    let username = username.clone();
                    let domain = domain.clone();
                    let ntlm = ntlm.clone();
                    tasks.spawn(async move {
                        let mut config = netraze_protocols::ldap::LdapClientConfig::new(&endpoint);
                        config.connect_timeout = timeout;
                        config.operation_timeout = timeout;
                        let result = netraze_protocols::ldap::inventory(
                            config,
                            &username,
                            &domain,
                            ntlm,
                        )
                        .await
                        .map_err(|error| error.to_string());
                        (endpoint, result)
                    });
                }
                while let Some(joined) = tasks.join_next().await {
                    completed += 1;
                    match joined {
                        Ok((endpoint, result)) => {
                            let result = result.map_err(|error| redact_secret(&error, &secret));
                            let (level, message) = match &result {
                                Ok(inventory) => (
                                    LogLevel::Success,
                                    format!(
                                        "{endpoint}: LDAP discovery completed ({} users, {} groups, {} computers)",
                                        inventory.users.items.len(),
                                        inventory.groups.items.len(),
                                        inventory.computers.items.len()
                                    ),
                                ),
                                Err(error) => (
                                    LogLevel::Error,
                                    format!("{endpoint}: LDAP discovery failed: {error}"),
                                ),
                            };
                            let _ = tx.send(RuntimeEvent::Log { level, message });
                            let _ = tx.send(RuntimeEvent::DirectoryResult {
                                endpoint,
                                cred_label: label.clone(),
                                result,
                            });
                        }
                        Err(error) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("LDAP discovery task failed: {error}"),
                            });
                        }
                    }
                    let _ = tx.send(RuntimeEvent::ScanProgress {
                        done: completed,
                        total,
                    });
                }
            }
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
        // Same label logic as `state::cred_label` — "(anonymous)" for the
        // null session, `.\user` / `DOMAIN\user` otherwise (guest logins
        // are just users without a secret).
        let cred_label = if username.is_empty() {
            "(anonymous)".to_owned()
        } else if domain.is_empty() {
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
                crate::state::CredType::Password => SmbCredential::new(&username, &domain, &secret),
            };
            let mut client = SmbClient::new(&ip).with_credential(smb_cred);
            let login_result = client.connect().await;
            let success = login_result.is_ok();
            let error_detail = login_result.err();
            let mut admin = false;

            if success {
                admin = client.check_admin().await;
                client.disconnect().await;
            }

            let admin_tag = if admin { " (Pwn3d!)" } else { "" };
            let _ = tx.send(RuntimeEvent::Log {
                level: if success {
                    LogLevel::Success
                } else {
                    LogLevel::Error
                },
                message: if success {
                    format!(
                        "{}: ✔ login réussi en tant que {cred_label_clone}{admin_tag}",
                        ip
                    )
                } else {
                    match error_detail {
                        Some(detail) => {
                            format!("{ip}: ✘ login échoué pour {cred_label_clone} — {detail}")
                        }
                        None => format!("{ip}: ✘ login échoué pour {cred_label_clone}"),
                    }
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
        cred: CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: énumération des shares..."),
        });

        let ip_clone = ip.clone();
        let hostname_clone = hostname.clone();
        let smb_cred = cred_to_smb(&cred);
        // Same label format as spawn_login_attempt — resolve_cred matches on it.
        let cred_label = crate::state::cred_label(&cred);
        self.runtime.spawn(async move {
            let mut client = SmbClient::new(&ip_clone).with_credential(smb_cred);
            let result = client.connect().await;
            let shares = if result.is_ok() {
                match client.enum_shares_with_access().await {
                    Ok(shares) => {
                        let formatted: Vec<String> = shares
                            .iter()
                            .map(|s| {
                                format!(
                                    "{} [{}] ({})",
                                    s.name,
                                    s.share_type.display_str(),
                                    s.access.display_str()
                                )
                            })
                            .collect();
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
                cred_label: Some(cred_label),
            });
        });
    }

    pub fn spawn_user_enum(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: crate::state::CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: énumération des utilisateurs..."),
        });

        let ip_clone = ip.clone();
        let hostname_clone = hostname.clone();
        let smb_cred = cred_to_smb(&cred);
        self.runtime.spawn(async move {
            // Keep an explicitly typed port (e.g. a container harness on
            // :1445); default to 445 only for bare hosts.
            let target = netraze_protocols::targets::with_default_port(&ip_clone, 445);
            let result = netraze_protocols::smb::users::enum_users(&target, &smb_cred)
                .await
                .map(|users| netraze_protocols::users::UserEnumerationOutcome {
                    users,
                    source: netraze_core::UserEnumerationSource::Samr,
                    fallback_used: false,
                });

            match &result {
                Ok(outcome) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!(
                            "{ip_clone}: {} utilisateur(s) trouvé(s) via {:?}{}",
                            outcome.users.len(),
                            outcome.source,
                            if outcome.fallback_used {
                                " (fallback)"
                            } else {
                                ""
                            }
                        ),
                    });
                }
                Err(e) => {
                    let (level, prefix) = if e.contains("ACCESS_DENIED (0x5)") {
                        (LogLevel::Warning, "accès refusé")
                    } else {
                        (LogLevel::Error, "erreur enum users")
                    };
                    let _ = tx.send(RuntimeEvent::Log {
                        level,
                        message: format!("{ip_clone}: {prefix}: {e}"),
                    });
                }
            }

            let _ = tx.send(RuntimeEvent::UserEnumResult {
                host_node_id,
                ip: ip_clone,
                hostname: hostname_clone,
                result,
            });
        });
    }

    pub fn spawn_dump_sam(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: crate::state::CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: SAM dump en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        let smb_cred = cred_to_smb(&cred);
        self.runtime.spawn(async move {
            let result = remote_dump_sam(&ip2, &smb_cred).await;

            let (entries, error) = match result {
                Ok(dump) => {
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
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: SAM dump failed: {e}"),
                    });
                    (Vec::new(), Some(e))
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

    pub fn spawn_dump_lsa(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: crate::state::CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: LSA dump en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        let smb_cred = cred_to_smb(&cred);
        self.runtime.spawn(async move {
            let result = remote_dump_lsa(&ip2, &smb_cred).await;

            let (entries, error) = match result {
                Ok(dump) => {
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
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: LSA dump failed: {e}"),
                    });
                    (Vec::new(), Some(e))
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

    pub fn spawn_enum_av(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: AV/EDR enumeration en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        let smb_cred = cred_to_smb(&cred);
        self.runtime.spawn(async move {
            // The portable backend is async — await it directly.
            let av_result = enum_av(&ip2, Some(&smb_cred)).await;

            let (products, error) = {
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

    /// List a directory on a remote share. `rel_path` is relative to the
    /// share root (`""` = root). A missing credential surfaces as a browse
    /// error instead of a silent no-op.
    pub fn spawn_browse_directory(
        &self,
        browser_id: usize,
        host: String,
        share: String,
        rel_path: String,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::BrowseResult {
                    browser_id,
                    entries: Vec::new(),
                    error: Some("no credential available for this share".to_string()),
                });
                return;
            };
            match list_directory(&host, &cred, &share, &rel_path).await {
                Ok(entries) => {
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
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::BrowseResult {
                        browser_id,
                        entries: Vec::new(),
                        error: Some(e),
                    });
                }
            }
        });
    }

    /// Download `rel_path` on `share` to `local_path`.
    pub fn spawn_download(
        &self,
        browser_id: usize,
        host: String,
        share: String,
        rel_path: String,
        local_path: String,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::FileOpResult {
                    browser_id,
                    success: false,
                    message: "no credential available for this share".to_string(),
                });
                return;
            };
            let (success, message) =
                match download_file(&host, &cred, &share, &rel_path, &local_path).await {
                    Ok(()) => (true, format!("Downloaded to {local_path}")),
                    Err(e) => (false, e),
                };
            let _ = tx.send(RuntimeEvent::FileOpResult {
                browser_id,
                success,
                message,
            });
        });
    }

    /// Upload `local_path` to `rel_path` on `share`.
    pub fn spawn_upload(
        &self,
        browser_id: usize,
        local_path: String,
        host: String,
        share: String,
        rel_path: String,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::FileOpResult {
                    browser_id,
                    success: false,
                    message: "no credential available for this share".to_string(),
                });
                return;
            };
            let result = upload_file(&host, &cred, &share, &rel_path, &local_path).await;
            let _ = tx.send(RuntimeEvent::FileOpResult {
                browser_id,
                success: result.is_ok(),
                message: match result {
                    Ok(()) => "Upload complete".to_string(),
                    Err(e) => e,
                },
            });
        });
    }

    /// Create a directory at `rel_path` on `share`.
    pub fn spawn_create_folder(
        &self,
        browser_id: usize,
        host: String,
        share: String,
        rel_path: String,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::FileOpResult {
                    browser_id,
                    success: false,
                    message: "no credential available for this share".to_string(),
                });
                return;
            };
            let result = create_directory(&host, &cred, &share, &rel_path).await;
            let _ = tx.send(RuntimeEvent::FileOpResult {
                browser_id,
                success: result.is_ok(),
                message: match result {
                    Ok(()) => "Folder created".to_string(),
                    Err(e) => e,
                },
            });
        });
    }

    /// Delete `rel_path` on `share` (file or directory — directories must
    /// be empty, same contract as the old RemoveDirectoryW backend).
    pub fn spawn_delete(
        &self,
        browser_id: usize,
        host: String,
        share: String,
        rel_path: String,
        is_dir: bool,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::FileOpResult {
                    browser_id,
                    success: false,
                    message: "no credential available for this share".to_string(),
                });
                return;
            };
            let result = if is_dir {
                delete_remote_directory(&host, &cred, &share, &rel_path).await
            } else {
                delete_remote_file(&host, &cred, &share, &rel_path).await
            };
            let _ = tx.send(RuntimeEvent::FileOpResult {
                browser_id,
                success: result.is_ok(),
                message: match result {
                    Ok(()) => "Deleted".to_string(),
                    Err(e) => e,
                },
            });
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
                        domain: if fp.dns_domain.is_empty() {
                            fp.domain
                        } else {
                            fp.dns_domain
                        },
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
            // The portable exec backend is async — await it directly so the
            // runtime can drive other tasks while the ADMIN$ poll loop
            // sleeps. Trace lines still stream to the UI through `live_tx`
            // (the closure stays sync).
            let live_tx = tx.clone();
            let ip_for_log = ip.clone();
            let logger = |line: &str| {
                let _ = live_tx.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!("{ip_for_log}[trace] {line}"),
                });
            };
            let result = match cred_type {
                crate::state::CredType::Hash => {
                    match SmbCredential::with_hash(&username, &domain, &secret) {
                        Ok(c) => execute_command_live(&ip, Some(&c), &command, &logger).await,
                        Err(e) => (Err(format!("hash invalide: {e}")), Vec::new()),
                    }
                }
                crate::state::CredType::Password => {
                    let cred = SmbCredential::new(&username, &domain, &secret);
                    execute_command_live(&ip, Some(&cred), &command, &logger).await
                }
            };

            match result {
                (Ok(output), _trace) => {
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
                (Err(e), _trace) => {
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
            }
        });
    }
}

/// Convert a desktop `CredentialRecord` into an `SmbCredential` usable by
/// the protocol layer.
pub(crate) fn cred_to_smb(cred: &crate::state::CredentialRecord) -> SmbCredential {
    match cred.cred_type {
        crate::state::CredType::Password => {
            SmbCredential::new(&cred.username, &cred.domain, &cred.secret)
        }
        crate::state::CredType::Hash => {
            let mut hash = [0u8; 16];
            let hex = cred.secret.trim();
            if hex.len() == 32 {
                for i in 0..16 {
                    if let Ok(b) = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                        hash[i] = b;
                    }
                }
            }
            SmbCredential {
                username: cred.username.clone(),
                domain: cred.domain.clone(),
                password: String::new(),
                nt_hash: Some(hash),
            }
        }
    }
}

pub(crate) fn cred_to_ntlm(
    cred: &crate::state::CredentialRecord,
) -> Result<netraze_protocols::ntlm::NtlmCredential, String> {
    if cred.username.trim().is_empty() {
        return Err("LDAP NTLM authentication requires a username".to_owned());
    }
    if cred.secret.is_empty() {
        return Err("LDAP NTLM authentication requires a password or NT hash".to_owned());
    }
    match cred.cred_type {
        crate::state::CredType::Password => Ok(netraze_protocols::ntlm::NtlmCredential::Password(
            cred.secret.clone(),
        )),
        crate::state::CredType::Hash => {
            netraze_protocols::ntlm::NtlmCredential::from_nt_hash_hex(&cred.secret)
                .map_err(|error| error.to_string())
        }
    }
}

fn redact_secret(message: &str, secret: &str) -> String {
    if secret.is_empty() {
        return message.to_owned();
    }
    let mut redacted = message.replace(secret, "<redacted>");
    redacted = redacted.replace(&secret.to_ascii_lowercase(), "<redacted>");
    redacted.replace(&secret.to_ascii_uppercase(), "<redacted>")
}

#[cfg(test)]
mod ldap_runtime_tests {
    use super::*;
    use crate::state::{CredType, anonymous_record};

    #[test]
    fn converts_saved_password_and_hash_credentials_strictly() {
        let password = CredentialRecord {
            username: "alice".to_owned(),
            domain: "EXAMPLE".to_owned(),
            secret: "test-only-password".to_owned(),
            ..anonymous_record()
        };
        assert!(matches!(
            cred_to_ntlm(&password),
            Ok(netraze_protocols::ntlm::NtlmCredential::Password(_))
        ));

        let valid_hash = CredentialRecord {
            cred_type: CredType::Hash,
            secret: "8846f7eaee8fb117ad06bdd830b7586c".to_owned(),
            ..password.clone()
        };
        assert!(matches!(
            cred_to_ntlm(&valid_hash),
            Ok(netraze_protocols::ntlm::NtlmCredential::NtHash(_))
        ));

        let invalid_hash = CredentialRecord {
            secret: "not-a-hash".to_owned(),
            ..valid_hash
        };
        assert!(cred_to_ntlm(&invalid_hash).is_err());
    }

    #[test]
    fn runtime_errors_redact_passwords_and_hashes() {
        assert_eq!(
            redact_secret("bind rejected test-only-password", "test-only-password"),
            "bind rejected <redacted>"
        );
        assert_eq!(
            redact_secret(
                "hash 8846F7EAEE8FB117AD06BDD830B7586C rejected",
                "8846f7eaee8fb117ad06bdd830b7586c"
            ),
            "hash <redacted> rejected"
        );
    }
}
