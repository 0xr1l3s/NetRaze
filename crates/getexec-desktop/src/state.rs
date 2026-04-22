use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::runtime::{LogLevel, RuntimeEvent, RuntimeLogEvent};
use crate::workflow::{WorkflowDocument, WorkflowNode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavTab {
    Workspace,
    Modules,
    Targets,
    Settings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    Accessible,
    Locked,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRecord {
    pub ip: String,
    pub hostname: String,
    pub status: HostStatus,
    pub os_info: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub signing: Option<bool>,
    #[serde(default)]
    pub smbv1: Option<bool>,
    pub shares: Vec<String>,
    pub admin: bool,
    pub users: Vec<String>,
}

/// A scan result subnet with discovered hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSubnet {
    pub cidr: String,
    pub hosts: Vec<HostRecord>,
    #[serde(default)]
    pub expanded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredType {
    Password,
    Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub username: String,
    pub domain: String,
    pub secret: String,
    pub cred_type: CredType,
    pub valid: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ModuleCategory {
    pub name: String,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct TargetConfig {
    pub target: String,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct CredentialConfig {
    pub username: String,
    pub password: String,
    pub ntlm_hash: String,
    pub kerberos_ticket: String,
}

#[derive(Debug)]
pub struct AppState {
    pub nav_tab: NavTab,
    pub workflow: WorkflowDocument,
    pub logs: Vec<LogLine>,
    pub module_categories: Vec<ModuleCategory>,
    pub selected_module: String,
    pub dragged_module: Option<String>,
    pub credentials: Vec<CredentialRecord>,
    pub selected_cred: Option<usize>,
    pub new_cred_username: String,
    pub new_cred_domain: String,
    pub new_cred_secret: String,
    pub new_cred_type: CredType,
    pub networks: Vec<NetworkSubnet>,
    pub selected_host: Option<String>,
    pub target_config: TargetConfig,
    pub credential_config: CredentialConfig,
    pub status_text: String,
    pub is_running: bool,
    pub threads: usize,
    pub timeout_seconds: u64,
    pub started_at: Option<std::time::Instant>,
    pub workspace_path: String,
    pub progress: f32,
    pub progress_message: String,
    pub pending_logins: Vec<(String, CredentialRecord)>,
    /// (host_node_id_raw, ip, hostname)
    pub pending_share_enums: Vec<(usize, String, String)>,
    /// (host_node_id_raw, ip, hostname)
    pub pending_user_enums: Vec<(usize, String, String)>,
    /// (host_node_id_raw, ip, hostname, dump_type)
    pub pending_dumps: Vec<(usize, String, String, String)>,
    /// (host_node_id_raw, ip, hostname, username, domain, secret)
    pub pending_enumav: Vec<(usize, String, String, String, String, String)>,
    pub share_browsers: Vec<crate::ui::share_browser::ShareBrowserState>,
    pub pending_browse: Vec<String>,
    pub pending_fingerprints: Vec<String>,
    pub consoles: Vec<crate::ui::console::ConsoleState>,
    /// (console_id, ip, credential, command)
    pub pending_exec_commands: Vec<(u64, String, CredentialRecord, String)>,
    pub next_console_id: u64,
    pub target_search: String,
    pub log_rx: UnboundedReceiver<RuntimeLogEvent>,
}

impl AppState {
    pub fn new(log_rx: UnboundedReceiver<RuntimeLogEvent>) -> Self {
        Self {
            nav_tab: NavTab::Workspace,
            workflow: WorkflowDocument::with_default_chain(),
            logs: Vec::new(),
            module_categories: vec![
                ModuleCategory {
                    name: "Enum".to_owned(),
                    items: vec!["SMB".to_owned(), "LDAP".to_owned(), "RDP".to_owned(), "WinRM".to_owned()],
                },
                ModuleCategory {
                    name: "Auth".to_owned(),
                    items: vec!["Kerberos".to_owned(), "Pass Spray".to_owned(), "NTLM".to_owned()],
                },
                ModuleCategory {
                    name: "Exploit".to_owned(),
                    items: vec!["MSSQL".to_owned(), "SSH".to_owned(), "FTP".to_owned()],
                },
                ModuleCategory {
                    name: "Post".to_owned(),
                    items: vec!["--shares".to_owned(), "--users".to_owned(), "--pass-pol".to_owned(), "--sam".to_owned(), "--lsa".to_owned(), "--dpapi".to_owned()],
                },
            ],
            selected_module: "SMB".to_owned(),
            dragged_module: None,
            credentials: Vec::new(),
            selected_cred: None,
            new_cred_username: String::new(),
            new_cred_domain: String::new(),
            new_cred_secret: String::new(),
            new_cred_type: CredType::Password,
            networks: Vec::new(),
            selected_host: None,
            target_config: TargetConfig {
                target: String::new(),
                protocol: "SMB".to_owned(),
            },
            credential_config: CredentialConfig {
                username: String::new(),
                password: String::new(),
                ntlm_hash: String::new(),
                kerberos_ticket: String::new(),
            },
            status_text: "Idle".to_owned(),
            is_running: false,
            threads: 16,
            timeout_seconds: 20,
            started_at: None,
            workspace_path: "workspace_getexec.json".to_owned(),
            progress: 0.0,
            progress_message: String::new(),
            pending_logins: Vec::new(),
            pending_share_enums: Vec::new(),
            pending_user_enums: Vec::new(),
            pending_dumps: Vec::new(),
            pending_enumav: Vec::new(),
            share_browsers: Vec::new(),
            pending_browse: Vec::new(),
            pending_fingerprints: Vec::new(),
            consoles: Vec::new(),
            pending_exec_commands: Vec::new(),
            next_console_id: 1,
            target_search: String::new(),
            log_rx,
        }
    }

    /// Allocate a new unique console id.
    pub fn alloc_console_id(&mut self) -> u64 {
        let id = self.next_console_id;
        self.next_console_id += 1;
        id
    }

    /// Open (or focus) a console for the given host using the given credential.
    /// Returns the console id.
    pub fn open_console(
        &mut self,
        host_ip: String,
        hostname: String,
        credential: CredentialRecord,
    ) -> u64 {
        // Reuse an existing open console for this (ip, username, domain) triple if any.
        if let Some(c) = self.consoles.iter_mut().find(|c| {
            c.open
                && c.host_ip == host_ip
                && c.credential.username == credential.username
                && c.credential.domain == credential.domain
        }) {
            return c.id;
        }
        let id = self.alloc_console_id();
        self.consoles.push(crate::ui::console::ConsoleState::new(
            id, host_ip, hostname, credential,
        ));
        id
    }

    pub fn poll_logs(&mut self) {
        while let Ok(event) = self.log_rx.try_recv() {
            match event {
                RuntimeEvent::Log { level, message } => {
                    self.logs.push(LogLine { level, message });
                }
                RuntimeEvent::ScanStarted { target_label } => {
                    // Create/reset the subnet for this scan
                    if let Some(subnet) = self.networks.iter_mut().find(|n| n.cidr == target_label) {
                        subnet.hosts.clear();
                        subnet.expanded = true;
                    } else {
                        self.networks.push(NetworkSubnet {
                            cidr: target_label,
                            hosts: Vec::new(),
                            expanded: true,
                        });
                    }
                }
                RuntimeEvent::SmbResult(result) => {
                    let hostname = result.hostname.clone().unwrap_or_default();
                    let status = if result.error.is_some() {
                        HostStatus::Unknown
                    } else if result.admin {
                        HostStatus::Accessible
                    } else {
                        HostStatus::Locked
                    };
                    let shares: Vec<String> = result
                        .shares
                        .iter()
                        .map(|s| format!("{} [{}] ({})", s.name, s.share_type.display_str(), s.access.display_str()))
                        .collect();
                    let users: Vec<String> = result
                        .users
                        .iter()
                        .map(|u| {
                            let tag = if u.disabled {
                                " (disabled)"
                            } else if u.locked {
                                " (locked)"
                            } else {
                                ""
                            };
                            format!("{}{}", u.name, tag)
                        })
                        .collect();
                    let os_info = result.os_info.clone().unwrap_or_default();

                    let new_host = HostRecord {
                        ip: result.target.clone(),
                        hostname,
                        status,
                        os_info,
                        domain: String::new(),
                        signing: None,
                        smbv1: None,
                        shares,
                        admin: result.admin,
                        users,
                    };

                    // Add to the most recent subnet (created by ScanStarted)
                    let subnet = self.networks.last_mut();
                    if let Some(subnet) = subnet {
                        if let Some(host) = subnet.hosts.iter_mut().find(|h| h.ip == result.target) {
                            *host = new_host;
                        } else {
                            subnet.hosts.push(new_host);
                        }
                    } else {
                        self.networks.push(NetworkSubnet {
                            cidr: "Scan Results".to_owned(),
                            hosts: vec![new_host],
                            expanded: true,
                        });
                    }
                }
                RuntimeEvent::ScanProgress { done, total } => {
                    if total > 0 {
                        self.progress = done as f32 / total as f32;
                        self.progress_message = format!("{}/{} cibles scannées", done, total);
                    }
                }
                RuntimeEvent::ScanFinished => {
                    self.is_running = false;
                    self.progress = 1.0;
                    self.progress_message = "Scan terminé".to_owned();
                    self.status_text = "Idle".to_owned();
                }
                RuntimeEvent::LoginResult { ip, cred_label, success, admin } => {
                    if success {
                        // Find the HostNode in the workspace snarl and set logged_in_cred + admin
                        for node in self.workflow.snarl.nodes_mut() {
                            if let WorkflowNode::HostNode { ip: node_ip, logged_in_cred, admin: node_admin, .. } = node {
                                if *node_ip == ip {
                                    *logged_in_cred = Some(cred_label.clone());
                                    *node_admin = admin;
                                }
                            }
                        }
                        // Sync back to networks
                        for net in &mut self.networks {
                            if let Some(h) = net.hosts.iter_mut().find(|h| h.ip == ip) {
                                h.admin = admin;
                                h.status = if admin { HostStatus::Accessible } else { HostStatus::Locked };
                            }
                        }
                    }
                }
                RuntimeEvent::ShareEnumResult { host_node_id, ip, hostname, shares } => {
                    // Sync shares back to networks
                    for net in &mut self.networks {
                        if let Some(h) = net.hosts.iter_mut().find(|h| h.ip == ip) {
                            h.shares = shares.clone();
                            if !hostname.is_empty() && h.hostname.is_empty() {
                                h.hostname = hostname.clone();
                            }
                        }
                    }
                    // Check if a SharesNode for this host already exists
                    let already_exists = self.workflow.snarl.nodes().any(|n| {
                        matches!(n, WorkflowNode::SharesNode { host_ip: existing, .. } if *existing == ip)
                    });
                    if !already_exists {
                        let count = self.workflow.snarl.nodes().count() as f32;
                        let pos = egui::Pos2::new(
                            40.0 + (count % 4.0) * 280.0,
                            40.0 + (count / 4.0).floor() * 200.0,
                        );
                        let new_id = self.workflow.snarl.insert_node(
                            pos,
                            WorkflowNode::SharesNode {
                                host_ip: ip,
                                hostname,
                                shares,
                            },
                        );
                        // Connect host → shares
                        let node_id = egui_snarl::NodeId(host_node_id);
                        let from = egui_snarl::OutPinId { node: node_id, output: 0 };
                        let to = egui_snarl::InPinId { node: new_id, input: 0 };
                        self.workflow.snarl.connect(from, to);
                    }
                }
                RuntimeEvent::BrowseResult { browser_id, entries, error } => {
                    if let Some(browser) = self.share_browsers.get_mut(browser_id) {
                        browser.loading = false;
                        browser.error = error;
                        browser.entries = entries
                            .into_iter()
                            .map(|(name, is_dir, size)| {
                                crate::ui::share_browser::BrowserEntry { name, is_dir, size }
                            })
                            .collect();
                    }
                }
                RuntimeEvent::FileOpResult { browser_id, success, message } => {
                    if let Some(browser) = self.share_browsers.get_mut(browser_id) {
                        browser.status = Some((message, success));
                        if success {
                            self.pending_browse.push(browser.current_unc());
                        }
                    }
                }
                RuntimeEvent::UserEnumResult { host_node_id, ip, hostname, users } => {
                    use crate::workflow::{UserEntry, WorkflowNode};
                    // Sync users back to networks
                    for net in &mut self.networks {
                        if let Some(h) = net.hosts.iter_mut().find(|h| h.ip == ip) {
                            h.users = users.iter().map(|(name, disabled, locked, _)| {
                                let tag = if *disabled { " (disabled)" } else if *locked { " (locked)" } else { "" };
                                format!("{name}{tag}")
                            }).collect();
                            if !hostname.is_empty() && h.hostname.is_empty() {
                                h.hostname = hostname.clone();
                            }
                        }
                    }
                    // Check if a UsersNode for this host already exists
                    let already_exists = self.workflow.snarl.nodes().any(|n| {
                        matches!(n, WorkflowNode::UsersNode { host_ip: existing, .. } if *existing == ip)
                    });
                    if !already_exists {
                        let count = self.workflow.snarl.nodes().count() as f32;
                        let pos = egui::Pos2::new(
                            40.0 + (count % 4.0) * 280.0,
                            40.0 + (count / 4.0).floor() * 200.0,
                        );
                        let user_entries: Vec<UserEntry> = users.into_iter().map(|(name, disabled, locked, priv_level)| {
                            UserEntry { name, disabled, locked, privilege_level: priv_level }
                        }).collect();
                        let new_id = self.workflow.snarl.insert_node(
                            pos,
                            WorkflowNode::UsersNode {
                                host_ip: ip,
                                hostname,
                                users: user_entries,
                            },
                        );
                        // Connect host → users
                        let node_id = egui_snarl::NodeId(host_node_id);
                        let from = egui_snarl::OutPinId { node: node_id, output: 0 };
                        let to = egui_snarl::InPinId { node: new_id, input: 0 };
                        self.workflow.snarl.connect(from, to);
                    }
                }
                RuntimeEvent::DumpResult { host_node_id, ip, hostname, dump_type, entries, error } => {
                    use crate::workflow::WorkflowNode;
                    let already_exists = self.workflow.snarl.nodes().any(|n| {
                        matches!(n, WorkflowNode::DumpNode { host_ip: existing, dump_type: dt, .. }
                            if *existing == ip && *dt == dump_type)
                    });
                    if already_exists {
                        for node in self.workflow.snarl.nodes_mut() {
                            if let WorkflowNode::DumpNode { host_ip: existing, dump_type: dt, entries: e, error: err, .. } = node {
                                if *existing == ip && *dt == dump_type {
                                    *e = entries.clone();
                                    *err = error.clone();
                                    break;
                                }
                            }
                        }
                    } else {
                        let count = self.workflow.snarl.nodes().count() as f32;
                        let pos = egui::Pos2::new(
                            40.0 + (count % 4.0) * 280.0,
                            40.0 + (count / 4.0).floor() * 200.0,
                        );
                        let new_id = self.workflow.snarl.insert_node(
                            pos,
                            WorkflowNode::DumpNode {
                                host_ip: ip,
                                hostname,
                                dump_type,
                                entries,
                                error,
                            },
                        );
                        let node_id = egui_snarl::NodeId(host_node_id);
                        let from = egui_snarl::OutPinId { node: node_id, output: 0 };
                        let to = egui_snarl::InPinId { node: new_id, input: 0 };
                        self.workflow.snarl.connect(from, to);
                    }
                }
                RuntimeEvent::EnumAvResult { host_node_id, ip, hostname, products, error } => {
                    use crate::workflow::WorkflowNode;
                    let already_exists = self.workflow.snarl.nodes().any(|n| {
                        matches!(n, WorkflowNode::EnumAvNode { host_ip: existing, .. }
                            if *existing == ip)
                    });
                    if already_exists {
                        for node in self.workflow.snarl.nodes_mut() {
                            if let WorkflowNode::EnumAvNode { host_ip: existing, products: p, error: err, .. } = node {
                                if *existing == ip {
                                    *p = products.clone();
                                    *err = error.clone();
                                    break;
                                }
                            }
                        }
                    } else {
                        let count = self.workflow.snarl.nodes().count() as f32;
                        let pos = egui::Pos2::new(
                            40.0 + (count % 4.0) * 280.0,
                            40.0 + (count / 4.0).floor() * 200.0,
                        );
                        let new_id = self.workflow.snarl.insert_node(
                            pos,
                            WorkflowNode::EnumAvNode {
                                host_ip: ip,
                                hostname,
                                products,
                                error,
                            },
                        );
                        let node_id = egui_snarl::NodeId(host_node_id);
                        let from = egui_snarl::OutPinId { node: node_id, output: 0 };
                        let to = egui_snarl::InPinId { node: new_id, input: 0 };
                        self.workflow.snarl.connect(from, to);
                    }
                }
            RuntimeEvent::FingerprintResult { ip, hostname, domain, os_info, signing, smbv1 } => {
                // Update HostNode in workspace
                for node in self.workflow.snarl.nodes_mut() {
                    if let WorkflowNode::HostNode {
                        ip: node_ip,
                        hostname: node_hostname,
                        os_info: node_os,
                        domain: node_domain,
                        signing: node_signing,
                        smbv1: node_smbv1,
                        ..
                    } = node
                    {
                        if *node_ip == ip {
                            if node_hostname.is_empty() && !hostname.is_empty() {
                                *node_hostname = hostname.clone();
                            }
                            if node_os.is_empty() && !os_info.is_empty() {
                                *node_os = os_info.clone();
                            }
                            if node_domain.is_empty() && !domain.is_empty() {
                                *node_domain = domain.clone();
                            }
                            *node_signing = Some(signing);
                            *node_smbv1 = Some(smbv1);
                        }
                    }
                }
                // Update networks
                for net in &mut self.networks {
                    if let Some(h) = net.hosts.iter_mut().find(|h| h.ip == ip) {
                        if h.hostname.is_empty() && !hostname.is_empty() {
                            h.hostname = hostname.clone();
                        }
                        if h.os_info.is_empty() && !os_info.is_empty() {
                            h.os_info = os_info.clone();
                        }
                        if h.domain.is_empty() && !domain.is_empty() {
                            h.domain = domain.clone();
                        }
                        h.signing = Some(signing);
                        h.smbv1 = Some(smbv1);
                    }
                }
            }
            RuntimeEvent::ExecResult { console_id, command, output, error } => {
                if let Some(c) = self.consoles.iter_mut().find(|c| c.id == console_id) {
                    c.push_result(command, output, error);
                }
            }
            }
        }
        if self.logs.len() > 2000 {
            let keep_from = self.logs.len().saturating_sub(2000);
            self.logs.drain(0..keep_from);
        }
    }

    pub fn add_log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.logs.push(LogLine {
            level,
            message: message.into(),
        });
    }

    pub fn elapsed_seconds(&self) -> u64 {
        self.started_at
            .map(|instant| instant.elapsed().as_secs())
            .unwrap_or(0)
    }

    pub fn discovered_hosts_count(&self) -> usize {
        self.networks.iter().map(|n| n.hosts.len()).sum()
    }

    pub fn credentials_count(&self) -> usize {
        self.credentials.len()
    }
}

/// Serializable workspace snapshot — everything worth saving.
#[derive(Serialize, Deserialize)]
pub struct WorkspaceSave {
    pub name: String,
    pub credentials: Vec<CredentialRecord>,
    pub networks: Vec<NetworkSubnet>,
    pub workflow: WorkflowDocument,
    pub logs: Vec<LogLine>,
    pub target_config: TargetConfigSave,
}

#[derive(Serialize, Deserialize)]
pub struct TargetConfigSave {
    pub target: String,
    pub protocol: String,
}

impl AppState {
    /// Create a saveable snapshot from current state.
    pub fn to_save(&self) -> WorkspaceSave {
        WorkspaceSave {
            name: self.workflow.name.clone(),
            credentials: self.credentials.clone(),
            networks: self.networks.clone(),
            workflow: self.workflow.clone(),
            logs: self.logs.clone(),
            target_config: TargetConfigSave {
                target: self.target_config.target.clone(),
                protocol: self.target_config.protocol.clone(),
            },
        }
    }

    /// Restore state from a saved workspace.
    pub fn load_from(&mut self, save: WorkspaceSave) {
        self.workflow = save.workflow;
        self.credentials = save.credentials;
        self.networks = save.networks;
        self.logs = save.logs;
        self.target_config.target = save.target_config.target;
        self.target_config.protocol = save.target_config.protocol;

        // Re-establish SMB sessions and auto-fingerprint hosts missing data
        for node in self.workflow.snarl.nodes() {
            if let crate::workflow::WorkflowNode::HostNode { ip, logged_in_cred, signing, .. } = node {
                // Auto-fingerprint hosts missing fingerprint data
                if signing.is_none() {
                    self.pending_fingerprints.push(ip.clone());
                }
                // Re-login if they had credentials
                if let Some(label) = logged_in_cred {
                    if let Some(cred) = self.credentials.iter().find(|c| {
                        let cred_label = if c.domain.is_empty() {
                            format!(".\\{}", c.username)
                        } else {
                            format!("{}\\{}", c.domain, c.username)
                        };
                        cred_label == *label
                    }) {
                        self.pending_logins.push((ip.clone(), cred.clone()));
                    }
                }
            }
        }
    }

    /// Save workspace to a JSON file.
    pub fn save_workspace(&self, path: &str) -> Result<(), String> {
        let data = self.to_save();
        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| format!("Serialize error: {e}"))?;
        std::fs::write(path, json)
            .map_err(|e| format!("Write error: {e}"))?;
        Ok(())
    }

    /// Load workspace from a JSON file.
    pub fn load_workspace(&mut self, path: &str) -> Result<(), String> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("Read error: {e}"))?;
        let save: WorkspaceSave = serde_json::from_str(&json)
            .map_err(|e| format!("Deserialize error: {e}"))?;
        self.load_from(save);
        Ok(())
    }
}
