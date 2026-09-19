use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::runtime::{LogLevel, RuntimeEvent, RuntimeLogEvent};
use crate::workflow::{WorkflowDocument, WorkflowNode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavTab {
    Workspace,
    Target,
    Module,
    CredentialManager,
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
    #[serde(default = "bool_true")]
    pub active: bool,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub created_at: Option<u64>,
}

/// Label under which a credential is tracked across the workspace
/// (host `logged_in_cred`, SharesNode `cred_label`, login logs):
/// `.\user`, `DOMAIN\user` — or `(anonymous)` when no username is set.
pub fn cred_label(cred: &CredentialRecord) -> String {
    if cred.username.is_empty() {
        "(anonymous)".to_owned()
    } else if cred.domain.is_empty() {
        format!(".\\{}", cred.username)
    } else {
        format!("{}\\{}", cred.domain, cred.username)
    }
}

/// The anonymous (null-session) credential. Empty username + empty
/// secret — the protocol layer's shape dispatch turns exactly this into
/// `Smb2Session::connect_anonymous`. Never appears in the saved list
/// (Add requires a username); `resolve_cred` synthesizes it on demand
/// for the `(anonymous)` label.
pub fn anonymous_record() -> CredentialRecord {
    CredentialRecord {
        username: String::new(),
        domain: String::new(),
        secret: String::new(),
        cred_type: CredType::Password,
        valid: None,
        active: true,
        protocol: String::new(),
        source: String::new(),
        notes: String::new(),
        tags: Vec::new(),
        created_at: None,
    }
}

fn bool_true() -> bool {
    true
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
pub struct CredentialManagerState {
    pub search_query: String,
    pub filter_type: Option<CredType>,
    pub filter_protocol: String,
    pub filter_valid: Option<bool>,
    pub filter_active_only: bool,
    pub selected_cred_idx: Option<usize>,
    pub edit_mode: bool,
    pub show_secrets: bool,
    pub form_username: String,
    pub form_domain: String,
    pub form_secret: String,
    pub form_cred_type: CredType,
    pub form_protocol: String,
    pub form_source: String,
    pub form_notes: String,
    pub form_tags: String,
    pub form_active: bool,
    // Reserved for future file-dialog persistence
    // pub import_path: String,
    // pub export_path: String,
}

impl Default for CredentialManagerState {
    fn default() -> Self {
        Self {
            search_query: String::new(),
            filter_type: None,
            filter_protocol: String::new(),
            filter_valid: None,
            filter_active_only: false,
            selected_cred_idx: None,
            edit_mode: false,
            show_secrets: false,
            form_username: String::new(),
            form_domain: String::new(),
            form_secret: String::new(),
            form_cred_type: CredType::Password,
            form_protocol: "SMB".to_owned(),
            form_source: String::new(),
            form_notes: String::new(),
            form_tags: String::new(),
            form_active: true,
        }
    }
}

#[derive(Debug)]
pub struct AppState {
    pub nav_tab: NavTab,
    pub workflow: WorkflowDocument,
    pub logs: Vec<LogLine>,
    pub selected_module: String,
    pub dragged_module: Option<String>,
    pub credentials: Vec<CredentialRecord>,
    pub selected_cred: Option<usize>,
    pub new_cred_username: String,
    pub new_cred_domain: String,
    pub new_cred_secret: String,
    pub new_cred_type: CredType,
    pub cm_state: CredentialManagerState,
    pub networks: Vec<NetworkSubnet>,
    pub selected_host: Option<String>,
    /// Raw NodeId.0 of the node currently selected in the config panel.
    pub selected_workflow_node: Option<usize>,
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
    /// (host_node_id_raw, ip, hostname, credential)
    pub pending_share_enums: Vec<(usize, String, String, CredentialRecord)>,
    /// (host_node_id_raw, ip, hostname, credential)
    pub pending_user_enums: Vec<(usize, String, String, CredentialRecord)>,
    /// (host_node_id_raw, ip, hostname, dump_type, credential)
    pub pending_dumps: Vec<(usize, String, String, String, CredentialRecord)>,
    /// (host_node_id_raw, ip, hostname, credential)
    pub pending_enumav: Vec<(usize, String, String, CredentialRecord)>,
    pub share_browsers: Vec<crate::ui::share_browser::ShareBrowserState>,
    /// Browser indices to (re)list — dispatched to the runtime by app.rs,
    /// which reads (host, share, path, credential) off the browser state.
    pub pending_browse: Vec<usize>,
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
            selected_module: "SMB".to_owned(),
            dragged_module: None,
            credentials: Vec::new(),
            selected_cred: None,
            new_cred_username: String::new(),
            new_cred_domain: String::new(),
            new_cred_secret: String::new(),
            new_cred_type: CredType::Password,
            cm_state: CredentialManagerState::default(),
            networks: Vec::new(),
            selected_host: None,
            selected_workflow_node: None,
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
            workspace_path: "workspace_netraze.json".to_owned(),
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

    /// Queue one manual user lookup per host and immediately expose its state.
    pub fn queue_user_enum(
        &mut self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: CredentialRecord,
    ) {
        let label = cred_label(&cred);
        if let Some(node) =
            self.workflow.snarl.nodes_mut().find(
                |node| matches!(node, WorkflowNode::UsersNode { host_ip, .. } if *host_ip == ip),
            )
        {
            if let WorkflowNode::UsersNode {
                users,
                source,
                fallback_used,
                error,
                done,
                loading,
                cred_label,
                ..
            } = node
            {
                if *loading {
                    return;
                }
                users.clear();
                *source = None;
                *fallback_used = false;
                *error = None;
                *done = false;
                *loading = true;
                *cred_label = Some(label);
            }
        } else {
            let count = self.workflow.snarl.nodes().count() as f32;
            let pos = egui::Pos2::new(
                40.0 + (count % 4.0) * 280.0,
                40.0 + (count / 4.0).floor() * 200.0,
            );
            let new_id = self.workflow.snarl.insert_node(
                pos,
                WorkflowNode::UsersNode {
                    host_ip: ip.clone(),
                    hostname: hostname.clone(),
                    users: Vec::new(),
                    source: None,
                    fallback_used: false,
                    error: None,
                    done: false,
                    loading: true,
                    cred_label: Some(label),
                },
            );
            let from = egui_snarl::OutPinId {
                node: egui_snarl::NodeId(host_node_id),
                output: 0,
            };
            let to = egui_snarl::InPinId {
                node: new_id,
                input: 0,
            };
            self.workflow.snarl.connect(from, to);
            self.selected_workflow_node = Some(new_id.0);
        }
        self.pending_user_enums
            .push((host_node_id, ip, hostname, cred));
    }

    pub fn poll_logs(&mut self) {
        while let Ok(event) = self.log_rx.try_recv() {
            match event {
                RuntimeEvent::Log { level, message } => {
                    self.logs.push(LogLine { level, message });
                }
                RuntimeEvent::ScanStarted { target_label } => {
                    // Create/reset the subnet for this scan
                    if let Some(subnet) = self.networks.iter_mut().find(|n| n.cidr == target_label)
                    {
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
                        .map(|s| {
                            format!(
                                "{} [{}] ({})",
                                s.name,
                                s.share_type.display_str(),
                                s.access.display_str()
                            )
                        })
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
                        if let Some(host) = subnet.hosts.iter_mut().find(|h| h.ip == result.target)
                        {
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
                RuntimeEvent::LoginResult {
                    ip,
                    cred_label,
                    success,
                    admin,
                } => {
                    if success {
                        // Find the HostNode in the workspace snarl and set logged_in_cred + admin
                        for node in self.workflow.snarl.nodes_mut() {
                            if let WorkflowNode::HostNode {
                                ip: node_ip,
                                logged_in_cred,
                                admin: node_admin,
                                ..
                            } = node
                            {
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
                                h.status = if admin {
                                    HostStatus::Accessible
                                } else {
                                    HostStatus::Locked
                                };
                            }
                        }
                    }
                }
                RuntimeEvent::ShareEnumResult {
                    host_node_id,
                    ip,
                    hostname,
                    shares,
                    cred_label,
                } => {
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
                                cred_label,
                            },
                        );
                        // Connect host → shares
                        let node_id = egui_snarl::NodeId(host_node_id);
                        let from = egui_snarl::OutPinId {
                            node: node_id,
                            output: 0,
                        };
                        let to = egui_snarl::InPinId {
                            node: new_id,
                            input: 0,
                        };
                        self.workflow.snarl.connect(from, to);
                    }
                }
                RuntimeEvent::BrowseResult {
                    browser_id,
                    entries,
                    error,
                } => {
                    if let Some(browser) = self.share_browsers.get_mut(browser_id) {
                        browser.loading = false;
                        browser.error = error;
                        browser.entries =
                            entries
                                .into_iter()
                                .map(|(name, is_dir, size)| {
                                    crate::ui::share_browser::BrowserEntry { name, is_dir, size }
                                })
                                .collect();
                    }
                }
                RuntimeEvent::FileOpResult {
                    browser_id,
                    success,
                    message,
                } => {
                    if let Some(browser) = self.share_browsers.get_mut(browser_id) {
                        browser.status = Some((message, success));
                        if success {
                            self.pending_browse.push(browser_id);
                        }
                    }
                }
                RuntimeEvent::UserEnumResult {
                    host_node_id,
                    ip,
                    hostname,
                    result,
                } => {
                    use crate::workflow::UserEntry;
                    let users = result
                        .as_ref()
                        .map(|outcome| outcome.users.as_slice())
                        .unwrap_or_default();
                    // Sync users back to networks
                    for net in &mut self.networks {
                        if let Some(h) = net.hosts.iter_mut().find(|h| h.ip == ip) {
                            h.users = users
                                .iter()
                                .map(|user| {
                                    let tag = if user.disabled {
                                        " (disabled)"
                                    } else if user.locked {
                                        " (locked)"
                                    } else {
                                        ""
                                    };
                                    format!("{}{tag}", user.name)
                                })
                                .collect();
                            if !hostname.is_empty() && h.hostname.is_empty() {
                                h.hostname = hostname.clone();
                            }
                        }
                    }
                    let _ = host_node_id;
                    for node in self.workflow.snarl.nodes_mut() {
                        if let WorkflowNode::UsersNode {
                            host_ip,
                            hostname: node_hostname,
                            users: node_users,
                            source,
                            fallback_used,
                            error,
                            done,
                            loading,
                            ..
                        } = node
                        {
                            if *host_ip != ip {
                                continue;
                            }
                            *node_hostname = hostname;
                            *loading = false;
                            *done = true;
                            match result {
                                Ok(outcome) => {
                                    *node_users = outcome
                                        .users
                                        .into_iter()
                                        .map(|user| UserEntry {
                                            name: user.name,
                                            disabled: user.disabled,
                                            locked: user.locked,
                                            privilege_level: user.privilege_level,
                                        })
                                        .collect();
                                    *source = Some(outcome.source);
                                    *fallback_used = outcome.fallback_used;
                                    *error = None;
                                }
                                Err(message) => {
                                    node_users.clear();
                                    *source = None;
                                    *fallback_used = false;
                                    *error = Some(message);
                                }
                            }
                            break;
                        }
                    }
                }
                RuntimeEvent::DirectoryResult {
                    endpoint,
                    cred_label,
                    result,
                } => {
                    let hostname = result
                        .as_ref()
                        .as_ref()
                        .ok()
                        .and_then(|inventory| inventory.server.dns_host_name.clone())
                        .unwrap_or_default();
                    let domain = result
                        .as_ref()
                        .as_ref()
                        .ok()
                        .map(|inventory| inventory.server.default_naming_context.clone())
                        .unwrap_or_default();
                    let user_names = result
                        .as_ref()
                        .as_ref()
                        .ok()
                        .map(|inventory| {
                            inventory
                                .users
                                .items
                                .iter()
                                .map(|user| user.name.clone())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let host = HostRecord {
                        ip: endpoint.clone(),
                        hostname: hostname.clone(),
                        status: if result.is_ok() {
                            HostStatus::Accessible
                        } else {
                            HostStatus::Unknown
                        },
                        os_info: "Active Directory (LDAP)".to_owned(),
                        domain,
                        signing: None,
                        smbv1: None,
                        shares: Vec::new(),
                        admin: false,
                        users: user_names.clone(),
                    };
                    if let Some(network) = self.networks.last_mut() {
                        if let Some(existing) =
                            network.hosts.iter_mut().find(|item| item.ip == endpoint)
                        {
                            *existing = host;
                        } else {
                            network.hosts.push(host);
                        }
                    }

                    let host_id = self
                        .workflow
                        .snarl
                        .node_ids()
                        .find_map(|(id, node)| match node {
                            WorkflowNode::HostNode { ip, .. } if *ip == endpoint => Some(id),
                            _ => None,
                        })
                        .unwrap_or_else(|| {
                            let count = self.workflow.snarl.nodes().count() as f32;
                            self.workflow.snarl.insert_node(
                                egui::Pos2::new(
                                    40.0 + (count % 4.0) * 280.0,
                                    40.0 + (count / 4.0).floor() * 200.0,
                                ),
                                WorkflowNode::HostNode {
                                    ip: endpoint.clone(),
                                    hostname: hostname.clone(),
                                    os_info: "Active Directory (LDAP)".to_owned(),
                                    domain: result
                                        .as_ref()
                                        .as_ref()
                                        .ok()
                                        .map(|inventory| {
                                            inventory.server.default_naming_context.clone()
                                        })
                                        .unwrap_or_default(),
                                    signing: None,
                                    smbv1: None,
                                    shares: Vec::new(),
                                    admin: false,
                                    users: user_names,
                                    logged_in_cred: Some(cred_label.clone()),
                                },
                            )
                        });

                    if let Some((directory_id, node)) = self
                        .workflow
                        .snarl
                        .nodes_ids_mut()
                        .find(|(_, node)| {
                            matches!(node, WorkflowNode::DirectoryNode { endpoint: value, .. } if *value == endpoint)
                        })
                    {
                        if let WorkflowNode::DirectoryNode {
                            hostname: node_hostname,
                            inventory,
                            error,
                            loading,
                            cred_label: node_cred_label,
                            ..
                        } = node
                        {
                            *node_hostname = hostname;
                            *loading = false;
                            *node_cred_label = Some(cred_label);
                            match *result {
                                Ok(value) => {
                                    *inventory = Some(Box::new(value));
                                    *error = None;
                                }
                                Err(message) => {
                                    *inventory = None;
                                    *error = Some(message);
                                }
                            }
                            self.selected_workflow_node = Some(directory_id.0);
                        }
                    } else {
                        let count = self.workflow.snarl.nodes().count() as f32;
                        let (inventory, error) = match *result {
                            Ok(value) => (Some(Box::new(value)), None),
                            Err(message) => (None, Some(message)),
                        };
                        let directory_id = self.workflow.snarl.insert_node(
                            egui::Pos2::new(
                                40.0 + (count % 4.0) * 280.0,
                                40.0 + (count / 4.0).floor() * 200.0,
                            ),
                            WorkflowNode::DirectoryNode {
                                endpoint,
                                hostname,
                                inventory,
                                error,
                                loading: false,
                                cred_label: Some(cred_label),
                            },
                        );
                        self.workflow.snarl.connect(
                            egui_snarl::OutPinId {
                                node: host_id,
                                output: 0,
                            },
                            egui_snarl::InPinId {
                                node: directory_id,
                                input: 0,
                            },
                        );
                        self.selected_workflow_node = Some(directory_id.0);
                    }
                }
                RuntimeEvent::DumpResult {
                    host_node_id,
                    ip,
                    hostname,
                    dump_type,
                    entries,
                    error,
                } => {
                    use crate::workflow::WorkflowNode;
                    let already_exists = self.workflow.snarl.nodes().any(|n| {
                        matches!(n, WorkflowNode::DumpNode { host_ip: existing, dump_type: dt, .. }
                            if *existing == ip && *dt == dump_type)
                    });
                    if already_exists {
                        for node in self.workflow.snarl.nodes_mut() {
                            if let WorkflowNode::DumpNode {
                                host_ip: existing,
                                dump_type: dt,
                                entries: e,
                                error: err,
                                ..
                            } = node
                            {
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
                        let from = egui_snarl::OutPinId {
                            node: node_id,
                            output: 0,
                        };
                        let to = egui_snarl::InPinId {
                            node: new_id,
                            input: 0,
                        };
                        self.workflow.snarl.connect(from, to);
                    }
                }
                RuntimeEvent::EnumAvResult {
                    host_node_id,
                    ip,
                    hostname,
                    products,
                    error,
                } => {
                    use crate::workflow::WorkflowNode;
                    let already_exists = self.workflow.snarl.nodes().any(|n| {
                        matches!(n, WorkflowNode::EnumAvNode { host_ip: existing, .. }
                            if *existing == ip)
                    });
                    if already_exists {
                        for node in self.workflow.snarl.nodes_mut() {
                            if let WorkflowNode::EnumAvNode {
                                host_ip: existing,
                                products: p,
                                error: err,
                                done,
                                ..
                            } = node
                            {
                                if *existing == ip {
                                    *p = products.clone();
                                    *err = error.clone();
                                    *done = true;
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
                                done: true,
                            },
                        );
                        let node_id = egui_snarl::NodeId(host_node_id);
                        let from = egui_snarl::OutPinId {
                            node: node_id,
                            output: 0,
                        };
                        let to = egui_snarl::InPinId {
                            node: new_id,
                            input: 0,
                        };
                        self.workflow.snarl.connect(from, to);
                    }
                }
                RuntimeEvent::FingerprintResult {
                    ip,
                    hostname,
                    domain,
                    os_info,
                    signing,
                    smbv1,
                } => {
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
                RuntimeEvent::ExecResult {
                    console_id,
                    command,
                    output,
                    error,
                } => {
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
            if let crate::workflow::WorkflowNode::HostNode {
                ip,
                logged_in_cred,
                signing,
                ..
            } = node
            {
                // Auto-fingerprint hosts missing fingerprint data
                if signing.is_none() {
                    self.pending_fingerprints.push(ip.clone());
                }
                // Re-login if they had credentials
                if let Some(label) = logged_in_cred {
                    if label == "(anonymous)" {
                        self.pending_logins.push((ip.clone(), anonymous_record()));
                    } else if let Some(cred) =
                        self.credentials.iter().find(|c| &cred_label(c) == label)
                    {
                        self.pending_logins.push((ip.clone(), cred.clone()));
                    }
                }
            }
        }
    }

    /// Save workspace to a JSON file.
    pub fn save_workspace(&self, path: &str) -> Result<(), String> {
        let data = self.to_save();
        let json =
            serde_json::to_string_pretty(&data).map_err(|e| format!("Serialize error: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("Write error: {e}"))?;
        Ok(())
    }

    /// Load workspace from a JSON file.
    pub fn load_workspace(&mut self, path: &str) -> Result<(), String> {
        let json = std::fs::read_to_string(path).map_err(|e| format!("Read error: {e}"))?;
        let save: WorkspaceSave =
            serde_json::from_str(&json).map_err(|e| format!("Deserialize error: {e}"))?;
        self.load_from(save);
        Ok(())
    }
}

#[cfg(test)]
mod user_enum_tests {
    use super::*;
    use netraze_core::{UserEnumerationSource, UserInfo};
    use netraze_protocols::users::UserEnumerationOutcome;

    fn state_with_host() -> (
        AppState,
        usize,
        tokio::sync::mpsc::UnboundedSender<RuntimeLogEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut state = AppState::new(rx);
        state.workflow.add_host_node(
            "127.0.0.1".into(),
            "dc".into(),
            String::new(),
            Vec::new(),
            false,
            Vec::new(),
        );
        let id = state
            .workflow
            .snarl
            .node_ids()
            .find_map(|(id, node)| matches!(node, WorkflowNode::HostNode { .. }).then_some(id.0))
            .unwrap();
        (state, id, tx)
    }

    #[test]
    fn queues_only_one_request_and_does_not_persist_a_secret_or_loading_state() {
        let (mut state, host_id, _tx) = state_with_host();
        let credential = CredentialRecord {
            username: "alice".into(),
            domain: "NETRAZE".into(),
            secret: "test-only-secret".into(),
            ..anonymous_record()
        };
        for _ in 0..2 {
            state.queue_user_enum(host_id, "127.0.0.1".into(), "dc".into(), credential.clone());
        }
        assert_eq!(state.pending_user_enums.len(), 1);
        let json = serde_json::to_string(&state.to_save()).unwrap();
        assert!(!json.contains("test-only-secret"));
        let node = state
            .workflow
            .snarl
            .nodes()
            .find(|node| matches!(node, WorkflowNode::UsersNode { .. }))
            .unwrap();
        let encoded = serde_json::to_string(node).unwrap();
        assert!(!encoded.contains("loading"));
    }

    #[test]
    fn empty_success_and_error_remain_distinct_after_refresh() {
        let (mut state, host_id, tx) = state_with_host();
        let cred = anonymous_record();
        state.queue_user_enum(host_id, "127.0.0.1".into(), "dc".into(), cred.clone());
        tx.send(RuntimeEvent::UserEnumResult {
            host_node_id: host_id,
            ip: "127.0.0.1".into(),
            hostname: "dc".into(),
            result: Ok(UserEnumerationOutcome {
                users: Vec::<UserInfo>::new(),
                source: UserEnumerationSource::Samr,
                fallback_used: false,
            }),
        })
        .unwrap();
        state.poll_logs();
        assert!(matches!(
            state
                .workflow
                .snarl
                .nodes()
                .find(|node| matches!(node, WorkflowNode::UsersNode { .. })),
            Some(WorkflowNode::UsersNode {
                done: true,
                error: None,
                source: Some(UserEnumerationSource::Samr),
                ..
            })
        ));

        state.queue_user_enum(host_id, "127.0.0.1".into(), "dc".into(), cred);
        tx.send(RuntimeEvent::UserEnumResult {
            host_node_id: host_id,
            ip: "127.0.0.1".into(),
            hostname: "dc".into(),
            result: Err("access denied".into()),
        })
        .unwrap();
        state.poll_logs();
        assert!(matches!(
            state.workflow.snarl.nodes().find(|node| matches!(node, WorkflowNode::UsersNode { .. })),
            Some(WorkflowNode::UsersNode { done: true, error: Some(message), source: None, .. }) if message == "access denied"
        ));
    }

    #[test]
    fn saved_users_nodes_without_new_fields_still_load() {
        let mut value = serde_json::to_value(WorkflowNode::UsersNode {
            host_ip: "127.0.0.1".into(),
            hostname: "dc".into(),
            users: Vec::new(),
            source: None,
            fallback_used: false,
            error: None,
            done: false,
            loading: false,
            cred_label: None,
        })
        .unwrap();
        let fields = value.get_mut("UsersNode").unwrap().as_object_mut().unwrap();
        for field in ["source", "fallback_used", "error", "done", "cred_label"] {
            fields.remove(field);
        }
        let node: WorkflowNode = serde_json::from_value(value).unwrap();
        assert!(matches!(
            node,
            WorkflowNode::UsersNode {
                source: None,
                fallback_used: false,
                error: None,
                done: false,
                loading: false,
                ..
            }
        ));
    }

    #[test]
    fn directory_results_create_connected_secret_free_nodes() {
        let (mut state, _host_id, tx) = state_with_host();
        let mut inventory = netraze_core::DirectoryInventory::default();
        inventory.server.endpoint = "127.0.0.1:389".to_owned();
        inventory.server.dns_host_name = Some("dc.example.test".to_owned());
        inventory.server.default_naming_context = "DC=example,DC=test".to_owned();
        inventory.users.items.push(netraze_core::DirectoryUser {
            name: "alice".to_owned(),
            ..netraze_core::DirectoryUser::default()
        });
        tx.send(RuntimeEvent::DirectoryResult {
            endpoint: "127.0.0.1:389".to_owned(),
            cred_label: "EXAMPLE\\alice".to_owned(),
            result: Box::new(Ok(inventory)),
        })
        .unwrap();
        state.poll_logs();

        let directory = state
            .workflow
            .snarl
            .nodes()
            .find(|node| matches!(node, WorkflowNode::DirectoryNode { .. }))
            .unwrap();
        assert!(matches!(
            directory,
            WorkflowNode::DirectoryNode {
                inventory: Some(value),
                error: None,
                loading: false,
                ..
            } if value.users.items.len() == 1
        ));
        let serialized = serde_json::to_string(&state.to_save()).unwrap();
        assert!(!serialized.contains("test-only-ldap-secret"));
        assert!(!serialized.contains("[REMOVED_NTLM_HASH]"));
        assert!(!serialized.contains("\"loading\""));
    }
}
