use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Capability {
    Authentication,
    CommandExecution,
    Enumeration,
    FileTransfer,
    SecretDump,
    DesktopAccess,
    DatabaseAccess,
    ModuleHooks,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolMetadata {
    pub key: String,
    pub display_name: String,
    pub default_port: u16,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModuleCategory {
    Enumeration,
    CredentialAccess,
    PrivilegeEscalation,
    Execution,
    Collection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleMetadata {
    pub key: String,
    pub description: String,
    pub supported_protocols: Vec<String>,
    pub category: ModuleCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRequest {
    pub protocol: String,
    pub raw_targets: Vec<String>,
    pub selected_module: Option<String>,
    pub options: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanPlan {
    pub request: ScanRequest,
    pub concurrency: usize,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub protocol: String,
    pub target_count: usize,
    pub module: Option<String>,
}

/// Backend that produced a user-enumeration record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UserEnumerationSource {
    Ldap,
    Samr,
}

/// Protocol-neutral user record shared by LDAP, SAMR, and presentation layers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserInfo {
    pub name: String,
    pub privilege_level: u32,
    pub flags: u32,
    pub disabled: bool,
    pub locked: bool,
    pub source: UserEnumerationSource,
}

pub trait ProtocolFactory: Send + Sync {
    fn metadata(&self) -> ProtocolMetadata;
}

pub trait ModuleFactory: Send + Sync {
    fn metadata(&self) -> ModuleMetadata;
}

#[derive(Debug, thiserror::Error)]
pub enum NetRazeError {
    #[error("unknown protocol: {0}")]
    UnknownProtocol(String),
    #[error("unknown module: {0}")]
    UnknownModule(String),
}
