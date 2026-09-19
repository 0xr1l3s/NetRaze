//! Protocol-neutral Active Directory inventory contracts.
//!
//! These types intentionally contain only read-only directory metadata. They
//! are shared by the LDAP protocol implementation, desktop presentation, and
//! future exporters without exposing LDAP BER representations or credentials.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectorySection<T> {
    pub items: Vec<T>,
    pub referrals: Vec<String>,
    pub error: Option<String>,
}

impl<T> DirectorySection<T> {
    #[must_use]
    pub fn success(items: Vec<T>, referrals: Vec<String>) -> Self {
        Self {
            items,
            referrals,
            error: None,
        }
    }

    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            items: Vec::new(),
            referrals: Vec::new(),
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryInventory {
    pub server: DirectoryServerInfo,
    pub users: DirectorySection<DirectoryUser>,
    pub groups: DirectorySection<DirectoryGroup>,
    pub computers: DirectorySection<DirectoryComputer>,
    pub organization: DirectorySection<DirectoryContainer>,
    pub topology: DirectorySection<DirectoryTopology>,
    pub privileged: DirectorySection<PrivilegedPrincipal>,
    pub services: DirectorySection<ServicePrincipal>,
    pub security: DirectorySection<DirectorySecuritySettings>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryServerInfo {
    pub endpoint: String,
    pub dns_host_name: Option<String>,
    pub server_name: Option<String>,
    pub service_name: Option<String>,
    pub default_naming_context: String,
    pub root_domain_naming_context: Option<String>,
    pub configuration_naming_context: Option<String>,
    pub schema_naming_context: Option<String>,
    pub naming_contexts: Vec<String>,
    pub supported_ldap_versions: Vec<String>,
    pub supported_sasl_mechanisms: Vec<String>,
    pub supported_controls: Vec<String>,
    pub supported_extensions: Vec<String>,
    pub supported_capabilities: Vec<String>,
    pub domain_controller_functionality: Option<u32>,
    pub domain_functionality: Option<u32>,
    pub forest_functionality: Option<u32>,
    pub global_catalog_ready: Option<bool>,
    pub synchronized: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryUser {
    pub dn: String,
    pub name: String,
    pub display_name: Option<String>,
    pub user_principal_name: Option<String>,
    pub description: Option<String>,
    pub object_sid: Option<String>,
    pub member_of: Vec<String>,
    pub primary_group_id: Option<u32>,
    pub user_account_control: u32,
    pub admin_count: bool,
    pub disabled: bool,
    pub locked: bool,
    pub password_never_expires: bool,
    pub password_not_required: bool,
    pub trusted_for_delegation: bool,
    pub last_logon_timestamp: Option<String>,
    pub password_last_set: Option<String>,
    pub when_created: Option<String>,
    pub service_principal_names: Vec<String>,
    pub supported_encryption_types: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryGroup {
    pub dn: String,
    pub name: String,
    pub description: Option<String>,
    pub object_sid: Option<String>,
    pub group_type: i32,
    pub members: Vec<String>,
    pub member_of: Vec<String>,
    pub admin_count: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryComputer {
    pub dn: String,
    pub name: String,
    pub dns_host_name: Option<String>,
    pub operating_system: Option<String>,
    pub operating_system_version: Option<String>,
    pub description: Option<String>,
    pub object_sid: Option<String>,
    pub member_of: Vec<String>,
    pub primary_group_id: Option<u32>,
    pub user_account_control: u32,
    pub disabled: bool,
    pub trusted_for_delegation: bool,
    pub trusted_to_auth_for_delegation: bool,
    pub last_logon_timestamp: Option<String>,
    pub password_last_set: Option<String>,
    pub service_principal_names: Vec<String>,
    pub supported_encryption_types: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryContainer {
    pub dn: String,
    pub name: String,
    pub parent_dn: Option<String>,
    pub description: Option<String>,
    pub is_organizational_unit: bool,
    pub gpo_links: Vec<GpoLink>,
    pub gpo_options: Option<u32>,
    pub when_created: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryTopology {
    pub domains: Vec<DirectoryDomain>,
    pub trusts: Vec<DirectoryTrust>,
    pub sites: Vec<DirectorySite>,
    pub subnets: Vec<DirectorySubnet>,
    pub group_policies: Vec<GroupPolicy>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryDomain {
    pub dn: String,
    pub dns_root: Option<String>,
    pub netbios_name: Option<String>,
    pub naming_context: Option<String>,
    pub object_sid: Option<String>,
    pub gpo_links: Vec<GpoLink>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryTrust {
    pub dn: String,
    pub partner: String,
    pub flat_name: Option<String>,
    pub direction: Option<u32>,
    pub trust_type: Option<u32>,
    pub attributes: Option<u32>,
    pub security_identifier: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectorySite {
    pub dn: String,
    pub name: String,
    pub description: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectorySubnet {
    pub dn: String,
    pub name: String,
    pub site_dn: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupPolicy {
    pub dn: String,
    pub id: String,
    pub display_name: Option<String>,
    pub file_system_path: Option<String>,
    pub flags: Option<u32>,
    pub version_number: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpoLink {
    pub target_dn: String,
    pub disabled: bool,
    pub enforced: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum DirectoryPrincipalKind {
    #[default]
    User,
    Group,
    Computer,
    ManagedServiceAccount,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivilegedPrincipal {
    pub dn: String,
    pub name: String,
    pub kind: DirectoryPrincipalKind,
    pub reasons: Vec<String>,
    pub member_of: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServicePrincipal {
    pub dn: String,
    pub name: String,
    pub kind: DirectoryPrincipalKind,
    pub dns_host_name: Option<String>,
    pub service_principal_names: Vec<String>,
    pub supported_encryption_types: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectorySecuritySettings {
    pub minimum_password_length: Option<u32>,
    pub password_history_length: Option<u32>,
    pub minimum_password_age_100ns: Option<i64>,
    pub maximum_password_age_100ns: Option<i64>,
    pub password_properties: Option<u32>,
    pub lockout_threshold: Option<u32>,
    pub lockout_duration_100ns: Option<i64>,
    pub lockout_observation_window_100ns: Option<i64>,
    pub machine_account_quota: Option<u32>,
    pub domain_behavior_version: Option<u32>,
    pub ldap_admin_limits: BTreeMap<String, String>,
    pub session_signing: bool,
    pub session_sealing: bool,
    pub signing_enforcement: Option<bool>,
    pub channel_binding_enforcement: Option<bool>,
    pub anonymous_access: Option<bool>,
    pub start_tls_available: Option<bool>,
    pub ldaps_available: Option<bool>,
}
