//! Pure-Rust LDAP client for Active Directory enumeration.
//!
//! The public API deliberately hides the `rasn-ldap` wire model.

mod ad;
pub mod bloodhound;
pub mod client;
mod controls;
mod directory;
mod inventory;
mod message;
mod search;

pub use bloodhound::{
    BloodHoundCeArtifacts, BloodHoundCeError, BloodHoundCeExportOptions, BloodHoundCeProgress,
    collect_and_export_ce, collect_and_export_ce_with_progress,
};
pub use client::{LdapClient, LdapClientConfig, LdapEntry, LdapError, SearchOutcome};
pub use inventory::{
    LdapAuthentication, inventory, inventory_anonymous, inventory_with_authentication,
};

use crate::StaticProtocolFactory;
use netraze_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "ldap",
        "LDAP",
        389,
        vec![
            Capability::Authentication,
            Capability::Enumeration,
            Capability::SecretDump,
            Capability::ModuleHooks,
        ],
    )
}
