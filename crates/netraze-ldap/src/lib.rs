//! Pure-Rust LDAP client for Active Directory enumeration.
//!
//! The public API deliberately hides the `rasn-ldap` wire model.

mod ad;
pub mod client;
mod controls;
mod message;
mod search;

pub use client::{LdapClient, LdapClientConfig, LdapEntry, LdapError, SearchOutcome};
