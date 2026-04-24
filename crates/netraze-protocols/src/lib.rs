mod ftp;
mod ldap;
mod mssql;
mod nfs;
mod rdp;
pub mod smb;
mod ssh;
pub mod targets;
mod vnc;
mod winrm;
mod wmi;

use netraze_core::{Capability, ProtocolFactory, ProtocolMetadata};

#[derive(Debug, Clone)]
pub struct StaticProtocolFactory {
    metadata: ProtocolMetadata,
}

impl StaticProtocolFactory {
    pub fn new(
        key: &str,
        display_name: &str,
        default_port: u16,
        capabilities: Vec<Capability>,
    ) -> Self {
        Self {
            metadata: ProtocolMetadata {
                key: key.to_owned(),
                display_name: display_name.to_owned(),
                default_port,
                capabilities,
            },
        }
    }
}

impl ProtocolFactory for StaticProtocolFactory {
    fn metadata(&self) -> ProtocolMetadata {
        self.metadata.clone()
    }
}

pub fn builtin_protocols() -> Vec<Box<dyn ProtocolFactory>> {
    vec![
        Box::new(smb::factory()),
        Box::new(ldap::factory()),
        Box::new(ssh::factory()),
        Box::new(winrm::factory()),
        Box::new(rdp::factory()),
        Box::new(ftp::factory()),
        Box::new(mssql::factory()),
        Box::new(nfs::factory()),
        Box::new(vnc::factory()),
        Box::new(wmi::factory()),
    ]
}
