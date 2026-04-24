//! Non-Windows stub for `smb::enum_av`. DCOM+WMI port lands in Phase 6.

use super::connection::SmbCredential;

#[derive(Debug, Clone)]
pub struct AvProduct {
    pub name: String,
    pub installed: bool,
    pub running: bool,
}

impl AvProduct {
    pub fn status_label(&self) -> &'static str {
        match (self.installed, self.running) {
            (true, true) => "INSTALLED and RUNNING",
            (true, false) => "INSTALLED",
            (false, true) => "RUNNING",
            (false, false) => "",
        }
    }

    pub fn to_line(&self) -> String {
        format!("{}|{}", self.name, self.status_label())
    }
}

pub struct EnumAvResult {
    pub products: Vec<AvProduct>,
    pub errors: Vec<String>,
}

pub fn enum_av(_target: &str, _credential: Option<&SmbCredential>) -> EnumAvResult {
    EnumAvResult {
        products: Vec::new(),
        errors: vec![crate::smb::NOT_PORTED.into()],
    }
}
