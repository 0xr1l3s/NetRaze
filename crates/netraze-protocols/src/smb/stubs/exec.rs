//! Non-Windows stub for `smb::exec`. Smbexec/atexec/wmiexec land in Phase 5+.

use super::connection;

pub fn execute_command_live(
    _target: &str,
    _credential: Option<&connection::SmbCredential>,
    _command: &str,
    _live_log: &dyn Fn(&str),
) -> (Result<String, String>, Vec<String>) {
    (Err(crate::smb::NOT_PORTED.into()), Vec::new())
}

pub fn execute_command(
    _target: &str,
    _credential: Option<&connection::SmbCredential>,
    _command: &str,
) -> Result<String, String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn execute_command_traced(
    _target: &str,
    _credential: Option<&connection::SmbCredential>,
    _command: &str,
) -> (Result<String, String>, Vec<String>) {
    (Err(crate::smb::NOT_PORTED.into()), Vec::new())
}
