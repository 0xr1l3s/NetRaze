//! Non-Windows stub for `smb::dump`. SAM/LSA dump lands in Phase 4.

use super::sam::SamHash;

pub struct SamDumpResult {
    pub hashes: Vec<SamHash>,
    pub errors: Vec<String>,
}

pub struct LsaDumpResult {
    pub secrets: Vec<String>,
    pub errors: Vec<String>,
}

pub fn remote_dump_sam(_target: &str) -> Result<SamDumpResult, String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn remote_dump_lsa(_target: &str) -> Result<LsaDumpResult, String> {
    Err(crate::smb::NOT_PORTED.into())
}
