use crate::StaticModuleFactory;
use netraze_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "dpapi_hash",
        "Extraction de materiel DPAPI pour cracking ou decryption ulterieure.",
        &["smb"],
        ModuleCategory::CredentialAccess,
    )
}
