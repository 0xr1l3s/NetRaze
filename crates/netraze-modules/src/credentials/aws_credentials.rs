use crate::StaticModuleFactory;
use netraze_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "aws-credentials",
        "Recherche de secrets AWS sur hotes Windows et Linux.",
        &["smb", "ssh", "winrm"],
        ModuleCategory::CredentialAccess,
    )
}
