use crate::StaticModuleFactory;
use getexec_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "gpp_password",
        "Collecte GPP et recherche de secrets historises dans SYSVOL.",
        &["smb"],
        ModuleCategory::CredentialAccess,
    )
}
