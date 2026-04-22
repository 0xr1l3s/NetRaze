use crate::StaticModuleFactory;
use getexec_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "adcs",
        "Enumere les services ADCS, templates et chemins d'abus PKI.",
        &["ldap"],
        ModuleCategory::Enumeration,
    )
}
