use crate::StaticModuleFactory;
use getexec_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "enum_av",
        "Detection des protections endpoint et produits AV/EDR visibles.",
        &["smb", "wmi", "winrm"],
        ModuleCategory::Enumeration,
    )
}
