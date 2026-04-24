use crate::StaticModuleFactory;
use netraze_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "coerce_plus",
        "Centralise les primitives de coercion SMB et leurs variantes.",
        &["smb"],
        ModuleCategory::PrivilegeEscalation,
    )
}
