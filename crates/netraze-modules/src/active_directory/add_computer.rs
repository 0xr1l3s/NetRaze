use crate::StaticModuleFactory;
use netraze_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "add-computer",
        "Ajoute, supprime ou modifie un compte machine dans l'AD.",
        &["ldap", "smb"],
        ModuleCategory::PrivilegeEscalation,
    )
}
