pub mod active_directory;
pub mod credentials;
pub mod reconnaissance;

use getexec_core::{ModuleCategory, ModuleFactory, ModuleMetadata};

#[derive(Debug, Clone)]
pub struct StaticModuleFactory {
    metadata: ModuleMetadata,
}

impl StaticModuleFactory {
    pub fn new(
        key: &str,
        description: &str,
        supported_protocols: &[&str],
        category: ModuleCategory,
    ) -> Self {
        Self {
            metadata: ModuleMetadata {
                key: key.to_owned(),
                description: description.to_owned(),
                supported_protocols: supported_protocols
                    .iter()
                    .map(|item| (*item).to_owned())
                    .collect(),
                category,
            },
        }
    }
}

impl ModuleFactory for StaticModuleFactory {
    fn metadata(&self) -> ModuleMetadata {
        self.metadata.clone()
    }
}

pub fn builtin_modules() -> Vec<Box<dyn ModuleFactory>> {
    vec![
        Box::new(active_directory::adcs::factory()),
        Box::new(active_directory::add_computer::factory()),
        Box::new(active_directory::coerce_plus::factory()),
        Box::new(credentials::aws_credentials::factory()),
        Box::new(credentials::dpapi_hash::factory()),
        Box::new(reconnaissance::enum_av::factory()),
        Box::new(reconnaissance::gpp_password::factory()),
    ]
}
