use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoggingConfig {
    pub verbose: bool,
    pub debug: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub threads: usize,
    pub timeout_seconds: u64,
    pub jitter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceConfig {
    pub name: String,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    pub workspace: WorkspaceConfig,
    pub runtime: RuntimeConfig,
    pub logging: LoggingConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            workspace: WorkspaceConfig {
                name: "default".to_owned(),
                root: ".getexec".to_owned(),
            },
            runtime: RuntimeConfig {
                threads: 256,
                timeout_seconds: 10,
                jitter: None,
            },
            logging: LoggingConfig {
                verbose: false,
                debug: false,
            },
        }
    }
}
