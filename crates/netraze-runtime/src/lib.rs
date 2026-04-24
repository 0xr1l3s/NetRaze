use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeProfile {
    pub threads: usize,
    pub timeout_seconds: u64,
}

impl RuntimeProfile {
    pub fn bounded_threads(&self) -> usize {
        self.threads.max(1)
    }
}
