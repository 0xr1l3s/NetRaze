use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceRecord {
    pub name: String,
    pub root: String,
}

#[async_trait]
pub trait WorkspaceStore: Send + Sync {
    async fn current_workspace(&self) -> WorkspaceRecord;
}

#[derive(Debug, Clone)]
pub struct InMemoryWorkspaceStore {
    workspace: WorkspaceRecord,
}

impl InMemoryWorkspaceStore {
    pub fn new(name: impl Into<String>, root: impl Into<String>) -> Self {
        Self {
            workspace: WorkspaceRecord {
                name: name.into(),
                root: root.into(),
            },
        }
    }
}

#[async_trait]
impl WorkspaceStore for InMemoryWorkspaceStore {
    async fn current_workspace(&self) -> WorkspaceRecord {
        self.workspace.clone()
    }
}
