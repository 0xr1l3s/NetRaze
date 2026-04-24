use anyhow::{Result, bail};
use netraze_config::AppConfig;
use netraze_core::{ExecutionOutcome, ModuleMetadata, ProtocolMetadata, ScanPlan, ScanRequest};
use netraze_modules::builtin_modules;
use netraze_output::{ConsoleReporter, OutputEvent, Reporter};
use netraze_protocols::builtin_protocols;
use netraze_runtime::RuntimeProfile;
use netraze_storage::{InMemoryWorkspaceStore, WorkspaceStore};
use netraze_targets::classify_target;
use std::collections::BTreeMap;

pub struct NetRazeApp {
    config: AppConfig,
    protocols: BTreeMap<String, ProtocolMetadata>,
    modules: BTreeMap<String, ModuleMetadata>,
    reporter: ConsoleReporter,
    workspace_store: InMemoryWorkspaceStore,
}

impl NetRazeApp {
    pub fn bootstrap(config: AppConfig) -> Self {
        let protocols = builtin_protocols()
            .into_iter()
            .map(|factory| {
                let metadata = factory.metadata();
                (metadata.key.clone(), metadata)
            })
            .collect();

        let modules = builtin_modules()
            .into_iter()
            .map(|factory| {
                let metadata = factory.metadata();
                (metadata.key.clone(), metadata)
            })
            .collect();

        let workspace_store = InMemoryWorkspaceStore::new(
            config.workspace.name.clone(),
            config.workspace.root.clone(),
        );

        Self {
            config,
            protocols,
            modules,
            reporter: ConsoleReporter,
            workspace_store,
        }
    }

    pub fn protocol_catalog(&self) -> Vec<&ProtocolMetadata> {
        self.protocols.values().collect()
    }

    pub fn module_catalog(&self) -> Vec<&ModuleMetadata> {
        self.modules.values().collect()
    }

    pub async fn plan_scan(&self, request: ScanRequest) -> Result<ScanPlan> {
        if !self.protocols.contains_key(&request.protocol) {
            bail!("unknown protocol: {}", request.protocol);
        }

        if let Some(module) = &request.selected_module
            && !self.modules.contains_key(module)
        {
            bail!("unknown module: {module}");
        }

        let profile = RuntimeProfile {
            threads: self.config.runtime.threads,
            timeout_seconds: self.config.runtime.timeout_seconds,
        };

        let workspace = self.workspace_store.current_workspace().await;
        let normalized_targets = request
            .raw_targets
            .iter()
            .map(|item| classify_target(item))
            .collect::<Vec<_>>();

        self.reporter.emit(OutputEvent::Info(format!(
            "workspace={} targets={} protocol={}",
            workspace.name,
            normalized_targets.len(),
            request.protocol,
        )));

        Ok(ScanPlan {
            request,
            concurrency: profile.bounded_threads(),
            timeout_seconds: profile.timeout_seconds,
        })
    }

    pub async fn dry_run(&self, request: ScanRequest) -> Result<ExecutionOutcome> {
        let plan = self.plan_scan(request).await?;
        Ok(ExecutionOutcome {
            protocol: plan.request.protocol,
            target_count: plan.request.raw_targets.len(),
            module: plan.request.selected_module,
        })
    }
}
