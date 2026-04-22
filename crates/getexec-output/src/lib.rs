#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputEvent {
    Info(String),
    Warning(String),
    Result(String),
}

pub trait Reporter: Send + Sync {
    fn emit(&self, event: OutputEvent);
}

#[derive(Debug, Default, Clone)]
pub struct ConsoleReporter;

impl Reporter for ConsoleReporter {
    fn emit(&self, event: OutputEvent) {
        match event {
            OutputEvent::Info(message) => tracing::info!(%message),
            OutputEvent::Warning(message) => tracing::warn!(%message),
            OutputEvent::Result(message) => tracing::info!(target = "result", %message),
        }
    }
}
