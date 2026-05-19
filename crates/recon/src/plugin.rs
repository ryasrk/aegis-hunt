use aegis_core::error::AegisResult;

/// Synchronous plugin trait for running recon tools as subprocesses.
pub trait ReconPluginSync: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, target: &str, scan_id: &str) -> AegisResult<Vec<String>>;
}
