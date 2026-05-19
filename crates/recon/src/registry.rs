use crate::plugin::ReconPluginSync;
use crate::subfinder::SubfinderPlugin;
use crate::httpx::HttpxPlugin;
use crate::nuclei::NucleiPlugin;
use aegis_core::error::AegisResult;

/// Registry of all available recon plugins.
pub struct PluginRegistry {
    plugins: Vec<Box<dyn ReconPluginSync>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        let plugins: Vec<Box<dyn ReconPluginSync>> = vec![
            Box::new(SubfinderPlugin),
            Box::new(HttpxPlugin),
            Box::new(NucleiPlugin),
        ];
        Self { plugins }
    }

    pub fn get(&self, name: &str) -> Option<&dyn ReconPluginSync> {
        self.plugins.iter().find(|p| p.name() == name).map(|p| p.as_ref())
    }

    pub fn all(&self) -> &[Box<dyn ReconPluginSync>] {
        &self.plugins
    }

    pub fn execute_all(&self, target: &str, scan_id: &str) -> AegisResult<()> {
        for plugin in &self.plugins {
            let result = plugin.execute(target, scan_id)?;
            tracing::info!(
                "[{}] {} produced {} results",
                scan_id, plugin.name(), result.len()
            );
        }
        Ok(())
    }

    pub fn execute_named(
        &self,
        names: &[String],
        target: &str,
        scan_id: &str,
    ) -> AegisResult<()> {
        for name in names {
            if let Some(plugin) = self.get(name) {
                let result = plugin.execute(target, scan_id)?;
                tracing::info!(
                    "[{}] {} produced {} results",
                    scan_id, name, result.len()
                );
            } else {
                tracing::warn!("[{}] Plugin '{}' not found", scan_id, name);
            }
        }
        Ok(())
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}
