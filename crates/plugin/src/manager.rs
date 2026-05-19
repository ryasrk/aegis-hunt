use crate::plugin::{HookPoint, PluginResult};
use crate::registry::PluginRegistry;

/// High-level plugin manager that coordinates plugin lifecycle.
pub struct PluginManager {
    registry: PluginRegistry,
}

impl PluginManager {
    pub fn new() -> Self {
        let mut registry = PluginRegistry::new();

        // Register built-in plugins
        registry.register(Box::new(
            crate::plugins::sqli_scanner::SqliScannerPlugin,
        ));
        registry.register(Box::new(
            crate::plugins::js_scanner::JsSecretScannerPlugin::new(),
        ));

        tracing::info!(
            "Plugin manager initialized with {} plugins",
            registry.count()
        );
        Self { registry }
    }

    /// Run all plugins against a target.
    pub fn run_plugins(&self, target: &str, scan_id: &str) -> Vec<PluginResult> {
        self.registry.run_all(target, scan_id)
    }

    /// Fire hook to all listening plugins.
    pub fn fire_hook(&self, hook: &HookPoint) -> Vec<PluginResult> {
        self.registry.fire_hook(hook)
    }

    /// Get plugin registry for inspection.
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    pub fn plugin_count(&self) -> usize {
        self.registry.count()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_manager_init() {
        let mgr = PluginManager::new();
        assert_eq!(mgr.plugin_count(), 2);
    }

    #[test]
    fn test_list_plugins() {
        let mgr = PluginManager::new();
        let list = mgr.registry().list();
        assert!(list.iter().any(|n| n.contains("sqli-scanner")));
        assert!(list.iter().any(|n| n.contains("js-secret-scanner")));
    }

    #[test]
    fn test_run_plugins() {
        let mgr = PluginManager::new();
        let results = mgr.run_plugins("example.com", "scan-123");
        assert_eq!(results.len(), 2);
    }
}
