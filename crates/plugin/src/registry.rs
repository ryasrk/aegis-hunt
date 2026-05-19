use crate::plugin::{AegisPlugin, HookPoint, PluginResult};
use std::collections::HashMap;

/// Registry of all installed plugins.
pub struct PluginRegistry {
    plugins: Vec<Box<dyn AegisPlugin>>,
    hook_index: HashMap<String, Vec<usize>>, // hook type -> plugin indices
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            hook_index: HashMap::new(),
        }
    }

    /// Register a plugin.
    pub fn register(&mut self, plugin: Box<dyn AegisPlugin>) {
        let name = plugin.name().to_string();
        let idx = self.plugins.len();
        self.plugins.push(plugin);

        // Index plugin by its hook points
        for hook in self.plugins[idx].hooks() {
            let hook_key = format!("{:?}", hook);
            // Strip the Finding data from the key for generic hooks
            let hook_key = if hook_key.starts_with("OnFinding") {
                "OnFinding".to_string()
            } else {
                hook_key
            };
            self.hook_index.entry(hook_key).or_default().push(idx);
        }

        tracing::info!(
            "Registered plugin: {} ({} hooks)",
            name,
            self.plugins[idx].hooks().len()
        );
    }

    /// Run all plugins against a target.
    pub fn run_all(&self, target: &str, scan_id: &str) -> Vec<PluginResult> {
        let mut results = Vec::new();
        for plugin in &self.plugins {
            match plugin.execute(target, scan_id) {
                Ok(result) => {
                    if !result.findings.is_empty() {
                        tracing::info!(
                            "Plugin {}: {} findings",
                            plugin.name(),
                            result.findings.len()
                        );
                    }
                    results.push(result);
                }
                Err(e) => {
                    tracing::warn!("Plugin {} failed: {}", plugin.name(), e);
                }
            }
        }
        results
    }

    /// Fire a hook to all plugins that registered for it.
    pub fn fire_hook(&self, hook: &HookPoint) -> Vec<PluginResult> {
        let mut results = Vec::new();
        let hook_key = format!("{:?}", hook);
        let hook_key = if hook_key.starts_with("OnFinding") {
            "OnFinding".to_string()
        } else {
            hook_key
        };

        if let Some(indices) = self.hook_index.get(&hook_key) {
            for &idx in indices {
                if let Ok(Some(result)) = self.plugins[idx].on_hook(hook) {
                    results.push(result);
                }
            }
        }
        results
    }

    /// Get a plugin by name.
    pub fn get(&self, name: &str) -> Option<&dyn AegisPlugin> {
        self.plugins.iter().find(|p| p.name() == name).map(|p| p.as_ref())
    }

    /// List all registered plugin names.
    pub fn list(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|p| format!("{} v{}", p.name(), p.version()))
            .collect()
    }

    pub fn count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}
