use aegis_core::error::AegisResult;
use aegis_core::types::Finding;

/// Hook points where plugins can inject behavior.
#[derive(Debug, Clone, PartialEq)]
pub enum HookPoint {
    BeforeRecon,
    AfterRecon,
    BeforeVerify,
    AfterVerify,
    OnFinding(Box<Finding>),
    BeforeReport,
    AfterReport,
}

/// Result returned by a plugin execution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginResult {
    pub plugin_name: String,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<String>,
    pub summary: String,
}

/// The core plugin trait. All Aegis plugins implement this.
pub trait AegisPlugin: Send + Sync {
    /// Unique name of this plugin.
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str {
        ""
    }

    /// Plugin version.
    fn version(&self) -> &str {
        "0.1.0"
    }

    /// Hook points this plugin wants to attach to.
    fn hooks(&self) -> Vec<HookPoint> {
        vec![]
    }

    /// Execute the plugin against a target.
    fn execute(&self, target: &str, scan_id: &str) -> AegisResult<PluginResult>;

    /// Handle a hook event. Default implementation does nothing.
    fn on_hook(&self, _hook: &HookPoint) -> AegisResult<Option<PluginResult>> {
        Ok(None)
    }

    /// Priority: lower number = runs first (default 100).
    fn priority(&self) -> u8 {
        100
    }
}
