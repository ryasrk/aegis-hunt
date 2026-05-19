use crate::plugin::ReconPluginSync;
use aegis_core::error::{AegisError, AegisResult};
use std::process::Command;
use tracing::info;

pub struct NucleiPlugin;

impl ReconPluginSync for NucleiPlugin {
    fn name(&self) -> &'static str {
        "nuclei"
    }

    fn execute(&self, target: &str, scan_id: &str) -> AegisResult<Vec<String>> {
        info!("[{}] Running nuclei on {}", scan_id, target);

        let output = Command::new("nuclei")
            .arg("-u")
            .arg(target)
            .arg("-silent")
            .arg("-severity")
            .arg("critical,high,medium")
            .arg("-json")
            .output()
            .map_err(|e| AegisError::ToolExecution(format!("nuclei spawn failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AegisError::ToolExecution(format!(
                "nuclei exited with {}: {}",
                output.status, stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let results: Vec<String> = stdout.lines().map(|l| l.to_string()).collect();
        info!("[{}] nuclei returned {} results", scan_id, results.len());
        Ok(results)
    }
}
