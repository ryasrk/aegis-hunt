use crate::plugin::ReconPluginSync;
use aegis_core::error::{AegisError, AegisResult};
use std::process::Command;
use tracing::info;

pub struct HttpxPlugin;

impl ReconPluginSync for HttpxPlugin {
    fn name(&self) -> &'static str {
        "httpx"
    }

    fn execute(&self, target: &str, scan_id: &str) -> AegisResult<Vec<String>> {
        info!("[{}] Running httpx on {}", scan_id, target);

        let output = Command::new("httpx")
            .arg("-u")
            .arg(target)
            .arg("-silent")
            .arg("-status-code")
            .arg("-title")
            .arg("-tech-detect")
            .arg("-content-length")
            .arg("-json")
            .output()
            .map_err(|e| AegisError::ToolExecution(format!("httpx spawn failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AegisError::ToolExecution(format!(
                "httpx exited with {}: {}",
                output.status, stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let results: Vec<String> = stdout.lines().map(|l| l.to_string()).collect();
        info!("[{}] httpx returned {} results", scan_id, results.len());
        Ok(results)
    }
}
