use crate::plugin::ReconPluginSync;
use aegis_core::error::{AegisError, AegisResult};
use std::process::Command;
use tracing::{info, error};

pub struct SubfinderPlugin;

impl ReconPluginSync for SubfinderPlugin {
    fn name(&self) -> &'static str {
        "subfinder"
    }

    fn execute(&self, target: &str, scan_id: &str) -> AegisResult<Vec<String>> {
        info!("[{}] Running subfinder on {}", scan_id, target);

        let output = Command::new("subfinder")
            .arg("-d")
            .arg(target)
            .arg("-silent")
            .arg("-all")
            .output()
            .map_err(|e| AegisError::ToolExecution(format!("subfinder spawn failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("[{}] subfinder error: {}", scan_id, stderr);
            return Err(AegisError::ToolExecution(format!(
                "subfinder exited with {}: {}",
                output.status, stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let domains: Vec<String> = stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        info!("[{}] subfinder found {} subdomains", scan_id, domains.len());
        Ok(domains)
    }
}
