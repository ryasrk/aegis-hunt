use std::process::Command;
use tracing::{info, warn};

pub struct Notifier;

impl Notifier {
    /// Notify via the `notify` CLI tool (installed at ~/go/bin/notify).
    pub fn notify_critical(scan_id: &str, title: &str, message: &str) {
        info!("[{}] CRITICAL ALERT: {} - {}", scan_id, title, message);

        if let Ok(output) = Command::new("notify")
            .arg("-silent")
            .arg("-bulk")
            .arg("-data")
            .arg(format!("[Aegis] {}: {}", title, message))
            .output()
        {
            if output.status.success() {
                info!("[{}] Notify sent: {}", scan_id, title);
            } else {
                warn!(
                    "[{}] Notify failed: {}",
                    scan_id,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        } else {
            warn!("[{}] notify CLI not found in PATH", scan_id);
        }
    }

    /// Notify on a finding event.
    pub fn on_finding(scan_id: &str, severity: &str, title: &str, endpoint: &str) {
        let msg = format!("[{}] {}: {} @ {}", scan_id, severity, title, endpoint);
        match severity {
            "CRITICAL" | "HIGH" => {
                Self::notify_critical(scan_id, msg.as_str(), "Action required")
            }
            _ => info!("[{}] Finding: {}", scan_id, msg),
        }
    }
}
