use aegis_core::types::{Severity, ScanReport};

pub struct MarkdownReport;

impl MarkdownReport {
    pub fn generate(report: &ScanReport) -> String {
        let mut output = String::new();

        // Header
        output.push_str("# Aegis Scan Report\n\n");
        output.push_str(&format!("**Target:** `{}`\n\n", report.target));
        output.push_str(&format!("**Scan ID:** `{}`\n\n", report.scan_id));
        output.push_str(&format!(
            "**Date:** {}\n\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        if let Some(dur) = report.duration_secs {
            let mins = dur / 60;
            let secs = dur % 60;
            output.push_str(&format!("**Duration:** {}m {}s\n\n", mins, secs));
        }

        // Severity breakdown
        let critical = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();

        output.push_str("## Summary\n\n");
        output.push_str("| Severity | Count |\n|----------|-------|\n");
        output.push_str(&format!("| 🔴 Critical | {} |\n", critical));
        output.push_str(&format!("| 🟠 High     | {} |\n", high));
        output.push_str(&format!("| 🟡 Medium   | {} |\n", medium));
        output.push_str(&format!("| 🔵 Low      | {} |\n", low));
        output.push('\n');

        output.push_str(&format!(
            "**Total Findings:** {}\n\n",
            report.findings.len()
        ));
        output.push_str(&format!(
            "**Subdomains Discovered:** {}\n\n",
            report.subdomains.len()
        ));
        output.push_str(&format!(
            "**Live Services:** {}\n\n",
            report.services.len()
        ));
        output.push_str(&format!(
            "**Technologies Detected:** {}\n\n",
            report.technologies.len()
        ));

        // Attack surface
        if !report.services.is_empty() {
            output.push_str("## Attack Surface\n\n");
            output.push_str("| URL | Status | Title | Tech |\n");
            output.push_str("|-----|--------|-------|------|\n");
            for s in &report.services {
                let title = s.title.as_deref().unwrap_or("-");
                let tech = if s.tech_stack.is_empty() {
                    "-".to_string()
                } else {
                    s.tech_stack.join(", ")
                };
                output.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    s.url, s.status_code, title, tech
                ));
            }
            output.push('\n');
        }

        // Findings
        if !report.findings.is_empty() {
            output.push_str("## Findings\n\n");
            for f in &report.findings {
                output.push_str(&format!("### [{}] {}\n\n", f.severity, f.title));
                output.push_str(&format!("**Confidence:** {}%\n\n", f.confidence));
                output.push_str(&format!("**Description:** {}\n\n", f.description));

                if let Some(ref evidence) = f.evidence {
                    output.push_str("**Evidence:**\n```\n");
                    output.push_str(evidence);
                    output.push_str("\n```\n\n");
                }

                if let Some(ref cve) = f.cve {
                    output.push_str(&format!("**CVE:** `{}`\n\n", cve));
                }
                if let Some(ref remediation) = f.remediation {
                    output.push_str(&format!("**Remediation:** {}\n\n", remediation));
                }
                output.push_str("---\n\n");
            }
        }

        // Exploit references
        if !report.exploit_refs.is_empty() {
            output.push_str("## Exploit References\n\n");
            output.push_str("| EDB ID | CVE | Title | Type | Path |\n");
            output.push_str("|--------|-----|-------|------|------|\n");
            for er in &report.exploit_refs {
                let cve = er.cve.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "| EDB-{} | {} | {} | {} | `{}` |\n",
                    er.edb_id, cve, er.title, er.exploit_type, er.file_path
                ));
            }
            output.push('\n');
        }

        output
    }

    pub fn write_to_file(report: &ScanReport, path: &str) -> std::io::Result<()> {
        let markdown = Self::generate(report);
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, markdown)
    }
}
