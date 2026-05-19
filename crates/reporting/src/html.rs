use aegis_core::types::{ScanReport, Severity};

pub struct HtmlReport;

impl HtmlReport {
    pub fn generate(report: &ScanReport) -> String {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>");
        html.push_str(&format!("Aegis Report - {}", report.target));
        html.push_str("</title><style>\n");
        html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }\n");
        html.push_str("h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }\n");
        html.push_str("h2 { color: #58a6ff; margin-top: 30px; }\n");
        html.push_str("h3 { margin: 15px 0 5px; }\n");
        html.push_str(".severity-critical { color: #f85149; font-weight: bold; }\n");
        html.push_str(".severity-high { color: #d29922; }\n");
        html.push_str(".severity-medium { color: #58a6ff; }\n");
        html.push_str(".severity-low { color: #8b949e; }\n");
        html.push_str(".finding { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 10px 0; }\n");
        html.push_str(".finding .title { font-size: 16px; font-weight: 600; margin-bottom: 8px; }\n");
        html.push_str(".finding .meta { font-size: 12px; color: #8b949e; margin-bottom: 8px; }\n");
        html.push_str(".finding .meta span { margin-right: 15px; }\n");
        html.push_str(".finding .evidence { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; margin-top: 8px; }\n");
        html.push_str("table { width: 100%; border-collapse: collapse; margin: 15px 0; }\n");
        html.push_str("th, td { border: 1px solid #30363d; padding: 8px 12px; text-align: left; }\n");
        html.push_str("th { background: #161b22; color: #58a6ff; }\n");
        html.push_str(".summary-box { display: inline-block; padding: 8px 16px; margin: 5px; border-radius: 6px; font-weight: bold; font-size: 24px; text-align: center; min-width: 80px; }\n");
        html.push_str(".summary-box.critical { background: #f85149; color: #fff; }\n");
        html.push_str(".summary-box.high { background: #d29922; color: #fff; }\n");
        html.push_str(".summary-box.medium { background: #58a6ff; color: #fff; }\n");
        html.push_str(".summary-box.low { background: #8b949e; color: #fff; }\n");
        html.push_str(".stats { display: flex; gap: 10px; flex-wrap: wrap; margin: 20px 0; }\n");
        html.push_str(".stat-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 20px; text-align: center; }\n");
        html.push_str(".stat-item .value { font-size: 28px; font-weight: bold; color: #58a6ff; }\n");
        html.push_str(".stat-item .label { font-size: 12px; color: #8b949e; }\n");
        html.push_str("</style></head><body>");

        // Header
        html.push_str(&format!("<h1>Aegis Scan Report: {}</h1>", report.target));
        html.push_str(&format!("<p>Scan ID: <code>{}</code></p>", report.scan_id));
        html.push_str(&format!("<p>Date: {}</p>", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
        if let Some(dur) = report.duration_secs {
            html.push_str(&format!("<p>Duration: {}m {}s</p>", dur / 60, dur % 60));
        }

        // Severity summary
        let critical = report.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = report.findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = report.findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = report.findings.iter().filter(|f| f.severity == Severity::Low).count();

        html.push_str("<h2>Summary</h2><div class='stats'>");
        html.push_str(&format!("<div class='stat-item'><div class='value' style='color:#f85149'>{}</div><div class='label'>Critical</div></div>", critical));
        html.push_str(&format!("<div class='stat-item'><div class='value' style='color:#d29922'>{}</div><div class='label'>High</div></div>", high));
        html.push_str(&format!("<div class='stat-item'><div class='value' style='color:#58a6ff'>{}</div><div class='label'>Medium</div></div>", medium));
        html.push_str(&format!("<div class='stat-item'><div class='value' style='color:#8b949e'>{}</div><div class='label'>Low</div></div>", low));
        html.push_str("</div>");

        html.push_str(&format!("<p><strong>Total:</strong> {} findings | <strong>Subdomains:</strong> {} | <strong>Services:</strong> {} | <strong>Technologies:</strong> {}</p>",
            report.findings.len(), report.subdomains.len(), report.services.len(), report.technologies.len()));

        // Attack surface table
        if !report.services.is_empty() {
            html.push_str("<h2>Attack Surface</h2><table><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr>");
            for s in &report.services {
                let title = s.title.as_deref().unwrap_or("-");
                let tech = s.tech_stack.join(", ");
                html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", s.url, s.status_code, title, if tech.is_empty() { "-".into() } else { tech }));
            }
            html.push_str("</table>");
        }

        // Findings
        if !report.findings.is_empty() {
            html.push_str("<h2>Findings</h2>");
            for f in &report.findings {
                let sev_class = format!("severity-{}", f.severity.to_string().to_lowercase());
                html.push_str(&format!("<div class='finding'><div class='title {}'>[{}] {}</div>",
                    sev_class, f.severity, f.title));
                html.push_str(&format!("<div class='meta'><span>Confidence: {}%</span></div>", f.confidence));
                html.push_str(&format!("<p>{}</p>", f.description));
                if let Some(ref evidence) = f.evidence {
                    html.push_str(&format!("<div class='evidence'>{}</div>", html_escape(evidence)));
                }
                if let Some(ref cve) = f.cve {
                    html.push_str(&format!("<p><strong>CVE:</strong> <code>{}</code></p>", cve));
                }
                if let Some(ref remediation) = f.remediation {
                    html.push_str(&format!("<p><strong>Remediation:</strong> {}</p>", remediation));
                }
                html.push_str("</div>");
            }
        }

        // Exploit references
        if !report.exploit_refs.is_empty() {
            html.push_str("<h2>Exploit References</h2><table><tr><th>EDB ID</th><th>CVE</th><th>Title</th><th>Path</th></tr>");
            for er in &report.exploit_refs {
                let cve = er.cve.as_deref().unwrap_or("-");
                html.push_str(&format!("<tr><td>EDB-{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>", er.edb_id, cve, er.title, er.file_path));
            }
            html.push_str("</table>");
        }

        html.push_str("</body></html>");
        html
    }

    pub fn write_to_file(report: &ScanReport, path: &str) -> std::io::Result<()> {
        let html = Self::generate(report);
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, html)
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
