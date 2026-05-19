use aegis_core::types::{ScanReport, Severity};

pub struct SarifReport;

impl SarifReport {
    pub fn generate(report: &ScanReport) -> serde_json::Result<String> {
        let mut sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Aegis",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/ryasrk/aegis-hunt"
                    }
                },
                "results": []
            }]
        });

        let results = sarif["runs"][0]["results"].as_array_mut().unwrap();

        for (i, finding) in report.findings.iter().enumerate() {
            let level = match finding.severity {
                Severity::Critical => "error",
                Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
                Severity::Info => "note",
            };

            let mut result = serde_json::json!({
                "ruleId": format!("{}-{:03}", finding.severity.to_string().to_lowercase(), i + 1),
                "level": level,
                "message": {
                    "text": format!("[{}] {}: {}", finding.severity, finding.title, finding.description)
                }
            });

            if let Some(ref cve) = finding.cve {
                result["message"]["text"] = serde_json::json!(
                    format!("[{}] {} (CVE: {}): {}", finding.severity, finding.title, cve, finding.description)
                );
            }

            results.push(result);
        }

        serde_json::to_string_pretty(&sarif)
    }

    pub fn write_to_file(report: &ScanReport, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = Self::generate(report)?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, json)?;
        Ok(())
    }
}
