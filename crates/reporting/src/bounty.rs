use aegis_core::types::{ExploitRef, Finding, Severity};

#[derive(Debug, Clone, serde::Serialize)]
pub struct BountyReport {
    pub title: String,
    pub severity: String,
    pub vulnerability_type: String,
    pub endpoint: String,
    pub description: String,
    pub steps_to_reproduce: Vec<String>,
    pub impact: String,
    pub remediation: String,
    pub proof_of_concept: Option<String>,
    pub expected_vs_actual: Option<String>,
    pub attachments: Vec<String>,
}

/// Format findings for HackerOne submission.
pub fn format_hackerone(findings: &[Finding], exploits: &[ExploitRef]) -> Vec<BountyReport> {
    findings
        .iter()
        .map(|f| {
            let poc = f
                .evidence
                .as_ref()
                .map(|e| format!("```\n{}\n```", e));

            let steps = vec![
                format!("1. Navigate to the affected endpoint"),
                format!("2. Send the request that triggers the vulnerability"),
                format!("3. Observe the unexpected behavior"),
                if let Some(ref cve) = f.cve {
                    format!("4. This corresponds to {}", cve)
                } else {
                    "4. Document the security impact".into()
                },
            ];

            // Find matching exploits
            let exploit_refs: Vec<String> = exploits
                .iter()
                .filter(|e| {
                    f.cve.as_ref().is_some_and(|c| {
                        e.cve.as_ref() == Some(c)
                    })
                })
                .map(|e| {
                    format!(
                        "- EDB-{}: {} ({})",
                        e.edb_id, e.title, e.file_path
                    )
                })
                .collect();

            let impact = match f.severity {
                Severity::Critical => "An attacker can fully compromise the system, access all data, and potentially pivot to internal infrastructure.".into(),
                Severity::High => "An attacker can access sensitive data or perform privileged actions without authorization.".into(),
                Severity::Medium => "An attacker can access limited information or perform actions that should be restricted.".into(),
                _ => "Limited information disclosure or minor security control bypass.".into(),
            };

            BountyReport {
                title: f.title.clone(),
                severity: f.severity.to_string(),
                vulnerability_type: classify_vulnerability(&f.title),
                endpoint: f.endpoint_id.as_ref().cloned().unwrap_or_default(),
                description: f.description.clone(),
                steps_to_reproduce: steps,
                impact,
                remediation: f
                    .remediation
                    .clone()
                    .unwrap_or_else(|| {
                        "Apply security patches and follow OWASP recommendations.".into()
                    }),
                proof_of_concept: poc,
                expected_vs_actual: Some("Expected: The application should enforce proper authorization/input validation.\nActual: The application fails to do so, allowing the described attack.".into()),
                attachments: exploit_refs,
            }
        })
        .collect()
}

/// Format findings for YesWeHack submission (matches YWH form fields).
pub fn format_yeswehack(
    findings: &[Finding],
    _exploits: &[ExploitRef],
) -> Vec<serde_json::Value> {
    findings
        .iter()
        .map(|f| {
            let vuln_type = classify_vulnerability(&f.title);
            let sev = match f.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "informational",
            };

            serde_json::json!({
                "title": f.title,
                "vulnerability_type": vuln_type,
                "severity": sev,
                "cve": f.cve,
                "description": f.description,
                "reproduction_steps": [
                    "1. Identify the affected endpoint/parameter",
                    format!("2. Send a crafted request to {}", f.endpoint_id.as_ref().unwrap_or(&"the endpoint".into())),
                    "3. Observe the security control bypass",
                ],
                "impact": match f.severity {
                    Severity::Critical => "Full system compromise or data breach",
                    Severity::High => "Unauthorized data access or privilege escalation",
                    Severity::Medium => "Limited information disclosure",
                    _ => "Minor security finding",
                },
                "remediation": f.remediation,
                "affected_urls": [f.endpoint_id],
                "proof_of_concept": f.evidence,
            })
        })
        .collect()
}

pub fn classify_vulnerability(title: &str) -> String {
    let lower = title.to_lowercase();
    if lower.contains("sql") {
        "SQL Injection".into()
    } else if lower.contains("xss") || lower.contains("cross-site") {
        "Cross-Site Scripting (XSS)".into()
    } else if lower.contains("ssrf") {
        "Server-Side Request Forgery (SSRF)".into()
    } else if lower.contains("lfi")
        || lower.contains("path traversal")
        || lower.contains("file inclusion")
    {
        "Local File Inclusion (LFI)".into()
    } else if lower.contains("idor")
        || lower.contains("insecure direct")
        || lower.contains("privilege escalation")
    {
        "Insecure Direct Object Reference (IDOR)".into()
    } else if lower.contains("rce")
        || lower.contains("remote code")
        || lower.contains("command injection")
    {
        "Remote Code Execution (RCE)".into()
    } else if lower.contains("ssti") || lower.contains("template") {
        "Server-Side Template Injection (SSTI)".into()
    } else if lower.contains("cors") {
        "CORS Misconfiguration".into()
    } else if lower.contains("redirect") || lower.contains("open redirect") {
        "Open Redirect".into()
    } else if lower.contains("csrf") || lower.contains("cross-site request") {
        "Cross-Site Request Forgery (CSRF)".into()
    } else if lower.contains("takeover") || lower.contains("subdomain") {
        "Subdomain Takeover".into()
    } else if lower.contains("jwt") || lower.contains("token") {
        "JWT/Token Vulnerability".into()
    } else if lower.contains("auth")
        || lower.contains("bypass")
        || lower.contains("authentication")
    {
        "Authentication Bypass".into()
    } else if lower.contains("info")
        || lower.contains("leak")
        || lower.contains("disclosure")
    {
        "Information Disclosure".into()
    } else if lower.contains("secret")
        || lower.contains("api key")
        || lower.contains("exposed")
    {
        "Exposed Secret/API Key".into()
    } else {
        "Security Misconfiguration".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::types::{Finding, Severity};
    use chrono::Utc;

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            id: "test".into(),
            service_id: None,
            endpoint_id: Some("https://target.com/api".into()),
            title: title.into(),
            severity,
            confidence: 80,
            description: "Description here".into(),
            evidence: Some("evidence".into()),
            cve: Some("CVE-2024-0001".into()),
            edb_id: None,
            remediation: Some("Fix it".into()),
            discovered_at: Utc::now(),
        }
    }

    #[test]
    fn test_hackerone_format() {
        let findings = vec![make_finding("SQL Injection", Severity::Critical)];
        let reports = format_hackerone(&findings, &[]);
        assert_eq!(reports.len(), 1);
        assert!(reports[0].steps_to_reproduce.len() >= 3);
    }

    #[test]
    fn test_yeswehack_format() {
        let findings = vec![make_finding("XSS in profile", Severity::High)];
        let reports = format_yeswehack(&findings, &[]);
        assert_eq!(reports.len(), 1);
        assert!(reports[0].get("title").is_some());
    }

    #[test]
    fn test_classify_sqli() {
        assert_eq!(
            classify_vulnerability("SQL Injection in login"),
            "SQL Injection"
        );
    }

    #[test]
    fn test_classify_xss() {
        assert_eq!(
            classify_vulnerability("Stored XSS"),
            "Cross-Site Scripting (XSS)"
        );
    }

    #[test]
    fn test_classify_ssrf() {
        assert_eq!(
            classify_vulnerability("SSRF via image URL"),
            "Server-Side Request Forgery (SSRF)"
        );
    }
}
