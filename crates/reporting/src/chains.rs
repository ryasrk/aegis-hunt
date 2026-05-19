use aegis_core::types::Finding;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackChain {
    pub name: String,
    pub severity: String,
    pub steps: Vec<String>,
    pub description: String,
}

/// Analyze findings for known attack chains.
pub fn find_chains(findings: &[Finding]) -> Vec<AttackChain> {
    let mut chains = Vec::new();

    // Check for SQLi → RCE chain
    let has_sqli = findings.iter().any(|f| f.title.to_lowercase().contains("sql"));
    let has_admin = findings.iter().any(|f| f.title.to_lowercase().contains("admin"));
    if has_sqli {
        chains.push(AttackChain {
            name: "SQL Injection → Data Exfiltration".into(),
            severity: if has_admin { "CRITICAL".into() } else { "HIGH".into() },
            steps: vec![
                "1. Exploit SQL injection to extract database contents".into(),
                "2. Extract admin credentials from users table".into(),
                "3. Login as admin via extracted credentials".into(),
                "4. Escalate to RCE via admin panel functionality".into(),
            ],
            description: format!("SQL injection found{} — can extract database, pivot to admin access, and potentially achieve RCE.",
                if has_admin { " with admin panel accessible" } else { "" }),
        });
    }

    // Check for XSS → Session hijack
    let has_xss = findings.iter().any(|f| f.title.to_lowercase().contains("xss") || f.title.to_lowercase().contains("cross-site"));
    if has_xss {
        chains.push(AttackChain {
            name: "Cross-Site Scripting → Account Takeover".into(),
            severity: "HIGH".into(),
            steps: vec![
                "1. Craft XSS payload targeting session cookies".into(),
                "2. Host proof-of-concept at attacker-controlled domain".into(),
                "3. Send victim link via phishing or vulnerable feature".into(),
                "4. Capture session cookie via XSS callback".into(),
                "5. Hijack victim's authenticated session".into(),
            ],
            description: "Stored/reflected XSS enables session hijacking by executing JavaScript in the victim's browser context.".into(),
        });
    }

    // Check for SSRF → Cloud metadata
    let has_ssrf = findings.iter().any(|f| f.title.to_lowercase().contains("ssrf"));
    if has_ssrf {
        chains.push(AttackChain {
            name: "SSRF → Cloud Metadata → Credential Theft".into(),
            severity: "CRITICAL".into(),
            steps: vec![
                "1. Identify injectable URL parameter".into(),
                "2. Inject cloud metadata URL: http://169.254.169.254/latest/meta-data/".into(),
                "3. Extract IAM credentials from metadata response".into(),
                "4. Use stolen credentials to access cloud resources".into(),
            ],
            description: "SSRF vulnerability allows access to cloud metadata service, leaking IAM credentials for privilege escalation.".into(),
        });
    }

    // SSRF + LFI
    let has_lfi = findings.iter().any(|f| f.title.to_lowercase().contains("lfi") || f.title.to_lowercase().contains("file inclusion"));
    if has_lfi && has_ssrf {
        chains.push(AttackChain {
            name: "LFI + SSRF → Full Internal Network Access".into(),
            severity: "CRITICAL".into(),
            steps: vec![
                "1. Use LFI to read source code and understand internal architecture".into(),
                "2. Identify internal service endpoints from source".into(),
                "3. Use SSRF to probe internal services found in source".into(),
                "4. Chain to further compromise internal systems".into(),
            ],
            description: "LFI provides internal intelligence that SSRF can then exploit for lateral movement.".into(),
        });
    }

    // Takeover + Phishing
    let has_takeover = findings.iter().any(|f| f.title.to_lowercase().contains("takeover") || f.title.to_lowercase().contains("subdomain"));
    if has_takeover {
        chains.push(AttackChain {
            name: "Subdomain Takeover → Phishing/Session Theft".into(),
            severity: "HIGH".into(),
            steps: vec![
                "1. Register the vulnerable cloud service at the claimed domain".into(),
                "2. Host a phishing page mirroring the login portal".into(),
                "3. Capture credentials from unsuspecting users".into(),
                "4. Use captured credentials for authenticated attacks".into(),
            ],
            description: "Unclaimed subdomain can be registered to an attacker-controlled service for phishing or session theft.".into(),
        });
    }

    chains
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::types::{Finding, Severity};
    use chrono::Utc;

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            id: "test".into(), service_id: None, endpoint_id: None,
            title: title.into(), severity, confidence: 80,
            description: "".into(), evidence: None,
            cve: None, edb_id: None, remediation: None,
            discovered_at: Utc::now(),
        }
    }

    #[test]
    fn test_sqli_chain() {
        let findings = vec![make_finding("SQL Injection in login", Severity::Critical)];
        let chains = find_chains(&findings);
        assert!(chains.iter().any(|c| c.name.contains("SQL")));
    }

    #[test]
    fn test_xss_chain() {
        let findings = vec![make_finding("Stored XSS in profile", Severity::High)];
        let chains = find_chains(&findings);
        assert!(chains.iter().any(|c| c.name.contains("Cross-Site Scripting")));
    }

    #[test]
    fn test_ssrf_lfi_chain() {
        let findings = vec![
            make_finding("SSRF in image upload", Severity::High),
            make_finding("LFI in download parameter", Severity::High),
        ];
        let chains = find_chains(&findings);
        assert!(chains.iter().any(|c| c.name.contains("LFI")));
        assert!(chains.iter().any(|c| c.name.contains("SSRF") && c.name.contains("Cloud")));
    }
}
