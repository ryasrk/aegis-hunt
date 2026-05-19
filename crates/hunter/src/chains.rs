pub struct ChainEngine;

impl ChainEngine {
    /// Given a list of vulnerability types found, generate all possible attack chains.
    pub fn find_chains(findings: &[VulnSummary]) -> Vec<AttackChain> {
        let mut chains = Vec::new();
        let types: Vec<&str> = findings.iter().map(|f| f.vuln_type.as_str()).collect();

        // Group findings by type
        let has_sqli = types.contains(&"sqli");
        let has_xss = types.contains(&"xss");
        let has_ssrf = types.contains(&"ssrf");
        let has_lfi = types.contains(&"lfi");
        let has_idor = types.contains(&"idor");
        let has_redirect = types.contains(&"open_redirect");
        let has_takeover = types.contains(&"takeover");
        let has_ssti = types.contains(&"ssti");
        let _has_rce = types.contains(&"rce");
        let has_cors = types.contains(&"cors");

        // 1. SSRF + IDOR = Full internal compromise
        if has_ssrf && has_idor {
            chains.push(AttackChain {
                name: "SSRF + IDOR → Full Internal Access".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "Use IDOR to gather internal service information (hostnames, ports)".into(),
                    "Identify SSRF-vulnerable endpoint".into(),
                    "Pivot through internal network using SSRF + IDOR intel".into(),
                    "Access internal services (databases, admin panels, cloud metadata)".into(),
                ],
                description: "IDOR reveals internal architecture, SSRF exploits it — combined they expose the entire internal network.".into(),
            });
        }
        if has_ssrf && has_lfi {
            chains.push(AttackChain {
                name: "SSRF + LFI → Source Code → Credentials".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "Use LFI to read application source code and config files".into(),
                    "Extract internal API endpoints and hardcoded credentials from source".into(),
                    "Use SSRF to access internal services discovered in source".into(),
                    "Escalate to full internal network compromise".into(),
                ],
                description: "LFI provides intelligence that SSRF weaponizes — read source to find internal endpoints, then hit them via SSRF.".into(),
            });
        }

        // 2. XSS + CORS = Full account takeover
        if has_xss && has_cors {
            chains.push(AttackChain {
                name: "Stored XSS + CORS → Zero-Click Account Takeover".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "CORS allows cross-origin reads from attacker's domain".into(),
                    "Craft XSS payload that uses CORS to exfiltrate sensitive data".into(),
                    "When victim views the XSS, CORS-enabled API calls leak their data".into(),
                    "Harvest PII, tokens, and perform actions as victim".into(),
                ],
                description: "XSS executes in victim context. CORS allows reading cross-origin responses. Together: complete account takeover on view.".into(),
            });
        }

        // 3. Redirect → OAuth Token Theft
        if has_redirect && has_xss {
            chains.push(AttackChain {
                name: "Open Redirect + XSS → OAuth Token Theft".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "Open redirect bypasses OAuth redirect URI validation".into(),
                    "Craft OAuth authorization URL pointing to attacker via redirect".into(),
                    "Victim authorizes, code/token flows through attacker's redirect".into(),
                    "Attacker captures OAuth code and exchanges for access token".into(),
                    "Full account takeover via compromised OAuth token".into(),
                ],
                description: "OAuth relies on redirect URIs for flow completion. Open redirect breaks this guarantee, leaking tokens to attacker.".into(),
            });
        }

        // 4. IDOR + SQLi = Full data breach
        if has_idor && has_sqli {
            chains.push(AttackChain {
                name: "IDOR + SQLi → Massive Data Breach".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "Use IDOR to identify data patterns (user IDs, record structures)".into(),
                    "Apply SQL injection to extract entire database".into(),
                    "Cross-reference SQLi output with IDOR-accessible endpoints".into(),
                    "Exfiltrate all user data, PII, secrets, and credentials".into(),
                ],
                description: "IDOR maps the data model, SQLi extracts the data — worst case for data breach scenarios.".into(),
            });
        }

        // 5. All chains that involve SSRF → Cloud
        if has_ssrf {
            chains.push(AttackChain {
                name: "SSRF → Cloud Metadata → Cloud Compromise".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "Inject cloud metadata endpoint (169.254.169.254) into SSRF-vulnerable parameter".into(),
                    "Extract IAM/instance credentials from metadata response".into(),
                    "Use stolen cloud credentials to access cloud resources".into(),
                    "Pivot from cloud access to further compromise".into(),
                ],
                description: "Single SSRF on cloud-hosted app can lead to full cloud account compromise via metadata service.".into(),
            });
        }

        // 6. SSTI → RCE
        if has_ssti {
            chains.push(AttackChain {
                name: "SSTI → Remote Code Execution".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "Identify template injection point (parameter, header, file name)".into(),
                    "Craft SSTI payload for detected template engine (Jinja2, Freemarker, etc.)".into(),
                    "Execute system commands on the server".into(),
                    "Establish persistent access for lateral movement".into(),
                ],
                description: "Server-Side Template Injection is a direct path to RCE on most template engines.".into(),
            });
        }

        // 7. Takeover + XSS
        if has_takeover && has_xss {
            chains.push(AttackChain {
                name: "Subdomain Takeover + XSS → Widespread Phishing".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "Register the unclaimed subdomain".into(),
                    "Deploy a functional clone of the login page with XSS payload".into(),
                    "XSS captures credentials and session tokens from victims".into(),
                    "Use stolen sessions for privileged access".into(),
                ],
                description: "Takeover gives control of trusted origin, combined with XSS creates multi-victim credential harvesting.".into(),
            });
        }

        // 8. LFI → RCE
        if has_lfi {
            chains.push(AttackChain {
                name: "LFI → Remote Code Execution".into(),
                severity: "CRITICAL".into(),
                steps: vec![
                    "Use LFI to read /proc/self/environ or access logs".into(),
                    "Inject PHP code into log files via User-Agent header".into(),
                    "Include the log file via LFI to execute injected code".into(),
                    "Achieve RCE with further shell access".into(),
                ],
                description: "LFI can be escalated to RCE through log poisoning, /proc/self/environ injection, or PHP wrapper deserialization.".into(),
            });
        }

        chains
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VulnSummary {
    pub vuln_type: String,
    pub title: String,
    pub severity: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackChain {
    pub name: String,
    pub severity: String,
    pub steps: Vec<String>,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ssrf_cloud_chain() {
        let findings = vec![VulnSummary { vuln_type: "ssrf".into(), title: "SSRF".into(), severity: "HIGH".into(), endpoint: "https://target".into() }];
        let chains = ChainEngine::find_chains(&findings);
        assert!(chains.iter().any(|c| c.name.contains("Cloud")));
    }
    #[test]
    fn test_xss_cors_chain() {
        let findings = vec![
            VulnSummary { vuln_type: "xss".into(), title: "XSS".into(), severity: "HIGH".into(), endpoint: "https://target".into() },
            VulnSummary { vuln_type: "cors".into(), title: "CORS".into(), severity: "MEDIUM".into(), endpoint: "https://target".into() },
        ];
        let chains = ChainEngine::find_chains(&findings);
        assert!(chains.iter().any(|c| c.name.contains("XSS + CORS")));
    }
    #[test]
    fn test_ssti_rce_chain() {
        let findings = vec![VulnSummary { vuln_type: "ssti".into(), title: "SSTI".into(), severity: "CRITICAL".into(), endpoint: "https://target".into() }];
        let chains = ChainEngine::find_chains(&findings);
        assert!(chains.iter().any(|c| c.name.contains("Remote Code Execution")));
    }
    #[test]
    fn test_no_chains_for_unrelated() {
        let findings = vec![VulnSummary { vuln_type: "info".into(), title: "CORS".into(), severity: "LOW".into(), endpoint: "https://target".into() }];
        let chains = ChainEngine::find_chains(&findings);
        assert!(chains.is_empty());
    }
}
