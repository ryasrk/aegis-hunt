#[derive(Debug, Clone, serde::Serialize)]
pub struct ParamVulnClass {
    pub parameter: String,
    pub likely_vuln: String,
    pub confidence: u8,
    pub reason: String,
    pub test_payload: String,
}

/// Known dangerous parameter names and what they typically indicate.
pub fn classify_parameters(params: &[String]) -> Vec<ParamVulnClass> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let classifications: Vec<(&str, &str, u8, &str, &str)> = vec![
        ("redirect", "Open Redirect", 90, "Redirect parameter is almost always exploitable", "https://evil.com"),
        ("redirect_url", "Open Redirect", 90, "Common redirect parameter name", "https://evil.com"),
        ("return", "Open Redirect", 85, "Return URL parameter", "https://evil.com"),
        ("next", "Open Redirect", 85, "Next/redirect parameter", "https://evil.com"),
        ("callback", "Open Redirect", 85, "Callback URL parameter", "https://evil.com"),
        ("url", "SSRF/Open Redirect", 80, "URL parameter may be used for server-side fetching", "http://169.254.169.254/latest/meta-data/"),
        ("image_url", "SSRF", 85, "Image URL is often fetched server-side", "http://169.254.169.254/latest/meta-data/"),
        ("file", "LFI/Path Traversal", 90, "File parameter suggests local file inclusion", "../../../etc/passwd"),
        ("file_path", "LFI", 90, "File path parameter strongly suggests LFI", "../../../etc/passwd"),
        ("filename", "LFI/Path Traversal", 80, "Filename parameter may allow path traversal", "../../../etc/passwd"),
        ("template", "SSTI", 85, "Template parameter suggests Server-Side Template Injection", "{{7*7}}"),
        ("page", "LFI", 75, "Page parameter often used for includes", "../../../etc/passwd"),
        ("include", "LFI", 85, "Include parameter suggests file inclusion", "../../../etc/passwd"),
        ("path", "LFI/Path Traversal", 80, "Path parameter may allow traversal", "../../../etc/passwd"),
        ("email", "NoSQLi/Account Enumeration", 80, "Email parameter may be injection point", "'||'1'=='1"),
        ("search", "SQLi/NoSQLi", 75, "Search parameter is often injectable", "' OR 1=1--"),
        ("q", "SQLi/NoSQLi", 70, "Query parameter is commonly injected", "' OR 1=1--"),
        ("query", "SQLi/GraphQL", 75, "Query parameter may be SQL or GraphQL injection", "' OR 1=1--"),
        ("id", "IDOR", 85, "ID parameter is the most common IDOR vector", "100"),
        ("user_id", "IDOR", 90, "User ID parameter is a high-confidence IDOR vector", "100"),
        ("uid", "IDOR", 85, "User ID parameter is an IDOR candidate", "100"),
        ("account_id", "IDOR", 85, "Account ID parameter is likely IDOR", "100"),
        ("customer_id", "IDOR", 85, "Customer ID parameter may be IDOR-able", "100"),
        ("order_id", "IDOR", 80, "Order ID parameter may expose other orders", "100"),
        ("token", "Token/Prediction", 80, "Token may be predictable or leaky", "testing"),
        ("api_key", "Secret Leak", 95, "API key in URL is a serious leak", "n/a"),
        ("secret", "Secret Leak", 90, "Secret in URL parameter is a leak", "n/a"),
        ("password", "Secret Leak", 95, "Password in URL is a serious security issue", "n/a"),
        ("debug", "Debug Mode", 90, "Debug parameter may enable debug output", "1"),
        ("env", "Info Leak", 80, "Environment parameter may leak configuration", "1"),
        ("format", "Format String", 75, "Format parameter may be injectable", "%x%x%x"),
    ];

    for param in params {
        let lower = param.to_lowercase();
        for &(name, vuln, confidence, reason, payload) in &classifications {
            if lower == name && seen.insert(name) {
                results.push(ParamVulnClass {
                    parameter: param.clone(),
                    likely_vuln: vuln.to_string(),
                    confidence,
                    reason: reason.to_string(),
                    test_payload: payload.to_string(),
                });
            }
        }
    }

    results.sort_by_key(|b| std::cmp::Reverse(b.confidence));
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_redirect_param() {
        let results = classify_parameters(&["redirect".into()]);
        assert!(results.iter().any(|r| r.likely_vuln.contains("Open Redirect")));
    }
    #[test]
    fn test_file_param() {
        let results = classify_parameters(&["file".into()]);
        assert!(results.iter().any(|r| r.likely_vuln.contains("LFI")));
    }
    #[test]
    fn test_id_param() {
        let results = classify_parameters(&["id".into()]);
        assert!(results.iter().any(|r| r.likely_vuln == "IDOR"));
    }
    #[test]
    fn test_url_param() {
        let results = classify_parameters(&["url".into()]);
        assert!(results.iter().any(|r| r.likely_vuln.contains("SSRF")));
    }
    #[test]
    fn test_multiple_params() {
        let results = classify_parameters(&["redirect".into(), "file".into(), "id".into()]);
        assert_eq!(results.len(), 3);
    }
}
