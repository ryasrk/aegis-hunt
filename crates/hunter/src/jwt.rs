use base64::Engine as _;

/// Analyze a JWT token for security weaknesses.
pub fn analyze_jwt(token: &str) -> Vec<JwtIssue> {
    let mut issues = Vec::new();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return issues; }

    // Decode header
    if let Ok(decoded) = decode_base64_url(parts[0]) {
        if let Ok(header) = serde_json::from_str::<serde_json::Value>(&decoded) {
            // Check for alg: none
            if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
                if alg == "none" {
                    issues.push(JwtIssue { issue_type: "alg_none".into(), severity: "CRITICAL".into(), description: "JWT accepts 'none' algorithm — authentication bypass via unsigned tokens".into() });
                }
            }
            // Check for empty key
            if header.get("alg").and_then(|v| v.as_str()) == Some("") {
                issues.push(JwtIssue { issue_type: "alg_empty".into(), severity: "CRITICAL".into(), description: "JWT accepts empty algorithm".into() });
            }
            // Check kid header
            if let Some(kid) = header.get("kid").and_then(|v| v.as_str()) {
                if kid.contains("..") || kid.starts_with('/') || kid.starts_with("file://") {
                    issues.push(JwtIssue { issue_type: "kid_injection".into(), severity: "HIGH".into(), description: format!("KID header may be injectable: {}", kid) });
                }
            }
        }
    }

    // Decode payload
    if let Ok(decoded) = decode_base64_url(parts[1]) {
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&decoded) {
            // Check for interesting claims
            for claim in &["admin", "role", "is_admin", "is_moderator", "superuser", "permissions"] {
                if let Some(val) = payload.get(claim) {
                    issues.push(JwtIssue { issue_type: "privilege_claim".into(), severity: "MEDIUM".into(), description: format!("Found privilege claim '{}': {:?}", claim, val) });
                }
            }
            // Check expiry
            if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                if exp == 0 || exp == 9999999999 {
                    issues.push(JwtIssue { issue_type: "never_expires".into(), severity: "HIGH".into(), description: "JWT never expires (exp=0 or max value)".into() });
                } else if exp < now {
                    issues.push(JwtIssue { issue_type: "expired_token".into(), severity: "INFO".into(), description: format!("Token expired {}s ago", now - exp) });
                }
            }
            // Check for iat in future
            if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                if iat > now + 3600 {
                    issues.push(JwtIssue { issue_type: "future_iat".into(), severity: "LOW".into(), description: "JWT issued in the future (iat > now)".into() });
                }
            }
            // Extract all claims for reporting
            let claim_list: Vec<String> = payload.as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default();
            if !claim_list.is_empty() {
                issues.push(JwtIssue { issue_type: "claims_found".into(), severity: "INFO".into(), description: format!("JWT claims: {}", claim_list.join(", ")) });
            }
        }
    }

    issues
}

fn decode_base64_url(input: &str) -> Result<String, String> {
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    let url_safe = padded.replace('-', "+").replace('_', "/");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&url_safe)
        .map_err(|e| format!("base64 decode error: {}", e))?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JwtIssue {
    pub issue_type: String,
    pub severity: String,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_alg_none_detection() {
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.hmac";
        let issues = analyze_jwt(token);
        assert!(issues.iter().any(|i| i.issue_type == "alg_none"));
    }
    #[test]
    fn test_privilege_extraction() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiaXNfYWRtaW4iOnRydWV9.test";
        let issues = analyze_jwt(token);
        assert!(issues.iter().any(|i| i.issue_type == "privilege_claim"));
    }
    #[test]
    fn test_kid_injection() {
        let token = "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uL3B1YmxpYy9rZXkifQ.eyJzdWIiOiIxIn0.test";
        let issues = analyze_jwt(token);
        assert!(issues.iter().any(|i| i.issue_type == "kid_injection"));
    }
    #[test]
    fn test_invalid_token() {
        let token = "not-a-valid-token";
        let issues = analyze_jwt(token);
        assert!(issues.is_empty());
    }
}
