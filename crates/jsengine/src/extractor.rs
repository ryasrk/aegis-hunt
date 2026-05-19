use regex::Regex;
use tracing::warn;
use crate::patterns;

#[derive(Debug, Clone, serde::Serialize)]
pub struct JsFinding {
    pub extract_type: String,
    pub value: String,
    pub context: String,
    pub source_url: String,
    pub confidence: u8,
    pub line_number: Option<usize>,
}

pub struct JsExtractor {
    patterns: Vec<(String, Regex, u8)>,  // (name, regex, confidence)
}

impl JsExtractor {
    pub fn new() -> Self {
        let mut patterns: Vec<(String, Regex, u8)> = Vec::new();

        macro_rules! add_pattern {
            ($name:expr, $re:expr, $confidence:expr) => {
                match Regex::new($re) {
                    Ok(re) => patterns.push(($name.to_string(), re, $confidence)),
                    Err(e) => warn!("Failed to compile regex '{}': {}", $name, e),
                }
            };
        }

        add_pattern!("api_endpoint", patterns::API_ENDPOINT, 70);
        add_pattern!("aws_key", patterns::AWS_KEY, 95);
        add_pattern!("graphql_endpoint", patterns::GRAPHQL_ENDPOINT, 80);
        add_pattern!("websocket", patterns::WEBSOCKET, 85);
        add_pattern!("postmessage", patterns::POSTMESSAGE, 75);
        add_pattern!("sourcemap", patterns::SOURCEMAP, 90);
        add_pattern!("cloud_bucket", patterns::CLOUD_BUCKET, 85);
        add_pattern!("internal_domain", patterns::INTERNAL_DOMAIN, 70);
        add_pattern!("jwt_token", patterns::JWT_TOKEN, 95);
        add_pattern!("firebase_url", patterns::FIREBASE_URL, 80);
        add_pattern!("hidden_endpoint", patterns::HIDDEN_ENDPOINT, 65);
        add_pattern!("google_api_key", patterns::GOOGLE_API_KEY, 90);
        add_pattern!("slack_token", patterns::SLACK_TOKEN, 95);
        add_pattern!("high_entropy", patterns::HIGH_ENTROPY, 40);
        add_pattern!("postmessage_origin_wildcard", patterns::POSTMESSAGE_ORIGIN, 85);

        Self { patterns }
    }
}

impl Default for JsExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl JsExtractor {

    /// Extract all findings from JS content.
    pub fn extract_all(&self, content: &str, source_url: &str) -> Vec<JsFinding> {
        let mut findings = Vec::new();

        for (name, re, confidence) in &self.patterns {
            for cap in re.find_iter(content) {
                // Get surrounding context (the line)
                let pos = cap.start();
                let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let line_end = content[pos..].find('\n').map(|i| pos + i).unwrap_or(content.len());
                let context_line = &content[line_start..line_end];

                // Count which line
                let line_number = content[..pos].matches('\n').count() + 1;

                findings.push(JsFinding {
                    extract_type: name.clone(),
                    value: cap.as_str().to_string(),
                    context: context_line.trim().to_string(),
                    source_url: source_url.to_string(),
                    confidence: *confidence,
                    line_number: Some(line_number),
                });
            }
        }

        // Deduplicate by (type, value)
        findings.sort_by_key(|a| (a.extract_type.clone(), a.value.clone()));
        findings.dedup_by(|a, b| a.extract_type == b.extract_type && a.value == b.value);

        // Sort by confidence descending
        findings.sort_by_key(|b| std::cmp::Reverse(b.confidence));

        findings
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_aws_key() {
        let extractor = JsExtractor::new();
        let content = r#"const aws_key = "AKIAIOSFODNN7EXAMPLE";"#;
        let findings = extractor.extract_all(content, "https://example.com/app.js");
        let aws: Vec<_> = findings.iter().filter(|f| f.extract_type == "aws_key").collect();
        assert!(!aws.is_empty(), "Should find AWS key");
        assert!(aws[0].value.contains("AKIA"));
    }

    #[test]
    fn test_extract_jwt() {
        let extractor = JsExtractor::new();
        let content = r#"const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSJ9.ktIXCketTq9I9MlwGfBfZQ";"#;
        let findings = extractor.extract_all(content, "https://example.com/app.js");
        let jwt: Vec<_> = findings.iter().filter(|f| f.extract_type == "jwt_token").collect();
        assert!(!jwt.is_empty(), "Should find JWT token");
    }

    #[test]
    fn test_extract_api_endpoint() {
        let extractor = JsExtractor::new();
        let content = r#"fetch("/api/v1/users/123")"#;
        let findings = extractor.extract_all(content, "https://example.com/app.js");
        let api: Vec<_> = findings.iter().filter(|f| f.extract_type == "api_endpoint").collect();
        assert!(!api.is_empty(), "Should find API endpoint");
    }

    #[test]
    fn test_extract_websocket() {
        let extractor = JsExtractor::new();
        let content = r#"new WebSocket("wss://ws.example.com/chat")"#;
        let findings = extractor.extract_all(content, "https://example.com/app.js");
        let ws: Vec<_> = findings.iter().filter(|f| f.extract_type == "websocket").collect();
        assert!(!ws.is_empty(), "Should find WebSocket");
    }

    #[test]
    fn test_extract_sourcemap() {
        let extractor = JsExtractor::new();
        let content = r#"//# sourceMappingURL=app.js.map"#;
        let findings = extractor.extract_all(content, "https://example.com/app.js");
        let sm: Vec<_> = findings.iter().filter(|f| f.extract_type == "sourcemap").collect();
        assert!(!sm.is_empty(), "Should find source map");
    }

    #[test]
    fn test_extract_postmessage() {
        let extractor = JsExtractor::new();
        let content = r#"window.parent.postMessage(data, "*")"#;
        let findings = extractor.extract_all(content, "https://example.com/app.js");
        let pm: Vec<_> = findings.iter().filter(|f| f.extract_type == "postmessage_origin_wildcard").collect();
        assert!(!pm.is_empty(), "Should find postMessage wildcard");
    }

    #[test]
    fn test_extract_cloud_bucket() {
        let extractor = JsExtractor::new();
        let content = r#"const bucket = "https://my-bucket.s3.amazonaws.com/data"#;
        let findings = extractor.extract_all(content, "https://example.com/app.js");
        let cb: Vec<_> = findings.iter().filter(|f| f.extract_type == "cloud_bucket").collect();
        assert!(!cb.is_empty(), "Should find cloud bucket");
    }

    #[test]
    fn test_extract_hidden_endpoint() {
        let extractor = JsExtractor::new();
        let content = r#"fetch("/admin/panel")"#;
        let findings = extractor.extract_all(content, "https://example.com/app.js");
        let he: Vec<_> = findings.iter().filter(|f| f.extract_type == "hidden_endpoint").collect();
        assert!(!he.is_empty(), "Should find hidden endpoint");
    }
}
