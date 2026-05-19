use aegis_core::error::{AegisError, AegisResult};
use std::time::Duration;

pub struct JsDownloader {
    client: reqwest::Client,
}

impl JsDownloader {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Mozilla/5.0 Aegis/0.1")
            .danger_accept_invalid_certs(false)
            .build()
            .expect("Failed to build reqwest client");
        Self { client }
    }
}

impl Default for JsDownloader {
    fn default() -> Self {
        Self::new()
    }
}

impl JsDownloader {

    /// Download JS content from a URL.
    pub async fn download(&self, url: &str) -> AegisResult<String> {
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(|e| AegisError::ToolExecution(format!("Failed to download JS: {}", e)))?;

        if !response.status().is_success() {
            return Err(AegisError::ToolExecution(format!(
                "HTTP {} downloading JS: {}",
                response.status(), url
            )));
        }

        let body = response.text()
            .await
            .map_err(|e| AegisError::ToolExecution(format!("Failed to read JS body: {}", e)))?;

        Ok(body)
    }

    /// Extract JS script URLs from HTML content.
    pub fn discover_js_urls(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut urls = Vec::new();

        // Match <script src="...">
        let re = regex::Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).unwrap();
        for cap in re.captures_iter(html) {
            if let Some(src) = cap.get(1) {
                let resolved = self.resolve_url(src.as_str(), base_url);
                urls.push(resolved);
            }
        }

        // Also find .js references in strings
        let js_re = regex::Regex::new(r#"["']([^"']+\.js(?:[?][^"']*)?)["']"#).unwrap();
        for cap in js_re.captures_iter(html) {
            if let Some(src) = cap.get(1) {
                let resolved = self.resolve_url(src.as_str(), base_url);
                if !urls.contains(&resolved) {
                    urls.push(resolved);
                }
            }
        }

        // Deduplicate
        urls.sort();
        urls.dedup();
        urls
    }

    fn resolve_url(&self, src: &str, base: &str) -> String {
        if src.starts_with("http://") || src.starts_with("https://") {
            src.to_string()
        } else if src.starts_with("//") {
            format!("https:{}", src)
        } else if src.starts_with('/') {
            let base_parsed = url::Url::parse(base).ok();
            base_parsed
                .map(|u| {
                    let scheme = u.scheme();
                    let host = u.host_str().unwrap_or("");
                    let port = u.port().map(|p| format!(":{}", p)).unwrap_or_default();
                    format!("{}://{}{}{}", scheme, host, port, src)
                })
                .unwrap_or_else(|| format!("{}{}", base.trim_end_matches('/'), src))
        } else {
            format!("{}/{}", base.trim_end_matches('/'), src.trim_start_matches("./"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_js_urls() {
        let downloader = JsDownloader::new();
        let html = r#"<html><script src="/static/app.js"></script><script src="https://cdn.example.com/lib.js"></script></html>"#;
        let urls = downloader.discover_js_urls(html, "https://example.com");
        assert!(urls.contains(&"https://example.com/static/app.js".to_string()));
        assert!(urls.contains(&"https://cdn.example.com/lib.js".to_string()));
    }

    #[test]
    fn test_resolve_absolute_url() {
        let downloader = JsDownloader::new();
        let result = downloader.resolve_url("https://cdn.example.com/lib.js", "https://example.com");
        assert_eq!(result, "https://cdn.example.com/lib.js");
    }

    #[test]
    fn test_resolve_relative_url() {
        let downloader = JsDownloader::new();
        let result = downloader.resolve_url("/static/app.js", "https://example.com");
        assert_eq!(result, "https://example.com/static/app.js");
    }

    #[test]
    fn test_resolve_protocol_relative() {
        let downloader = JsDownloader::new();
        let result = downloader.resolve_url("//cdn.example.com/lib.js", "https://example.com");
        assert_eq!(result, "https://cdn.example.com/lib.js");
    }
}
