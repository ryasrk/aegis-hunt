#[derive(Debug, Clone, serde::Serialize)]
pub struct CorsResult {
    pub url: String,
    pub vulnerable: bool,
    pub reflects_origin: bool,
    pub wildcard: bool,
    pub credentials_allowed: bool,
    pub detail: String,
}

pub struct CorsTester {
    client: reqwest::Client,
}

impl CorsTester {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        Self { client }
    }

    /// Test a URL for CORS misconfiguration.
    pub async fn test_url(&self, url: &str) -> CorsResult {
        let evil_origin = "https://evil-attacker.com";
        let response = self
            .client
            .get(url)
            .header("Origin", evil_origin)
            .header("Referer", "https://evil-attacker.com/page")
            .send()
            .await;

        match response {
            Ok(resp) => {
                let cors_origin = resp
                    .headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let cors_creds = resp
                    .headers()
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let cors_wildcard = resp
                    .headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s == "*")
                    .unwrap_or(false);

                let reflects = cors_origin.as_deref() == Some(evil_origin);
                let creds = cors_creds.as_deref() == Some("true");

                let detail = if reflects && creds {
                    "CRITICAL: Reflects origin with credentials - full account takeover via script"
                        .into()
                } else if reflects {
                    "HIGH: Reflects arbitrary origins - allows cross-origin read".into()
                } else if cors_wildcard && creds {
                    "HIGH: Wildcard origin with credentials enabled (invalid config)".into()
                } else if cors_wildcard {
                    "MEDIUM: Wildcard CORS - allows any origin (no auth)".into()
                } else {
                    "Not vulnerable".into()
                };

                CorsResult {
                    url: url.to_string(),
                    vulnerable: reflects || (cors_wildcard && creds),
                    reflects_origin: reflects,
                    wildcard: cors_wildcard,
                    credentials_allowed: creds,
                    detail,
                }
            }
            Err(e) => CorsResult {
                url: url.to_string(),
                vulnerable: false,
                reflects_origin: false,
                wildcard: false,
                credentials_allowed: false,
                detail: format!("Error: {}", e),
            },
        }
    }
}

impl Default for CorsTester {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cors_tester_creation() {
        let _tester = CorsTester::new();
        // No live tests — structural validation only
        assert!(true);
    }
}
