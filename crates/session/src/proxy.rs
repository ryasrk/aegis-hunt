use std::sync::Mutex;
use rand::Rng;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyConfig {
    pub proxies: Vec<String>,
    pub current_index: usize,
    pub rotate_on_status: Vec<u16>,
    pub user_agents: Vec<String>,
}

/// Common user agents to rotate through.
pub const DEFAULT_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
];

pub struct SmartProxy {
    config: Mutex<ProxyConfig>,
    rng: Mutex<rand::rngs::ThreadRng>,
}

impl SmartProxy {
    pub fn new() -> Self {
        let user_agents: Vec<String> = DEFAULT_USER_AGENTS.iter().map(|s| s.to_string()).collect();
        Self {
            config: Mutex::new(ProxyConfig {
                proxies: vec![],
                current_index: 0,
                rotate_on_status: vec![429, 403, 401, 503],
                user_agents,
            }),
            rng: Mutex::new(rand::thread_rng()),
        }
    }

    pub fn new_with(proxies: Vec<String>) -> Self {
        let proxy = Self::new();
        proxy.config.lock().unwrap().proxies = proxies;
        proxy
    }

    /// Get a random User-Agent string.
    pub fn random_user_agent(&self) -> String {
        let agents = self.config.lock().unwrap().user_agents.clone();
        let idx = self.rng.lock().unwrap().gen_range(0..agents.len());
        agents[idx].clone()
    }

    /// Get the current proxy URL, or None if no proxies configured.
    pub fn current_proxy(&self) -> Option<String> {
        let config = self.config.lock().unwrap();
        if config.proxies.is_empty() {
            None
        } else {
            Some(config.proxies[config.current_index % config.proxies.len()].clone())
        }
    }

    /// Rotate to the next proxy.
    #[allow(dead_code)]
    pub fn rotate(&self) -> Option<String> {
        let mut config = self.config.lock().unwrap();
        if config.proxies.is_empty() {
            return None;
        }
        config.current_index = (config.current_index + 1) % config.proxies.len();
        Some(config.proxies[config.current_index].clone())
    }

    /// Check if a status code should trigger proxy rotation.
    pub fn should_rotate(&self, status: u16) -> bool {
        self.config.lock().unwrap().rotate_on_status.contains(&status)
    }

    /// Add a proxy to the rotation pool.
    pub fn add_proxy(&self, proxy: &str) {
        self.config.lock().unwrap().proxies.push(proxy.to_string());
    }

    /// Add delay between requests (randomized jitter).
    pub fn jitter_delay_ms(&self) -> u64 {
        let mut rng = self.rng.lock().unwrap();
        // 500-3000ms random delay
        500 + rng.gen_range(0..2500)
    }

    /// Build randomized headers for a request.
    pub fn randomized_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        headers.push(("User-Agent".into(), self.random_user_agent()));
        headers.push((
            "Accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        ));
        headers.push((
            "Accept-Language".into(),
            if self.rng.lock().unwrap().gen_bool(0.5) {
                "en-US,en;q=0.5".into()
            } else {
                "en-GB,en;q=0.5".into()
            },
        ));
        headers.push(("Accept-Encoding".into(), "gzip, deflate".into()));
        headers.push((
            "Connection".into(),
            if self.rng.lock().unwrap().gen_bool(0.7) {
                "keep-alive".into()
            } else {
                "close".into()
            },
        ));
        headers.push(("Upgrade-Insecure-Requests".into(), "1".into()));

        // Sometimes add a random cache-busting header
        if self.rng.lock().unwrap().gen_bool(0.3) {
            headers.push(("Cache-Control".into(), "no-cache".into()));
        }

        headers
    }

    pub fn proxy_count(&self) -> usize {
        self.config.lock().unwrap().proxies.len()
    }
}

impl Default for SmartProxy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_user_agent() {
        let proxy = SmartProxy::new();
        let ua = proxy.random_user_agent();
        assert!(ua.contains("Mozilla"));
        assert!(ua.contains("Chrome") || ua.contains("Firefox") || ua.contains("Safari"));
    }

    #[test]
    fn test_no_proxy_by_default() {
        let proxy = SmartProxy::new();
        assert!(proxy.current_proxy().is_none());
    }

    #[test]
    fn test_add_and_rotate_proxy() {
        let proxy = SmartProxy::new();
        proxy.add_proxy("http://proxy1:8080");
        proxy.add_proxy("http://proxy2:8080");
        assert_eq!(proxy.proxy_count(), 2);
        assert!(proxy.current_proxy().is_some());
    }

    #[test]
    fn test_should_rotate_429() {
        let proxy = SmartProxy::new();
        assert!(proxy.should_rotate(429));
        assert!(!proxy.should_rotate(200));
    }

    #[test]
    fn test_jitter_delay_range() {
        let proxy = SmartProxy::new();
        let delay = proxy.jitter_delay_ms();
        assert!(delay >= 500);
        assert!(delay <= 3500);
    }

    #[test]
    fn test_randomized_headers() {
        let proxy = SmartProxy::new();
        let headers = proxy.randomized_headers();
        assert!(headers.iter().any(|(k, _)| k == "User-Agent"));
        assert!(headers.iter().any(|(k, _)| k == "Accept"));
    }
}
