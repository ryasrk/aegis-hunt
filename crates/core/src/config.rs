use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub max_concurrency: usize,
    pub request_timeout_secs: u64,
    pub retry_attempts: u32,
    pub user_agent: String,
    pub workspace_dir: Option<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            max_concurrency: num_cpus::get(),
            request_timeout_secs: 30,
            retry_attempts: 3,
            user_agent: "Aegis/0.1.0".to_string(),
            workspace_dir: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub concurrent_requests: usize,
    pub burst_size: u32,
    pub delay_between_requests_ms: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10,
            requests_per_minute: 200,
            concurrent_requests: num_cpus::get() * 2,
            burst_size: 5,
            delay_between_requests_ms: 100,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathConfig {
    pub wordlist_dir: Option<String>,
    pub output_dir: Option<String>,
    pub data_dir: Option<String>,
    pub log_dir: Option<String>,
    pub cache_dir: Option<String>,
    pub config_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled_plugins: Vec<String>,
    pub custom_plugin_dir: Option<String>,
    pub allow_remote_plugins: bool,
    pub plugin_timeout_secs: u64,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled_plugins: vec![],
            custom_plugin_dir: None,
            allow_remote_plugins: false,
            plugin_timeout_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub rate_limit: RateLimitConfig,
    pub paths: PathConfig,
    pub plugins: PluginConfig,
}
