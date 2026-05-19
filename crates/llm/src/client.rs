use aegis_core::error::{AegisError, AegisResult};
use serde_json::Value;

/// Configuration for an OpenAI-compatible LLM API.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmConfig {
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    pub temperature: f64,
    pub max_tokens: u32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://api.openai.com/v1".into(),
            api_key: String::new(),
            model: "gpt-4".into(),
            temperature: 0.7,
            max_tokens: 2048,
        }
    }
}

/// OpenAI-compatible LLM client.
pub struct LlmClient {
    config: LlmConfig,
    client: reqwest::Client,
}

impl LlmClient {
    pub fn new(config: LlmConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .unwrap();
        Self { config, client }
    }

    /// Send a chat completion request.
    pub async fn chat(&self, system_prompt: &str, user_message: &str) -> AegisResult<String> {
        let url = format!(
            "{}/chat/completions",
            self.config.endpoint.trim_end_matches('/')
        );

        let body = serde_json::json!({
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        });

        let mut request = self.client.post(&url).json(&body);

        // Add authorization header if API key is set
        if !self.config.api_key.is_empty() {
            let header_value = format!("Bearer {}", self.config.api_key);
            request = request.header("Authorization", header_value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| AegisError::ToolExecution(format!("LLM request failed: {}", e)))?;

        let status = response.status();
        let json: Value = response
            .json()
            .await
            .map_err(|e| AegisError::Parse(format!("LLM response parse failed: {}", e)))?;

        if !status.is_success() {
            let error_msg = json
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown LLM error");
            return Err(AegisError::ToolExecution(format!(
                "LLM API error ({}): {}",
                status, error_msg
            )));
        }

        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| AegisError::Parse("LLM response missing content".into()))?
            .to_string();

        Ok(content)
    }

    /// Get current config (masked API key).
    pub fn config(&self) -> &LlmConfig {
        &self.config
    }
}
