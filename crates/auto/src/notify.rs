use aegis_core::error::{AegisError, AegisResult};

#[derive(Debug, Clone, serde::Serialize)]
pub enum NotifyChannel {
    Slack(String),
    Discord(String),
    Telegram(String, String), // bot_token, chat_id
}

pub struct Notifier {
    channels: Vec<NotifyChannel>,
    client: reqwest::Client,
}

impl Notifier {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build().unwrap(),
        }
    }

    pub fn add_slack(&mut self, webhook_url: &str) {
        self.channels.push(NotifyChannel::Slack(webhook_url.to_string()));
    }

    pub fn add_discord(&mut self, webhook_url: &str) {
        self.channels.push(NotifyChannel::Discord(webhook_url.to_string()));
    }

    pub fn add_telegram(&mut self, bot_token: &str, chat_id: &str) {
        self.channels.push(NotifyChannel::Telegram(bot_token.to_string(), chat_id.to_string()));
    }

    /// Send a notification to all configured channels.
    pub async fn notify(&self, title: &str, message: &str, severity: &str) {
        for channel in &self.channels {
            if let Err(e) = self.send_to_channel(channel, title, message, severity).await {
                tracing::warn!("Failed to send notification: {}", e);
            }
        }
    }

    async fn send_to_channel(&self, channel: &NotifyChannel, title: &str, message: &str, severity: &str) -> AegisResult<()> {
        match channel {
            NotifyChannel::Slack(webhook) => {
                let color = match severity {
                    "CRITICAL" => "#ff0000",
                    "HIGH" => "#ff6600",
                    _ => "#36a64f",
                };
                let payload = serde_json::json!({
                    "attachments": [{
                        "color": color,
                        "title": title,
                        "text": message,
                        "footer": "Aegis Security Scanner",
                    }]
                });
                self.client.post(webhook).json(&payload).send().await
                    .map_err(|e| AegisError::ToolExecution(format!("Slack notify error: {}", e)))?;
            }
            NotifyChannel::Discord(webhook) => {
                let color = match severity {
                    "CRITICAL" => 0xff0000,
                    "HIGH" => 0xff6600,
                    _ => 0x36a64f,
                };
                let payload = serde_json::json!({
                    "embeds": [{
                        "title": format!("[{}] {}", severity, title),
                        "description": message,
                        "color": color,
                        "footer": { "text": "Aegis Security Scanner" },
                    }]
                });
                self.client.post(webhook).json(&payload).send().await
                    .map_err(|e| AegisError::ToolExecution(format!("Discord notify error: {}", e)))?;
            }
            NotifyChannel::Telegram(bot_token, chat_id) => {
                let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
                let text = format!("[{}] {}\n{}", severity, title, message);
                let payload = serde_json::json!({
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                });
                self.client.post(&url).json(&payload).send().await
                    .map_err(|e| AegisError::ToolExecution(format!("Telegram notify error: {}", e)))?;
            }
        }
        Ok(())
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_notifier() {
        let n = Notifier::new();
        assert_eq!(n.channel_count(), 0);
    }

    #[test]
    fn test_add_channels() {
        let mut n = Notifier::new();
        n.add_slack("https://hooks.slack.com/test");
        n.add_discord("https://discord.com/api/webhooks/test");
        assert_eq!(n.channel_count(), 2);
    }

    #[test]
    fn test_add_telegram() {
        let mut n = Notifier::new();
        n.add_telegram("bot123:abc", "-123456");
        assert_eq!(n.channel_count(), 1);
    }
}
