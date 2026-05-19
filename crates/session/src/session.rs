use std::collections::HashMap;
use std::sync::Mutex;
use reqwest::header::{HeaderMap, HeaderValue, COOKIE};
use aegis_core::error::{AegisError, AegisResult};

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthSession {
    pub target: String,
    pub username: String,
    pub cookies: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub csrf_token: Option<String>,
    pub is_authenticated: bool,
}

pub struct SessionManager {
    sessions: Mutex<HashMap<String, AuthSession>>,
    client: reqwest::Client,
}

impl SessionManager {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) Aegis/0.1")
            .build()
            .unwrap();
        Self {
            sessions: Mutex::new(HashMap::new()),
            client,
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Login to a target using form-based authentication.
    pub async fn form_login(
        &self,
        target: &str,
        login_url: &str,
        username_field: &str,
        password_field: &str,
        username: &str,
        password: &str,
        success_indicator: &str,
    ) -> AegisResult<AuthSession> {
        let mut form_data = HashMap::new();
        form_data.insert(username_field.to_string(), username.to_string());
        form_data.insert(password_field.to_string(), password.to_string());

        let resp = self
            .client
            .post(login_url)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| AegisError::ToolExecution(format!("Login request failed: {}", e)))?;

        let status = resp.status().as_u16();

        // Extract cookies from response
        let mut cookies = HashMap::new();
        let mut headers = HashMap::new();
        for (name, value) in resp.headers() {
            if name == "set-cookie" {
                if let Ok(val) = value.to_str() {
                    // Parse "key=value; ..." format
                    if let Some(semi_pos) = val.find(';') {
                        let cookie_part = &val[..semi_pos];
                        if let Some(eq_pos) = cookie_part.find('=') {
                            let key = cookie_part[..eq_pos].to_string();
                            let val = cookie_part[eq_pos + 1..].to_string();
                            cookies.insert(key, val);
                        }
                    }
                }
            }
            headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
        }

        let body = resp.text().await.unwrap_or_default();
        let is_auth = body.contains(success_indicator) || status == 302;

        // Try to extract CSRF token
        let csrf_token = extract_csrf(&body);

        let session = AuthSession {
            target: target.to_string(),
            username: username.to_string(),
            cookies,
            headers,
            csrf_token,
            is_authenticated: is_auth,
        };

        self.sessions
            .lock()
            .unwrap()
            .insert(target.to_string(), session.clone());
        Ok(session)
    }

    /// Login using Bearer token (JWT/API key).
    pub fn bearer_login(&self, target: &str, token: &str) -> AuthSession {
        let mut headers = HashMap::new();
        headers.insert("authorization".into(), format!("Bearer {}", token));

        let session = AuthSession {
            target: target.to_string(),
            username: "token".into(),
            cookies: HashMap::new(),
            headers,
            csrf_token: None,
            is_authenticated: true,
        };

        self.sessions
            .lock()
            .unwrap()
            .insert(target.to_string(), session.clone());
        session
    }

    /// Get headers for authenticated requests to a target.
    pub fn auth_headers(&self, target: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();

        if let Some(session) = self.sessions.lock().unwrap().get(target) {
            // Add cookies
            if !session.cookies.is_empty() {
                let cookie_str: String = session
                    .cookies
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("; ");
                if let Ok(val) = HeaderValue::from_str(&cookie_str) {
                    headers.insert(COOKIE, val);
                }
            }

            // Add CSRF token
            if let Some(ref token) = session.csrf_token {
                if let Ok(val) = HeaderValue::from_str(token) {
                    headers.insert("x-csrf-token", val.clone());
                    headers.insert("x-xsrf-token", val);
                }
            }
        }

        headers
    }

    /// Check if we have a valid session for a target.
    pub fn has_session(&self, target: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(target)
            .map(|s| s.is_authenticated)
            .unwrap_or(false)
    }

    /// Clear a session (logout).
    pub fn clear(&self, target: &str) {
        self.sessions.lock().unwrap().remove(target);
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

fn extract_csrf(body: &str) -> Option<String> {
    // Try common CSRF token patterns
    let patterns = [
        r#"name="csrf_token" value="([^"]+)""#,
        r#"name="csrf" value="([^"]+)""#,
        r#"name="_token" value="([^"]+)""#,
        r#"name="authenticity_token" value="([^"]+)""#,
        r#""csrfToken":"([^"]+)""#,
        r#""csrf":"([^"]+)""#,
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(cap) = re.captures(body) {
                if let Some(val) = cap.get(1) {
                    return Some(val.as_str().to_string());
                }
            }
        }
    }
    None
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_extraction() {
        let html = r#"<input name="csrf_token" value="abc123def456">"#;
        let token = extract_csrf(html);
        assert_eq!(token, Some("abc123def456".into()));
    }

    #[test]
    fn test_csrf_json() {
        let html = r#"{"csrfToken":"tok_12345"}"#;
        let token = extract_csrf(html);
        assert_eq!(token, Some("tok_12345".into()));
    }

    #[test]
    fn test_bearer_login() {
        let mgr = SessionManager::new();
        let session = mgr.bearer_login("https://api.target.com", "jwt_token_here");
        assert!(session.is_authenticated);
        assert!(session.headers.contains_key("authorization"));
    }

    #[test]
    fn test_has_session() {
        let mgr = SessionManager::new();
        assert!(!mgr.has_session("https://target.com"));
        mgr.bearer_login("https://target.com", "test");
        assert!(mgr.has_session("https://target.com"));
    }
}
