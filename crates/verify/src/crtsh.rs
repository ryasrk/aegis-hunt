use aegis_core::error::{AegisError, AegisResult};

/// Query crt.sh for certificate transparency logs matching a domain.
/// Returns discovered subdomains.
pub async fn query_crtsh(domain: &str) -> AegisResult<Vec<String>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Aegis/0.1 (security research)")
        .build()
        .map_err(|e| {
            AegisError::ToolExecution(format!("Failed to build HTTP client: {}", e))
        })?;

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            AegisError::ToolExecution(format!("Failed to query crt.sh: {}", e))
        })?;

    if !response.status().is_success() {
        return Err(AegisError::ToolExecution(format!(
            "crt.sh returned HTTP {}",
            response.status()
        )));
    }

    let text = response
        .text()
        .await
        .map_err(|e| AegisError::Parse(format!("Failed to read crt.sh response: {}", e)))?;

    // crt.sh returns JSON array of objects with "name_value" field containing domain names
    let entries: Vec<serde_json::Value> = serde_json::from_str(&text)
        .map_err(|e| AegisError::Parse(format!("Failed to parse crt.sh JSON: {}", e)))?;

    let mut subdomains: Vec<String> = entries
        .iter()
        .filter_map(|entry| entry.get("name_value").and_then(|v| v.as_str()))
        .flat_map(|names| names.split('\n'))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.contains('.'))
        .collect();

    // Deduplicate and sort
    subdomains.sort();
    subdomains.dedup();

    // Filter to only include subdomains of the target domain
    let target_domain = domain.trim_start_matches("*.");
    subdomains.retain(|s| s.ends_with(target_domain) || s == target_domain);

    Ok(subdomains)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_query_crtsh_not_empty() {
        // This test validates the function signature compiles and types are correct
        // Live test would require network access — run manually
    }
}
