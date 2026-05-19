use crate::client::LlmClient;
use aegis_core::error::AegisResult;
use aegis_core::types::{Finding, Severity};

/// Analyze findings and provide security insights.
pub async fn analyze_findings(
    client: &LlmClient,
    findings: &[Finding],
    target: &str,
) -> AegisResult<String> {
    let findings_summary: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                "[{}] {} - {} (confidence: {}%)",
                f.severity, f.title, f.description, f.confidence
            )
        })
        .collect();

    let system_prompt = "You are a senior penetration testing analyst. Analyze the following security findings \
        and provide: 1) A brief executive summary 2) The most critical findings that need immediate attention \
        3) Recommended exploitation approach for each critical finding 4) Potential attack chains combining multiple findings. \
        Be concise and actionable.";

    let user_message = format!(
        "Target: {}\n\nFindings ({}/{} critical/high):\n{}",
        target,
        findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        findings_summary.join("\n")
    );

    client.chat(system_prompt, &user_message).await
}

/// Generate an executive report summary.
pub async fn generate_executive_summary(
    client: &LlmClient,
    target: &str,
    findings_count: usize,
    critical_count: usize,
    high_count: usize,
) -> AegisResult<String> {
    let system_prompt = "You are a cybersecurity report writer. Write a concise executive summary \
        for a penetration test report. Focus on business impact and risk level. Keep it under 200 words.";

    let user_message = format!(
        "Target: {}\nFindings: {} total ({} critical, {} high)",
        target, findings_count, critical_count, high_count
    );

    client.chat(system_prompt, &user_message).await
}

/// Suggest exploitation commands for a finding.
pub async fn suggest_exploit(
    client: &LlmClient,
    finding: &Finding,
    endpoint: &str,
) -> AegisResult<String> {
    let system_prompt = "You are an exploitation specialist. Given a vulnerability finding, suggest \
        specific curl commands and techniques to verify and exploit it. Provide 2-3 concrete commands. \
        Be specific with URLs and payloads. Do NOT include disclaimer text, just the technical commands.";

    let user_message = format!(
        "Vulnerability: {} (severity: {})\nDescription: {}\nEndpoint: {}\nCVE: {}",
        finding.title,
        finding.severity,
        finding.description,
        endpoint,
        finding.cve.as_deref().unwrap_or("N/A")
    );

    client.chat(system_prompt, &user_message).await
}

/// Generate report markdown with LLM assistance.
pub async fn enhance_report(
    client: &LlmClient,
    target: &str,
    findings_json: &str,
) -> AegisResult<String> {
    let system_prompt = "You are a penetration testing report generator. Generate a professional \
        markdown security assessment report based on the provided findings data. Structure it with: \
        Executive Summary, Findings Summary Table (severity/count), Detailed Findings (each with \
        Description, Impact, Proof of Concept, Remediation), Attack Chain Analysis, and Recommendations. \
        Use security report formatting conventions.";

    let user_message = format!(
        "Generate a pentest report for target: {}\n\nFindings data:\n{}",
        target, findings_json
    );

    client.chat(system_prompt, &user_message).await
}

#[cfg(test)]
mod tests {
    use crate::client::{LlmClient, LlmConfig};

    #[test]
    fn test_default_config() {
        let config = LlmConfig::default();
        assert_eq!(config.model, "gpt-4");
        assert!((config.temperature - 0.7).abs() < 0.01);
    }

    #[test]
    fn test_client_creation() {
        let config = LlmConfig::default();
        let client = LlmClient::new(config);
        assert_eq!(client.config().model, "gpt-4");
    }
}
