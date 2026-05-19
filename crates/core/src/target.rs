use crate::error::{AegisError, AegisResult};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Target {
    pub raw: String,
    pub normalized: String,
    pub is_file: bool,
    pub targets: Vec<String>,
}

/// Scope configuration: which targets are in-scope and which are out-of-scope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScopeConfig {
    /// Domains/patterns that ARE in scope (e.g. "*.example.com", "api.example.com")
    pub in_scope: Vec<String>,
    /// Domains/patterns that are OUT of scope and should be excluded
    /// (e.g. "pay.example.com", "admin.example.com")
    pub out_of_scope: Vec<String>,
    /// File path to load scope from (optional, YAML/JSON)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_file: Option<String>,
}

impl ScopeConfig {
    pub fn new() -> Self {
        Self {
            in_scope: Vec::new(),
            out_of_scope: Vec::new(),
            scope_file: None,
        }
    }

    pub fn new_with(in_scope: Vec<String>, out_of_scope: Vec<String>) -> Self {
        Self { in_scope, out_of_scope, scope_file: None }
    }

    /// Load scope from a YAML/JSON file.
    pub fn load(path: &str) -> AegisResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AegisError::Config(format!("Failed to read scope file: {}", e)))?;

        // JSON scope files only
        serde_json::from_str(&content)
            .map_err(|e| AegisError::Config(format!("Invalid scope JSON (expected ScopeConfig format): {}", e)))
    }

    /// Check if a target matches any in-scope pattern.
    pub fn is_in_scope(&self, target: &str) -> bool {
        if self.in_scope.is_empty() {
            return true; // No scope restriction = everything allowed
        }
        target_matches_any(target, &self.in_scope)
    }

    /// Check if a target matches any out-of-scope pattern.
    pub fn is_out_of_scope(&self, target: &str) -> bool {
        if self.out_of_scope.is_empty() {
            return false;
        }
        target_matches_any(target, &self.out_of_scope)
    }

    /// Check if a target is valid (in scope AND not out of scope).
    pub fn is_allowed(&self, target: &str) -> bool {
        self.is_in_scope(target) && !self.is_out_of_scope(target)
    }

    /// Filter a list of subdomains/URLs, removing OOS items.
    pub fn filter<T: AsRef<str>>(&self, items: &[T]) -> Vec<String> {
        items.iter()
            .filter(|item| self.is_allowed(item.as_ref()))
            .map(|item| item.as_ref().to_string())
            .collect()
    }

    /// Get a human-readable summary of the scope.
    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("IN SCOPE ({}):\n", self.in_scope.len()));
        for scope in &self.in_scope {
            s.push_str(&format!("  + {}\n", scope));
        }
        s.push_str(&format!("OUT OF SCOPE ({}):\n", self.out_of_scope.len()));
        for oos in &self.out_of_scope {
            s.push_str(&format!("  - {}\n", oos));
        }
        s
    }
}

/// Check if a target matches any pattern in a list.
/// Supports exact match, subdomain match, and wildcard (*.) prefix.
fn target_matches_any(target: &str, patterns: &[String]) -> bool {
    let target = target.trim().to_lowercase();
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim().to_lowercase();
        if let Some(base) = pattern.strip_prefix("*.") {
            // Wildcard: *.example.com matches sub.example.com and example.com
            target == base || target.ends_with(&format!(".{}", base))
        } else {
            // Exact match or subdomain match
            target == pattern || target.ends_with(&format!(".{}", pattern))
        }
    })
}

pub struct TargetValidator;

impl TargetValidator {
    /// Parse a target input which is either a file path (reads lines as targets)
    /// or a single domain/URL. Normalizes each target.
    #[must_use = "parse returns a Target with the parsed result"]
    pub fn parse(input: &str) -> AegisResult<Target> {
        let input = input.trim();
        if input.is_empty() {
            return Err(AegisError::Parse("Input cannot be empty".into()));
        }

        if Path::new(input).exists() {
            let content =
                std::fs::read_to_string(input).map_err(AegisError::Io)?;

            let targets: Vec<String> = content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| Self::normalize_domain(&l))
                .collect();

            if targets.is_empty() {
                return Err(AegisError::Parse(
                    "File contains no valid targets".into(),
                ));
            }

            Ok(Target {
                raw: input.to_string(),
                normalized: targets.join(", "),
                is_file: true,
                targets,
            })
        } else {
            let normalized = Self::normalize_domain(input);
            Ok(Target {
                raw: input.to_string(),
                normalized: normalized.clone(),
                is_file: false,
                targets: vec![normalized],
            })
        }
    }

    /// Validate a target is within the allowed scope list.
    /// Returns `Ok(())` if the target matches any scope entry (exact match or
    /// subdomain match) or if the scope list is empty (no restriction).
    #[must_use = "validate_scope returns Ok(()) if the target is in scope"]
    pub fn validate_scope(target: &str, scope_list: &[String]) -> AegisResult<()> {
        if scope_list.is_empty() {
            return Ok(());
        }

        let target = target.trim().to_lowercase();
        let in_scope = scope_list.iter().any(|scope| {
            let scope = scope.trim().to_lowercase();
            let scope_base = scope.trim_start_matches("*.");
            target == scope_base || target == scope || target.ends_with(&format!(".{}", scope_base))
        });

        if in_scope {
            Ok(())
        } else {
            Err(AegisError::ScopeViolation(format!(
                "Target '{}' is not in scope. Allowed scopes: {:?}",
                target, scope_list
            )))
        }
    }

    /// Normalize a domain by stripping protocol, trailing slash, and path,
    /// then lowercasing.
    fn normalize_domain(domain: &str) -> String {
        let domain = domain.trim();
        let domain = domain
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let domain = domain.trim_end_matches('/');
        let domain = domain.split('/').next().unwrap_or(domain);
        domain.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_domain() {
        let target = TargetValidator::parse("example.com").unwrap();
        assert!(!target.is_file);
        assert_eq!(target.targets, vec!["example.com"]);
    }

    #[test]
    fn test_parse_domain_with_protocol() {
        let target = TargetValidator::parse("https://example.com/path?q=1").unwrap();
        assert_eq!(target.normalized, "example.com");
    }

    #[test]
    fn test_parse_empty_input() {
        let result = TargetValidator::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_scope_exact_match() {
        let scopes = vec!["example.com".to_string(), "test.org".to_string()];
        assert!(TargetValidator::validate_scope("example.com", &scopes).is_ok());
    }

    #[test]
    fn test_validate_scope_subdomain_match() {
        let scopes = vec!["example.com".to_string()];
        assert!(TargetValidator::validate_scope("sub.example.com", &scopes).is_ok());
    }

    #[test]
    fn test_validate_scope_no_match() {
        let scopes = vec!["example.com".to_string()];
        let result = TargetValidator::validate_scope("other.com", &scopes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AegisError::ScopeViolation(_)));
    }

    #[test]
    fn test_validate_scope_wildcard() {
        let scopes = vec!["*.example.com".to_string()];
        assert!(TargetValidator::validate_scope("sub.example.com", &scopes).is_ok());
        assert!(TargetValidator::validate_scope("example.com", &scopes).is_ok());
    }

    #[test]
    fn test_validate_scope_empty_list() {
        let scopes: Vec<String> = vec![];
        assert!(TargetValidator::validate_scope("anything", &scopes).is_ok());
    }

    // === ScopeConfig (IN/OOS) Tests ===

    #[test]
    fn test_scope_config_in_scope() {
        let scope = ScopeConfig::new_with(
            vec!["*.example.com".into()],
            vec!["pay.example.com".into()],
        );
        assert!(scope.is_allowed("app.example.com"));
        assert!(scope.is_allowed("api.example.com"));
    }

    #[test]
    fn test_scope_config_out_of_scope() {
        let scope = ScopeConfig::new_with(
            vec!["*.example.com".into()],
            vec!["pay.example.com".into()],
        );
        assert!(!scope.is_allowed("pay.example.com"));
    }

    #[test]
    fn test_scope_config_all_in_scope_default() {
        let scope = ScopeConfig::new();
        assert!(scope.is_allowed("anything.com"));
    }

    #[test]
    fn test_scope_config_filter() {
        let scope = ScopeConfig::new_with(
            vec!["*.example.com".into()],
            vec!["pay.example.com".into()],
        );
        let items = vec!["app.example.com", "pay.example.com", "api.example.com"];
        let filtered = scope.filter(&items);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"app.example.com".to_string()));
        assert!(filtered.contains(&"api.example.com".to_string()));
        assert!(!filtered.contains(&"pay.example.com".to_string()));
    }

    #[test]
    fn test_scope_config_out_of_scope_multiple() {
        let scope = ScopeConfig::new_with(
            vec!["*.example.com".into()],
            vec!["pay.example.com".into(), "admin.example.com".into()],
        );
        assert!(!scope.is_allowed("pay.example.com"));
        assert!(!scope.is_allowed("admin.example.com"));
        assert!(scope.is_allowed("blog.example.com"));
    }

    #[test]
    fn test_target_matches_any_exact() {
        assert!(target_matches_any("example.com", &vec!["example.com".into()]));
        assert!(!target_matches_any("other.com", &vec!["example.com".into()]));
    }

    #[test]
    fn test_target_matches_any_wildcard() {
        assert!(target_matches_any("sub.example.com", &vec!["*.example.com".into()]));
        assert!(target_matches_any("example.com", &vec!["*.example.com".into()]));
        assert!(!target_matches_any("example.org", &vec!["*.example.com".into()]));
    }

    #[test]
    fn test_scope_config_summary() {
        let scope = ScopeConfig::new_with(
            vec!["*.example.com".into()],
            vec!["pay.example.com".into()],
        );
        let summary = scope.summary();
        assert!(summary.contains("IN SCOPE"));
        assert!(summary.contains("OUT OF SCOPE"));
    }
}
