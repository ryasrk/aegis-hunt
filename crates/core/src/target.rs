use crate::error::{AegisError, AegisResult};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Target {
    pub raw: String,
    pub normalized: String,
    pub is_file: bool,
    pub targets: Vec<String>,
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
}
