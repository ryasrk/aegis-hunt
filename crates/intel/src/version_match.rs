/// Parse a version string into comparable parts.
pub fn parse_version(version: &str) -> Vec<u32> {
    version
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|s| s.parse::<u32>().ok())
        .collect()
}

/// Check if a version falls within an affected range string like "<= 2.4.49", ">= 2.4.0 < 2.4.50"
pub fn version_in_range(version: &str, range_str: &str) -> bool {
    let ver_parts = parse_version(version);
    if ver_parts.is_empty() {
        return false;
    }

    // Parse simple cases: "2.4.49", "<= 2.4.49", ">= 2.4.0", "2.4.0 - 2.4.49"
    let range = range_str.trim();

    // Exact version match
    if let Ok(exact) = range.parse::<semver::Version>() {
        if let Ok(v) = semver::Version::parse(version) {
            return v == exact;
        }
    }

    // Range with comparison operators
    if let Some(stripped) = range.strip_prefix("<=") {
        let target = parse_version(stripped.trim());
        return ver_parts.len() >= target.len() && ver_parts <= target;
    }
    if let Some(stripped) = range.strip_prefix(">=") {
        let target = parse_version(stripped.trim());
        return ver_parts.len() >= target.len() && ver_parts >= target;
    }
    if let Some(stripped) = range.strip_prefix('<') {
        let target = parse_version(stripped.trim());
        return ver_parts.len() >= target.len() && ver_parts < target;
    }
    if let Some(stripped) = range.strip_prefix('>') {
        let target = parse_version(stripped.trim());
        return ver_parts.len() >= target.len() && ver_parts > target;
    }

    // Range with dash
    if let Some(dash_pos) = range.find(" - ") {
        let low = parse_version(&range[..dash_pos]);
        let high = parse_version(&range[dash_pos + 3..]);
        return ver_parts >= low && ver_parts <= high;
    }

    // Single version - check if major.minor matches
    let single = parse_version(range);
    if single.len() <= 1 {
        return false;
    }
    ver_parts.len() >= single.len() && ver_parts[..single.len()] == single[..]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_version_simple() {
        assert_eq!(parse_version("2.4.49"), vec![2, 4, 49]);
    }
    #[test]
    fn test_parse_version_with_prefix() {
        assert_eq!(parse_version("v1.20.3"), vec![1, 20, 3]);
    }
    #[test]
    fn test_version_exact_match() {
        assert!(version_in_range("2.4.49", "<= 2.4.49"));
    }
    #[test]
    fn test_version_less_than() {
        assert!(version_in_range("2.4.48", "<= 2.4.49"));
    }
    #[test]
    fn test_version_greater_than() {
        assert!(version_in_range("2.4.50", ">= 2.4.49"));
    }
    #[test]
    fn test_version_range() {
        assert!(version_in_range("2.4.20", "2.4.0 - 2.4.49"));
    }
    #[test]
    fn test_version_no_match() {
        assert!(!version_in_range("3.0.0", "<= 2.4.49"));
    }
}
