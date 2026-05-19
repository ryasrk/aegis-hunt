use std::collections::HashSet;
use std::fs;
use std::path::Path;
use aegis_core::error::AegisResult;

#[derive(Debug, Clone, serde::Serialize)]
pub struct MonitorDiff {
    pub target: String,
    pub new_subdomains: Vec<String>,
    pub new_services: Vec<String>,
    pub new_technologies: Vec<String>,
    pub removed_subdomains: Vec<String>,
    pub changed_technologies: Vec<Vec<String>>,
}

pub struct MonitorEngine;

impl MonitorEngine {
    /// Compare two scans and detect changes.
    pub fn diff_scans(
        target: &str,
        previous_file: &str,
        current_file: &str,
    ) -> AegisResult<MonitorDiff> {
        let prev = Self::load_lines(previous_file);
        let curr = Self::load_lines(current_file);

        let prev_set: HashSet<_> = prev.iter().collect();
        let curr_set: HashSet<_> = curr.iter().collect();

        let new_subdomains: Vec<String> = curr_set.difference(&prev_set)
            .map(|s| (*s).clone()).collect();

        let removed: Vec<String> = prev_set.difference(&curr_set)
            .map(|s| (*s).clone()).collect();

        Ok(MonitorDiff {
            target: target.to_string(),
            new_subdomains,
            new_services: Vec::new(),
            new_technologies: Vec::new(),
            removed_subdomains: removed,
            changed_technologies: Vec::new(),
        })
    }

    /// Load a file into lines, handling missing files gracefully.
    fn load_lines(path: &str) -> Vec<String> {
        if !Path::new(path).exists() {
            return Vec::new();
        }
        fs::read_to_string(path)
            .map(|content| {
                content.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Generate a human-readable diff summary.
    pub fn diff_summary(diff: &MonitorDiff) -> String {
        let mut summary = String::new();

        if diff.new_subdomains.is_empty() && diff.removed_subdomains.is_empty() {
            summary.push_str(&format!("No changes detected for {}\n", diff.target));
            return summary;
        }

        summary.push_str(&format!("=== Changes detected for {} ===\n", diff.target));

        if !diff.new_subdomains.is_empty() {
            summary.push_str(&format!("\n[+] New subdomains ({}):\n", diff.new_subdomains.len()));
            for sub in &diff.new_subdomains {
                summary.push_str(&format!("  + {}\n", sub));
            }
        }

        if !diff.removed_subdomains.is_empty() {
            summary.push_str(&format!("\n[-] Removed subdomains ({}):\n", diff.removed_subdomains.len()));
            for sub in &diff.removed_subdomains {
                summary.push_str(&format!("  - {}\n", sub));
            }
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_new_subdomains() {
        let dir = std::env::temp_dir().join("aegis_test_monitor");
        let _ = fs::create_dir_all(&dir);

        let prev = dir.join("prev.txt");
        let curr = dir.join("curr.txt");

        fs::write(&prev, "a.example.com\nb.example.com\n").unwrap();
        fs::write(&curr, "a.example.com\nb.example.com\nc.example.com\n").unwrap();

        let diff = MonitorEngine::diff_scans(
            "example.com",
            prev.to_str().unwrap(),
            curr.to_str().unwrap(),
        ).unwrap();

        assert!(diff.new_subdomains.contains(&"c.example.com".to_string()));
        assert!(diff.removed_subdomains.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_diff_removed_subdomains() {
        let dir = std::env::temp_dir().join("aegis_test_monitor2");
        let _ = fs::create_dir_all(&dir);

        let prev = dir.join("prev.txt");
        let curr = dir.join("curr.txt");

        fs::write(&prev, "a.example.com\nb.example.com\nc.example.com\n").unwrap();
        fs::write(&curr, "a.example.com\nb.example.com\n").unwrap();

        let diff = MonitorEngine::diff_scans(
            "example.com",
            prev.to_str().unwrap(),
            curr.to_str().unwrap(),
        ).unwrap();

        assert!(diff.removed_subdomains.contains(&"c.example.com".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_no_changes() {
        let dir = std::env::temp_dir().join("aegis_test_monitor3");
        let _ = fs::create_dir_all(&dir);

        let prev = dir.join("prev.txt");
        let curr = dir.join("curr.txt");

        fs::write(&prev, "a.example.com\n").unwrap();
        fs::write(&curr, "a.example.com\n").unwrap();

        let diff = MonitorEngine::diff_scans(
            "example.com",
            prev.to_str().unwrap(),
            curr.to_str().unwrap(),
        ).unwrap();

        assert!(diff.new_subdomains.is_empty());
        assert!(diff.removed_subdomains.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_missing_files() {
        let diff = MonitorEngine::diff_scans(
            "example.com",
            "/tmp/nonexistent_prev.txt",
            "/tmp/nonexistent_curr.txt",
        ).unwrap();
        assert!(diff.new_subdomains.is_empty());
    }

    #[test]
    fn test_diff_summary_no_changes() {
        let diff = MonitorDiff {
            target: "example.com".into(),
            new_subdomains: vec![],
            new_services: vec![],
            new_technologies: vec![],
            removed_subdomains: vec![],
            changed_technologies: vec![],
        };
        let summary = MonitorEngine::diff_summary(&diff);
        assert!(summary.contains("No changes"));
    }

    #[test]
    fn test_diff_summary_with_changes() {
        let diff = MonitorDiff {
            target: "example.com".into(),
            new_subdomains: vec!["c.example.com".into()],
            new_services: vec![],
            new_technologies: vec![],
            removed_subdomains: vec!["a.example.com".into()],
            changed_technologies: vec![],
        };
        let summary = MonitorEngine::diff_summary(&diff);
        assert!(summary.contains("[+]"));
        assert!(summary.contains("[-]"));
    }
}
