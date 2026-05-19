use crate::graph::AttackGraph;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackPath {
    pub path: Vec<String>,
    pub length: usize,
    pub severity_score: u8,
    pub description: String,
}

/// Analyze attack paths from the graph.
pub fn analyze_paths(graph: &AttackGraph) -> Vec<AttackPath> {
    let mut paths = Vec::new();

    // Find paths to exploits
    let exploit_paths = graph.find_paths_to("exploit");
    for p in &exploit_paths {
        paths.push(AttackPath {
            path: p.clone(),
            length: p.len(),
            severity_score: 90,
            description: format!("{} steps to exploitable finding", p.len()),
        });
    }

    // Find paths to critical/high findings
    let finding_paths = graph.find_paths_to("finding");
    for p in &finding_paths {
        if !paths.iter().any(|existing| existing.path == *p) {
            paths.push(AttackPath {
                path: p.clone(),
                length: p.len(),
                severity_score: 70,
                description: format!("{} steps to security finding", p.len()),
            });
        }
    }

    // Find paths to admin panels
    let admin_paths = graph.find_paths_to("admin");
    for p in &admin_paths {
        if !paths.iter().any(|existing| existing.path == *p) {
            paths.push(AttackPath {
                path: p.clone(),
                length: p.len(),
                severity_score: 60,
                description: format!("Potential admin panel at {} steps", p.len()),
            });
        }
    }

    // Find paths to cloud resources
    let cloud_paths = graph.find_paths_to("cloud");
    for p in &cloud_paths {
        if !paths.iter().any(|existing| existing.path == *p) {
            paths.push(AttackPath {
                path: p.clone(),
                length: p.len(),
                severity_score: 85,
                description: format!("Cloud resource reachable in {} steps", p.len()),
            });
        }
    }

    // Sort by severity
    paths.sort_by_key(|b| std::cmp::Reverse(b.severity_score));
    paths.truncate(20);
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::AttackGraph;

    #[test]
    fn test_analyze_empty() {
        let g = AttackGraph::new();
        let paths = analyze_paths(&g);
        assert!(paths.is_empty());
    }
}
