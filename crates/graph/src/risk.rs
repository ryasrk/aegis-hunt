use crate::graph::AttackGraph;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RiskReport {
    pub total_risk_score: u32,
    pub node_count: usize,
    pub high_risk_nodes: Vec<String>,
    pub risk_distribution: RiskDistribution,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RiskDistribution {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Calculate risk score for the entire graph.
pub fn calculate_risk(graph: &AttackGraph) -> RiskReport {
    let node_count = graph.node_count();
    let has_exploit = graph.has_exploitable_findings();
    let exploit_paths = graph.find_paths_to("exploit");
    let finding_paths = graph.find_paths_to("finding");
    let admin_paths = graph.find_paths_to("admin");
    let cloud_paths = graph.find_paths_to("cloud");

    // Score calculation
    let mut score: u32 = 0;

    // Base risk from exploitable findings
    if has_exploit {
        score += 300;
    }

    // Risk from number of attack paths
    score += (exploit_paths.len() as u32) * 50;
    score += (finding_paths.len() as u32) * 30;
    score += (admin_paths.len() as u32) * 20;
    score += (cloud_paths.len() as u32) * 40;

    // Node density risk (more nodes = more attack surface)
    score += (node_count as u32).saturating_mul(5);

    let total = score.min(1000);

    RiskReport {
        total_risk_score: total,
        node_count,
        high_risk_nodes: vec![
            if exploit_paths.is_empty() {
                String::new()
            } else {
                format!("{} exploitable paths found", exploit_paths.len())
            },
            if cloud_paths.is_empty() {
                String::new()
            } else {
                format!("{} cloud resource paths", cloud_paths.len())
            },
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect(),
        risk_distribution: RiskDistribution {
            critical: exploit_paths.len(),
            high: finding_paths.len(),
            medium: admin_paths.len(),
            low: cloud_paths.len(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::AttackGraph;

    #[test]
    fn test_empty_risk() {
        let g = AttackGraph::new();
        let risk = calculate_risk(&g);
        assert_eq!(risk.total_risk_score, 0);
    }

    #[test]
    fn test_risk_score_range() {
        let g = AttackGraph::new();
        let risk = calculate_risk(&g);
        assert!(risk.total_risk_score <= 1000);
    }
}
