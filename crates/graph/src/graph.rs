use aegis_core::types::{ExploitRef, Finding, HttpService, Subdomain, Technology};
use petgraph::algo;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

/// Types of nodes in the attack graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GraphNode {
    Domain(String),
    Subdomain(String),
    Service(String),
    Technology(String, Option<String>), // name, version
    Finding(String, String),            // title, severity
    Exploit(u32, String),               // edb_id, title
    Metadata(String),                   // IP, ASN, etc.
}

/// Types of edges in the attack graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GraphEdge {
    ResolvesTo,
    RunsOn,
    HasFinding,
    HasExploit,
    CanChainTo,
    IncreasesRisk,
    RelatedTo,
}

/// The attack graph — a directed graph of all assets and their relationships.
pub struct AttackGraph {
    graph: DiGraph<GraphNode, GraphEdge>,
    node_indices: HashMap<String, NodeIndex>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
        }
    }

    /// Add a node to the graph, deduplicating by key.
    fn add_node(&mut self, key: &str, node: GraphNode) -> NodeIndex {
        if let Some(&idx) = self.node_indices.get(key) {
            return idx;
        }
        let idx = self.graph.add_node(node);
        self.node_indices.insert(key.to_string(), idx);
        idx
    }

    /// Add a directed edge between two nodes.
    fn add_edge(&mut self, from: &str, to: &str, edge: GraphEdge) {
        if let (Some(&from_idx), Some(&to_idx)) =
            (self.node_indices.get(from), self.node_indices.get(to))
        {
            self.graph.add_edge(from_idx, to_idx, edge);
        }
    }

    /// Build the graph from scan results.
    pub fn build(
        &mut self,
        subdomains: &[Subdomain],
        services: &[HttpService],
        technologies: &[Technology],
        findings: &[Finding],
        exploits: &[ExploitRef],
    ) {
        // Add domain root
        if let Some(first_sub) = subdomains.first() {
            let domain = Self::extract_domain(&first_sub.subdomain);
            self.add_node(&domain, GraphNode::Domain(domain.clone()));
        }

        // Add subdomains and link to domain
        for sub in subdomains {
            let domain = Self::extract_domain(&sub.subdomain);
            self.add_node(&domain, GraphNode::Domain(domain.clone()));
            self.add_node(&sub.subdomain, GraphNode::Subdomain(sub.subdomain.clone()));
            self.add_edge(&domain, &sub.subdomain, GraphEdge::ResolvesTo);
        }

        // Add services and link to subdomains
        for svc in services {
            self.add_node(&svc.url, GraphNode::Service(svc.url.clone()));
            // Link service to its subdomain (extract hostname from URL)
            if let Some(host) = extract_host(&svc.url) {
                self.add_edge(&host, &svc.url, GraphEdge::RunsOn);
            }
        }

        // Add technologies and link to their services
        for tech in technologies {
            let tech_key = format!(
                "{}/{}",
                tech.name,
                tech.version.as_deref().unwrap_or("unknown")
            );
            self.add_node(
                &tech_key,
                GraphNode::Technology(tech.name.clone(), tech.version.clone()),
            );
            self.add_edge(&tech.service_id, &tech_key, GraphEdge::RelatedTo);
        }

        // Add findings and link to affected services
        for finding in findings {
            let finding_key = format!("finding-{}", finding.id);
            self.add_node(
                &finding_key,
                GraphNode::Finding(finding.title.clone(), finding.severity.to_string()),
            );
            if let Some(ref svc_id) = finding.service_id {
                self.add_edge(&finding_key, svc_id, GraphEdge::HasFinding);
            }
        }

        // Add exploits
        for exploit in exploits {
            let exploit_key = format!("edb-{}", exploit.edb_id);
            self.add_node(
                &exploit_key,
                GraphNode::Exploit(exploit.edb_id, exploit.title.clone()),
            );
            if let Some(ref cve) = exploit.cve {
                self.add_edge(&exploit_key, cve, GraphEdge::HasExploit);
            }
        }
    }

    /// Find attack paths from a starting node to a target node type.
    pub fn find_paths_to(&self, target_type: &str) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        let target_keywords: Vec<&str> = match target_type {
            "exploit" => vec!["edb-"],
            "finding" => vec!["finding-"],
            "admin" => vec!["admin", "dashboard", "management"],
            "cloud" => vec!["aws", "azure", "gcp", "cloud", "s3", "metadata"],
            _ => return paths,
        };

        // Simple path finding: find nodes matching target, then BFS from all entry points
        for (key, &idx) in &self.node_indices {
            let is_target = target_keywords.iter().any(|kw| key.contains(kw));
            if !is_target {
                continue;
            }

            // Find paths from domain nodes to this target
            for (entry_key, &entry_idx) in &self.node_indices {
                if !entry_key.contains('.') || entry_key.contains('/') {
                    continue;
                }
                if entry_key == key {
                    continue;
                }

                if let Some(path) = algo::astar(&self.graph, entry_idx, |n| n == idx, |_e| 1, |_| 0)
                {
                    let path_strs: Vec<String> = path
                        .1
                        .iter()
                        .filter_map(|n| match &self.graph[*n] {
                            GraphNode::Subdomain(s) => Some(s.clone()),
                            GraphNode::Service(s) => Some(s.clone()),
                            GraphNode::Finding(t, s) => Some(format!("[{}] {}", s, t)),
                            GraphNode::Exploit(id, t) => Some(format!("EDB-{}: {}", id, t)),
                            _ => None,
                        })
                        .collect();
                    if !path_strs.is_empty() {
                        paths.push(path_strs);
                    }
                }
            }
        }

        // Sort shortest paths first
        paths.sort_by_key(|p| p.len());
        paths.truncate(10);
        paths
    }

    /// Get the number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Check if the graph has any findings that can be exploited.
    pub fn has_exploitable_findings(&self) -> bool {
        self.node_indices.keys().any(|k| k.starts_with("finding-"))
    }

    /// Export the graph as JSON-serializable structure.
    pub fn export_json(&self) -> serde_json::Value {
        let nodes: Vec<&GraphNode> = self.graph.node_indices().map(|i| &self.graph[i]).collect();
        serde_json::json!({
            "nodes": nodes,
            "node_count": self.node_count(),
            "edge_count": self.edge_count(),
            "has_exploit_paths": self.has_exploitable_findings(),
        })
    }

    fn extract_domain(subdomain: &str) -> String {
        let parts: Vec<&str> = subdomain.split('.').collect();
        if parts.len() >= 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            subdomain.to_string()
        }
    }
}

fn extract_host(url: &str) -> Option<String> {
    url.split('/')
        .nth(2)
        .map(|s| s.split(':').next().unwrap_or(s).to_string())
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::types::Severity;
    use chrono::Utc;

    fn make_subdomain(name: &str) -> Subdomain {
        Subdomain {
            id: name.into(),
            domain_id: "d1".into(),
            subdomain: name.into(),
            source: "test".into(),
            discovered_at: Utc::now(),
        }
    }

    #[allow(dead_code)]
    fn make_service(url: &str) -> HttpService {
        HttpService {
            id: url.into(),
            subdomain_id: "".into(),
            url: url.into(),
            status_code: 200,
            title: None,
            content_type: None,
            content_length: None,
            server: None,
            tech_stack: vec![],
            screenshot_path: None,
        }
    }

    #[test]
    fn test_empty_graph() {
        let g = AttackGraph::new();
        assert_eq!(g.node_count(), 0);
    }

    #[test]
    fn test_add_subdomain() {
        let mut g = AttackGraph::new();
        let subs = vec![make_subdomain("app.example.com"), make_subdomain("api.example.com")];
        g.build(&subs, &[], &[], &[], &[]);
        assert!(g.node_count() >= 3); // domain + 2 subdomains
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(AttackGraph::extract_domain("app.example.com"), "example.com");
        assert_eq!(AttackGraph::extract_domain("deep.sub.example.co.uk"), "co.uk");
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://app.example.com/path").unwrap(),
            "app.example.com"
        );
        assert_eq!(extract_host("http://localhost:8080").unwrap(), "localhost");
    }

    #[test]
    fn test_graph_with_findings() {
        let mut g = AttackGraph::new();
        let finding = Finding {
            id: "f1".into(),
            service_id: None,
            endpoint_id: None,
            title: "SQL Injection".into(),
            severity: Severity::Critical,
            confidence: 90,
            description: "test".into(),
            evidence: None,
            cve: None,
            edb_id: None,
            remediation: None,
            discovered_at: Utc::now(),
        };
        g.build(&[], &[], &[], &[finding], &[]);
        assert!(g.has_exploitable_findings());
    }

    #[test]
    fn test_export_json() {
        let g = AttackGraph::new();
        let json = g.export_json();
        assert_eq!(json["node_count"].as_i64().unwrap(), 0);
    }
}
