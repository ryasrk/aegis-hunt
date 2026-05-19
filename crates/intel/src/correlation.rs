use crate::exploitdb::ExploitDbIndex;
use aegis_core::types::ExploitRef;

/// Result of correlating a technology with matching exploits.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CorrelatedExploit {
    pub trigger_technology: String,
    pub exploit: ExploitRef,
}

/// Engine that matches detected technologies and CVEs to known exploits.
pub struct CorrelationEngine {
    exploit_db: ExploitDbIndex,
}

impl CorrelationEngine {
    pub fn new(exploit_db: ExploitDbIndex) -> Self {
        Self { exploit_db }
    }

    /// Given a list of detected technologies, return all matching exploits.
    pub fn correlate_technologies(&self, technologies: &[String]) -> Vec<CorrelatedExploit> {
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for tech in technologies {
            let matches = self.exploit_db.search_by_tech(tech);
            for exploit in matches {
                if seen.insert(exploit.edb_id) {
                    results.push(CorrelatedExploit {
                        trigger_technology: tech.clone(),
                        exploit: exploit.clone(),
                    });
                }
            }
        }

        results
    }

    /// Given a CVE ID, find matching exploit details (a CVE may have multiple exploits).
    pub fn correlate_cve(&self, cve: &str) -> Vec<&ExploitRef> {
        self.exploit_db.search_by_cve(cve)
    }

    pub fn exploit_db(&self) -> &ExploitDbIndex {
        &self.exploit_db
    }
}
