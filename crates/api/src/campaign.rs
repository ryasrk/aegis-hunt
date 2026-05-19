use std::collections::HashMap;
use std::sync::Mutex;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Campaign {
    pub id: String,
    pub name: String,
    pub targets: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: CampaignStatus,
    pub scan_ids: HashMap<String, String>, // target -> scan_id
    pub findings_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub enum CampaignStatus {
    Running,
    Completed,
    Failed,
}

pub struct CampaignManager {
    campaigns: Mutex<HashMap<String, Campaign>>,
}

impl CampaignManager {
    pub fn new() -> Self {
        Self {
            campaigns: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new campaign from a list of targets.
    pub fn create(&self, name: &str, targets: Vec<String>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let campaign = Campaign {
            id: id.clone(),
            name: name.to_string(),
            targets,
            created_at: Utc::now(),
            completed_at: None,
            status: CampaignStatus::Running,
            scan_ids: HashMap::new(),
            findings_count: 0,
        };
        self.campaigns.lock().unwrap().insert(id.clone(), campaign);
        id
    }

    /// Register a scan completion for a campaign target.
    pub fn register_scan(
        &self,
        campaign_id: &str,
        target: &str,
        scan_id: &str,
        findings: usize,
    ) {
        if let Some(campaign) = self.campaigns.lock().unwrap().get_mut(campaign_id) {
            campaign
                .scan_ids
                .insert(target.to_string(), scan_id.to_string());
            campaign.findings_count += findings;
        }
    }

    /// Mark a campaign as completed.
    pub fn complete(&self, campaign_id: &str) {
        if let Some(campaign) = self.campaigns.lock().unwrap().get_mut(campaign_id) {
            campaign.status = CampaignStatus::Completed;
            campaign.completed_at = Some(Utc::now());
        }
    }

    /// Get a campaign by ID.
    pub fn get(&self, campaign_id: &str) -> Option<Campaign> {
        self.campaigns.lock().unwrap().get(campaign_id).cloned()
    }

    /// List all campaigns.
    pub fn list(&self) -> Vec<Campaign> {
        self.campaigns
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Check if all targets in a campaign have been scanned.
    pub fn is_complete(&self, campaign_id: &str) -> bool {
        if let Some(campaign) = self.campaigns.lock().unwrap().get(campaign_id) {
            campaign
                .targets
                .iter()
                .all(|t| campaign.scan_ids.contains_key(t))
        } else {
            false
        }
    }
}

impl Default for CampaignManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_campaign() {
        let mgr = CampaignManager::new();
        let id = mgr.create(
            "test-campaign",
            vec!["target1.com".into(), "target2.com".into()],
        );
        let c = mgr.get(&id).unwrap();
        assert_eq!(c.name, "test-campaign");
        assert_eq!(c.targets.len(), 2);
        assert_eq!(c.status, CampaignStatus::Running);
    }

    #[test]
    fn test_register_scan() {
        let mgr = CampaignManager::new();
        let id = mgr.create("test", vec!["t1.com".into()]);
        mgr.register_scan(&id, "t1.com", "scan-123", 5);
        let c = mgr.get(&id).unwrap();
        assert_eq!(c.findings_count, 5);
        assert_eq!(c.scan_ids.get("t1.com").unwrap(), "scan-123");
    }

    #[test]
    fn test_complete_campaign() {
        let mgr = CampaignManager::new();
        let id = mgr.create("test", vec!["t1.com".into()]);
        mgr.register_scan(&id, "t1.com", "scan-123", 0);
        mgr.complete(&id);
        let c = mgr.get(&id).unwrap();
        assert_eq!(c.status, CampaignStatus::Completed);
        assert!(c.completed_at.is_some());
    }

    #[test]
    fn test_is_complete() {
        let mgr = CampaignManager::new();
        let id = mgr.create("test", vec!["t1.com".into(), "t2.com".into()]);
        mgr.register_scan(&id, "t1.com", "s1", 0);
        assert!(!mgr.is_complete(&id));
        mgr.register_scan(&id, "t2.com", "s2", 0);
        assert!(mgr.is_complete(&id));
    }

    #[test]
    fn test_list_campaigns() {
        let mgr = CampaignManager::new();
        mgr.create("c1", vec![]);
        mgr.create("c2", vec![]);
        assert_eq!(mgr.list().len(), 2);
    }
}
