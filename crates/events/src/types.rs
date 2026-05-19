use chrono::{DateTime, Utc};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Event {
    // Lifecycle
    ScanStarted { scan_id: String, target: String, timestamp: DateTime<Utc> },
    ScanCompleted { scan_id: String, timestamp: DateTime<Utc>, duration_secs: u64 },
    PhaseStarted { scan_id: String, phase: String, timestamp: DateTime<Utc> },
    PhaseCompleted { scan_id: String, phase: String, timestamp: DateTime<Utc> },

    // Recon
    SubdomainDiscovered { scan_id: String, subdomain: String, source: String, timestamp: DateTime<Utc> },
    DnsResolved { scan_id: String, subdomain: String, ip: String, timestamp: DateTime<Utc> },
    HttpServiceDetected { scan_id: String, url: String, status_code: u16, title: Option<String>, tech: Vec<String>, timestamp: DateTime<Utc> },
    UrlDiscovered { scan_id: String, url: String, source: String, timestamp: DateTime<Utc> },
    ParameterDetected { scan_id: String, url: String, parameter: String, timestamp: DateTime<Utc> },
    TechnologyDetected { scan_id: String, url: String, technology: String, version: Option<String>, timestamp: DateTime<Utc> },
    JsAssetDiscovered { scan_id: String, url: String, asset_url: String, timestamp: DateTime<Utc> },
    ApiEndpointDiscovered { scan_id: String, url: String, method: String, timestamp: DateTime<Utc> },
    SecretDetected { scan_id: String, url: String, secret_type: String, context: String, timestamp: DateTime<Utc> },

    // Intel
    ExploitCorrelated { scan_id: String, technology: String, edb_id: u32, cve: Option<String>, timestamp: DateTime<Utc> },

    // Findings
    CandidateFinding { scan_id: String, finding_id: String, title: String, severity: String, timestamp: DateTime<Utc> },
    VerifiedFinding { scan_id: String, finding_id: String, confidence: u8, timestamp: DateTime<Utc> },
    AttackPathGenerated { scan_id: String, path: Vec<String>, timestamp: DateTime<Utc> },

    // Error / Control
    Error { scan_id: String, message: String, timestamp: DateTime<Utc> },
    RateLimited { scan_id: String, host: String, retry_ms: u64, timestamp: DateTime<Utc> },
}

impl Event {
    /// Returns the scan_id associated with this event, if any.
    pub fn scan_id(&self) -> Option<&str> {
        match self {
            Event::ScanStarted { scan_id, .. } => Some(scan_id),
            Event::ScanCompleted { scan_id, .. } => Some(scan_id),
            Event::PhaseStarted { scan_id, .. } => Some(scan_id),
            Event::PhaseCompleted { scan_id, .. } => Some(scan_id),
            Event::SubdomainDiscovered { scan_id, .. } => Some(scan_id),
            Event::DnsResolved { scan_id, .. } => Some(scan_id),
            Event::HttpServiceDetected { scan_id, .. } => Some(scan_id),
            Event::UrlDiscovered { scan_id, .. } => Some(scan_id),
            Event::ParameterDetected { scan_id, .. } => Some(scan_id),
            Event::TechnologyDetected { scan_id, .. } => Some(scan_id),
            Event::JsAssetDiscovered { scan_id, .. } => Some(scan_id),
            Event::ApiEndpointDiscovered { scan_id, .. } => Some(scan_id),
            Event::SecretDetected { scan_id, .. } => Some(scan_id),
            Event::ExploitCorrelated { scan_id, .. } => Some(scan_id),
            Event::CandidateFinding { scan_id, .. } => Some(scan_id),
            Event::VerifiedFinding { scan_id, .. } => Some(scan_id),
            Event::AttackPathGenerated { scan_id, .. } => Some(scan_id),
            Event::Error { scan_id, .. } => Some(scan_id),
            Event::RateLimited { scan_id, .. } => Some(scan_id),
        }
    }

    /// Categorize an event into a broad kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::ScanStarted { .. } | Event::ScanCompleted { .. }
            | Event::PhaseStarted { .. } | Event::PhaseCompleted { .. } => "lifecycle",
            Event::SubdomainDiscovered { .. } | Event::DnsResolved { .. }
            | Event::HttpServiceDetected { .. } | Event::UrlDiscovered { .. }
            | Event::ParameterDetected { .. } | Event::TechnologyDetected { .. }
            | Event::JsAssetDiscovered { .. } | Event::ApiEndpointDiscovered { .. }
            | Event::SecretDetected { .. } => "recon",
            Event::ExploitCorrelated { .. } => "intel",
            Event::CandidateFinding { .. } | Event::VerifiedFinding { .. }
            | Event::AttackPathGenerated { .. } => "finding",
            Event::Error { .. } | Event::RateLimited { .. } => "error",
        }
    }
}
