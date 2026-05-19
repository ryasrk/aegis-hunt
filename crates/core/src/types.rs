use chrono::{DateTime, Utc};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// A discovered domain or target organization.
pub struct Domain {
    pub id: String,
    pub domain: String,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// A subdomain discovered during reconnaissance.
pub struct Subdomain {
    pub id: String,
    pub domain_id: String,
    pub subdomain: String,
    pub source: String,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// An IP address associated with a resolved subdomain.
pub struct IpAddress {
    pub id: String,
    pub subdomain_id: String,
    pub ip: std::net::IpAddr,
    pub asn: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// An HTTP service detected on a live host.
pub struct HttpService {
    pub id: String,
    pub subdomain_id: String,
    pub url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub server: Option<String>,
    pub tech_stack: Vec<String>,
    pub screenshot_path: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// A technology or framework detected on a service.
pub struct Technology {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    /// Confidence level (0-100, where 100 = certain).
    pub confidence: u8,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// A URL endpoint discovered during crawling or extraction.
pub struct Endpoint {
    pub id: String,
    pub service_id: String,
    pub path: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub is_api: bool,
    pub discovered_by: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// A security finding or vulnerability discovered during testing.
pub struct Finding {
    pub id: String,
    pub service_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub title: String,
    pub severity: Severity,
    /// Confidence level (0-100, where 100 = certain).
    pub confidence: u8,
    pub description: String,
    pub evidence: Option<String>,
    pub cve: Option<String>,
    pub edb_id: Option<u32>,
    pub remediation: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

/// The severity of a security finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    /// Critical severity — immediate exploitation possible with severe impact.
    Critical,
    /// High severity — significant security impact.
    High,
    /// Medium severity — moderate security risk.
    Medium,
    /// Low severity — minor security concern.
    Low,
    /// Informational — no direct security impact but noteworthy.
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    #[must_use]
    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 100,
            Severity::High => 70,
            Severity::Medium => 40,
            Severity::Low => 20,
            Severity::Info => 5,
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Ok(Severity::Critical),
            "HIGH" => Ok(Severity::High),
            "MEDIUM" => Ok(Severity::Medium),
            "LOW" => Ok(Severity::Low),
            "INFO" => Ok(Severity::Info),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExploitRef {
    pub edb_id: u32,
    pub cve: Option<String>,
    pub title: String,
    pub exploit_type: String,
    pub platform: String,
    pub file_path: String,
    pub verified: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_secs: Option<u64>,
    pub domains: Vec<Domain>,
    pub subdomains: Vec<Subdomain>,
    pub services: Vec<HttpService>,
    pub technologies: Vec<Technology>,
    pub endpoints: Vec<Endpoint>,
    pub findings: Vec<Finding>,
    pub exploit_refs: Vec<ExploitRef>,
}
