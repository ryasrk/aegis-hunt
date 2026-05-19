use aegis_core::error::AegisError;
use aegis_core::types::{Finding, HttpService, Severity};

use crate::db::Database;

impl Database {
    /// Create a new scan record and return its UUID.
    pub fn create_scan(&self, target: &str) -> Result<String, AegisError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO scans (id, target, started_at, status) VALUES (?1, ?2, ?3, 'running')",
            rusqlite::params![id, target, now],
        )
        .map_err(|e| AegisError::Database(e.to_string()))?;
        Ok(id)
    }

    /// Mark a scan as completed with the current timestamp.
    pub fn complete_scan(&self, scan_id: &str) -> Result<(), AegisError> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn();
        conn.execute(
            "UPDATE scans SET completed_at = ?1, status = 'completed' WHERE id = ?2",
            rusqlite::params![now, scan_id],
        )
        .map_err(|e| AegisError::Database(e.to_string()))?;
        Ok(())
    }

    /// Insert a domain record.
    pub fn insert_domain(&self, scan_id: &str, domain: &str) -> Result<String, AegisError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO domains (id, scan_id, domain, discovered_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, scan_id, domain, now],
        )
        .map_err(|e| AegisError::Database(e.to_string()))?;
        Ok(id)
    }

    /// Insert a subdomain record.
    pub fn insert_subdomain(
        &self,
        scan_id: &str,
        subdomain: &str,
        source: &str,
    ) -> Result<String, AegisError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO subdomains (id, scan_id, subdomain, source, discovered_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![id, scan_id, subdomain, source, now],
        )
        .map_err(|e| AegisError::Database(e.to_string()))?;
        Ok(id)
    }

    /// Insert an HTTP service record. `tech` is serialized to JSON for storage.
    pub fn insert_service(
        &self,
        scan_id: &str,
        subdomain_id: &str,
        url: &str,
        status_code: u16,
        title: Option<&str>,
        tech: &[String],
    ) -> Result<String, AegisError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let tech_json = serde_json::to_string(tech)
            .map_err(AegisError::Serialization)?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO services (id, scan_id, subdomain_id, url, status_code, title, tech_json, discovered_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![id, scan_id, subdomain_id, url, status_code, title, tech_json, now],
        )
        .map_err(|e| AegisError::Database(e.to_string()))?;
        Ok(id)
    }

    /// Insert a security finding.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_finding(
        &self,
        scan_id: &str,
        service_id: Option<&str>,
        title: &str,
        severity: &str,
        confidence: u8,
        description: &str,
        cve: Option<&str>,
        remediation: Option<&str>,
    ) -> Result<String, AegisError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let severity_upper = severity.to_uppercase();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO findings (id, scan_id, service_id, title, severity, confidence, description, cve, remediation, discovered_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![id, scan_id, service_id, title, severity_upper, confidence, description, cve, remediation, now],
        )
        .map_err(|e| AegisError::Database(e.to_string()))?;
        Ok(id)
    }

    /// Retrieve all findings for a scan, ordered by severity (highest first).
    pub fn get_findings_by_scan(&self, scan_id: &str) -> Result<Vec<Finding>, AegisError> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, service_id, endpoint_id, title, severity, confidence, \
                        description, evidence, cve, edb_id, remediation, discovered_at \
                 FROM findings WHERE scan_id = ?1 \
                 ORDER BY \
                   CASE severity \
                     WHEN 'CRITICAL' THEN 0 \
                     WHEN 'HIGH' THEN 1 \
                     WHEN 'MEDIUM' THEN 2 \
                     WHEN 'LOW' THEN 3 \
                     ELSE 4 \
                   END",
            )
            .map_err(|e| AegisError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(rusqlite::params![scan_id], |row| {
                Ok(Finding {
                    id: row.get(0)?,
                    service_id: row.get(1)?,
                    endpoint_id: row.get(2)?,
                    title: row.get(3)?,
                    severity: row
                        .get::<_, String>(4)?
                        .parse::<Severity>()
                        .unwrap_or(Severity::Info),
                    confidence: row.get::<_, i32>(5)? as u8,
                    description: row.get(6)?,
                    evidence: row.get(7)?,
                    cve: row.get(8)?,
                    edb_id: row.get::<_, Option<i32>>(9).map(|v| v.map(|x| x as u32))?,
                    remediation: row.get(10)?,
                    discovered_at: row
                        .get::<_, String>(11)?
                        .parse::<chrono::DateTime<chrono::Utc>>()
                        .unwrap_or_else(|_| chrono::Utc::now()),
                })
            })
            .map_err(|e| AegisError::Database(e.to_string()))?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row.map_err(|e| AegisError::Database(e.to_string()))?);
        }
        Ok(findings)
    }

    /// Retrieve all services for a scan.
    pub fn get_services_by_scan(&self, scan_id: &str) -> Result<Vec<HttpService>, AegisError> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, subdomain_id, url, status_code, title, content_type, \
                        content_length, server, tech_json, screenshot_path \
                 FROM services WHERE scan_id = ?1",
            )
            .map_err(|e| AegisError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(rusqlite::params![scan_id], |row| {
                let tech_json: Option<String> = row.get(8)?;
                let tech_stack: Vec<String> = tech_json
                    .and_then(|j| serde_json::from_str(&j).ok())
                    .unwrap_or_default();

                Ok(HttpService {
                    id: row.get(0)?,
                    subdomain_id: row.get(1)?,
                    url: row.get(2)?,
                    status_code: row.get::<_, i32>(3)? as u16,
                    title: row.get(4)?,
                    content_type: row.get(5)?,
                    content_length: row.get::<_, Option<i64>>(6).ok().flatten().map(|v| v as u64),
                    server: row.get(7)?,
                    tech_stack,
                    screenshot_path: row.get(9)?,
                })
            })
            .map_err(|e| AegisError::Database(e.to_string()))?;

        let mut services = Vec::new();
        for row in rows {
            services.push(row.map_err(|e| AegisError::Database(e.to_string()))?);
        }
        Ok(services)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn test_create_and_query_scan() {
        let db = Database::open_in_memory().expect("Failed to open in-memory DB");

        // Create a scan
        let scan_id = db.create_scan("example.com").expect("Failed to create scan");
        assert!(!scan_id.is_empty(), "Scan ID should not be empty");

        // Complete the scan
        db.complete_scan(&scan_id).expect("Failed to complete scan");

        // Verify no findings for a fresh scan
        let findings = db
            .get_findings_by_scan(&scan_id)
            .expect("Failed to query findings");
        assert!(findings.is_empty(), "New scan should have no findings");

        // Verify no services for a fresh scan
        let services = db
            .get_services_by_scan(&scan_id)
            .expect("Failed to query services");
        assert!(services.is_empty(), "New scan should have no services");
    }

    #[test]
    fn test_insert_and_retrieve_findings() {
        let db = Database::open_in_memory().expect("Failed to open in-memory DB");
        let scan_id = db.create_scan("test.com").expect("Failed to create scan");

        // Insert a finding
        db.insert_finding(
            &scan_id,
            None,
            "SQL Injection",
            "CRITICAL",
            90,
            "SQL injection in login parameter",
            Some("CVE-2024-0001"),
            Some("Use parameterized queries"),
        )
        .expect("Failed to insert finding");

        let findings = db
            .get_findings_by_scan(&scan_id)
            .expect("Failed to query findings");
        assert_eq!(findings.len(), 1, "Should have one finding");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].title, "SQL Injection");
        assert_eq!(
            findings[0].cve.as_deref(),
            Some("CVE-2024-0001"),
            "CVE should match"
        );
    }

    #[test]
    fn test_insert_and_retrieve_services() {
        let db = Database::open_in_memory().expect("Failed to open in-memory DB");
        let scan_id = db.create_scan("test.com").expect("Failed to create scan");

        let tech = vec!["React".to_string(), "Nginx".to_string()];
        let service_id = db
            .insert_service(&scan_id, "sub-1", "https://test.com", 200, Some("Test Page"), &tech)
            .expect("Failed to insert service");

        let services = db
            .get_services_by_scan(&scan_id)
            .expect("Failed to query services");
        assert_eq!(services.len(), 1, "Should have one service");
        assert_eq!(services[0].id, service_id);
        assert_eq!(services[0].status_code, 200);
        assert_eq!(services[0].title.as_deref(), Some("Test Page"));
        assert_eq!(services[0].tech_stack.len(), 2);
        assert!(services[0].tech_stack.contains(&"React".to_string()));
    }
}
