use aegis_core::error::AegisResult;
use crate::db::Database;
use std::sync::Arc;

/// Async-safe wrapper around Database that uses tokio::task::spawn_blocking.
pub struct AsyncDatabase {
    inner: Arc<Database>,
}

impl AsyncDatabase {
    pub fn new(db: Database) -> Self {
        Self { inner: Arc::new(db) }
    }

    pub fn from_arc(db: Arc<Database>) -> Self {
        Self { inner: db }
    }

    pub async fn create_scan(&self, target: &str) -> AegisResult<String> {
        let db = self.inner.clone();
        let target = target.to_string();
        tokio::task::spawn_blocking(move || {
            db.create_scan(&target).map_err(|e| aegis_core::error::AegisError::Database(e.to_string()))
        }).await
          .map_err(|e| aegis_core::error::AegisError::Unknown(format!("Join error: {}", e)))?
    }

    pub async fn complete_scan(&self, scan_id: &str) -> AegisResult<()> {
        let db = self.inner.clone();
        let scan_id = scan_id.to_string();
        tokio::task::spawn_blocking(move || {
            db.complete_scan(&scan_id).map_err(|e| aegis_core::error::AegisError::Database(e.to_string()))
        }).await
          .map_err(|e| aegis_core::error::AegisError::Unknown(format!("Join error: {}", e)))?
    }

    pub async fn insert_subdomain(&self, scan_id: &str, subdomain: &str, source: &str) -> AegisResult<String> {
        let db = self.inner.clone();
        let scan_id = scan_id.to_string();
        let subdomain = subdomain.to_string();
        let source = source.to_string();
        tokio::task::spawn_blocking(move || {
            db.insert_subdomain(&scan_id, &subdomain, &source)
        }).await
          .map_err(|e| aegis_core::error::AegisError::Unknown(format!("Join error: {}", e)))?
    }

    pub async fn insert_service(&self, scan_id: &str, subdomain_id: &str, url: &str, status_code: u16, title: Option<&str>, tech: &[String]) -> AegisResult<String> {
        let db = self.inner.clone();
        let scan_id = scan_id.to_string();
        let subdomain_id = subdomain_id.to_string();
        let url = url.to_string();
        let title = title.map(|s| s.to_string());
        let tech: Vec<String> = tech.to_vec();
        tokio::task::spawn_blocking(move || {
            db.insert_service(&scan_id, &subdomain_id, &url, status_code, title.as_deref(), &tech)
        }).await
          .map_err(|e| aegis_core::error::AegisError::Unknown(format!("Join error: {}", e)))?
    }

    pub async fn get_findings_by_scan(&self, scan_id: &str) -> AegisResult<Vec<aegis_core::types::Finding>> {
        let db = self.inner.clone();
        let scan_id = scan_id.to_string();
        tokio::task::spawn_blocking(move || {
            db.get_findings_by_scan(&scan_id)
        }).await
          .map_err(|e| aegis_core::error::AegisError::Unknown(format!("Join error: {}", e)))?
    }

    pub async fn get_services_by_scan(&self, scan_id: &str) -> AegisResult<Vec<aegis_core::types::HttpService>> {
        let db = self.inner.clone();
        let scan_id = scan_id.to_string();
        tokio::task::spawn_blocking(move || {
            db.get_services_by_scan(&scan_id)
        }).await
          .map_err(|e| aegis_core::error::AegisError::Unknown(format!("Join error: {}", e)))?
    }
}
