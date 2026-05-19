use rusqlite::Connection;
use tracing::info;

pub fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS domains (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            domain_id TEXT,
            subdomain TEXT NOT NULL,
            source TEXT NOT NULL,
            resolved_ip TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS services (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            subdomain_id TEXT,
            url TEXT NOT NULL,
            status_code INTEGER,
            title TEXT,
            content_type TEXT,
            content_length INTEGER,
            server TEXT,
            tech_json TEXT,
            screenshot_path TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS technologies (
            id TEXT PRIMARY KEY,
            service_id TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT,
            category TEXT,
            confidence INTEGER DEFAULT 100,
            FOREIGN KEY (service_id) REFERENCES services(id)
        );

        CREATE TABLE IF NOT EXISTS endpoints (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            service_id TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            parameters TEXT,
            is_api INTEGER DEFAULT 0,
            discovered_by TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (service_id) REFERENCES services(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            service_id TEXT,
            endpoint_id TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER DEFAULT 50,
            description TEXT,
            evidence TEXT,
            cve TEXT,
            edb_id INTEGER,
            remediation TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS exploit_refs (
            id TEXT PRIMARY KEY,
            finding_id TEXT,
            edb_id INTEGER NOT NULL,
            cve TEXT,
            exploit_title TEXT NOT NULL,
            exploit_type TEXT,
            platform TEXT,
            file_path TEXT,
            verified INTEGER DEFAULT 0,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        );

        CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
        CREATE INDEX IF NOT EXISTS idx_services_scan ON services(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies(name);
    ",
    )?;

    info!("Database schema initialized");
    Ok(())
}
