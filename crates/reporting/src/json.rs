use aegis_core::types::ScanReport;

pub struct JsonReport;

impl JsonReport {
    pub fn generate(report: &ScanReport) -> serde_json::Result<String> {
        serde_json::to_string_pretty(report)
    }

    pub fn write_to_file(
        report: &ScanReport,
        path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = Self::generate(report)?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, json)?;
        Ok(())
    }
}
