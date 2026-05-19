#[derive(Debug, Clone, serde::Serialize)]
pub struct CloudCheck {
    pub provider: String,
    pub service: String,
    pub check: String,
    pub description: String,
}

/// Generate cloud-specific checks based on detected technologies and URLs.
pub fn cloud_checks(technologies: &[String], urls: &[String]) -> Vec<CloudCheck> {
    let mut checks = Vec::new();
    let all_tech: String = technologies.join(" ").to_lowercase();
    let all_urls: String = urls.join(" ").to_lowercase();

    // AWS
    if all_tech.contains("aws") || all_tech.contains("amazon") || all_tech.contains("ec2") || all_urls.contains("amazonaws.com") {
        checks.push(CloudCheck { provider: "AWS".into(), service: "S3".into(), check: "S3 Bucket Listing".into(), description: "Check if S3 buckets allow public listing".into() });
        checks.push(CloudCheck { provider: "AWS".into(), service: "EC2".into(), check: "Metadata Service".into(), description: "Test if SSRF can reach 169.254.169.254 for IAM credentials".into() });
        checks.push(CloudCheck { provider: "AWS".into(), service: "CloudFront".into(), check: "CloudFront Misconfig".into(), description: "Check for CloudFront origin access restriction bypass".into() });
    }

    // GCP
    if all_tech.contains("gcp") || all_tech.contains("google cloud") || all_tech.contains("gce") || all_urls.contains("googleapis.com") || all_urls.contains("storage.googleapis.com") {
        checks.push(CloudCheck { provider: "GCP".into(), service: "GCS".into(), check: "Bucket Discovery".into(), description: "Try common GCS bucket names and check for public access".into() });
        checks.push(CloudCheck { provider: "GCP".into(), service: "GCE".into(), check: "Metadata Service".into(), description: "Test if SSRF can reach metadata.google.internal".into() });
    }

    // Azure
    if all_tech.contains("azure") || all_tech.contains("microsoft") || all_urls.contains("azureedge.net") || all_urls.contains("blob.core.windows.net") || all_urls.contains("azurefd.net") {
        checks.push(CloudCheck { provider: "Azure".into(), service: "Blob".into(), check: "Blob Storage Access".into(), description: "Check for publicly accessible Azure blobs".into() });
        checks.push(CloudCheck { provider: "Azure".into(), service: "IMDS".into(), check: "Metadata Service".into(), description: "Test if SSRF can reach 169.254.169.254/metadata/instance".into() });
    }

    // Generic / Multi-cloud
    if all_urls.contains("s3") || all_urls.contains("bucket") || all_urls.contains("storage") {
        checks.push(CloudCheck { provider: "Multi".into(), service: "Object Storage".into(), check: "Directory Listing".into(), description: "Check if cloud storage directories are publicly listable".into() });
    }

    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_aws_checks() {
        let checks = cloud_checks(&["AWS EC2".into(), "nginx".into()], &["https://my-bucket.s3.amazonaws.com".into()]);
        assert!(checks.iter().any(|c| c.provider == "AWS"));
        assert!(checks.iter().any(|c| c.check.contains("Metadata")));
    }
    #[test]
    fn test_gcp_checks() {
        let checks = cloud_checks(&["Google Cloud".into(), "GCE".into()], &["https://storage.googleapis.com/bucket".into()]);
        assert!(checks.iter().any(|c| c.provider == "GCP"));
    }
    #[test]
    fn test_azure_checks() {
        let checks = cloud_checks(&["Azure".into()], &["https://cdn.azureedge.net".into()]);
        assert!(checks.iter().any(|c| c.provider == "Azure"));
    }
    #[test]
    fn test_no_cloud() {
        let checks = cloud_checks(&["nginx".into(), "php".into()], &["https://example.com".into()]);
        assert!(checks.is_empty());
    }
}
