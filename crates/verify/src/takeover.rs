#[derive(Debug, Clone, serde::Serialize)]
pub struct TakeoverResult {
    pub subdomain: String,
    pub cname: Option<String>,
    pub service: Option<String>,
    pub vulnerable: bool,
    pub fingerprint: String,
}

pub struct TakeoverChecker;

impl TakeoverChecker {
    pub fn new() -> Self {
        Self
    }

    /// Check a subdomain's CNAME for known takeoverable services.
    pub fn check_cname(&self, subdomain: &str, cname: &str) -> TakeoverResult {
        let lower = cname.to_lowercase();
        let service = if lower.contains("cloudfront.net") {
            Some("AWS CloudFront".into())
        } else if lower.contains("s3") && lower.contains("amazonaws.com") {
            Some("AWS S3".into())
        } else if lower.contains("elasticbeanstalk.com") {
            Some("AWS Elastic Beanstalk".into())
        } else if lower.contains("azureedge.net") || lower.contains("azurefd.net") {
            Some("Azure CDN".into())
        } else if lower.contains("trafficmanager.net") {
            Some("Azure Traffic Manager".into())
        } else if lower.contains("github.io") {
            Some("GitHub Pages".into())
        } else if lower.contains("herokuapp.com") || lower.contains("herokudns.com") {
            Some("Heroku".into())
        } else if lower.contains("pantheon.io") || lower.contains("pantheonsite.io") {
            Some("Pantheon".into())
        } else if lower.contains("cname.to") || lower.contains("cname.bitbucket.org") {
            Some("Bitbucket".into())
        } else if lower.contains("cdn.shopify.com") || lower.contains("myshopify.com") {
            Some("Shopify".into())
        } else if lower.contains("firebaseapp.com") || lower.contains("web.app") {
            Some("Firebase".into())
        } else if lower.contains("unbouncepages.com") {
            Some("Unbounce".into())
        } else if lower.contains("squarespace.com") {
            Some("Squarespace".into())
        } else if lower.contains("zendesk.com") {
            Some("Zendesk".into())
        } else if lower.contains("freshdesk.com") {
            Some("Freshdesk".into())
        } else if lower.contains("helpscout.net") {
            Some("HelpScout".into())
        } else if lower.contains("fastly.net") || lower.contains("fastly.com") {
            Some("Fastly".into())
        } else if lower.contains("surge.sh") {
            Some("Surge".into())
        } else if lower.contains("readme.io") {
            Some("ReadMe".into())
        } else if lower.contains("statuspage.io") {
            Some("StatusPage".into())
        } else {
            None
        };

        let vuln = service.is_some()
            || lower.contains("unbounce")
            || lower.contains("elasticbeanstalk");

        TakeoverResult {
            subdomain: subdomain.to_string(),
            cname: Some(cname.to_string()),
            service,
            vulnerable: vuln,
            fingerprint: format!("CNAME: {}", cname),
        }
    }

    /// Check without CNAME (just check if the service looks vulnerable to takeover).
    pub fn check_by_response(&self, subdomain: &str, body: &str, status: u16) -> TakeoverResult {
        let lower = body.to_lowercase();
        let mut vulnerable = false;
        let mut service = None;
        let mut fingerprint = String::new();

        if status == 404 {
            if lower.contains("there is no app configured") {
                vulnerable = true;
                service = Some("Heroku".into());
                fingerprint = "Heroku: No app configured".into();
            } else if lower.contains("no such bucket") {
                vulnerable = true;
                service = Some("AWS S3".into());
                fingerprint = "S3: No such bucket".into();
            } else if lower.contains("repository not found") {
                vulnerable = true;
                service = Some("GitHub Pages".into());
                fingerprint = "GitHub: Repo not found".into();
            } else if lower.contains("this page is not available") || lower.contains("tumblr") {
                vulnerable = true;
                service = Some("Tumblr".into());
            } else if lower.contains("there is nothing here") || lower.contains("unbounce") {
                vulnerable = true;
                service = Some("Unbounce".into());
            } else if lower.contains("does not exist")
                || lower.contains("doesn't exist")
                || lower.contains("not found")
            {
                fingerprint = "Generic 404 — possible takeover".into();
            }
        }

        TakeoverResult {
            subdomain: subdomain.to_string(),
            cname: None,
            service,
            vulnerable,
            fingerprint,
        }
    }
}

impl Default for TakeoverChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_takeover_cloudfront() {
        let checker = TakeoverChecker::new();
        let result = checker.check_cname("cdn.example.com", "d123.cloudfront.net");
        assert!(result.vulnerable);
        assert_eq!(result.service.unwrap(), "AWS CloudFront");
    }
    #[test]
    fn test_takeover_s3() {
        let checker = TakeoverChecker::new();
        let result = checker.check_cname("assets.example.com", "my-bucket.s3.amazonaws.com");
        assert!(result.vulnerable);
        assert_eq!(result.service.unwrap(), "AWS S3");
    }
    #[test]
    fn test_takeover_heroku_404() {
        let checker = TakeoverChecker::new();
        let result =
            checker.check_by_response("app.example.com", "There is no app configured here", 404);
        assert!(result.vulnerable);
        assert_eq!(result.service.unwrap(), "Heroku");
    }
    #[test]
    fn test_no_takeover() {
        let checker = TakeoverChecker::new();
        let result = checker.check_cname(
            "www.example.com",
            "prod-ec2-54-123-45-67.compute-1.amazonaws.com",
        );
        assert!(!result.vulnerable);
    }
}
