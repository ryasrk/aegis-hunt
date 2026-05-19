#[derive(Debug, Clone, serde::Serialize)]
pub struct EndpointClass {
    pub path: String,
    pub category: String,
    pub risk_level: String,
    pub why: String,
}

/// Classify an endpoint by its path patterns.
pub fn classify_endpoint(path: &str) -> Option<EndpointClass> {
    let lower = path.to_lowercase();

    // Authentication endpoints
    if lower.contains("login") || lower.contains("signin") || lower.contains("auth") {
        return Some(EndpointClass { path: path.into(), category: "Authentication".into(), risk_level: "HIGH".into(), why: "Auth endpoints may be vulnerable to bypass, brute force, or logic flaws".into() });
    }
    if lower.contains("register") || lower.contains("signup") || lower.contains("create_account") {
        return Some(EndpointClass { path: path.into(), category: "Registration".into(), risk_level: "HIGH".into(), why: "Registration may be vulnerable to mass account creation, rate limiting bypass, or privilege escalation".into() });
    }
    if lower.contains("reset") || lower.contains("forgot") || lower.contains("recover") {
        return Some(EndpointClass { path: path.into(), category: "Password Reset".into(), risk_level: "CRITICAL".into(), why: "Password reset is often vulnerable to token prediction, poisoning, or host header injection".into() });
    }
    if lower.contains("2fa") || lower.contains("two-factor") || lower.contains("mfa") || lower.contains("otp") {
        return Some(EndpointClass { path: path.into(), category: "2FA".into(), risk_level: "CRITICAL".into(), why: "2FA frequently has bypasses: race conditions, rate limiting issues, backup code abuse".into() });
    }

    // Financial/Sensitive
    if lower.contains("payment") || lower.contains("checkout") || lower.contains("billing") || lower.contains("charge") {
        return Some(EndpointClass { path: path.into(), category: "Payment".into(), risk_level: "CRITICAL".into(), why: "Payment endpoints may have price manipulation, race conditions, or integer overflow bugs".into() });
    }
    if lower.contains("refund") || lower.contains("cancel") || lower.contains("delete") || lower.contains("remove") {
        return Some(EndpointClass { path: path.into(), category: "Destructive Action".into(), risk_level: "HIGH".into(), why: "Destructive operations need proper authorization checks".into() });
    }
    if lower.contains("transfer") || lower.contains("withdraw") || lower.contains("redeem") || lower.contains("claim") {
        return Some(EndpointClass { path: path.into(), category: "Financial Transaction".into(), risk_level: "CRITICAL".into(), why: "Money movement endpoints often have race conditions or business logic flaws".into() });
    }
    if lower.contains("coupon") || lower.contains("discount") || lower.contains("promo") || lower.contains("voucher") {
        return Some(EndpointClass { path: path.into(), category: "Discount/Promo".into(), risk_level: "HIGH".into(), why: "Promo code endpoints may have replay, race condition, or abuse issues".into() });
    }

    // User management
    if lower.contains("upload") || lower.contains("image") || lower.contains("file") || lower.contains("attach") {
        return Some(EndpointClass { path: path.into(), category: "File Upload".into(), risk_level: "CRITICAL".into(), why: "File upload is a common RCE vector via unrestricted upload, path traversal, or content bypass".into() });
    }
    if lower.contains("admin") || lower.contains("dashboard") || lower.contains("manage") || lower.contains("control") {
        return Some(EndpointClass { path: path.into(), category: "Admin Panel".into(), risk_level: "CRITICAL".into(), why: "Admin panels frequently have auth bypass, IDOR, or privilege escalation vulnerabilities".into() });
    }
    if lower.contains("search") || lower.contains("query") || lower.contains("filter") || lower.contains("sort") {
        return Some(EndpointClass { path: path.into(), category: "Search/Query".into(), risk_level: "MEDIUM".into(), why: "Search endpoints may have SQL injection, NoSQL injection, or parameter pollution".into() });
    }

    // API/Data
    if lower.contains("export") || lower.contains("download") || lower.contains("csv") || lower.contains("report") {
        return Some(EndpointClass { path: path.into(), category: "Data Export".into(), risk_level: "HIGH".into(), why: "Data export endpoints may leak other users' data via IDOR".into() });
    }
    if lower.contains("proxy") || lower.contains("webhook") || lower.contains("callback") || lower.contains("redirect") || lower == "/redirect" {
        return Some(EndpointClass { path: path.into(), category: "SSRF/Redirect".into(), risk_level: "HIGH".into(), why: "URL-manipulating endpoints are SSRF and open redirect candidates".into() });
    }
    if lower.contains("import") || lower.contains("upload") {
        return Some(EndpointClass { path: path.into(), category: "Data Import".into(), risk_level: "HIGH".into(), why: "Import features may be vulnerable to XXE, CSV injection, or mass assignment".into() });
    }

    None
}

/// Classify all endpoints and group by category.
pub fn classify_all(endpoints: &[String]) -> Vec<EndpointClass> {
    endpoints.iter()
        .filter_map(|e| classify_endpoint(e))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_classify_login() {
        let c = classify_endpoint("/api/v1/login").unwrap();
        assert_eq!(c.category, "Authentication");
        assert_eq!(c.risk_level, "HIGH");
    }
    #[test]
    fn test_classify_payment() {
        let c = classify_endpoint("/checkout/payment").unwrap();
        assert_eq!(c.category, "Payment");
    }
    #[test]
    fn test_classify_upload() {
        let c = classify_endpoint("/upload/profile-pic").unwrap();
        assert_eq!(c.category, "File Upload");
    }
    #[test]
    fn test_classify_admin() {
        let c = classify_endpoint("/admin/panel").unwrap();
        assert_eq!(c.category, "Admin Panel");
    }
    #[test]
    fn test_classify_2fa() {
        let c = classify_endpoint("/api/2fa/verify").unwrap();
        assert_eq!(c.category, "2FA");
    }
    #[test]
    fn test_unknown_endpoint() {
        let c = classify_endpoint("/static/style.css");
        assert!(c.is_none());
    }
}
