/// Pattern: API endpoint paths like /api/v1/, /v2/, /rest/
pub const API_ENDPOINT: &str = r#""(?:/?(?:api|v[0-9]+|rest|graphql|swagger|docs)/[^"']{0,200})""#;

/// Pattern: AWS access keys
pub const AWS_KEY: &str = r#"AKIA[0-9A-Z]{16}"#;

/// Pattern: GraphQL endpoint references
pub const GRAPHQL_ENDPOINT: &str = r#""[^"']*(?:graphql|gql|query)[^"']*""#;

/// Pattern: WebSocket URLs and constructor calls
pub const WEBSOCKET: &str = r#"(?:wss?://[^"'\s]{3,200}|new\s+WebSocket\s*\(\s*['\"][^'\"]+['\"])"#;

/// Pattern: postMessage calls and message event listeners
pub const POSTMESSAGE: &str = r#"\.postMessage\s*\(|addEventListener\s*\(\s*['\"]message['\"]"#;

/// Pattern: Source map references
pub const SOURCEMAP: &str = r#"sourceMappingURL=([^\s]+)"#;

/// Pattern: Cloud storage buckets (S3, GCS, Azure)
pub const CLOUD_BUCKET: &str = r#"(?:[a-z0-9-]+\.s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|[a-z0-9-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com)"#;

/// Pattern: Internal/hidden domains
pub const INTERNAL_DOMAIN: &str = r#""(?:https?://)?(?:internal|staging|dev|stage|test|admin|management|intranet|private|corp)\.[^"']{2,100}""#;

/// Pattern: JWT tokens
pub const JWT_TOKEN: &str = r#"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"#;

/// Pattern: Firebase URLs
pub const FIREBASE_URL: &str = r#"[a-z0-9-]+\.firebaseio\.com"#;

/// Pattern: Hidden/sensitive endpoints (admin, debug, config, etc.)
pub const HIDDEN_ENDPOINT: &str = r#""[^"']*(?:admin|debug|config|internal|hidden|private|secret|token|credential|password|key|backup|log|dump)[^"']*""#;

/// Pattern: Google API keys, OAuth client IDs
pub const GOOGLE_API_KEY: &str = r#"AIza[0-9A-Za-z_-]{35}"#;

/// Pattern: Slack tokens/bots
pub const SLACK_TOKEN: &str = r#"xox[baprs]-[0-9a-zA-Z-]{10,}"#;

/// Pattern: Generic high-entropy strings (potential secrets) — base64-ish, 32+ chars
pub const HIGH_ENTROPY: &str = r#""[a-zA-Z0-9+/=_\-]{40,120}""#;

/// Pattern: postMessage origin validation (dangerous: * or missing check)
pub const POSTMESSAGE_ORIGIN: &str = r#"postMessage\s*\([^,]+,\s*['\"]\*['\"]"#;
