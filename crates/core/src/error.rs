use thiserror::Error;

#[derive(Error, Debug)]
pub enum AegisError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Plugin error: {0}")]
    Plugin(String),
    #[error("Tool execution error: {0}")]
    ToolExecution(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Rate limited: retry after {0}ms")]
    RateLimited(u64),
    #[error("Scope violation: {0}")]
    ScopeViolation(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type AegisResult<T> = Result<T, AegisError>;
