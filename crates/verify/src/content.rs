/// Common web content wordlists to try in order.
pub const WORDLIST_CASCADE: &[&str] = &[
    "common.txt",
    "raft-medium-directories.txt",
    "raft-large-directories.txt",
    "api-endpoints.txt",
    "graphql.txt",
    "iis-shortname.txt",
];

/// Extensions to try per wordlist level.
pub const EXTENSIONS_LEVEL1: &[&str] = &["php", "html", "js"];
pub const EXTENSIONS_LEVEL2: &[&str] = &["php", "html", "js", "json", "xml", "bak", "txt", "env"];
pub const EXTENSIONS_LEVEL3: &[&str] = &[
    "php", "html", "js", "json", "xml", "bak", "txt", "env", "sql", "tar.gz", "zip", "old", "swp",
    "yaml", "yml", "toml", "conf", "config", "log", "db",
];

#[derive(Debug, Clone, serde::Serialize)]
pub struct ContentDiscoveryCascade {
    pub target_url: String,
    pub wordlist: String,
    pub level: u8,
    pub ffuf_command: String,
}

/// Build the content discovery cascade for a target URL.
/// Returns ffuf commands ordered by depth.
pub fn build_cascade(target_url: &str, seclists_path: &str) -> Vec<String> {
    let mut commands = Vec::new();

    // Level 1: Fast common paths
    let wordlist1 = format!("{}/Discovery/Web-Content/common.txt", seclists_path);
    commands.push(format!(
        "ffuf -u {}/FUZZ -w {} -mc 200,204,301,302,307,401,403,405 -fc 404 -t 50 -o ffuf-common.json",
        target_url.trim_end_matches('/'),
        wordlist1
    ));

    // Level 2: Raft medium directories
    let wordlist2 = format!(
        "{}/Discovery/Web-Content/raft-medium-directories.txt",
        seclists_path
    );
    commands.push(format!(
        "ffuf -u {}/FUZZ -w {} -mc 200,204,301,302,307,401,403,405 -fc 404 -t 30 -e .php,.html,.js,.json,.bak,.txt,.env -o ffuf-raft.json",
        target_url.trim_end_matches('/'),
        wordlist2
    ));

    // Level 3: API endpoints
    let wordlist3 = format!(
        "{}/Discovery/Web-Content/api/api-endpoints.txt",
        seclists_path
    );
    commands.push(format!(
        "ffuf -u {}/FUZZ -w {} -mc 200,204,301,302,307,401,403 -fc 404 -t 20 -o ffuf-api.json",
        target_url.trim_end_matches('/'),
        wordlist3
    ));

    commands
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_build_cascade() {
        let commands = build_cascade("https://example.com", "/home/ryasr/wordlists/SecLists");
        assert_eq!(commands.len(), 3);
        assert!(commands[0].contains("ffuf"));
        assert!(commands[0].contains("common.txt"));
        assert!(commands[1].contains("raft-medium"));
        assert!(commands[2].contains("api-endpoints"));
    }
}
