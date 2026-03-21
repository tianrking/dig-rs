//! DNS resolver implementation
//!
//! Cross-platform resolver configuration reading

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use tracing::{debug, warn};

use crate::error::{DigError, Result};

/// DNS resolver configuration
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// DNS server addresses
    pub nameservers: Vec<SocketAddr>,
    /// Search domains
    pub search: Vec<String>,
    /// Local domain
    pub domain: Option<String>,
    /// Number of dots before doing absolute query
    pub ndots: u32,
    /// Query timeout
    pub timeout: Duration,
    /// Number of retry attempts
    pub attempts: u32,
    /// Enable DNSSEC
    pub dnssec: bool,
    /// Use round-robin selection of nameservers
    pub rotate: bool,
    /// Enable EDNS0
    pub edns0: bool,
    /// Use TCP for queries
    pub use_tcp: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            nameservers: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
            ],
            search: Vec::new(),
            domain: None,
            ndots: 1,
            timeout: Duration::from_secs(5),
            attempts: 3,
            dnssec: false,
            rotate: false,
            edns0: true,
            use_tcp: false,
        }
    }
}

impl ResolverConfig {
    /// Create a new resolver config with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Load resolver configuration from system
    pub fn from_system() -> Self {
        let config = Self::default();

        // Try to read from resolv.conf
        #[cfg(unix)]
        {
            if let Ok(loaded) = Self::from_resolv_conf("/etc/resolv.conf") {
                return loaded;
            }
        }

        // Windows: use system DNS servers
        #[cfg(windows)]
        {
            if let Ok(servers) = get_windows_dns_servers() {
                if !servers.is_empty() {
                    return Self {
                        nameservers: servers,
                        ..config
                    };
                }
            }
        }

        // macOS: also check for resolver directory
        #[cfg(target_os = "macos")]
        {
            // macOS can have per-domain resolvers in /etc/resolver/
            // For now, we'll just use the main resolv.conf
        }

        config
    }

    /// Parse a resolv.conf file
    #[cfg(unix)]
    pub fn from_resolv_conf<P: AsRef<Path>>(path: P) -> Result<Self> {
        use std::fs;
        use std::io::{BufRead, BufReader};

        let content = fs::File::open(path.as_ref())
            .map_err(|e| DigError::ConfigError(format!("Failed to open resolv.conf: {}", e)))?;

        let reader = BufReader::new(content);
        let mut config = Self::default();
        config.nameservers.clear();

        for line in reader.lines() {
            let line = line.map_err(|e| {
                DigError::ConfigError(format!("Failed to read resolv.conf: {}", e))
            })?;

            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
            if parts.len() != 2 {
                continue;
            }

            let keyword = parts[0].to_lowercase();
            let value = parts[1].trim();

            match keyword.as_str() {
                "nameserver" => {
                    if let Ok(addr) = parse_nameserver(value) {
                        config.nameservers.push(addr);
                    } else {
                        warn!("Failed to parse nameserver: {}", value);
                    }
                }
                "domain" => {
                    config.domain = Some(value.to_string());
                }
                "search" => {
                    config.search = value
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                }
                "options" => {
                    for opt in value.split_whitespace() {
                        match opt {
                            "ndots" => {
                                // Handled below with ndots:N format
                            }
                            opt if opt.starts_with("ndots:") => {
                                if let Ok(n) = opt[6..].parse() {
                                    config.ndots = n;
                                }
                            }
                            "timeout" => {
                                // Handled below with timeout:N format
                            }
                            opt if opt.starts_with("timeout:") => {
                                if let Ok(n) = opt[8..].parse() {
                                    config.timeout = Duration::from_secs(n);
                                }
                            }
                            "attempts" => {
                                // Handled below with attempts:N format
                            }
                            opt if opt.starts_with("attempts:") => {
                                if let Ok(n) = opt[9..].parse() {
                                    config.attempts = n;
                                }
                            }
                            "rotate" => {
                                config.rotate = true;
                            }
                            "no-rotate" => {
                                config.rotate = false;
                            }
                            "edns0" => {
                                config.edns0 = true;
                            }
                            "no-edns" | "no-edns0" => {
                                config.edns0 = false;
                            }
                            "dnssec" => {
                                config.dnssec = true;
                            }
                            "use-vc" | "usevc" => {
                                config.use_tcp = true;
                            }
                            "single-request" => {
                                // Not applicable for our implementation
                            }
                            "single-request-reopen" => {
                                // Not applicable for our implementation
                            }
                            _ => {
                                debug!("Unknown resolv.conf option: {}", opt);
                            }
                        }
                    }
                }
                _ => {
                    debug!("Unknown resolv.conf keyword: {}", keyword);
                }
            }
        }

        if config.nameservers.is_empty() {
            warn!("No nameservers found in resolv.conf, using defaults");
            config.nameservers = vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
            ];
        }

        debug!("Loaded resolver config: {:?}", config);
        Ok(config)
    }

    /// Add a nameserver
    pub fn add_nameserver(&mut self, addr: SocketAddr) {
        self.nameservers.push(addr);
    }

    /// Set search domains
    pub fn set_search(&mut self, search: Vec<String>) {
        self.search = search;
    }

    /// Get the default nameserver
    pub fn default_nameserver(&self) -> Option<SocketAddr> {
        self.nameservers.first().copied()
    }
}

/// Parse a nameserver address from resolv.conf
fn parse_nameserver(s: &str) -> std::result::Result<SocketAddr, String> {
    let s = s.trim();

    // Try parsing as IP address with default port 53
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }

    // Try parsing as socket address
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }

    Err(format!("Invalid nameserver address: {}", s))
}

/// Get DNS servers on Windows
#[cfg(windows)]
fn get_windows_dns_servers() -> Result<Vec<SocketAddr>> {
    use std::process::Command;

    let output = Command::new("powershell")
        .args([
            "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses | Sort-Object -Unique",
        ])
        .output()
        .map_err(|e| DigError::ConfigError(format!("Failed to get Windows DNS servers: {}", e)))?;

    if !output.status.success() {
        // Fallback to ipconfig
        let output = Command::new("ipconfig")
            .args(["/all"])
            .output()
            .map_err(|e| {
                DigError::ConfigError(format!("Failed to run ipconfig: {}", e))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut servers = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.contains("DNS Servers") || line.contains("DNS 服务器") {
                if let Some(addr_str) = line.split(':').nth(1) {
                    let addr_str = addr_str.trim();
                    if let Ok(ip) = addr_str.parse::<IpAddr>() {
                        servers.push(SocketAddr::new(ip, 53));
                    }
                }
            }
        }

        if servers.is_empty() {
            // Use default DNS servers
            servers = vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
            ];
        }

        return Ok(servers);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut servers = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if let Ok(ip) = line.parse::<IpAddr>() {
            servers.push(SocketAddr::new(ip, 53));
        }
    }

    if servers.is_empty() {
        servers = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
        ];
    }

    Ok(servers)
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn get_windows_dns_servers() -> Result<Vec<SocketAddr>> {
    Ok(vec![])
}

/// DNS resolver for executing queries
pub struct DigResolver {
    config: ResolverConfig,
}

impl DigResolver {
    /// Create a new resolver with the given configuration
    pub fn new(config: ResolverConfig) -> Self {
        Self { config }
    }

    /// Create a resolver with system configuration
    pub fn from_system_config() -> Self {
        Self::new(ResolverConfig::from_system())
    }

    /// Get the resolver configuration
    pub fn config(&self) -> &ResolverConfig {
        &self.config
    }

    /// Get mutable access to the resolver configuration
    pub fn config_mut(&mut self) -> &mut ResolverConfig {
        &mut self.config
    }

    /// Get the nameservers
    pub fn nameservers(&self) -> &[SocketAddr] {
        &self.config.nameservers
    }
}

impl Default for DigResolver {
    fn default() -> Self {
        Self::from_system_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nameserver() {
        let addr = parse_nameserver("8.8.8.8").unwrap();
        assert_eq!(addr.port(), 53);

        let addr = parse_nameserver("8.8.8.8:5353").unwrap();
        assert_eq!(addr.port(), 5353);

        let addr = parse_nameserver("2001:4860:4860::8888").unwrap();
        assert_eq!(addr.port(), 53);
    }
}
