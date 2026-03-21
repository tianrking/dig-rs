//! Configuration types for dig-rs
//!
//! This module provides comprehensive configuration options that mirror
//! BIND9 dig's capabilities while adding modern features like JSON output.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default EDNS buffer size (1232 bytes as recommended by DNS flag day)
pub const DEFAULT_EDNS_BUFSIZE: u16 = 1232;

/// Default UDP timeout in seconds
pub const DEFAULT_UDP_TIMEOUT: u64 = 5;

/// Default TCP timeout in seconds
pub const DEFAULT_TCP_TIMEOUT: u64 = 10;

/// Default retry count
pub const DEFAULT_RETRIES: u32 = 3;

/// DNS query class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum QueryClass {
    /// Internet (IN)
    #[default]
    IN,
    /// Chaos (CH)
    CH,
    /// Hesiod (HS)
    HS,
    /// None (for updates)
    NONE,
    /// Any class
    ANY,
}

impl std::fmt::Display for QueryClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryClass::IN => write!(f, "IN"),
            QueryClass::CH => write!(f, "CH"),
            QueryClass::HS => write!(f, "HS"),
            QueryClass::NONE => write!(f, "NONE"),
            QueryClass::ANY => write!(f, "ANY"),
        }
    }
}

impl std::str::FromStr for QueryClass {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "IN" | "INTERNET" => Ok(QueryClass::IN),
            "CH" | "CHAOS" => Ok(QueryClass::CH),
            "HS" | "HESIOD" => Ok(QueryClass::HS),
            "NONE" => Ok(QueryClass::NONE),
            "ANY" => Ok(QueryClass::ANY),
            _ => Err(format!("Unknown query class: {}", s)),
        }
    }
}

/// Transport protocol for DNS queries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Transport {
    /// UDP (default for most queries)
    #[default]
    Udp,
    /// TCP (for large responses, zone transfers)
    Tcp,
    /// DNS over TLS (DoT)
    Tls,
    /// DNS over HTTPS (DoH)
    Https,
    /// DNS over QUIC (DoQ)
    Quic,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Udp => write!(f, "UDP"),
            Transport::Tcp => write!(f, "TCP"),
            Transport::Tls => write!(f, "TLS"),
            Transport::Https => write!(f, "HTTPS"),
            Transport::Quic => write!(f, "QUIC"),
        }
    }
}

/// EDNS(0) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdnsConfig {
    /// EDNS version (0 for EDNS(0))
    pub version: u8,
    /// UDP buffer size
    pub udp_size: u16,
    /// Enable EDNS padding (for privacy)
    pub padding: bool,
    /// Enable NSID (Name Server Identifier)
    pub nsid: bool,
    /// Client subnet for ECS (EDNS Client Subnet)
    pub client_subnet: Option<IpAddr>,
    /// Client subnet prefix length
    pub client_subnet_prefix: u8,
    /// Cookie option
    pub cookie: Option<Vec<u8>>,
}

impl Default for EdnsConfig {
    fn default() -> Self {
        Self {
            version: 0,
            udp_size: DEFAULT_EDNS_BUFSIZE,
            padding: false,
            nsid: false,
            client_subnet: None,
            client_subnet_prefix: 0,
            cookie: None,
        }
    }
}

/// DNSSEC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecConfig {
    /// Set DNSSEC OK bit (DO)
    pub do_flag: bool,
    /// Set Checking Disabled bit (CD)
    pub cd_flag: bool,
    /// Set Authenticated Data bit (AD)
    pub ad_flag: bool,
    /// Request DNSSEC records (RRSIG, DNSKEY, etc.)
    pub dnssec: bool,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            do_flag: false,
            cd_flag: false,
            ad_flag: false,
            dnssec: false,
        }
    }
}

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutputFormat {
    /// Standard dig output format
    #[default]
    Standard,
    /// Short output (just the answers)
    Short,
    /// JSON output
    Json,
    /// YAML output
    Yaml,
    /// Table format
    Table,
    /// XML format
    Xml,
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    /// Show comments in output
    pub comments: bool,
    /// Show question section
    pub question: bool,
    /// Show answer section
    pub answer: bool,
    /// Show authority section
    pub authority: bool,
    /// Show additional section
    pub additional: bool,
    /// Show statistics
    pub stats: bool,
    /// Show TTL in human-readable format
    pub ttl_units: bool,
    /// Show multi-line records
    pub multiline: bool,
    /// Color output
    pub color: bool,
    /// Show header
    pub header: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Standard,
            comments: true,
            question: true,
            answer: true,
            authority: true,
            additional: true,
            stats: true,
            ttl_units: false,
            multiline: false,
            color: false,
            header: true,
        }
    }
}

/// DNS server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server address (IP or hostname)
    pub address: String,
    /// Server port
    pub port: u16,
    /// Transport protocol
    pub transport: Transport,
    /// TLS hostname for DoT/DoH
    pub tls_hostname: Option<String>,
    /// CA file for TLS verification
    pub tls_ca_file: Option<String>,
    /// HTTP path for DoH
    pub https_path: Option<String>,
    /// Use HTTP GET for DoH
    pub https_get: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: 53,
            transport: Transport::Udp,
            tls_hostname: None,
            tls_ca_file: None,
            https_path: Some("/dns-query".to_string()),
            https_get: false,
        }
    }
}

impl ServerConfig {
    /// Create a new server config from an address string
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            ..Default::default()
        }
    }

    /// Create a server config with port
    pub fn with_port(address: impl Into<String>, port: u16) -> Self {
        Self {
            address: address.into(),
            port,
            ..Default::default()
        }
    }

    /// Parse server address (supports @server, @server#port formats)
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.strip_prefix('@').unwrap_or(s);

        if let Some(hash_pos) = s.find('#') {
            let (addr, port_str) = s.split_at(hash_pos);
            let port: u16 = port_str[1..].parse().ok()?;
            Some(Self::with_port(addr, port))
        } else {
            Some(Self::new(s))
        }
    }
}

/// Main configuration for dig operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigConfig {
    // Query parameters
    /// Domain name to query
    pub name: String,
    /// Query type
    pub query_type: String,
    /// Query class
    pub query_class: QueryClass,

    // Server configuration
    /// DNS servers to query
    pub servers: Vec<ServerConfig>,
    /// Use system default servers if none specified
    pub use_system_servers: bool,

    // Transport options
    /// Force specific transport
    pub transport: Transport,
    /// Bind to specific local address
    pub bind_address: Option<IpAddr>,
    /// Source port
    pub source_port: Option<u16>,

    // Timing options
    /// Query timeout
    pub timeout: Duration,
    /// Number of retries
    pub retries: u32,
    /// Interval between retries
    pub retry_interval: Duration,

    // EDNS options
    /// EDNS configuration
    pub edns: EdnsConfig,

    // DNSSEC options
    /// DNSSEC configuration
    pub dnssec: DnssecConfig,

    // Query flags
    /// Recursion Desired
    pub recurse: bool,
    /// Authoritative Answer only
    pub aa_only: bool,
    /// Set AA flag in query
    pub aa_flag: bool,
    /// Ignore truncation (try TCP anyway)
    pub ignore_truncation: bool,
    /// Header only (no question)
    pub header_only: bool,
    /// Opcode (QUERY, NOTIFY, UPDATE)
    pub opcode: u16,

    // Special modes
    /// Trace delegation path from root
    pub trace: bool,
    /// DNS reverse lookup
    pub reverse: bool,
    /// Search list for relative names
    pub search: bool,
    /// Show all nameservers for domain
    pub nssearch: bool,
    /// Compare responses from multiple servers
    pub compare: bool,

    // Output options
    /// Output configuration
    pub output: OutputConfig,

    // IPv4/IPv6 options
    /// Use IPv4 only
    pub ipv4: bool,
    /// Use IPv6 only
    pub ipv6: bool,

    // TSIG options
    /// TSIG key name
    pub tsig_name: Option<String>,
    /// TSIG key data
    pub tsig_key: Option<String>,
    /// TSIG algorithm
    pub tsig_algorithm: Option<String>,
}

impl Default for DigConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            query_type: "A".to_string(),
            query_class: QueryClass::IN,
            servers: Vec::new(),
            use_system_servers: true,
            transport: Transport::Udp,
            bind_address: None,
            source_port: None,
            timeout: Duration::from_secs(DEFAULT_UDP_TIMEOUT),
            retries: DEFAULT_RETRIES,
            retry_interval: Duration::from_secs(1),
            edns: EdnsConfig::default(),
            dnssec: DnssecConfig::default(),
            recurse: true,
            aa_only: false,
            aa_flag: false,
            ignore_truncation: false,
            header_only: false,
            opcode: 0, // QUERY
            trace: false,
            reverse: false,
            search: true,
            nssearch: false,
            compare: false,
            output: OutputConfig::default(),
            ipv4: false,
            ipv6: false,
            tsig_name: None,
            tsig_key: None,
            tsig_algorithm: None,
        }
    }
}

impl DigConfig {
    /// Create a new configuration for a domain query
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Set query type
    pub fn with_query_type(mut self, query_type: impl Into<String>) -> Self {
        self.query_type = query_type.into();
        self
    }

    /// Set query class
    pub fn with_query_class(mut self, query_class: QueryClass) -> Self {
        self.query_class = query_class;
        self
    }

    /// Add a server
    pub fn with_server(mut self, server: ServerConfig) -> Self {
        self.servers.push(server);
        self.use_system_servers = false;
        self
    }

    /// Set transport
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable DNSSEC
    pub fn with_dnssec(mut self, enable: bool) -> Self {
        self.dnssec.dnssec = enable;
        self.dnssec.do_flag = enable;
        self
    }

    /// Enable trace mode
    pub fn with_trace(mut self, enable: bool) -> Self {
        self.trace = enable;
        self
    }

    /// Set output format
    pub fn with_output_format(mut self, format: OutputFormat) -> Self {
        self.output.format = format;
        self
    }

    /// Enable JSON output
    pub fn json(mut self) -> Self {
        self.output.format = OutputFormat::Json;
        self
    }

    /// Enable short output
    pub fn short(mut self) -> Self {
        self.output.format = OutputFormat::Short;
        self.output.comments = false;
        self.output.stats = false;
        self
    }

    /// Enable reverse lookup
    pub fn with_reverse(mut self, ip: impl Into<String>) -> Self {
        self.reverse = true;
        self.name = ip.into();
        self.query_type = "PTR".to_string();
        self
    }

    /// Build resolver socket addresses
    pub fn resolver_addresses(&self) -> Vec<SocketAddr> {
        self.servers
            .iter()
            .filter_map(|s| {
                let addr: IpAddr = s.address.parse().ok()?;
                Some(SocketAddr::new(addr, s.port))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_class_parsing() {
        assert_eq!("IN".parse::<QueryClass>().unwrap(), QueryClass::IN);
        assert_eq!("CHAOS".parse::<QueryClass>().unwrap(), QueryClass::CH);
        assert_eq!("any".parse::<QueryClass>().unwrap(), QueryClass::ANY);
    }

    #[test]
    fn test_server_config_parsing() {
        let config = ServerConfig::parse("@8.8.8.8").unwrap();
        assert_eq!(config.address, "8.8.8.8");
        assert_eq!(config.port, 53);

        let config = ServerConfig::parse("@8.8.8.8#5353").unwrap();
        assert_eq!(config.address, "8.8.8.8");
        assert_eq!(config.port, 5353);
    }

    #[test]
    fn test_dig_config_builder() {
        let config = DigConfig::new("example.com")
            .with_query_type("AAAA")
            .with_query_class(QueryClass::IN)
            .json();

        assert_eq!(config.name, "example.com");
        assert_eq!(config.query_type, "AAAA");
        assert_eq!(config.output.format, OutputFormat::Json);
    }
}
