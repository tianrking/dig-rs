//! Structured JSON output for modern DNS tooling
//!
//! This module provides JSON-first output designed for:
//! - Machine parsing and automation
//! - API integration
//! - Monitoring and alerting
//! - DevOps workflows

use std::io;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use dig_core::lookup::LookupResult;

/// Structured DNS response
///
/// This is the primary JSON schema for dig-rs output,
/// designed to be both human-readable and machine-parsable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredDnsResponse {
    /// Domain queried
    pub domain: String,
    /// Query status
    pub status: ResponseStatus,
    /// Records grouped by type
    pub records: RecordsByType,
    /// Resolver information
    pub resolver: ResolverInfo,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// Additional metadata
    pub metadata: ResponseMetadata,
}

/// Response status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseStatus {
    /// HTTP-style status code
    pub code: u16,
    /// Status text (OK, ERROR, NXDOMAIN)
    pub text: String,
    /// DNS response code
    pub rcode: String,
    /// Whether the query was successful
    pub success: bool,
}

/// Records grouped by type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordsByType {
    /// A records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub A: Option<Vec<IpRecord>>,
    /// AAAA records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub AAAA: Option<Vec<IpRecord>>,
    /// CNAME records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub CNAME: Option<Vec<String>>,
    /// MX records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub MX: Option<Vec<MxRecord>>,
    /// TXT records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub TXT: Option<Vec<Vec<String>>>,
    /// NS records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub NS: Option<Vec<String>>,
    /// SOA records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub SOA: Option<Vec<SoaRecord>>,
    /// SRV records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub SRV: Option<Vec<SrvRecord>>,
    /// Other record types
    #[serde(flatten)]
    pub other: HashMap<String, Vec<Value>>,
}

/// IP address record (A/AAAA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRecord {
    /// IP address
    pub address: String,
    /// TTL in seconds
    pub ttl: u32,
}

/// MX record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    /// Preference
    pub preference: u16,
    /// Mail exchange hostname
    pub exchange: String,
    /// TTL in seconds
    pub ttl: u32,
}

/// SOA record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoaRecord {
    /// Primary name server
    pub mname: String,
    /// Responsible mailbox
    pub rname: String,
    /// Serial number
    pub serial: u32,
    /// Refresh interval
    pub refresh: u32,
    /// Retry interval
    pub retry: u32,
    /// Expire limit
    pub expire: u32,
    /// Minimum TTL
    pub minimum: u32,
    /// TTL in seconds
    pub ttl: u32,
}

/// SRV record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrvRecord {
    /// Priority
    pub priority: u16,
    /// Weight
    pub weight: u16,
    /// Port
    pub port: u16,
    /// Target hostname
    pub target: String,
    /// TTL in seconds
    pub ttl: u32,
}

/// Resolver information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverInfo {
    /// Resolver address
    pub address: String,
    /// Resolver type (system, custom, DoH, DoT)
    pub resolver_type: String,
    /// Transport used (UDP, TCP, DoT, DoH)
    pub transport: String,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Query time in milliseconds
    pub latency_ms: u64,
    /// Response size in bytes
    pub size_bytes: usize,
    /// Number of answers received
    pub answer_count: usize,
}

/// Response metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    /// Query timestamp
    pub timestamp: String,
    /// Query type
    pub query_type: String,
    /// Query class
    pub query_class: String,
    /// Message ID
    pub message_id: u16,
    /// DNS flags
    pub flags: DnsFlags,
}

/// DNS flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFlags {
    /// Authoritative Answer
    pub aa: bool,
    /// Truncated
    pub tc: bool,
    /// Recursion Desired
    pub rd: bool,
    /// Recursion Available
    pub ra: bool,
    /// Authentic Data (DNSSEC)
    pub ad: bool,
    /// Checking Disabled (DNSSEC)
    pub cd: bool,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Domain checked
    pub domain: String,
    /// Overall health status
    pub health: HealthStatus,
    /// Individual checks
    pub checks: Vec<HealthCheckItem>,
    /// Issues found
    pub issues: Vec<HealthIssue>,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Timestamp
    pub timestamp: String,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Status: healthy, warning, critical, failed
    pub status: String,
    /// Status score (0-100)
    pub score: u8,
}

/// Health check item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckItem {
    /// Check name
    pub name: String,
    /// Check description
    pub description: String,
    /// Status: pass, warning, fail, skip
    pub status: String,
    /// Value (if applicable)
    pub value: Option<String>,
    /// Expected value
    pub expected: Option<String>,
}

/// Health issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthIssue {
    /// Severity: info, warning, error, critical
    pub severity: String,
    /// Category: resolution, performance, consistency, security
    pub category: String,
    /// Description
    pub description: String,
    /// Details
    pub details: Option<String>,
}

/// Comparison response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResponse {
    /// Domain queried
    pub domain: String,
    /// Query type
    pub query_type: String,
    /// Results from each resolver
    pub resolvers: Vec<ResolverComparison>,
    /// Consistency check
    pub consistency: ConsistencyInfo,
    /// Timestamp
    pub timestamp: String,
}

/// Resolver comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverComparison {
    /// Resolver identifier
    pub resolver: String,
    /// Query successful
    pub success: bool,
    /// Latency in milliseconds
    pub latency_ms: u64,
    /// Answers (IPs for A/AAAA queries)
    pub answers: Vec<String>,
    /// Response code
    pub rcode: String,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Consistency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyInfo {
    /// All resolvers returned consistent results
    pub consistent: bool,
    /// Number of unique result sets
    pub unique_results: usize,
    /// Inconsistencies detected
    pub inconsistencies: Vec<InconsistencyInfo>,
}

/// Inconsistency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InconsistencyInfo {
    /// Type: different_answers, partial_failure, different_rcode, timing_anomaly
    pub inconsistency_type: String,
    /// Description
    pub description: String,
    /// Affected resolvers
    pub affected_resolvers: Vec<String>,
}

/// Structured JSON formatter
pub struct StructuredFormatter {
    /// Pretty print JSON
    pretty: bool,
    /// Include metadata
    include_metadata: bool,
}

impl StructuredFormatter {
    /// Create a new structured formatter
    pub fn new() -> Self {
        Self {
            pretty: true,
            include_metadata: true,
        }
    }

    /// Create with custom settings
    pub fn with_settings(pretty: bool, include_metadata: bool) -> Self {
        Self {
            pretty,
            include_metadata,
        }
    }

    /// Format lookup result as structured JSON
    pub fn format_lookup(&self, result: &LookupResult) -> Result<String, serde_json::Error> {
        let response = self.to_structured_response(result);

        if self.pretty {
            serde_json::to_string_pretty(&response)
        } else {
            serde_json::to_string(&response)
        }
    }

    /// Convert lookup result to structured response
    fn to_structured_response(&self, result: &LookupResult) -> StructuredDnsResponse {
        let (status_code, status_text, success) = match result.message.rcode.as_str() {
            "NOERROR" => (200, "OK".to_string(), true),
            "NXDOMAIN" => (404, "Not Found".to_string(), true),
            _ => (500, "Server Error".to_string(), false),
        };

        let mut records_by_type = RecordsByType {
            A: None,
            AAAA: None,
            CNAME: None,
            MX: None,
            TXT: None,
            NS: None,
            SOA: None,
            SRV: None,
            other: HashMap::new(),
        };

        // Group records by type
        for record in &result.message.answer {
            match record.rtype.as_str() {
                "A" => {
                    if records_by_type.A.is_none() {
                        records_by_type.A = Some(Vec::new());
                    }
                    records_by_type.A.as_mut().unwrap().push(IpRecord {
                        address: record.rdata.clone(),
                        ttl: record.ttl,
                    });
                }
                "AAAA" => {
                    if records_by_type.AAAA.is_none() {
                        records_by_type.AAAA = Some(Vec::new());
                    }
                    records_by_type.AAAA.as_mut().unwrap().push(IpRecord {
                        address: record.rdata.clone(),
                        ttl: record.ttl,
                    });
                }
                "CNAME" => {
                    if records_by_type.CNAME.is_none() {
                        records_by_type.CNAME = Some(Vec::new());
                    }
                    records_by_type.CNAME.as_mut().unwrap().push(record.rdata.clone());
                }
                "MX" => {
                    if records_by_type.MX.is_none() {
                        records_by_type.MX = Some(Vec::new());
                    }
                    // Parse MX record (format: "priority exchange")
                    if let Some(space_pos) = record.rdata.find(' ') {
                        let preference = record.rdata[..space_pos].parse().unwrap_or(0);
                        let exchange = record.rdata[space_pos + 1..].trim().to_string();
                        records_by_type.MX.as_mut().unwrap().push(MxRecord {
                            preference,
                            exchange,
                            ttl: record.ttl,
                        });
                    }
                }
                "TXT" => {
                    if records_by_type.TXT.is_none() {
                        records_by_type.TXT = Some(Vec::new());
                    }
                    // TXT records can have multiple strings
                    let txt_parts: Vec<String> = record.rdata
                        .split('"')
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    records_by_type.TXT.as_mut().unwrap().push(txt_parts);
                }
                "NS" => {
                    if records_by_type.NS.is_none() {
                        records_by_type.NS = Some(Vec::new());
                    }
                    records_by_type.NS.as_mut().unwrap().push(record.rdata.clone());
                }
                "SOA" => {
                    // Parse SOA record
                    let parts: Vec<&str> = record.rdata.split_whitespace().collect();
                    if parts.len() >= 7 {
                        if records_by_type.SOA.is_none() {
                            records_by_type.SOA = Some(Vec::new());
                        }
                        records_by_type.SOA.as_mut().unwrap().push(SoaRecord {
                            mname: parts[0].to_string(),
                            rname: parts[1].to_string(),
                            serial: parts[2].parse().unwrap_or(0),
                            refresh: parts[3].parse().unwrap_or(0),
                            retry: parts[4].parse().unwrap_or(0),
                            expire: parts[5].parse().unwrap_or(0),
                            minimum: parts[6].parse().unwrap_or(0),
                            ttl: record.ttl,
                        });
                    }
                }
                "SRV" => {
                    let parts: Vec<&str> = record.rdata.split_whitespace().collect();
                    if parts.len() >= 4 {
                        if records_by_type.SRV.is_none() {
                            records_by_type.SRV = Some(Vec::new());
                        }
                        records_by_type.SRV.as_mut().unwrap().push(SrvRecord {
                            priority: parts[0].parse().unwrap_or(0),
                            weight: parts[1].parse().unwrap_or(0),
                            port: parts[2].parse().unwrap_or(0),
                            target: parts[3].to_string(),
                            ttl: record.ttl,
                        });
                    }
                }
                _ => {
                    // Other record types
                    if !records_by_type.other.contains_key(&record.rtype) {
                        records_by_type.other.insert(record.rtype.clone(), Vec::new());
                    }
                    records_by_type.other.get_mut(&record.rtype).unwrap().push(json!({
                        "data": record.rdata,
                        "ttl": record.ttl,
                    }));
                }
            }
        }

        StructuredDnsResponse {
            domain: result.query_name.clone(),
            status: ResponseStatus {
                code: status_code,
                text: status_text,
                rcode: result.message.rcode.clone(),
                success,
            },
            records: records_by_type,
            resolver: ResolverInfo {
                address: result.server.clone(),
                resolver_type: "custom".to_string(), // TODO: detect resolver type
                transport: "UDP".to_string(), // TODO: detect transport
            },
            performance: PerformanceMetrics {
                latency_ms: result.query_time_ms,
                size_bytes: result.message_size,
                answer_count: result.message.answer.len(),
            },
            metadata: ResponseMetadata {
                timestamp: result.timestamp.clone(),
                query_type: result.query_type.clone(),
                query_class: result.query_class.clone(),
                message_id: result.message.id,
                flags: DnsFlags {
                    aa: result.message.flags.aa,
                    tc: result.message.flags.tc,
                    rd: result.message.flags.rd,
                    ra: result.message.flags.ra,
                    ad: result.message.flags.ad,
                    cd: result.message.flags.cd,
                },
            },
        }
    }
}

impl Default for StructuredFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structured_formatter_create() {
        let formatter = StructuredFormatter::new();
        assert!(formatter.pretty);
    }

    #[test]
    fn test_ip_record_serialization() {
        let record = IpRecord {
            address: "1.1.1.1".to_string(),
            ttl: 300,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("1.1.1.1"));
        assert!(json.contains("300"));
    }

    #[test]
    fn test_mx_record_serialization() {
        let record = MxRecord {
            preference: 10,
            exchange: "mail.example.com".to_string(),
            ttl: 3600,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("10"));
        assert!(json.contains("mail.example.com"));
    }

    #[test]
    fn test_response_status() {
        let status = ResponseStatus {
            code: 200,
            text: "OK".to_string(),
            rcode: "NOERROR".to_string(),
            success: true,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("200"));
        assert!(json.contains("NOERROR"));
    }
}
